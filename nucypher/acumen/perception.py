"""
 This file is part of nucypher.

 nucypher is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 nucypher is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with nucypher.  If not, see <https://www.gnu.org/licenses/>.
"""


import random
from collections import OrderedDict
from collections import namedtuple, defaultdict
from typing import Iterator, Callable, List, Dict, Union, Optional

import binascii
import maya
from bytestring_splitter import BytestringSplitter
from constant_sorrow.constants import NO_KNOWN_NODES

from nucypher.crypto.api import keccak_digest
from nucypher.utilities.logging import Logger
from .comprehension import PRUNING_STRATEGIES, BUCKETS
from .nicknames import Nickname

NO_KNOWN_NODES.bool_value(False)


class FleetSensor:
    """
    A representation of a fleet of NuCypher nodes, and more!.
    """
    _checksum = NO_KNOWN_NODES
    _nickname = NO_KNOWN_NODES
    _tracking = False
    most_recent_node_change = NO_KNOWN_NODES
    snapshot_splitter = BytestringSplitter(32, 4)
    log = Logger("Learning")
    FleetState = namedtuple("FleetState", ("nickname", "icon", "nodes", "updated", "checksum"))

    class UnknownLabel(KeyError):
        pass

    class UnknownNode(ValueError):
        pass

    class WrongDomain(ValueError):
        pass

    def __init__(self, domain: str, discovery_labels=None):

        # Public
        self.domain = domain
        self.discovery_labels = discovery_labels  # TODO: Only track certain labels?
        self.additional_nodes_to_track = []
        self.updated = maya.now()

        # Private
        self.__states = OrderedDict()
        self.__nodes = OrderedDict()       # memory.  # TODO: keep both collections or reduce to use one?
        self.__marked = defaultdict(list)  # bucketing.

    def track(self, node_or_sprout) -> None:
        if node_or_sprout.domain != self.domain:
            raise self.WrongDomain(f'Learning about {self.domain} but node is on {node_or_sprout.domain}')
        self.__nodes[node_or_sprout.checksum_address] = node_or_sprout
        if self._tracking:
            self.log.info("Updating fleet state after saving node {}".format(node_or_sprout))
            self.record_fleet_state()

    def __bool__(self):
        return bool(self.__nodes)

    def __contains__(self, item):
        return item in self.__nodes.keys() or item in self.__nodes.values()

    def __len__(self):
        return len(self.__nodes)

    def __eq__(self, other):
        return self.__nodes == other.__nodes

    def __repr__(self):
        return self.__nodes.__repr__()

    def population(self):
        return len(self) + len(self.additional_nodes_to_track)

    @property
    def states(self):
        return self.__states

    @property
    def checksum(self):
        return self._checksum

    @checksum.setter
    def checksum(self, checksum_value):
        self._checksum = checksum_value
        self._nickname = Nickname.from_seed(checksum_value, length=1)

    @property
    def nickname(self):
        return self._nickname

    @property
    def icon(self) -> str:
        if self.nickname is NO_KNOWN_NODES:
            return str(NO_KNOWN_NODES)
        return self.nickname.icon

    def addresses(self):
        return self.__nodes.keys()

    def snapshot(self):
        fleet_state_checksum_bytes = binascii.unhexlify(self.checksum)
        fleet_state_updated_bytes = self.updated.epoch.to_bytes(4, byteorder="big")
        return fleet_state_checksum_bytes + fleet_state_updated_bytes

    def record_fleet_state(self, additional_nodes_to_track=None):
        if additional_nodes_to_track:
            self.additional_nodes_to_track.extend(additional_nodes_to_track)

        if not self.__nodes:
            # No news here.
            return
        sorted_nodes = self.sorted()

        sorted_nodes_joined = b"".join(bytes(n) for n in sorted_nodes)
        checksum = keccak_digest(sorted_nodes_joined).hex()
        if checksum not in self.states:
            self.checksum = keccak_digest(b"".join(bytes(n) for n in self.sorted())).hex()
            self.updated = maya.now()
            # For now we store the sorted node list.  Someday we probably spin this out into
            # its own class, FleetState, and use it as the basis for partial updates.
            new_state = self.FleetState(nickname=self.nickname,
                                        nodes=sorted_nodes,
                                        icon=self.icon,
                                        updated=self.updated,
                                        checksum=self.checksum)
            self.states[checksum] = new_state
            return checksum, new_state

    def start_tracking_state(self, additional_nodes_to_track=None):
        if additional_nodes_to_track is None:
            additional_nodes_to_track = list()
        self.additional_nodes_to_track.extend(additional_nodes_to_track)
        self._tracking = True
        self.record_fleet_state(additional_nodes_to_track)

    def sorted(self):
        nodes_to_consider = list(self.__nodes.values()) + self.additional_nodes_to_track
        return sorted(nodes_to_consider, key=lambda n: n.checksum_address)

    def shuffled(self):
        nodes_we_know_about = list(self.__nodes.values())
        random.shuffle(nodes_we_know_about)
        return nodes_we_know_about

    def abridged_states_dict(self):
        abridged_states = {}
        for k, v in self.states.items():
            abridged_states[k] = self.abridged_state_details(v)
        return abridged_states

    @staticmethod
    def abridged_state_details(state):
        return {"nickname": str(state.nickname),
                # TODO: generalize in case we want to extend the number of symbols in the state nickname
                "symbol": state.nickname.characters[0].symbol,
                "color_hex": state.nickname.characters[0].color_hex,
                "color_name": state.nickname.characters[0].color_name,
                "updated": state.updated.rfc2822()
                }

    def get_nodes(self, label=None) -> Iterator["Teacher"]:
        """If label is None return all known nodes"""
        if label is None:
            return iter(self.__nodes.values())

        if label not in BUCKETS:
            raise self.UnknownLabel(f'{label} is not a valid node label')

        try:
            nodes = iter(self.__marked[label])
        except KeyError:
            return list()  # empty
        return nodes

    def get_node(self, checksum_address: str, label: Optional[str] = None) -> "Teacher":
        try:
            node = self.__nodes[checksum_address]
        except KeyError:
            raise self.UnknownNode
        if label:
            existing_label = self.get_label(node=node)
            if label == existing_label:
                return node
            else:
                raise self.UnknownNode
        return node

    def get_label(self, node: "Teacher") -> Union["Teacher", None]:
        for _label in BUCKETS:
            if node in self.__marked[_label]:
                return _label
        return None

    def label(self, label, node: "Teacher") -> None:
        """
        Apply a label to a known node.  Removes any exiting labels before adding the new one.
        If the provided label is not valid UnknownLabel is raised.
        If the provided node is not known UnknownNode is raised.
        """
        if label not in BUCKETS:
            raise self.UnknownLabel(f'{label} is not a valid node label')
        if self.__nodes.get(node.checksum_address):
            self.unlabel(node=node)            # Remove any existing labels...
            self.__marked[label].append(node)  # Set the new label
        else:
            raise self.UnknownNode(f'Cannot label an unknown node ({node}).')

    def unlabel(self, node: "Teacher", label=None) -> None:
        """Removes a label from a node, or if label is None, all labels are removed."""

        # Remove one label
        if label:
            if node in self.__marked[label]:
                self.__marked[label].remove(node)
            return

        # Remove all labels
        node_labels = []
        for _label in BUCKETS:
            if node in self.__marked[_label]:
                self.__marked[_label].remove(node)
                node_labels.append(_label)

        # extra check to ensure that nodes only ever have one label
        if len(node_labels) > 1:
            # well this is unexpected :(
            self.log.warn(f"Unlabelled node ({node}), but it had multiple labels: {node_labels}")

    def prune_bucket(self, label):
        """Apply pruning strategies to a single node bucket once"""
        try:
            strategies = PRUNING_STRATEGIES[label]
        except KeyError:
            raise ValueError(f'"{label}" does not have a pruning strategy.')
        for node in self.get_nodes(label=label):
            for strategy in strategies:
                keep = strategy(node=node)
                if not keep:
                    del self.__nodes[node.checksum_address]  # prune node
                    self.unlabel(node=node, label=label)     # prune corresponding label
                    break  # this node is already doomed anyways
                    # TODO: forget node from disk too
                    # TODO: Trash can label?

    def prune_nodes(self) -> None:
        """Apply node pruning strategies to all marked nodes once"""
        self._pruning_strategies: Dict[type, List[Callable]]
        for label in BUCKETS:
            if label in PRUNING_STRATEGIES:
                self.prune_bucket(label=label)
