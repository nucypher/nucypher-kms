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

import pytest

from nucypher.config.constants import TEMPORARY_DOMAIN
from nucypher.acumen.perception import FleetSensor
from nucypher.characters.lawful import Ursula
from nucypher.crypto.api import keccak_digest
from nucypher.datastore.models import TreasureMap as DatastoreTreasureMap
from nucypher.policy.collections import TreasureMap as FederatedTreasureMap


def test_alice_creates_policy_with_correct_hrac(federated_alice, federated_bob, idle_federated_policy):
    """
    Alice creates a Policy.  It has the proper HRAC, unique per her, Bob, and the label
    """
    assert idle_federated_policy.hrac == keccak_digest(bytes(federated_alice.stamp)
                                                       + bytes(federated_bob.stamp)
                                                       + idle_federated_policy.label)[:16]


def test_alice_sets_treasure_map(federated_alice, federated_bob, enacted_federated_policy):
    """
    Having enacted all the policies of a PolicyGroup, Alice creates a TreasureMap and ...... TODO
    """
    treasure_map_id = enacted_federated_policy.treasure_map.public_id()
    found = 0
    for node in federated_bob.matching_nodes_among(federated_alice.known_nodes):
        with node.datastore.describe(DatastoreTreasureMap, treasure_map_id) as treasure_map_on_node:
            assert FederatedTreasureMap.from_bytes(treasure_map_on_node.treasure_map) == enacted_federated_policy.treasure_map
        found += 1
    assert found


def test_treasure_map_stored_by_ursula_is_the_correct_one_for_bob(federated_alice, federated_bob, federated_ursulas,
                                                                  enacted_federated_policy):
    """
    The TreasureMap given by Alice to Ursula is the correct one for Bob; he can decrypt and read it.
    """

    treasure_map_id = enacted_federated_policy.treasure_map.public_id()
    sensor = FleetSensor(domain=TEMPORARY_DOMAIN)
    for u in federated_ursulas:
        sensor.track(node_or_sprout=u)
    an_ursula = federated_bob.matching_nodes_among(sensor)[0]
    with an_ursula.datastore.describe(DatastoreTreasureMap, treasure_map_id) as treasure_map_record:
        treasure_map_on_network = FederatedTreasureMap.from_bytes(treasure_map_record.treasure_map)

    hrac_by_bob = federated_bob.construct_policy_hrac(federated_alice.stamp, enacted_federated_policy.label)
    assert enacted_federated_policy.hrac == hrac_by_bob

    map_id_by_bob = federated_bob.construct_map_id(federated_alice.stamp, enacted_federated_policy.label)
    assert map_id_by_bob == treasure_map_on_network.public_id()


def test_bob_can_retrieve_the_treasure_map_and_decrypt_it(federated_alice, federated_bob, enacted_federated_policy):
    """
    Above, we showed that the TreasureMap saved on the network is the correct one for Bob.  Here, we show
    that Bob can retrieve it with only the information about which he is privy pursuant to the PolicyGroup.
    """
    bob = federated_bob
    _previous_domain = bob.domain
    bob.domain = None  # Bob has no knowledge of the network.

    # Of course, in the real world, Bob has sufficient information to reconstitute a PolicyGroup, gleaned, we presume,
    # through a side-channel with Alice.

    # If Bob doesn't know about any Ursulas, he can't find the TreasureMap via the REST swarm:
    with pytest.raises(bob.NotEnoughTeachers):
        treasure_map_from_wire = bob.get_treasure_map(federated_alice.stamp,
                                                      enacted_federated_policy.label)


    # Bob finds out about one Ursula (in the real world, a seed node, hardcoded based on his learning domain)
    bob.done_seeding = False
    bob.domain = _previous_domain

    # ...and then learns about the rest of the network.
    bob.learn_from_teacher_node(eager=True)

    # Now he'll have better success finding that map.
    treasure_map_from_wire = bob.get_treasure_map(federated_alice.stamp,
                                                  enacted_federated_policy.label)

    assert enacted_federated_policy.treasure_map == treasure_map_from_wire


def test_treasure_map_is_legit(federated_bob, enacted_federated_policy):
    """
    Sure, the TreasureMap can get to Bob, but we also need to know that each Ursula in the TreasureMap is on the network.
    """
    for ursula_address, _node_id in enacted_federated_policy.treasure_map:
        if ursula_address not in federated_bob.known_nodes.addresses():
            pytest.fail(f"Bob didn't know about {ursula_address}")


def test_alice_does_not_update_with_old_ursula_info(federated_alice, federated_ursulas):
    ursula = list(federated_ursulas)[0]
    old_metadata = bytes(ursula)

    # Alice has remembered Ursula.
    assert federated_alice.known_nodes.get_node(checksum_address=ursula.checksum_address) == ursula

    # But now, Ursula wants to sign and date her interface info again.  This causes a new timestamp.
    ursula._sign_and_date_interface_info()

    # Indeed, her metadata is not the same now.
    assert bytes(ursula) != old_metadata

    old_ursula = Ursula.from_bytes(old_metadata)

    # Once Alice learns about Ursula's updated info...
    federated_alice.remember_node(ursula)

    # ...she can't learn about old ursula anymore.
    federated_alice.remember_node(old_ursula)

    new_metadata = bytes(federated_alice.known_nodes.get_node(checksum_address=ursula.checksum_address))
    assert new_metadata != old_metadata
