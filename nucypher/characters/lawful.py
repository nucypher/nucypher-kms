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
import contextlib
from threading import get_ident
import json
import maya
import random
import time
from base64 import b64decode, b64encode
from collections import OrderedDict, defaultdict
from datetime import datetime
from functools import partial
from json.decoder import JSONDecodeError
from queue import Queue
from random import shuffle
from typing import Dict, Iterable, List, Optional, Set, Tuple, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate, NameOID, load_pem_x509_certificate
from eth_utils import to_checksum_address
from flask import Response, request
from twisted.internet import reactor, stdio, threads
from twisted.internet.defer import DeferredList, Deferred, CancelledError
from twisted.internet.task import LoopingCall

import nucypher
from bytestring_splitter import BytestringKwargifier, BytestringSplitter, BytestringSplittingError, \
    VariableLengthBytestring
from constant_sorrow import constants
from constant_sorrow.constants import (INCLUDED_IN_BYTESTRING,
                                       PUBLIC_ONLY,
                                       STRANGER_ALICE,
                                       UNKNOWN_VERSION,
                                       READY,
                                       INVALIDATED)
from nucypher.acumen.nicknames import Nickname
from nucypher.acumen.perception import FleetSensor
from nucypher.blockchain.eth.actors import BlockchainPolicyAuthor, Worker
from nucypher.blockchain.eth.agents import ContractAgency, StakingEscrowAgent
from nucypher.blockchain.eth.constants import LENGTH_ECDSA_SIGNATURE_WITH_RECOVERY, ETH_ADDRESS_BYTE_LENGTH
from nucypher.blockchain.eth.interfaces import BlockchainInterfaceFactory
from nucypher.blockchain.eth.registry import BaseContractRegistry
from nucypher.blockchain.eth.signers.software import Web3Signer
from nucypher.blockchain.eth.token import WorkTracker
from nucypher.characters.banners import ALICE_BANNER, BOB_BANNER, ENRICO_BANNER, URSULA_BANNER
from nucypher.characters.base import Character, Learner
from nucypher.characters.control.controllers import (
    WebController
)
from nucypher.characters.control.emitters import StdoutEmitter
from nucypher.characters.control.interfaces import AliceInterface, BobInterface, EnricoInterface
from nucypher.cli.processes import UrsulaCommandProtocol
from nucypher.config.storages import ForgetfulNodeStorage, NodeStorage
from nucypher.crypto.api import encrypt_and_sign, keccak_digest
from nucypher.crypto.constants import HRAC_LENGTH, PUBLIC_KEY_LENGTH
from nucypher.crypto.keypairs import HostingKeypair
from nucypher.crypto.kits import UmbralMessageKit
from nucypher.crypto.powers import DecryptingPower, DelegatingPower, PowerUpError, SigningPower, TransactingPower
from nucypher.crypto.signing import InvalidSignature
from nucypher.datastore.datastore import DatastoreTransactionError, RecordNotFound
from nucypher.datastore.models import PolicyArrangement, TreasureMap as DatastoreTreasureMap
from nucypher.network.exceptions import NodeSeemsToBeDown
from nucypher.network.middleware import RestMiddleware
from nucypher.network.nodes import NodeSprout, Teacher
from nucypher.network.protocols import InterfaceInfo, parse_node_uri
from nucypher.network.server import ProxyRESTServer, TLSHostingPower, make_rest_app
from nucypher.network.trackers import AvailabilityTracker
from nucypher.utilities.logging import Logger
from umbral import pre
from umbral.keys import UmbralPublicKey
from umbral.kfrags import KFrag
from umbral.pre import UmbralCorrectnessError
from umbral.signing import Signature


class Alice(Character, BlockchainPolicyAuthor):
    banner = ALICE_BANNER
    _interface_class = AliceInterface
    _default_crypto_powerups = [SigningPower, DecryptingPower, DelegatingPower]

    def __init__(self,

                 # Mode
                 is_me: bool = True,
                 federated_only: bool = False,
                 signer=None,

                 # Ownership
                 checksum_address: str = None,
                 client_password: str = None,
                 cache_password: bool = False,

                 # M of N
                 m: int = None,
                 n: int = None,

                 # Policy Value
                 rate: int = None,
                 duration_periods: int = None,

                 # Middleware
                 timeout: int = 10,  # seconds  # TODO: configure  NRN
                 network_middleware: RestMiddleware = None,
                 controller: bool = True,

                 *args, **kwargs) -> None:

        #
        # Fallback Policy Values
        #

        self.timeout = timeout

        if is_me:
            self.m = m
            self.n = n

            self._policy_queue = Queue()
            self._policy_queue.put(READY)
        else:
            self.m = STRANGER_ALICE
            self.n = STRANGER_ALICE

        Character.__init__(self,
                           known_node_class=Ursula,
                           is_me=is_me,
                           federated_only=federated_only,
                           checksum_address=checksum_address,
                           network_middleware=network_middleware,
                           *args, **kwargs)

        if is_me and not federated_only:  # TODO: #289
            blockchain = BlockchainInterfaceFactory.get_interface(provider_uri=self.provider_uri)
            transacting_power = TransactingPower(account=self.checksum_address,
                                                 password=client_password,
                                                 cache=cache_password,
                                                 signer=signer or Web3Signer(blockchain.client))

            self._crypto_power.consume_power_up(transacting_power)
            BlockchainPolicyAuthor.__init__(self,
                                            registry=self.registry,
                                            rate=rate,
                                            duration_periods=duration_periods,
                                            checksum_address=checksum_address)

        if is_me and controller:
            self.make_cli_controller()

        self.log = Logger(self.__class__.__name__)
        self.log.info(self.banner)

        self.active_policies = dict()
        self.revocation_kits = dict()

    def add_active_policy(self, active_policy):
        """
        Adds a Policy object that is active on the NuCypher network to Alice's
        `active_policies` dictionary by the policy ID.
        The policy ID is a Keccak hash of the policy label and Bob's stamp bytes
        """
        if active_policy.id in self.active_policies:
            raise KeyError("Policy already exists in active_policies.")
        self.active_policies[active_policy.id] = active_policy

    def generate_kfrags(self,
                        bob: 'Bob',
                        label: bytes,
                        m: int = None,
                        n: int = None
                        ) -> List:
        """
        Generates re-encryption key frags ("KFrags") and returns them.

        These KFrags can be used by Ursula to re-encrypt a Capsule for Bob so
        that he can activate the Capsule.

        :param bob: Bob instance which will be able to decrypt messages re-encrypted with these kfrags.
        :param m: Minimum number of kfrags needed to activate a Capsule.
        :param n: Total number of kfrags to generate
        """

        bob_encrypting_key = bob.public_keys(DecryptingPower)
        delegating_power = self._crypto_power.power_ups(DelegatingPower)
        return delegating_power.generate_kfrags(bob_pubkey_enc=bob_encrypting_key,
                                                signer=self.stamp,
                                                label=label,
                                                m=m or self.m,
                                                n=n or self.n)

    def create_policy(self, bob: "Bob", label: bytes, **policy_params):
        """
        Create a Policy so that Bob has access to all resources under label.
        Generates KFrags and attaches them.
        """

        policy_params = self.generate_policy_parameters(**policy_params)
        N = policy_params.pop('n')

        # Generate KFrags
        public_key, kfrags = self.generate_kfrags(bob=bob,
                                                  label=label,
                                                  m=policy_params['m'],
                                                  n=N)

        payload = dict(label=label,
                       bob=bob,
                       kfrags=kfrags,
                       public_key=public_key,
                       m=policy_params['m'],
                       expiration=policy_params['expiration'])

        if self.federated_only:
            # Use known nodes
            from nucypher.policy.policies import FederatedPolicy
            policy = FederatedPolicy(alice=self, **payload)

        else:
            # Sample from blockchain PolicyManager
            from nucypher.policy.policies import BlockchainPolicy
            payload.update(**policy_params)
            policy = BlockchainPolicy(alice=self, **payload)

        return policy

    def generate_policy_parameters(self,
                                   m: int = None,
                                   n: int = None,
                                   duration_periods: int = None,
                                   expiration: maya.MayaDT = None,
                                   *args, **kwargs
                                   ) -> dict:
        """
        Construct policy creation from parameters or overrides.
        """

        if not duration_periods and not expiration:
            raise ValueError("Policy end time must be specified as 'expiration' or 'duration_periods', got neither.")

        # Merge injected and default params.
        m = m or self.m
        n = n or self.n
        base_payload = dict(m=m, n=n, expiration=expiration)

        # Calculate Policy Rate and Value
        if not self.federated_only:
            payload = super().generate_policy_parameters(number_of_ursulas=n,
                                                         duration_periods=duration_periods,
                                                         expiration=expiration,
                                                         *args, **kwargs)
            base_payload.update(payload)
        elif not expiration:
            raise TypeError("For a federated policy, you must specify expiration (duration_periods don't count).")
        return base_payload

    def grant(self,
              bob: "Bob",
              label: bytes,
              handpicked_ursulas: set = None,
              discover_on_this_thread: bool = True,
              timeout: int = None,
              publish_treasure_map: bool = True,
              block_until_success_is_reasonably_likely: bool = True,
              **policy_params):

        timeout = timeout or self.timeout

        #
        # Policy Creation
        #

        if handpicked_ursulas:
            # This might be the first time alice learns about the handpicked Ursulas.
            for handpicked_ursula in handpicked_ursulas:
                self.remember_node(node=handpicked_ursula)

        policy = self.create_policy(bob=bob, label=label, **policy_params)
        self.log.debug(f"Successfully created {policy} ... ")

        #
        # We'll find n Ursulas by default.  It's possible to "play the field" by trying different
        # value and expiration combinations on a limited number of Ursulas;
        # Users may decide to inject some market strategies here.
        #

        # If we're federated only, we need to block to make sure we have enough nodes.
        if self.federated_only and len(self.known_nodes) < policy.n:
            good_to_go = self.block_until_number_of_known_nodes_is(number_of_nodes_to_know=policy.n,
                                                                   learn_on_this_thread=discover_on_this_thread,
                                                                   timeout=timeout)
            if not good_to_go:
                raise ValueError(
                    "To make a Policy in federated mode, you need to know about "
                    "all the Ursulas you need (in this case, {}); there's no other way to "
                    "know which nodes to use.  Either pass them here or when you make the Policy, "
                    "or run the learning loop on a network with enough Ursulas.".format(policy.n))

        self.log.debug(f"Making arrangements for {policy} ... ")
        policy.make_arrangements(network_middleware=self.network_middleware,
                                 handpicked_ursulas=handpicked_ursulas,
                                 discover_on_this_thread=discover_on_this_thread)

        # REST call happens here, as does population of TreasureMap.
        self.log.debug(f"Enacting {policy} ... ")

        # TODO: Make it optional to publish to blockchain?  Or is this presumptive based on the `Policy` type?
        policy.enact(network_middleware=self.network_middleware, publish_treasure_map=publish_treasure_map)

        if publish_treasure_map and block_until_success_is_reasonably_likely:
            policy.publishing_mutex.block_until_success_is_reasonably_likely()
        return policy  # Now with TreasureMap affixed!

    def get_policy_encrypting_key_from_label(self, label: bytes) -> UmbralPublicKey:
        alice_delegating_power = self._crypto_power.power_ups(DelegatingPower)
        policy_pubkey = alice_delegating_power.get_pubkey_from_label(label)
        return policy_pubkey

    def revoke(self, policy) -> Dict:
        """
        Parses the treasure map and revokes arrangements in it.
        If any arrangements can't be revoked, then the node_id is added to a
        dict as a key, and the revocation and Ursula's response is added as
        a value.
        """
        try:
            # Wait for a revocation threshold of nodes to be known ((n - m) + 1)
            revocation_threshold = ((policy.n - policy.treasure_map.m) + 1)
            self.block_until_specific_nodes_are_known(
                policy.revocation_kit.revokable_addresses,
                allow_missing=(policy.n - revocation_threshold))

        except self.NotEnoughTeachers:
            raise  # TODO  NRN

        else:
            failed_revocations = dict()
            for node_id in policy.revocation_kit.revokable_addresses:
                ursula = self.known_nodes[node_id]
                revocation = policy.revocation_kit[node_id]
                try:
                    response = self.network_middleware.revoke_arrangement(ursula, revocation)
                except self.network_middleware.NotFound:
                    failed_revocations[node_id] = (revocation, self.network_middleware.NotFound)
                except self.network_middleware.UnexpectedResponse:
                    failed_revocations[node_id] = (revocation, self.network_middleware.UnexpectedResponse)
                else:
                    if response.status_code != 200:
                        raise self.ActorError(f"Failed to revoke {policy.id} with status code {response.status_code}")

        return failed_revocations

    def decrypt_message_kit(self,
                            message_kit: UmbralMessageKit,
                            data_source: Character,
                            label: bytes
                            ) -> List[bytes]:

        """
        Decrypt this Alice's own encrypted data.

        I/O signatures match Bob's retrieve interface.
        """

        cleartexts = [self.verify_from(
            data_source,
            message_kit,
            signature=message_kit.signature,
            decrypt=True,
            label=label
        )]
        return cleartexts

    def make_web_controller(drone_alice, crash_on_error: bool = False):
        app_name = bytes(drone_alice.stamp).hex()[:6]
        controller = WebController(app_name=app_name,
                                   crash_on_error=crash_on_error,
                                   interface=drone_alice._interface_class(character=drone_alice))
        drone_alice.controller = controller

        # Register Flask Decorator
        alice_flask_control = controller.make_control_transport()

        #
        # Character Control HTTP Endpoints
        #

        @alice_flask_control.route('/public_keys', methods=['GET'])
        def public_keys():
            """
            Character control endpoint for getting Alice's encrypting and signing public keys
            """
            return controller(method_name='public_keys', control_request=request)

        @alice_flask_control.route("/create_policy", methods=['PUT'])
        def create_policy() -> Response:
            """
            Character control endpoint for creating a policy and making
            arrangements with Ursulas.
            """
            response = controller(method_name='create_policy', control_request=request)
            return response

        @alice_flask_control.route("/decrypt", methods=['POST'])
        def decrypt():
            """
            Character control endpoint for decryption of Alice's own policy data.
            """
            response = controller(method_name='decrypt', control_request=request)
            return response

        @alice_flask_control.route('/derive_policy_encrypting_key/<label>', methods=['POST'])
        def derive_policy_encrypting_key(label) -> Response:
            """
            Character control endpoint for deriving a policy encrypting given a unicode label.
            """
            response = controller(method_name='derive_policy_encrypting_key', control_request=request, label=label)
            return response

        @alice_flask_control.route("/grant", methods=['PUT'])
        def grant() -> Response:
            """
            Character control endpoint for policy granting.
            """
            response = controller(method_name='grant', control_request=request)
            return response

        @alice_flask_control.route("/revoke", methods=['DELETE'])
        def revoke():
            """
            Character control endpoint for policy revocation.
            """
            response = controller(method_name='revoke', control_request=request)
            return response

        return controller


class Bob(Character):
    banner = BOB_BANNER
    _interface_class = BobInterface

    _default_crypto_powerups = [SigningPower, DecryptingPower]

    class IncorrectCFragsReceived(Exception):
        """
        Raised when Bob detects incorrect CFrags returned by some Ursulas
        """

        def __init__(self, evidence: List):
            self.evidence = evidence

    def __init__(self, treasure_maps: Optional[Dict] = None, controller: bool = True, *args, **kwargs) -> None:
        Character.__init__(self, known_node_class=Ursula, *args, **kwargs)

        if controller:
            self.make_cli_controller()

        if not treasure_maps:
            treasure_maps = dict()
        self.treasure_maps = treasure_maps

        from nucypher.policy.collections import WorkOrderHistory  # Need a bigger strategy to avoid circulars.
        self._completed_work_orders = WorkOrderHistory()

        self.log = Logger(self.__class__.__name__)
        self.log.info(self.banner)

    def peek_at_treasure_map(self, treasure_map=None):
        """
        Take a quick gander at the TreasureMap matching map_id to see which
        nodes are already known to us.

        Don't do any learning, pinging, or anything other than just seeing
        whether we know or don't know the nodes.

        Return two sets: nodes that are unknown to us, nodes that are known to us.
        """

        # The intersection of the map and our known nodes will be the known Ursulas...
        known_treasure_ursulas = treasure_map.destinations.keys() & self.known_nodes.addresses()

        # while the difference will be the unknown Ursulas.
        unknown_treasure_ursulas = treasure_map.destinations.keys() - self.known_nodes.addresses()

        return unknown_treasure_ursulas, known_treasure_ursulas

    def follow_treasure_map(self,
                            treasure_map=None,
                            block=False,
                            new_thread=False,
                            timeout=10,
                            allow_missing=0):
        """
        Follows a known TreasureMap.

        Determines which Ursulas are known and which are unknown.

        If block, will block until either unknown nodes are discovered or until timeout seconds have elapsed.
        After timeout seconds, if more than allow_missing nodes are still unknown, raises NotEnoughUrsulas.

        If block and new_thread, does the same thing but on a different thread, returning a Deferred which
        fires after the blocking has concluded.

        Otherwise, returns (unknown_nodes, known_nodes).

        # TODO: Check if nodes are up, declare them phantom if not.  567
        """
        unknown_ursulas, known_ursulas = self.peek_at_treasure_map(treasure_map=treasure_map)

        if unknown_ursulas:
            self.learn_about_specific_nodes(unknown_ursulas)

        self._push_certain_newly_discovered_nodes_here(known_ursulas, unknown_ursulas)

        if block:
            if new_thread:
                return threads.deferToThread(self.block_until_specific_nodes_are_known, unknown_ursulas,
                                             timeout=timeout,
                                             allow_missing=allow_missing)
            else:
                self.block_until_specific_nodes_are_known(unknown_ursulas,
                                                          timeout=timeout,
                                                          allow_missing=allow_missing,
                                                          learn_on_this_thread=True)

        return unknown_ursulas, known_ursulas, treasure_map.m

    def _try_orient(self, treasure_map, alice_verifying_key):
        alice = Alice.from_public_keys(verifying_key=alice_verifying_key)
        compass = self.make_compass_for_alice(alice)
        try:
            treasure_map.orient(compass)
        except treasure_map.InvalidSignature:
            raise  # TODO: Maybe do something here?  NRN

    def get_treasure_map(self, alice_verifying_key, label):
        map_identifier = self.construct_map_id(verifying_key=alice_verifying_key, label=label)

        if not self.known_nodes and not self._learning_task.running:
            # Quick sanity check - if we don't know of *any* Ursulas, and we have no
            # plans to learn about any more, than this function will surely fail.
            if not self.done_seeding:
                self.learn_from_teacher_node()

            # If we still don't know of any nodes, we gotta bail.
            if not self.known_nodes:
                raise self.NotEnoughTeachers("Can't retrieve without knowing about any nodes at all.  Pass a teacher or seed node.")

        treasure_map = self.get_treasure_map_from_known_ursulas(self.network_middleware,
                                                                map_identifier)
        self._try_orient(treasure_map, alice_verifying_key)
        self.treasure_maps[map_identifier] = treasure_map # TODO: make a part of _try_orient()?
        return treasure_map

    def make_compass_for_alice(self, alice):
        return partial(self.verify_from, alice, decrypt=True)

    def construct_policy_hrac(self, verifying_key: Union[bytes, UmbralPublicKey], label: bytes) -> bytes:
        _hrac = keccak_digest(bytes(verifying_key) + self.stamp + label)[:HRAC_LENGTH]
        return _hrac

    def construct_map_id(self, verifying_key, label):
        hrac = self.construct_policy_hrac(verifying_key, label)

        # Ugh stupid federated only mode....
        if not self.federated_only:
            map_id = hrac.hex()
        else:
            map_id = keccak_digest(bytes(verifying_key) + hrac).hex()

        return map_id

    def get_treasure_map_from_known_ursulas(self, network_middleware, map_identifier, timeout=3):
        """
        Iterate through the nodes we know, asking for the TreasureMap.
        Return the first one who has it.
        """
        if self.federated_only:
            from nucypher.policy.collections import TreasureMap as _MapClass
        else:
            from nucypher.policy.collections import SignedTreasureMap as _MapClass

        start = maya.now()

        # Spend no more than half the timeout finding the nodes.  8 nodes is arbitrary.  Come at me.
        self.block_until_number_of_known_nodes_is(8, timeout=timeout/2, learn_on_this_thread=True)
        while True:
            nodes_with_map = self.matching_nodes_among(self.known_nodes)
            random.shuffle(nodes_with_map)

            for node in nodes_with_map:
                try:
                    response = network_middleware.get_treasure_map_from_node(node, map_identifier)
                except (*NodeSeemsToBeDown, self.NotEnoughNodes):
                    continue
                except network_middleware.NotFound:
                    self.log.info(f"Node {node} claimed not to have TreasureMap {map_identifier}")
                    continue

                if response.status_code == 200 and response.content:
                    try:
                        treasure_map = _MapClass.from_bytes(response.content)
                        return treasure_map
                    except InvalidSignature:
                        # TODO: What if a node gives a bunk TreasureMap?  NRN
                        raise
                else:
                    continue  # TODO: Actually, handle error case here.  NRN
            else:
                self.learn_from_teacher_node()

            if (start - maya.now()).seconds > timeout:
                raise _MapClass.NowhereToBeFound(f"Asked {len(self.known_nodes)} nodes, but none had map {map_identifier} ")

    def work_orders_for_capsules(self,
                                 *capsules,
                                 alice_verifying_key: UmbralPublicKey,
                                 treasure_map: 'TreasureMap' = None,
                                 num_ursulas: int = None,
                                 ):

        from nucypher.policy.collections import WorkOrder  # Prevent circular import

        if treasure_map:
            treasure_map_to_use = treasure_map
        else:
            try:
                treasure_map_to_use = self.treasure_maps[map_id]
            except KeyError:
                raise KeyError(f"Bob doesn't have the TreasureMap {map_id}; can't generate work orders.")

        incomplete_work_orders = OrderedDict()
        complete_work_orders = defaultdict(lambda: [])

        if not treasure_map_to_use:
            raise ValueError(f"Bob doesn't have a TreasureMap to match any of these capsules: {capsules}")

        random_walk = list(treasure_map)
        shuffle(random_walk)  # Mutates list in-place
        for node_id, arrangement_id in random_walk:

            capsules_to_include = []
            for capsule in capsules:
                try:
                    precedent_work_order = self._completed_work_orders.most_recent_replete(capsule)[node_id]
                    self.log.debug(f"{capsule} already has a saved WorkOrder for this Node:{node_id}.")
                    complete_work_orders[capsule].append(precedent_work_order)
                except KeyError:
                    # Don't have a precedent completed WorkOrder for this Ursula for this Capsule.
                    # We need to make a new one.
                    capsules_to_include.append(capsule)

            # TODO: Bob crashes if he hasn't learned about this Ursula #999
            ursula = self.known_nodes[node_id]

            if capsules_to_include:
                work_order = WorkOrder.construct_by_bob(arrangement_id=arrangement_id,
                                                        alice_verifying=alice_verifying_key,
                                                        capsules=capsules_to_include,
                                                        ursula=ursula,
                                                        bob=self)
                incomplete_work_orders[node_id] = work_order
            else:
                self.log.debug(f"All of these Capsules already have WorkOrders for this node: {node_id}")
            if num_ursulas == len(incomplete_work_orders):
                # TODO: Presently, the order here is haphazard .  Do we want to do the complete or incomplete specifically first? NRN
                break

        if len(incomplete_work_orders) == 0:
            self.log.warn(
                "No new WorkOrders created.  Try calling this with different parameters.")  # TODO: Clearer instructions.  NRN

        return incomplete_work_orders, complete_work_orders

    def join_policy(self, label, alice_verifying_key, node_list=None, block=False):
        if node_list:
            self._node_ids_to_learn_about_immediately.update(node_list)
        treasure_map = self.get_treasure_map(alice_verifying_key, label)
        self.follow_treasure_map(treasure_map=treasure_map, block=block)

    def _fix_message_kits(self, message_kits, enrico, policy_encrypting_key, use_attached_cfrags):
        for message in message_kits:
            if message.sender:
                if enrico and message.sender != enrico:
                    raise ValueError
            elif enrico:
                message.sender = enrico
            elif message.sender_verifying_key and policy_encrypting_key:
                # Well, after all, this is all we *really* need.
                message.sender = Enrico.from_public_keys(verifying_key=message.sender_verifying_key,
                                                         policy_encrypting_key=policy_encrypting_key)
            else:
                raise TypeError

            # Second sanity check: If we're not using attached cfrags, we don't want a Capsule which has them.

            if len(message.capsule) > 0:
                if not use_attached_cfrags:
                    raise TypeError(
                        "Not using cached retrievals, but the MessageKit's capsule has attached CFrags.  In order to retrieve this message, you must set cache=True.  To use Bob in 'KMS mode', use cache=False the first time you retrieve a message.")

    def _filter_work_orders_and_capsules(self, work_orders, capsules, m):
        remaining_work_orders = []
        remaining_capsules = set(capsule for capsule in capsules if len(capsule) < m)
        for work_order in work_orders.values():
            for capsule in work_order.tasks:
                work_order_is_useful = False
                if len(capsule) >= m:
                    remaining_capsules.discard(capsule)
                else:
                    work_order_is_useful = True
                    break

            # If all the capsules are now activated, we can stop here.
            if not remaining_capsules:
                break

            if not work_order_is_useful:
                # None of the Capsules for this particular WorkOrder need to be activated.  Move on to the next one.
                continue

            remaining_work_orders.append(work_order)

        return remaining_work_orders, remaining_capsules


    class ReencryptError(RuntimeError):
        pass

    class AvailabilityError(RuntimeError):
        pass

    def _reencrypt(self, work_order, retain_cfrags=False):

        if work_order.completed:
            raise TypeError(
                "This WorkOrder is already complete; if you want Ursula to perform additional service, make a new WorkOrder.")

        # We don't have enough CFrags yet.  Let's get another one from a WorkOrder.
        try:
            cfrags_and_signatures = self.network_middleware.reencrypt(work_order)
        except NodeSeemsToBeDown as e:
            # TODO: What to do here?  Ursula isn't supposed to be down.  NRN
            self.log.info(f"Ursula ({work_order.ursula}) seems to be down while trying to complete WorkOrder: {work_order}")
            raise self.AvailabilityError() # TODO: return a grievance?
        except self.network_middleware.NotFound:
            # This Ursula claims not to have a matching KFrag.  Maybe this has been revoked?
            # TODO: What's the thing to do here?  Do we want to track these Ursulas in some way in case they're lying?  567
            self.log.warn(f"Ursula ({work_order.ursula}) claims not to have the KFrag to complete WorkOrder: {work_order}.  Has accessed been revoked?")
            raise self.AvailabilityError() # TODO: return a grievance?
        except self.network_middleware.UnexpectedResponse:
            raise # TODO: Handle this

        cfrags = work_order.complete(cfrags_and_signatures)

        # TODO: hopefully GIL will allow this to execute concurrently...
        # or we'll have to modify tests that rely on it
        self._completed_work_orders.save_work_order(work_order, as_replete=retain_cfrags)

        the_airing_of_grievances = []
        for capsule, pre_task in work_order.tasks.items():
            if not pre_task.cfrag.verify_correctness(capsule):
                # TODO: WARNING - This block is untested.
                from nucypher.policy.collections import IndisputableEvidence
                evidence = IndisputableEvidence(task=pre_task, work_order=work_order)
                # I got a lot of problems with you people ...
                the_airing_of_grievances.append(evidence)

        if the_airing_of_grievances:
            raise ReencryptError(the_airing_of_grievances)

        return work_order

    def retrieve(self,
                 *message_kits: UmbralMessageKit,
                 alice_verifying_key: UmbralPublicKey,
                 label: bytes,
                 enrico: "Enrico" = None,
                 retain_cfrags: bool = False,
                 use_attached_cfrags: bool = False,
                 use_precedent_work_orders: bool = False,
                 policy_encrypting_key: UmbralPublicKey = None,
                 treasure_map: Union['TreasureMap', bytes] = None):

        # Try our best to get an UmbralPublicKey from input
        alice_verifying_key = UmbralPublicKey.from_bytes(bytes(alice_verifying_key))

        if treasure_map is not None:

            if self.federated_only:
                from nucypher.policy.collections import TreasureMap as _MapClass
            else:
                from nucypher.policy.collections import SignedTreasureMap as _MapClass

            # TODO: This LBYL is ugly and fraught with danger.  NRN
            if isinstance(treasure_map, bytes):
                treasure_map = _MapClass.from_bytes(treasure_map)

            if isinstance(treasure_map, str):
                tmap_bytes = treasure_map.encode()
                treasure_map = _MapClass.from_bytes(b64decode(tmap_bytes))

            self._try_orient(treasure_map, alice_verifying_key)
            # self.treasure_maps[treasure_map.public_id()] = treasure_map # TODO: Can we?
        else:
            map_id = self.construct_map_id(alice_verifying_key, label)
            treasure_map = self.treasure_maps[map_id]

        _unknown_ursulas, _known_ursulas, m = self.follow_treasure_map(treasure_map=treasure_map, block=True)

        # Part I: Assembling the WorkOrders.
        capsules_to_activate = set(mk.capsule for mk in message_kits)

        # Sanity checks and normalization
        self._fix_message_kits(message_kits, enrico, policy_encrypting_key, use_attached_cfrags)

        # OK, with the sanity checks behind us, we'll proceed to the WorkOrder assembly.
        # We'll start by following the treasure map, setting the correctness keys, and attaching cfrags from
        # WorkOrders that we have already completed in the past.

        for message in message_kits:
            capsule = message.capsule

            capsule.set_correctness_keys(receiving=self.public_keys(DecryptingPower))
            capsule.set_correctness_keys(verifying=alice_verifying_key)

        new_work_orders, complete_work_orders = self.work_orders_for_capsules(
            treasure_map=treasure_map,
            alice_verifying_key=alice_verifying_key,
            *capsules_to_activate)

        # TODO: enabling this causes `builtins.KeyError: 'Capsule'` in logging.
        #self.log.info(f"Found {len(complete_work_orders)} for Capsules ({capsules_to_activate}).")

        if complete_work_orders:
            if use_precedent_work_orders:
                for capsule, work_orders in complete_work_orders.items():
                    for work_order in work_orders:
                        cfrag_in_question = work_order.tasks[capsule].cfrag
                        capsule.attach_cfrag(cfrag_in_question)
            else:
                self.log.warn(
                    "Found existing complete WorkOrders, but use_precedent_work_orders is set to False.  To use Bob in 'KMS mode', set retain_cfrags=False as well.")

        # Part II: Getting the cleartexts.
        cleartexts = []

        try:
            # TODO Optimization: Block here (or maybe even later) until map is done being followed (instead of blocking above). #1114
            the_airing_of_grievances = []

            remaining_work_orders, capsules_to_activate = self._filter_work_orders_and_capsules(
                new_work_orders, capsules_to_activate, m)

            # If all the capsules are now activated, we can stop here.
            if capsules_to_activate and remaining_work_orders:
                # OK, so we're going to need to do some network activity for this retrieval.  Let's make sure we've seeded.
                if not self.done_seeding:
                    self.learn_from_teacher_node()

                workers = [
                    partial(self._reencrypt, work_order, retain_cfrags)
                    for work_order in remaining_work_orders]

                partial_list = ParallelRunner(workers)
                #successes, failures = partial_list.wait()
                successes, failures = partial_list.wait_sequential()

                for work_order in successes:

                    if not any(capsule in capsules_to_activate for capsule, pre_task in work_order.tasks.items()):
                        continue

                    for capsule, pre_task in work_order.tasks.items():
                        capsule.attach_cfrag(pre_task.cfrag) # already verified, will not fail
                        if len(capsule) >= m:
                            capsules_to_activate.discard(capsule)

                for error in failures:
                    if isinstance(error, self.AvailabilityError):
                        continue
                    if isinstance(error, self.ReencryptError) and error.args:
                        the_airing_of_grievances.extend(error.args[0])
                    else:
                        raise error

            if capsules_to_activate:
                raise Ursula.NotEnoughUrsulas(
                    "Unable to reach m Ursulas.  See the logs for which Ursulas are down or noncompliant.")

            if the_airing_of_grievances:
                # ... and now you're gonna hear about it!
                raise self.IncorrectCFragsReceived(the_airing_of_grievances)
                # TODO: Find a better strategy for handling incorrect CFrags #500
                #  - There maybe enough cfrags to still open the capsule
                #  - This line is unreachable when NotEnoughUrsulas

            # TODO: what if `verify_from` fails?
            for message in message_kits:
                delivered_cleartext = self.verify_from(message.sender, message, decrypt=True)
                cleartexts.append(delivered_cleartext)
        finally:
            if not retain_cfrags:
                for message in message_kits:
                    message.capsule.clear_cfrags()
                for work_order in new_work_orders.values():
                    work_order.sanitize()

        return cleartexts

    def matching_nodes_among(self,
                             nodes: FleetSensor,
                             no_less_than=7):  # Somewhat arbitrary floor here.
        # Look for nodes whose checksum address has the second character of Bob's encrypting key in the first
        # few characters.
        # Think of it as a cheap knockoff hamming distance.
        # The good news is that Bob can construct the list easily.
        # And - famous last words incoming - there's no cognizable attack surface.
        # Sure, Bob can mine encrypting keypairs until he gets the set of target Ursulas on which Alice can
        # store a TreasureMap.  And then... ???... profit?

        # Sanity check - do we even have enough nodes?
        if len(nodes) < no_less_than:
            raise ValueError(f"Can't select {no_less_than} from {len(nodes)} (Fleet state: {nodes.FleetState})")

        search_boundary = 2
        target_nodes = []
        target_hex_match = self.public_keys(DecryptingPower).hex()[1]
        while len(target_nodes) < no_less_than:
            target_nodes = []
            search_boundary += 2

            if search_boundary > 42:  # We've searched the entire string and can't match any.  TODO: Portable learning is a nice idea here.
                # Not enough matching nodes.  Fine, we'll just publish to the first few.
                try:
                    # TODO: This is almost certainly happening in a test.  If it does happen in production, it's a bit of a problem.  Need to fix #2124 to mitigate.
                    target_nodes = list(nodes._nodes.values())[0:6]
                    return target_nodes
                except IndexError:
                    raise self.NotEnoughNodes("There aren't enough nodes on the network to enact this policy.  Unless this is day one of the network and nodes are still getting spun up, something is bonkers.")

            # TODO: 1995 all throughout here (we might not (need to) know the checksum address yet; canonical will do.)
            # This might be a performance issue above a few thousand nodes.
            target_nodes = [node for node in nodes if target_hex_match in node.checksum_address[2:search_boundary]]
        return target_nodes

    def make_web_controller(drone_bob, crash_on_error: bool = False):

        app_name = bytes(drone_bob.stamp).hex()[:6]
        controller = WebController(app_name=app_name,
                                   crash_on_error=crash_on_error,
                                   interface=drone_bob._interface_class(character=drone_bob))

        drone_bob.controller = controller.make_control_transport()

        # Register Flask Decorator
        bob_control = controller.make_control_transport()

        #
        # Character Control HTTP Endpoints
        #

        @bob_control.route('/public_keys', methods=['GET'])
        def public_keys():
            """
            Character control endpoint for getting Bob's encrypting and signing public keys
            """
            return controller(method_name='public_keys', control_request=request)

        @bob_control.route('/join_policy', methods=['POST'])
        def join_policy():
            """
            Character control endpoint for joining a policy on the network.

            This is an unfinished endpoint. You're probably looking for retrieve.
            """
            return controller(method_name='join_policy', control_request=request)

        @bob_control.route('/retrieve', methods=['POST'])
        def retrieve():
            """
            Character control endpoint for re-encrypting and decrypting policy
            data.
            """
            return controller(method_name='retrieve', control_request=request)

        return controller


def worker_wrapper(worker, pdl, i):
    try:
        result = worker()
        pdl._process_result(result, i, True)
    except Exception as e:
        pdl._process_result(e, i, False)


class ParallelRunner:

    def __init__(self, workers):

        self._workers = workers
        self._queue = Queue()
        self._successes = {}
        self._failures = {}

    def _process_result(self, result, index, succeeded):
        if succeeded:
            self._successes[index] = result
        else:
            self._failures[index] = result

        if len(self._successes) + len(self._failures) == len(self._workers):
            self._queue.put((dict(self._successes), dict(self._failures)))

        return result

    def wait_sequential(self):
        for i, worker in enumerate(self._workers):
            worker_wrapper(worker, self, i)
        successes, failures = self._queue.get()
        return list(successes.values()), list(failures.values())


    def wait(self):

        self._deferred_list = []
        for i, worker in enumerate(self._workers):
            self._deferred_list.append(threads.deferToThread(partial(worker_wrapper, worker, self, i)))

        successes, failures = self._queue.get()
        return list(successes.values()), list(failures.values())


class Ursula(Teacher, Character, Worker):
    banner = URSULA_BANNER
    _alice_class = Alice

    # TODO: Maybe this wants to be a registry, so that, for example,  NRN
    # TLSHostingPower still can enjoy default status, but on a different class  NRN
    _default_crypto_powerups = [SigningPower, DecryptingPower]

    _pruning_interval = 60  # seconds

    class NotEnoughUrsulas(Learner.NotEnoughTeachers, StakingEscrowAgent.NotEnoughStakers):
        """
        All Characters depend on knowing about enough Ursulas to perform their role.
        This exception is raised when a piece of logic can't proceed without more Ursulas.
        """

    class NotFound(Exception):
        pass

    def __init__(self,

                 # Ursula
                 rest_host: str,
                 rest_port: int,
                 domain: str = None,  # For now, serving and learning domain will be the same.
                 certificate: Certificate = None,
                 certificate_filepath: str = None,
                 db_filepath: str = None,
                 is_me: bool = True,
                 interface_signature=None,
                 timestamp=None,
                 availability_check: bool = False,
                 prune_datastore: bool = True,

                 # Blockchain
                 decentralized_identity_evidence: bytes = constants.NOT_SIGNED,
                 checksum_address: str = None,
                 worker_address: str = None,  # TODO: deprecate, and rename to "checksum_address"
                 block_until_ready: bool = True,
                 # TODO: Must be true in order to set staker address - Allow for manual staker addr to be passed too!
                 work_tracker: WorkTracker = None,
                 start_working_now: bool = True,
                 client_password: str = None,

                 # Character
                 abort_on_learning_error: bool = False,
                 federated_only: bool = False,
                 start_learning_now: bool = None,
                 crypto_power=None,
                 tls_curve: EllipticCurve = None,
                 known_nodes: Iterable = None,

                 **character_kwargs
                 ) -> None:

        #
        # Character
        #

        if domain is None:
            # TODO: Move defaults to configuration, Off character.
            from nucypher.config.node import CharacterConfiguration
            domain = CharacterConfiguration.DEFAULT_DOMAIN

        if is_me:
            # If we're federated only, we assume that all other nodes in our domain are as well.
            self.set_federated_mode(federated_only)

        Character.__init__(self,
                           is_me=is_me,
                           checksum_address=checksum_address,
                           start_learning_now=start_learning_now,
                           federated_only=self._federated_only_instances,
                           # TODO: 'Ursula' object has no attribute '_federated_only_instances' if an is_me Ursula is not inited prior to this moment  NRN
                           crypto_power=crypto_power,
                           abort_on_learning_error=abort_on_learning_error,
                           known_nodes=known_nodes,
                           domain=domain,
                           known_node_class=Ursula,
                           **character_kwargs)

        if is_me:
            # Learner
            self._start_learning_now = start_learning_now

            # Self-Health Checks
            self._availability_check = availability_check
            self._availability_tracker = AvailabilityTracker(ursula=self)

            # Datastore Pruning
            self.__pruning_task = None
            self._prune_datastore = prune_datastore
            self._datastore_pruning_task = LoopingCall(f=self.__prune_datastore)

        #
        # Ursula the Decentralized Worker (Self)
        #

        if is_me and not federated_only:  # TODO: #429

            # Prepare a TransactingPower from worker node's transacting keys
            _transacting_power = TransactingPower(account=worker_address,
                                                  password=client_password,
                                                  signer=self.signer,
                                                  cache=True)

            self.transacting_power = _transacting_power
            self._crypto_power.consume_power_up(_transacting_power)
            self._set_checksum_address(checksum_address)

            # Use this power to substantiate the stamp
            self.substantiate_stamp()
            self.log.debug(
                f"Created decentralized identity evidence: {self.decentralized_identity_evidence[:10].hex()}")
            decentralized_identity_evidence = self.decentralized_identity_evidence

            try:
                Worker.__init__(self,
                                is_me=is_me,
                                registry=self.registry,
                                checksum_address=checksum_address,
                                worker_address=worker_address,
                                work_tracker=work_tracker,
                                start_working_now=start_working_now,
                                block_until_ready=block_until_ready)
            except (Exception, self.WorkerError):  # FIXME
                # TODO: Do not announce self to "other nodes" until this init is finished.
                # It's not possible to finish constructing this node.
                self.stop(halt_reactor=False)
                raise

        if not crypto_power or (TLSHostingPower not in crypto_power):

            #
            # Development Ursula
            #

            if is_me:
                self.suspicious_activities_witnessed = {'vladimirs': [],
                                                        'bad_treasure_maps': [],
                                                        'freeriders': []}

                # REST Server (Ephemeral Self-Ursula)
                rest_app, datastore = make_rest_app(
                    this_node=self,
                    db_filepath=db_filepath,
                    domain=domain,
                )

                # TLSHostingPower (Ephemeral Powers and Private Keys)
                tls_hosting_keypair = HostingKeypair(curve=tls_curve, host=rest_host,
                                                     checksum_address=self.checksum_address)
                tls_hosting_power = TLSHostingPower(keypair=tls_hosting_keypair, host=rest_host)
                self.rest_server = ProxyRESTServer(rest_host=rest_host, rest_port=rest_port,
                                                   rest_app=rest_app, datastore=datastore,
                                                   hosting_power=tls_hosting_power)

            #
            # Stranger-Ursula
            #

            else:

                # TLSHostingPower
                if certificate or certificate_filepath:
                    tls_hosting_power = TLSHostingPower(host=rest_host,
                                                        public_certificate_filepath=certificate_filepath,
                                                        public_certificate=certificate)
                else:
                    tls_hosting_keypair = HostingKeypair(curve=tls_curve, host=rest_host, generate_certificate=False)
                    tls_hosting_power = TLSHostingPower(host=rest_host, keypair=tls_hosting_keypair)

                # REST Server
                # Unless the caller passed a crypto power we'll make our own TLSHostingPower for this stranger.
                self.rest_server = ProxyRESTServer(
                    rest_host=rest_host,
                    rest_port=rest_port,
                    hosting_power=tls_hosting_power
                )

            # OK - Now we have a ProxyRestServer and a TLSHostingPower for some Ursula
            self._crypto_power.consume_power_up(tls_hosting_power)  # Consume!

        #
        # Teacher (Verifiable Node)
        #

        certificate_filepath = self._crypto_power.power_ups(TLSHostingPower).keypair.certificate_filepath
        certificate = self._crypto_power.power_ups(TLSHostingPower).keypair.certificate
        Teacher.__init__(self,
                         domain=domain,
                         certificate=certificate,
                         certificate_filepath=certificate_filepath,
                         interface_signature=interface_signature,
                         timestamp=timestamp,
                         decentralized_identity_evidence=decentralized_identity_evidence)

        if is_me:
            self.known_nodes.record_fleet_state(additional_nodes_to_track=[self])  # Initial Impression

            message = "THIS IS YOU: {}: {}".format(self.__class__.__name__, self)
            self.log.info(message)
            self.log.info(self.banner.format(self.nickname))
        else:
            message = "Initialized Stranger {} | {}".format(self.__class__.__name__, self)
            self.log.debug(message)

    def __prune_datastore(self) -> None:
        """Deletes all expired arrangements, kfrags, and treasure maps in the datastore."""
        now = maya.MayaDT.from_datetime(datetime.fromtimestamp(self._datastore_pruning_task.clock.seconds()))
        try:
            with self.datastore.query_by(PolicyArrangement,
                                         filter_field='expiration',
                                         filter_func=lambda expiration: expiration <= now,
                                         writeable=True) as expired_policies:
                for policy in expired_policies:
                    policy.delete()
                result = len(expired_policies)
        except RecordNotFound:
            self.log.debug("No expired policy arrangements found.")
        except DatastoreTransactionError:
            self.log.warn(f"Failed to prune policy arrangements; DB session rolled back.")
        else:
            if result > 0:
                self.log.debug(f"Pruned {result} policy arrangements.")

        try:
            with self.datastore.query_by(DatastoreTreasureMap,
                                         filter_field='expiration',
                                         filter_func=lambda expiration: expiration <= now,
                                         writeable=True) as expired_treasure_maps:
                for treasure_map in expired_treasure_maps:
                    treasure_map.delete()
                result = len(expired_treasure_maps)
        except RecordNotFound:
            self.log.debug("No expired treasure maps found.")
        except DatastoreTransactionError:
            self.log.warn(f"Failed to prune expired treasure maps; DB session rolled back.")
        else:
            if result > 0:
                self.log.debug(f"Pruned {result} treasure maps.")

    def run(self,
            emitter: StdoutEmitter = None,
            hendrix: bool = True,
            learning: bool = True,
            availability: bool = True,
            worker: bool = True,
            pruning: bool = True,
            interactive: bool = False,
            start_reactor: bool = True,
            prometheus_config: 'PrometheusMetricsConfig' = None,
            ) -> None:

        """Schedule and start select ursula services, then optionally start the reactor."""

        #
        # Async loops ordered by schedule priority
        #

        if emitter:
            emitter.message(f"Starting services...", color='yellow')

        if pruning:
            self.__pruning_task = self._datastore_pruning_task.start(interval=self._pruning_interval, now=True)
            if emitter:
                emitter.message(f"✓ Database pruning", color='green')

        # TODO: block until specific nodes are known here?
        # if learning:  # TODO: Include learning startup here with the rest of the services?
        #     self.start_learning_loop(now=self._start_learning_now)
        #     if emitter:
        #         emitter.message(f"✓ Node Discovery ({','.join(self.domain)})", color='green')

        if self._availability_check and availability:
            self._availability_tracker.start(now=False)  # wait...
            if emitter:
                emitter.message(f"✓ Availability Checks", color='green')

        if worker and not self.federated_only:
            self.work_tracker.start(act_now=True)  # requirement_func=self._availability_tracker.status)  # TODO: #2277
            if emitter:
                emitter.message(f"✓ Work Tracking", color='green')

        #
        # Non-order dependant services
        #

        if prometheus_config:
            # Locally scoped to prevent import without prometheus explicitly installed
            from nucypher.utilities.prometheus.metrics import start_prometheus_exporter
            # TODO: Integrate with Hendrix TLS Deploy?
            start_prometheus_exporter(ursula=self, prometheus_config=prometheus_config)
            if emitter:
                emitter.message(f"✓ Prometheus Exporter", color='green')

        if interactive and emitter:
            stdio.StandardIO(UrsulaCommandProtocol(ursula=self, emitter=emitter))

        if hendrix:

            if emitter:
                emitter.message(f"Starting Ursula on {self.rest_interface}", color='green', bold=True)

            deployer = self.get_deployer()
            deployer.addServices()
            deployer.catalogServers(deployer.hendrix)

            if not start_reactor:
                return

            if emitter:
                emitter.message("Working ~ Keep Ursula Online!", color='blue', bold=True)

            try:
                deployer.run()  # <--- Blocking Call (Reactor)
            except Exception as e:
                self.log.critical(str(e))
                if emitter:
                    emitter.message(f"{e.__class__.__name__} {e}", color='red', bold=True)
                raise  # Crash :-(

        elif start_reactor:  # ... without hendrix
            reactor.run()  # <--- Blocking Call (Reactor)

    def stop(self, halt_reactor: bool = False) -> None:
        """
        Stop services for partially or fully initialized characters.
        # CAUTION #
        """
        self.log.debug(f"---------Stopping {self}")
        # Handles the shutdown of a partially initialized character.
        with contextlib.suppress(AttributeError):  # TODO: Is this acceptable here, what are alternatives?
            self._availability_tracker.stop()
            self.stop_learning_loop()
            if not self.federated_only:
                self.work_tracker.stop()
            if self._datastore_pruning_task.running:
                self._datastore_pruning_task.stop()
        if halt_reactor:
            reactor.stop()

    def _finalize(self):
        """
        Cleans up Ursula from objects that may eat up system resources.
        Useful for testing purposes, where many Ursulas are created and destroyed,
        and references to them may persist for too long.
        This method is not needed if all references to the Ursula are released.

        **Warning:** invalidates the Ursula.
        """

        # `rest_server` holds references to the datastore (directly and via `rest_app`).
        # An open datastore hogs up file descriptors.
        self.rest_server = INVALIDATED

    def rest_information(self):
        hosting_power = self._crypto_power.power_ups(TLSHostingPower)

        return (
            self.rest_server.rest_interface,
            hosting_power.keypair.certificate,
            hosting_power.keypair.pubkey
        )

    @property
    def rest_interface(self):
        return self.rest_server.rest_interface

    def get_deployer(self):
        port = self.rest_interface.port
        deployer = self._crypto_power.power_ups(TLSHostingPower).get_deployer(rest_app=self.rest_app, port=port)
        return deployer

    def rest_server_certificate(self):
        return self._crypto_power.power_ups(TLSHostingPower).keypair.certificate

    def __bytes__(self):

        version = self.TEACHER_VERSION.to_bytes(2, "big")
        interface_info = VariableLengthBytestring(bytes(self.rest_interface))

        certificate = self.rest_server_certificate()
        cert_vbytes = VariableLengthBytestring(certificate.public_bytes(Encoding.PEM))

        as_bytes = bytes().join((version,
                                 self.canonical_public_address,
                                 bytes(VariableLengthBytestring(self.domain.encode('utf-8'))),
                                 self.timestamp_bytes(),
                                 bytes(self._interface_signature),
                                 bytes(VariableLengthBytestring(self.decentralized_identity_evidence)),  # FIXME: Fixed length doesn't work with federated
                                 bytes(self.public_keys(SigningPower)),
                                 bytes(self.public_keys(DecryptingPower)),
                                 bytes(cert_vbytes),
                                 bytes(interface_info))
                                )
        return as_bytes

    #
    # Alternate Constructors
    #

    @classmethod
    def from_rest_url(cls,
                      network_middleware: RestMiddleware,
                      host: str,
                      port: int,
                      certificate_filepath,
                      *args, **kwargs
                      ):
        response_data = network_middleware.client.node_information(host, port,
                                                                   certificate_filepath=certificate_filepath)

        stranger_ursula_from_public_keys = cls.from_bytes(response_data,
                                                          *args, **kwargs)

        return stranger_ursula_from_public_keys

    @classmethod
    def from_seednode_metadata(cls, seednode_metadata, *args, **kwargs):
        """
        Essentially another deserialization method, but this one doesn't reconstruct a complete
        node from bytes; instead it's just enough to connect to and verify a node.

        NOTE: This is a federated only method.
        """
        seed_uri = f'{seednode_metadata.checksum_address}@{seednode_metadata.rest_host}:{seednode_metadata.rest_port}'
        return cls.from_seed_and_stake_info(seed_uri=seed_uri, *args, **kwargs)

    @classmethod
    def from_teacher_uri(cls,
                         federated_only: bool,
                         teacher_uri: str,
                         min_stake: int,
                         network_middleware: RestMiddleware = None,
                         registry: BaseContractRegistry = None,
                         retry_attempts: int = 2,
                         retry_interval: int = 2
                         ) -> 'Ursula':

        def __attempt(attempt=1, interval=retry_interval) -> Ursula:
            if attempt >= retry_attempts:
                raise ConnectionRefusedError("Host {} Refused Connection".format(teacher_uri))

            try:
                teacher = cls.from_seed_and_stake_info(seed_uri=teacher_uri,
                                                       federated_only=federated_only,
                                                       minimum_stake=min_stake,
                                                       network_middleware=network_middleware,
                                                       registry=registry)

            except NodeSeemsToBeDown as e:
                log = Logger(cls.__name__)
                log.warn(
                    "Can't connect to seed node (attempt {}).  Will retry in {} seconds.".format(attempt, interval))
                time.sleep(interval)
                return __attempt(attempt=attempt + 1)
            else:
                return teacher

        return __attempt()

    @classmethod
    def from_seed_and_stake_info(cls,
                                 seed_uri: str,
                                 federated_only: bool = False,
                                 minimum_stake: int = 0,
                                 registry: BaseContractRegistry = None,
                                 network_middleware: RestMiddleware = None,
                                 *args,
                                 **kwargs
                                 ) -> 'Ursula':

        if network_middleware is None:
            network_middleware = RestMiddleware(registry=registry)

        #
        # WARNING: xxx Poison xxx
        # Let's learn what we can about the ... "seednode".
        #

        # Parse node URI
        host, port, checksum_address = parse_node_uri(seed_uri)

        # Fetch the hosts TLS certificate and read the common name
        try:
            certificate = network_middleware.get_certificate(host=host, port=port)
        except NodeSeemsToBeDown as e:
            e.args += (f"While trying to load seednode {seed_uri}",)
            e.crash_right_now = True
            raise
        real_host = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        # Create a temporary certificate storage area
        temp_node_storage = ForgetfulNodeStorage(federated_only=federated_only)
        temp_certificate_filepath = temp_node_storage.store_node_certificate(certificate=certificate)

        # Load the host as a potential seed node
        potential_seed_node = cls.from_rest_url(
            host=real_host,
            port=port,
            network_middleware=network_middleware,
            certificate_filepath=temp_certificate_filepath,
            *args,
            **kwargs
        )

        # Check the node's stake (optional)
        if minimum_stake > 0 and not federated_only:
            staking_agent = ContractAgency.get_agent(StakingEscrowAgent, registry=registry)
            seednode_stake = staking_agent.get_locked_tokens(staker_address=checksum_address)
            if seednode_stake < minimum_stake:
                raise Learner.NotATeacher(
                    f"{checksum_address} is staking less than the specified minimum stake value ({minimum_stake}).")

        # OK - everyone get out
        temp_node_storage.forget()
        return potential_seed_node

    @classmethod
    def payload_splitter(cls, splittable, partial=False):
        splitter = BytestringKwargifier(
            _receiver=cls.from_processed_bytes,
            _partial_receiver=NodeSprout,
            public_address=ETH_ADDRESS_BYTE_LENGTH,
            domain=VariableLengthBytestring,
            timestamp=(int, 4, {'byteorder': 'big'}),
            interface_signature=Signature,
            decentralized_identity_evidence=VariableLengthBytestring,  # FIXME: Fixed length doesn't work with federated. It was LENGTH_ECDSA_SIGNATURE_WITH_RECOVERY,
            verifying_key=(UmbralPublicKey, PUBLIC_KEY_LENGTH),
            encrypting_key=(UmbralPublicKey, PUBLIC_KEY_LENGTH),
            certificate=(load_pem_x509_certificate, VariableLengthBytestring, {"backend": default_backend()}),
            rest_interface=InterfaceInfo,
        )
        result = splitter(splittable, partial=partial)
        return result

    @classmethod
    def is_compatible_version(cls, version: int) -> bool:
        return cls.LOWEST_COMPATIBLE_VERSION <= version <= cls.LEARNER_VERSION

    @classmethod
    def from_bytes(cls,
                   ursula_as_bytes: bytes,
                   version: int = INCLUDED_IN_BYTESTRING,
                   fail_fast=False,
                   ) -> 'Ursula':

        if version is INCLUDED_IN_BYTESTRING:
            version, payload = cls.version_splitter(ursula_as_bytes, return_remainder=True)
        else:
            payload = ursula_as_bytes

        # Check version is compatible and prepare to handle potential failures otherwise
        if not cls.is_compatible_version(version):
            version_exception_class = cls.IsFromTheFuture if version > cls.LEARNER_VERSION else cls.AreYouFromThePast

            # Try to handle failure, even during failure, graceful degradation
            # TODO: #154 - Some auto-updater logic?

            try:
                canonical_address, _ = BytestringSplitter(ETH_ADDRESS_BYTE_LENGTH)(payload, return_remainder=True)
                checksum_address = to_checksum_address(canonical_address)
                nickname = Nickname.from_seed(checksum_address)
                display_name = cls._display_name_template.format(cls.__name__, nickname, checksum_address)
                message = cls.unknown_version_message.format(display_name, version, cls.LEARNER_VERSION)
                if version > cls.LEARNER_VERSION:
                    message += " Is there a newer version of NuCypher?"
            except BytestringSplittingError:
                message = cls.really_unknown_version_message.format(version, cls.LEARNER_VERSION)

            if fail_fast:
                raise version_exception_class(message)
            else:
                cls.log.warn(message)
                return UNKNOWN_VERSION
        else:
            # Version stuff checked out.  Moving on.
            node_sprout = cls.payload_splitter(payload, partial=True)
            return node_sprout

    @classmethod
    def from_processed_bytes(cls, **processed_objects):
        """
        A convenience method for completing the maturation of a NodeSprout.
        TODO: Either deprecate or consolidate this logic; it's mostly just workarounds.  NRN
        """
        #### This is kind of a ridiculous workaround and repeated logic from Ursula.from_bytes
        interface_info = processed_objects.pop("rest_interface")
        rest_host = interface_info.host
        rest_port = interface_info.port
        checksum_address = to_checksum_address(processed_objects.pop('public_address'))

        domain = processed_objects.pop('domain').decode('utf-8')

        timestamp = maya.MayaDT(processed_objects.pop('timestamp'))

        ursula = cls.from_public_keys(rest_host=rest_host,
                                      rest_port=rest_port,
                                      checksum_address=checksum_address,
                                      domain=domain,
                                      timestamp=timestamp,
                                      **processed_objects)
        return ursula

    @classmethod
    def batch_from_bytes(cls,
                         ursulas_as_bytes: Iterable[bytes],
                         fail_fast: bool = False,
                         ) -> List['Ursula']:

        node_splitter = BytestringSplitter(VariableLengthBytestring)
        nodes_vbytes = node_splitter.repeat(ursulas_as_bytes)
        version_splitter = BytestringSplitter((int, 2, {"byteorder": "big"}))
        versions_and_node_bytes = [version_splitter(n, return_remainder=True) for n in nodes_vbytes]

        sprouts = []
        for version, node_bytes in versions_and_node_bytes:
            try:
                sprout = cls.from_bytes(node_bytes,
                                        version=version)
                if sprout is UNKNOWN_VERSION:
                    continue
            except BytestringSplittingError:
                message = cls.really_unknown_version_message.format(version, cls.LEARNER_VERSION)
                if fail_fast:
                    raise cls.IsFromTheFuture(message)
                else:
                    cls.log.warn(message)
                    continue
            except Ursula.IsFromTheFuture as e:
                if fail_fast:
                    raise
                else:
                    cls.log.warn(e.args[0])
                    continue
            else:
                sprouts.append(sprout)
        return sprouts

    @classmethod
    def from_storage(cls,
                     node_storage: NodeStorage,
                     checksum_adress: str,
                     federated_only: bool = False) -> 'Ursula':
        return node_storage.get(checksum_address=checksum_adress,
                                federated_only=federated_only)

    #
    # Properties
    #
    @property
    def datastore(self):
        try:
            return self.rest_server.datastore
        except AttributeError:
            raise AttributeError("No rest server attached")

    @property
    def rest_url(self):
        try:
            return self.rest_server.rest_url
        except AttributeError:
            raise AttributeError("No rest server attached")

    @property
    def rest_app(self):
        rest_app_on_server = self.rest_server.rest_app

        if rest_app_on_server is PUBLIC_ONLY or not rest_app_on_server:
            m = "This Ursula doesn't have a REST app attached. If you want one, init with is_me and attach_server."
            raise PowerUpError(m)
        else:
            return rest_app_on_server

    def interface_info_with_metadata(self):
        # TODO: Do we ever actually use this without using the rest of the serialized Ursula?  337
        return constants.BYTESTRING_IS_URSULA_IFACE_INFO + bytes(self)

    #
    # Re-Encryption
    #

    def _reencrypt(self, kfrag: KFrag, work_order: 'WorkOrder', alice_verifying_key: UmbralPublicKey):

        # Prepare a bytestring for concatenating re-encrypted
        # capsule data for each work order task.
        cfrag_byte_stream = bytes()
        for capsule, task in work_order.tasks.items():
            # Ursula signs on top of Bob's signature of each task.
            # Now both are committed to the same task.  See #259.
            reencryption_metadata = bytes(self.stamp(bytes(task.signature)))

            # Ursula sets Alice's verifying key for capsule correctness verification.
            capsule.set_correctness_keys(verifying=alice_verifying_key)

            # Then re-encrypts the fragment.
            cfrag = pre.reencrypt(kfrag, capsule, metadata=reencryption_metadata)  # <--- pyUmbral
            self.log.info(f"Re-encrypted capsule {capsule} -> made {cfrag}.")

            # Next, Ursula signs to commit to her results.
            reencryption_signature = self.stamp(bytes(cfrag))
            cfrag_byte_stream += VariableLengthBytestring(cfrag) + reencryption_signature

        # ... and finally returns all the re-encrypted bytes
        return cfrag_byte_stream


class Enrico(Character):
    """A Character that represents a Data Source that encrypts data for some policy's public key"""

    banner = ENRICO_BANNER
    _interface_class = EnricoInterface
    _default_crypto_powerups = [SigningPower]

    def __init__(self, policy_encrypting_key=None, controller: bool = True, *args, **kwargs):
        self._policy_pubkey = policy_encrypting_key

        # Enrico never uses the blockchain, hence federated_only)
        kwargs['federated_only'] = True
        kwargs['known_node_class'] = None
        super().__init__(*args, **kwargs)

        if controller:
            self.make_cli_controller()

        self.log = Logger(f'{self.__class__.__name__}-{bytes(self.public_keys(SigningPower)).hex()[:6]}')
        self.log.info(self.banner.format(policy_encrypting_key))

    def encrypt_message(self, plaintext: bytes) -> Tuple[UmbralMessageKit, Signature]:
        # TODO: #2107 Rename to "encrypt"
        message_kit, signature = encrypt_and_sign(self.policy_pubkey,
                                                  plaintext=plaintext,
                                                  signer=self.stamp)
        message_kit.policy_pubkey = self.policy_pubkey  # TODO: We can probably do better here.  NRN
        return message_kit, signature

    @classmethod
    def from_alice(cls, alice: Alice, label: bytes):
        """
        :param alice: Not a stranger.  This is your Alice who will derive the policy keypair, leaving Enrico with the public part.
        :param label: The label with which to derive the key.
        :return:
        """
        policy_pubkey_enc = alice.get_policy_encrypting_key_from_label(label)
        return cls(crypto_power_ups={SigningPower: alice.stamp.as_umbral_pubkey()},
                   policy_encrypting_key=policy_pubkey_enc)

    @property
    def policy_pubkey(self):
        if not self._policy_pubkey:
            raise TypeError("This Enrico doesn't know which policy encrypting key he used.  Oh well.")
        return self._policy_pubkey

    def _set_known_node_class(self, *args, **kwargs):
        """
        Enrico doesn't init nodes, so it doesn't care what class they are.
        """

    def make_web_controller(drone_enrico, crash_on_error: bool = False):

        app_name = bytes(drone_enrico.stamp).hex()[:6]
        controller = WebController(app_name=app_name,
                                   crash_on_error=crash_on_error,
                                   interface=drone_enrico._interface_class(character=drone_enrico))

        drone_enrico.controller = controller

        # Register Flask Decorator
        enrico_control = controller.make_control_transport()

        #
        # Character Control HTTP Endpoints
        #

        @enrico_control.route('/encrypt_message', methods=['POST'])
        def encrypt_message():
            """
            Character control endpoint for encrypting data for a policy and
            receiving the messagekit (and signature) to give to Bob.
            """
            try:
                request_data = json.loads(request.data)
                message = request_data['message']
            except (KeyError, JSONDecodeError) as e:
                return Response(str(e), status=400)

            # Encrypt
            message_kit, signature = drone_enrico.encrypt_message(bytes(message, encoding='utf-8'))

            response_data = {
                'result': {
                    'message_kit': b64encode(message_kit.to_bytes()).decode(),  # FIXME, but NRN
                    'signature': b64encode(bytes(signature)).decode(),
                },
                'version': str(nucypher.__version__)
            }

            return Response(json.dumps(response_data), status=200)

        return controller
