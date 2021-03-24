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


import datetime
from collections import OrderedDict
from queue import Queue, Empty
from typing import Callable, Tuple, Sequence, Set, Optional, Iterable, List, Dict, Type

import math
import maya
import random
import time
from abc import ABC, abstractmethod
from bytestring_splitter import BytestringSplitter, VariableLengthBytestring
from constant_sorrow.constants import NOT_SIGNED
from eth_typing.evm import ChecksumAddress
from hexbytes import HexBytes
from twisted._threads import AlreadyQuit
from twisted.internet import reactor
from twisted.internet.defer import ensureDeferred, Deferred
from twisted.python.threadpool import ThreadPool
from nucypher.crypto.umbral_adapter import UmbralPublicKey, KFrag

from nucypher.blockchain.eth.actors import BlockchainPolicyAuthor
from nucypher.blockchain.eth.agents import PolicyManagerAgent, StakersReservoir, StakingEscrowAgent
from nucypher.characters.lawful import Alice, Ursula
from nucypher.crypto.api import keccak_digest, secure_random
from nucypher.crypto.constants import HRAC_LENGTH, PUBLIC_KEY_LENGTH
from nucypher.crypto.kits import RevocationKit
from nucypher.crypto.powers import DecryptingPower, SigningPower, TransactingPower
from nucypher.crypto.utils import construct_policy_id
from nucypher.network.exceptions import NodeSeemsToBeDown
from nucypher.network.middleware import RestMiddleware
from nucypher.utilities.concurrency import WorkerPool, AllAtOnceFactory
from nucypher.utilities.logging import Logger


class Arrangement:
    """
    A contract between Alice and a single Ursula.
    """
    ID_LENGTH = 32

    splitter = BytestringSplitter((UmbralPublicKey, PUBLIC_KEY_LENGTH),  # alive_verifying_key
                                  (bytes, ID_LENGTH),  # arrangement_id
                                  (bytes, VariableLengthBytestring))  # expiration

    @classmethod
    def from_alice(cls, alice: Alice, expiration: maya.MayaDT) -> 'Arrangement':
        arrangement_id = secure_random(cls.ID_LENGTH)
        alice_verifying_key = alice.stamp.as_umbral_pubkey()
        return cls(alice_verifying_key, expiration, arrangement_id)

    def __init__(self,
                 alice_verifying_key: UmbralPublicKey,
                 expiration: maya.MayaDT,
                 arrangement_id: bytes,
                 ) -> None:
        if len(arrangement_id) != self.ID_LENGTH:
            raise ValueError(f"Arrangement ID must be of length {self.ID_LENGTH}.")
        self.id = arrangement_id
        self.expiration = expiration
        self.alice_verifying_key = alice_verifying_key

    def __bytes__(self):
        return bytes(self.alice_verifying_key) + self.id + bytes(VariableLengthBytestring(self.expiration.iso8601().encode()))

    @classmethod
    def from_bytes(cls, arrangement_as_bytes: bytes) -> 'Arrangement':
        alice_verifying_key, arrangement_id, expiration_bytes = cls.splitter(arrangement_as_bytes)
        expiration = maya.MayaDT.from_iso8601(iso8601_string=expiration_bytes.decode())
        return cls(alice_verifying_key=alice_verifying_key, arrangement_id=arrangement_id, expiration=expiration)

    def __repr__(self):
        return f"Arrangement(client_key={self.alice_verifying_key})"


class TreasureMapPublisher:

    log = Logger('TreasureMapPublisher')

    def __init__(self,
                 worker,
                 nodes,
                 percent_to_complete_before_release=5,
                 threadpool_size=120,
                 timeout=20):

        self._total = len(nodes)
        self._block_until_this_many_are_complete = math.ceil(len(nodes) * percent_to_complete_before_release / 100)
        self._worker_pool = WorkerPool(worker=worker,
                                       value_factory=AllAtOnceFactory(nodes),
                                       target_successes=self._block_until_this_many_are_complete,
                                       timeout=timeout,
                                       stagger_timeout=0,
                                       threadpool_size=threadpool_size)

    @property
    def completed(self):
        # TODO: lock dict before copying?
        return self._worker_pool.get_successes()

    def start(self):
        self.log.info(f"TreasureMapPublisher starting")
        self._worker_pool.start()
        if reactor.running:
            reactor.callInThread(self.block_until_complete)

    def block_until_success_is_reasonably_likely(self):
        # Note: `OutOfValues`/`TimedOut` may be raised here, which means we didn't even get to
        # `percent_to_complete_before_release` successes. For now just letting it fire.
        self._worker_pool.block_until_target_successes()
        completed = self.completed
        self.log.debug(f"The minimal amount of nodes ({len(completed)}) was contacted "
                       "while blocking for treasure map publication.")
        return completed

    def block_until_complete(self):
        self._worker_pool.join()


class MergedReservoir:
    """
    A reservoir made of a list of addresses and a StakersReservoir.
    Draws the values from the list first, then from StakersReservoir,
    then returns None on subsequent calls.
    """

    def __init__(self, values: Iterable, reservoir: StakersReservoir):
        self.values = list(values)
        self.reservoir = reservoir

    def __call__(self) -> Optional[ChecksumAddress]:
        if self.values:
            return self.values.pop(0)
        elif len(self.reservoir) > 0:
            return self.reservoir.draw(1)[0]
        else:
            return None


class PrefetchStrategy:
    """
    Encapsulates the batch draw strategy from a reservoir.
    Determines how many values to draw based on the number of values
    that have already led to successes.
    """

    def __init__(self, reservoir: MergedReservoir, need_successes: int):
        self.reservoir = reservoir
        self.need_successes = need_successes

    def __call__(self, successes: int) -> Optional[List[ChecksumAddress]]:
        batch = []
        for i in range(self.need_successes - successes):
            value = self.reservoir()
            if value is None:
                break
            batch.append(value)
        if not batch:
            return None
        return batch


class Policy(ABC):
    """
    An edict by Alice, arranged with n Ursulas, to perform re-encryption for a specific Bob.
    """

    POLICY_ID_LENGTH = 16

    log = Logger("Policy")

    class NotEnoughUrsulas(Exception):
        """
        Raised when a Policy has been used to generate Arrangements with Ursulas insufficient number
        such that we don't have enough KFrags to give to each Ursula.
        """

    class EnactmentError(Exception):
        """
        Raised if one or more Ursulas failed to enact the policy.
        """

    def __init__(self,
                 alice: Alice,
                 label: bytes,
                 expiration: maya.MayaDT,
                 bob: 'Bob',
                 kfrags: Sequence[KFrag],
                 public_key: UmbralPublicKey,
                 m: int,
                 ):

        """
        :param kfrags:  A list of KFrags to distribute per this Policy.
        :param label: The identity of the resource to which Bob is granted access.
        """

        self.m = m
        self.n = len(kfrags)
        self.alice = alice
        self.label = label
        self.bob = bob
        self.kfrags = kfrags
        self.public_key = public_key
        self.expiration = expiration

        self._id = construct_policy_id(self.label, bytes(self.bob.stamp))

        """
        # TODO: #180 - This attribute is hanging on for dear life.
        After 180 is closed, it can be completely deprecated.

        The "hashed resource authentication code".

        A hash of:
        * Alice's public key
        * Bob's public key
        * the label

        Alice and Bob have all the information they need to construct this.
        Ursula does not, so we share it with her.
        """
        self.hrac = keccak_digest(bytes(self.alice.stamp) + bytes(self.bob.stamp) + self.label)[:HRAC_LENGTH]

    def __repr__(self):
        return f"{self.__class__.__name__}:{self._id.hex()[:6]}"

    def _propose_arrangement(self,
                             address: ChecksumAddress,
                             network_middleware: RestMiddleware,
                             ) -> Tuple[Ursula, Arrangement]:
        """
        Attempt to propose an arrangement to the node with the given address.
        """

        if address not in self.alice.known_nodes:
            raise RuntimeError(f"{address} is not known")

        ursula = self.alice.known_nodes[address]
        arrangement = Arrangement.from_alice(alice=self.alice, expiration=self.expiration)

        self.log.debug(f"Proposing arrangement {arrangement} to {ursula}")
        negotiation_response = network_middleware.propose_arrangement(ursula, arrangement)
        status = negotiation_response.status_code

        if status == 200:
            self.log.debug(f"Arrangement accepted by {ursula}")
        else:
            message = f"Proposing arrangement to {ursula} failed with {status}"
            self.log.debug(message)
            raise RuntimeError(message)

        # We could just return the arrangement and get the Ursula object
        # from `known_nodes` later, but when we introduce slashing in FleetSensor,
        # the address can already disappear from `known_nodes` by that time.
        return (ursula, arrangement)

    @abstractmethod
    def _make_reservoir(self, handpicked_addresses: Sequence[ChecksumAddress]) -> MergedReservoir:
        """
        Builds a `MergedReservoir` to use for drawing addresses to send proposals to.
        """
        raise NotImplementedError

    def _make_arrangements(self,
                           network_middleware: RestMiddleware,
                           handpicked_ursulas: Optional[Iterable[Ursula]] = None,
                           timeout: int = 10,
                           ) -> Dict[Ursula, Arrangement]:
        """
        Pick some Ursula addresses and send them arrangement proposals.
        Returns a dictionary of Ursulas to Arrangements if it managed to get `n` responses.
        """

        if handpicked_ursulas is None:
            handpicked_ursulas = []
        handpicked_addresses = [ursula.checksum_address for ursula in handpicked_ursulas]

        reservoir = self._make_reservoir(handpicked_addresses)
        value_factory = PrefetchStrategy(reservoir, self.n)

        def worker(address):
            return self._propose_arrangement(address, network_middleware)

        self.alice.block_until_number_of_known_nodes_is(self.n, learn_on_this_thread=True, eager=True)

        worker_pool = WorkerPool(worker=worker,
                                 value_factory=value_factory,
                                 target_successes=self.n,
                                 timeout=timeout,
                                 stagger_timeout=1,
                                 threadpool_size=self.n)
        worker_pool.start()
        try:
            successes = worker_pool.block_until_target_successes()
        except (WorkerPool.OutOfValues, WorkerPool.TimedOut):
            # It's possible to raise some other exceptions here,
            # but we will use the logic below.
            successes = worker_pool.get_successes()
        finally:
            worker_pool.cancel()
            worker_pool.join()

        accepted_arrangements = {ursula: arrangement for ursula, arrangement in successes.values()}
        failures = worker_pool.get_failures()

        accepted_addresses = ", ".join(ursula.checksum_address for ursula in accepted_arrangements)

        if len(accepted_arrangements) < self.n:

            rejected_proposals = "\n".join(f"{address}: {value}" for address, (type_, value, traceback) in failures.items())

            self.log.debug(
                "Could not find enough Ursulas to accept proposals.\n"
                f"Accepted: {accepted_addresses}\n"
                f"Rejected:\n{rejected_proposals}")

            raise self._not_enough_ursulas_exception()
        else:
            self.log.debug(f"Finished proposing arrangements; accepted: {accepted_addresses}")

        return accepted_arrangements

    def _enact_arrangements(self,
                            network_middleware: RestMiddleware,
                            arrangements: Dict[Ursula, Arrangement],
                            publication_transaction: Optional[HexBytes] = None,
                            publish_treasure_map: bool = True,
                            timeout: int = 10,
                            ):
        """
        Attempts to distribute kfrags to Ursulas that accepted arrangements earlier.
        """

        def worker(ursula_and_kfrag):
            ursula, kfrag = ursula_and_kfrag
            arrangement = arrangements[ursula]

            # TODO: seems like it would be enough to just encrypt this with Ursula's public key,
            # and not create a whole capsule.
            # Can't change for now since it's node protocol.
            payload = self._make_enactment_payload(publication_transaction, kfrag)
            message_kit, _signature = self.alice.encrypt_for(ursula, payload)

            try:
                # TODO: Concurrency
                response = network_middleware.enact_policy(ursula,
                                                           arrangement.id,
                                                           message_kit.to_bytes())
            except network_middleware.UnexpectedResponse as e:
                status = e.status
            else:
                status = response.status_code

            return status

        value_factory = AllAtOnceFactory(list(zip(arrangements, self.kfrags)))
        worker_pool = WorkerPool(worker=worker,
                                 value_factory=value_factory,
                                 target_successes=self.n,
                                 timeout=timeout,
                                 threadpool_size=self.n)

        worker_pool.start()

        # Block until everything is complete. We need all the workers to finish.
        worker_pool.join()

        successes = worker_pool.get_successes()

        if len(successes) != self.n:
            raise Policy.EnactmentError()

        # TODO: Enable re-tries?
        statuses = {ursula_and_kfrag[0].checksum_address: status for ursula_and_kfrag, status in successes.items()}
        if not all(status == 200 for status in statuses.values()):
            report = "\n".join(f"{address}: {status}" for address, status in statuses.items())
            self.log.debug(f"Policy enactment failed. Request statuses:\n{report}")

            # OK, let's check: if two or more Ursulas claimed we didn't pay,
            # we need to re-evaulate our situation here.
            number_of_claims_of_freeloading = sum(status == 402 for status in statuses.values())

            # TODO: a better exception here?
            if number_of_claims_of_freeloading > 2:
                raise self.alice.NotEnoughNodes

            # otherwise just raise a more generic error
            raise Policy.EnactmentError()

    def _make_treasure_map(self,
                           network_middleware: RestMiddleware,
                           arrangements: Dict[Ursula, Arrangement],
                           ) -> 'TreasureMap':
        """
        Creates a treasure map for given arrangements.
        """

        treasure_map = self._treasure_map_class(m=self.m)

        for ursula, arrangement in arrangements.items():
            treasure_map.add_arrangement(ursula, arrangement)

        treasure_map.prepare_for_publication(bob_encrypting_key=self.bob.public_keys(DecryptingPower),
                                             bob_verifying_key=self.bob.public_keys(SigningPower),
                                             alice_stamp=self.alice.stamp,
                                             label=self.label)

        return treasure_map

    def _make_publisher(self,
                        treasure_map: 'TreasureMap',
                        network_middleware: RestMiddleware,
                        ) -> TreasureMapPublisher:

        # TODO (#2516): remove hardcoding of 8 nodes
        self.alice.block_until_number_of_known_nodes_is(8, timeout=2, learn_on_this_thread=True)
        target_nodes = self.bob.matching_nodes_among(self.alice.known_nodes)
        treasure_map_bytes = bytes(treasure_map) # prevent the closure from holding the reference

        def put_treasure_map_on_node(node):
            try:
                response = network_middleware.put_treasure_map_on_node(node=node,
                                                                       map_payload=treasure_map_bytes)
            except Exception as e:
                self.log.warn(f"Putting treasure map on {node} failed: {e}")
                raise

            if response.status_code == 201:
                return response
            else:
                message = f"Putting treasure map on {node} failed with response status: {response.status}"
                self.log.warn(message)
                # TODO: What happens if this is a 300 or 400 level response?
                raise Exception(message)

        return TreasureMapPublisher(worker=put_treasure_map_on_node,
                                   nodes=target_nodes)

    def enact(self,
              network_middleware: RestMiddleware,
              handpicked_ursulas: Optional[Iterable[Ursula]] = None,
              publish_treasure_map: bool = True,
              ) -> 'EnactedPolicy':
        """
        Attempts to enact the policy, returns an `EnactedPolicy` object on success.
        """

        arrangements = self._make_arrangements(network_middleware=network_middleware,
                                               handpicked_ursulas=handpicked_ursulas)

        self._enact_arrangements(network_middleware=network_middleware,
                                 arrangements=arrangements,
                                 publish_treasure_map=publish_treasure_map)

        treasure_map = self._make_treasure_map(network_middleware=network_middleware,
                                               arrangements=arrangements)
        treasure_map_publisher = self._make_publisher(treasure_map=treasure_map,
                                                      network_middleware=network_middleware)
        revocation_kit = RevocationKit(treasure_map, self.alice.stamp)

        enacted_policy = EnactedPolicy(self._id,
                                       self.hrac,
                                       self.label,
                                       self.public_key,
                                       treasure_map,
                                       treasure_map_publisher,
                                       revocation_kit,
                                       self.alice.stamp)

        if publish_treasure_map is True:
            enacted_policy.publish_treasure_map()

        return enacted_policy

    @abstractmethod
    def _not_enough_ursulas_exception(self) -> Type[Exception]:
        """
        Returns an exception to raise when there were not enough Ursulas
        to distribute arrangements to.
        """
        raise NotImplementedError

    @abstractmethod
    def _make_enactment_payload(self, publication_transaction: Optional[HexBytes], kfrag: KFrag) -> bytes:
        """
        Serializes a given kfrag and policy publication transaction to send to Ursula.
        """
        raise NotImplementedError


class FederatedPolicy(Policy):

    from nucypher.policy.collections import TreasureMap as _treasure_map_class  # TODO: Circular Import

    def _not_enough_ursulas_exception(self):
        return Policy.NotEnoughUrsulas

    def _make_reservoir(self, handpicked_addresses):
        addresses = {
            ursula.checksum_address: 1 for ursula in self.alice.known_nodes
            if ursula.checksum_address not in handpicked_addresses}

        return MergedReservoir(handpicked_addresses, StakersReservoir(addresses))

    def _make_enactment_payload(self, publication_transaction, kfrag):
        assert publication_transaction is None # sanity check; should not ever be hit
        return bytes(kfrag)


class BlockchainPolicy(Policy):
    """
    A collection of n Arrangements representing a single Policy
    """

    from nucypher.policy.collections import SignedTreasureMap as _treasure_map_class  # TODO: Circular Import

    class InvalidPolicyValue(ValueError):
        pass

    class NotEnoughBlockchainUrsulas(Policy.NotEnoughUrsulas):
        pass

    def __init__(self,
                 value: int,
                 rate: int,
                 duration_periods: int,
                 *args,
                 **kwargs,
                 ):

        super().__init__(*args, **kwargs)

        self.duration_periods = duration_periods
        self.value = value
        self.rate = rate

        self._validate_fee_value()

    def _not_enough_ursulas_exception(self):
        return BlockchainPolicy.NotEnoughBlockchainUrsulas

    def _validate_fee_value(self) -> None:
        rate_per_period = self.value // self.n // self.duration_periods  # wei
        recalculated_value = self.duration_periods * rate_per_period * self.n
        if recalculated_value != self.value:
            raise ValueError(f"Invalid policy value calculation - "
                             f"{self.value} can't be divided into {self.n} staker payments per period "
                             f"for {self.duration_periods} periods without a remainder")

    @staticmethod
    def generate_policy_parameters(n: int,
                                   duration_periods: int,
                                   value: int = None,
                                   rate: int = None) -> dict:

        # Check for negative inputs
        if sum(True for i in (n, duration_periods, value, rate) if i is not None and i < 0) > 0:
            raise BlockchainPolicy.InvalidPolicyValue(f"Negative policy parameters are not allowed. Be positive.")

        # Check for policy params
        if not (bool(value) ^ bool(rate)):
            if not (value == 0 or rate == 0):  # Support a min fee rate of 0
                raise BlockchainPolicy.InvalidPolicyValue(f"Either 'value' or 'rate'  must be provided for policy. "
                                                          f"Got value: {value} and rate: {rate}")

        if value is None:
            value = rate * duration_periods * n

        else:
            value_per_node = value // n
            if value_per_node * n != value:
                raise BlockchainPolicy.InvalidPolicyValue(f"Policy value of ({value} wei) cannot be"
                                                          f" divided by N ({n}) without a remainder.")

            rate = value_per_node // duration_periods
            if rate * duration_periods != value_per_node:
                raise BlockchainPolicy.InvalidPolicyValue(f"Policy value of ({value_per_node} wei) per node "
                                                          f"cannot be divided by duration ({duration_periods} periods)"
                                                          f" without a remainder.")

        params = dict(rate=rate, value=value)
        return params

    def _make_reservoir(self, handpicked_addresses):
        try:
            reservoir = self.alice.get_stakers_reservoir(duration=self.duration_periods,
                                                         without=handpicked_addresses)
        except StakingEscrowAgent.NotEnoughStakers:
            # TODO: do that in `get_stakers_reservoir()`?
            reservoir = StakersReservoir({})

        return MergedReservoir(handpicked_addresses, reservoir)

    def _publish_to_blockchain(self, ursulas) -> dict:

        addresses = [ursula.checksum_address for ursula in ursulas]

        # Transact  # TODO: Move this logic to BlockchainPolicyActor
        receipt = self.alice.policy_agent.create_policy(
            policy_id=self.hrac,  # bytes16 _policyID
            transacting_power=self.alice.transacting_power,
            value=self.value,
            end_timestamp=self.expiration.epoch,  # uint16 _numberOfPeriods
            node_addresses=addresses  # address[] memory _nodes
        )

        # Capture Response
        return receipt['transactionHash']

    def _make_enactment_payload(self, publication_transaction, kfrag):
        return bytes(publication_transaction) + bytes(kfrag)

    def _enact_arrangements(self,
                            network_middleware,
                            arrangements,
                            publish_treasure_map=True) -> TreasureMapPublisher:
        transaction = self._publish_to_blockchain(list(arrangements))
        return super()._enact_arrangements(network_middleware=network_middleware,
                                           arrangements=arrangements,
                                           publish_treasure_map=publish_treasure_map,
                                           publication_transaction=transaction)

    def _make_treasure_map(self,
                           network_middleware: RestMiddleware,
                           arrangements: Dict[Ursula, Arrangement],
                           ) -> 'TreasureMap':

        treasure_map = super()._make_treasure_map(network_middleware, arrangements)
        transacting_power = self.alice._crypto_power.power_ups(TransactingPower)
        treasure_map.include_blockchain_signature(transacting_power.sign_message)
        return treasure_map


class EnactedPolicy:

    def __init__(self,
                 id: bytes,
                 hrac: bytes,
                 label: bytes,
                 public_key: UmbralPublicKey,
                 treasure_map: 'TreasureMap',
                 treasure_map_publisher: TreasureMapPublisher,
                 revocation_kit: RevocationKit,
                 alice_verifying_key: UmbralPublicKey,
                 ):

        self.id = id # TODO: is it even used anywhere?
        self.hrac = hrac
        self.label = label
        self.public_key = public_key
        self.treasure_map = treasure_map
        self.treasure_map_publisher = treasure_map_publisher
        self.revocation_kit = revocation_kit
        self.n = len(self.treasure_map.destinations)
        self.alice_verifying_key = alice_verifying_key

    def publish_treasure_map(self):
        self.treasure_map_publisher.start()
