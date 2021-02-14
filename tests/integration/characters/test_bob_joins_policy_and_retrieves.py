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
import maya
import os
import pytest
import time
from constant_sorrow.constants import NO_DECRYPTION_PERFORMED
from twisted.internet.task import Clock

from nucypher.characters.lawful import Bob, Enrico, Ursula
from nucypher.policy.collections import TreasureMap
from tests.constants import (MOCK_POLICY_DEFAULT_M, NUMBER_OF_URSULAS_IN_DEVELOPMENT_NETWORK)
from nucypher.config.constants import TEMPORARY_DOMAIN
from tests.utils.middleware import MockRestMiddleware


def test_federated_bob_full_retrieve_flow(federated_ursulas,
                                          federated_bob,
                                          federated_alice,
                                          capsule_side_channel,
                                          enacted_federated_policy):
    # Assume for the moment that Bob has already received a TreasureMap.
    treasure_map = enacted_federated_policy.treasure_map
    federated_bob.treasure_maps[treasure_map.public_id()] = treasure_map

    for ursula in federated_ursulas:
        federated_bob.remember_node(ursula)

    # The side channel delivers all that Bob needs at this point:
    # - A single MessageKit, containing a Capsule
    # - A representation of the data source
    the_message_kit = capsule_side_channel()
    alices_verifying_key = federated_alice.stamp.as_umbral_pubkey()

    delivered_cleartexts = federated_bob.retrieve(the_message_kit,
                                                  enrico=capsule_side_channel.enrico,
                                                  alice_verifying_key=alices_verifying_key,
                                                  label=enacted_federated_policy.label)

    # We show that indeed this is the passage originally encrypted by the Enrico.
    assert b"Welcome to flippering number 1." == delivered_cleartexts[0]


def test_bob_joins_policy_and_retrieves(federated_alice,
                                        federated_ursulas,
                                        certificates_tempdir,
                                        ):
    # Let's partition Ursulas in two parts
    a_couple_of_ursulas = list(federated_ursulas)[:2]
    rest_of_ursulas = list(federated_ursulas)[2:]

    # Bob becomes
    bob = Bob(federated_only=True,
              domain=TEMPORARY_DOMAIN,
              start_learning_now=True,
              network_middleware=MockRestMiddleware(),
              abort_on_learning_error=True,
              known_nodes=a_couple_of_ursulas,
              )

    # Bob has only connected to - at most - 2 nodes.
    assert sum(node.verified_node for node in bob.known_nodes.get_nodes()) <= 2

    # Alice creates a policy granting access to Bob
    # Just for fun, let's assume she distributes KFrags among Ursulas unknown to Bob
    n = NUMBER_OF_URSULAS_IN_DEVELOPMENT_NETWORK - 2
    label = b'label://' + os.urandom(32)
    contract_end_datetime = maya.now() + datetime.timedelta(days=5)
    policy = federated_alice.grant(bob=bob,
                                   label=label,
                                   m=3,
                                   n=n,
                                   expiration=contract_end_datetime,
                                   handpicked_ursulas=set(rest_of_ursulas),
                                   )

    assert label == policy.label

    try:
        # Now, Bob joins the policy
        bob.join_policy(label=label,
                        alice_verifying_key=federated_alice.stamp,
                        block=True)
    except policy.treasure_map.NowhereToBeFound:
        maps = []
        for ursula in federated_ursulas:
            for map in ursula.treasure_maps.values():
                maps.append(map)
        if policy.treasure_map in maps:
            # This is a nice place to put a breakpoint to examine Bob's failure to join a policy.
            bob.join_policy(label=label,
                            alice_verifying_key=federated_alice.stamp,
                            block=True)
            pytest.fail(f"Bob didn't find map {policy.treasure_map} even though it was available.  Come on, Bob.")
        else:
            pytest.fail(f"It seems that Alice didn't publish {policy.treasure_map}.  Come on, Alice.")

    # In the end, Bob should know all the Ursulas
    assert len(bob.known_nodes) == len(federated_ursulas)

    # Enrico becomes
    enrico = Enrico(policy_encrypting_key=policy.public_key)

    plaintext = b"What's your approach?  Mississippis or what?"
    message_kit, _signature = enrico.encrypt_message(plaintext)

    alices_verifying_key = federated_alice.stamp.as_umbral_pubkey()

    # Bob takes the message_kit and retrieves the message within
    delivered_cleartexts = bob.retrieve(message_kit,
                                        enrico=enrico,
                                        alice_verifying_key=alices_verifying_key,
                                        label=policy.label,
                                        retain_cfrags=True)

    assert plaintext == delivered_cleartexts[0]

    # Bob tries to retrieve again, but without using the cached CFrags, it fails.
    with pytest.raises(TypeError):
        delivered_cleartexts = bob.retrieve(message_kit,
                                            enrico=enrico,
                                            alice_verifying_key=alices_verifying_key,
                                            label=policy.label)

    cleartexts_delivered_a_second_time = bob.retrieve(message_kit,
                                                      enrico=enrico,
                                                      alice_verifying_key=alices_verifying_key,
                                                      label=policy.label,
                                                      use_attached_cfrags=True)

    # Indeed, they're the same cleartexts.
    assert delivered_cleartexts == cleartexts_delivered_a_second_time

    # Let's try retrieve again, but Alice revoked the policy.
    failed_revocations = federated_alice.revoke(policy)
    assert len(failed_revocations) == 0

    # One thing to note here is that Bob *can* still retrieve with the cached CFrags, even though this Policy has been revoked.  #892
    _cleartexts = bob.retrieve(message_kit,
                               enrico=enrico,
                               alice_verifying_key=alices_verifying_key,
                               label=policy.label,
                               use_precedent_work_orders=True,
                               )
    assert _cleartexts == delivered_cleartexts  # TODO: 892

    # OK, but we imagine that the message_kit is fresh here.
    message_kit.capsule.clear_cfrags()

    with pytest.raises(Ursula.NotEnoughUrsulas):
        _cleartexts = bob.retrieve(message_kit,
                                   enrico=enrico,
                                   alice_verifying_key=alices_verifying_key,
                                   label=policy.label,
                                   )

    bob.disenchant()


def test_treasure_map_serialization(enacted_federated_policy, federated_alice, federated_bob):
    treasure_map = enacted_federated_policy.treasure_map
    assert treasure_map.m is not None
    assert treasure_map.m != NO_DECRYPTION_PERFORMED
    assert treasure_map.m == MOCK_POLICY_DEFAULT_M, 'm value is not correct'

    serialized_map = bytes(treasure_map)
    deserialized_map = TreasureMap.from_bytes(serialized_map)
    assert deserialized_map._hrac == treasure_map._hrac

    # TreasureMap is currently encrypted
    with pytest.raises(TypeError):
        deserialized_map.m

    with pytest.raises(TypeError):
        deserialized_map.destinations

    compass = federated_bob.make_compass_for_alice(federated_alice)
    deserialized_map.orient(compass)
    assert deserialized_map.m == treasure_map.m
    assert deserialized_map.destinations == treasure_map.destinations


def test_bob_retrieves_with_treasure_map(
        federated_bob, federated_ursulas,
        enacted_federated_policy, capsule_side_channel):
    enrico = capsule_side_channel.enrico
    message_kit = capsule_side_channel()
    treasure_map = enacted_federated_policy.treasure_map
    alice_verifying_key = enacted_federated_policy.alice_verifying_key

    # Teach Bob about the network
    federated_bob.remember_node(list(federated_ursulas)[0])
    federated_bob.learn_from_teacher_node(eager=True)

    # Deserialized treasure map
    text1 = federated_bob.retrieve(
        message_kit,
        enrico=enrico,
        alice_verifying_key=alice_verifying_key,
        label=enacted_federated_policy.label,
        treasure_map=treasure_map)

    message_kit.capsule.clear_cfrags()  # Return back to a non re-encrypted state
    # Serialized treasure map
    text2 = federated_bob.retrieve(
        message_kit,
        enrico=enrico,
        alice_verifying_key=alice_verifying_key,
        label=enacted_federated_policy.label,
        treasure_map=bytes(treasure_map))

    assert text1[0] == text2[0] == b'Welcome to flippering number 2.'


def test_bob_retrieves_too_late(federated_bob, federated_ursulas,
                                enacted_federated_policy, capsule_side_channel):

    clock = Clock()
    clock.advance(time.time())
    for urs in federated_ursulas:
        if urs._datastore_pruning_task.running:
            urs._datastore_pruning_task.stop()
        urs._datastore_pruning_task.clock = clock
        urs._datastore_pruning_task.start(interval=Ursula._datastore_pruning_interval)

    clock.advance(86400 * 8)  # 1 week  # TODO: this is supposed to be seven days, not eight

    enrico = capsule_side_channel.enrico
    message_kit = capsule_side_channel()
    treasure_map = enacted_federated_policy.treasure_map
    alice_verifying_key = enacted_federated_policy.alice_verifying_key

    with pytest.raises(Ursula.NotEnoughUrsulas):
        federated_bob.retrieve(
            message_kit,
            enrico=enrico,
            alice_verifying_key=alice_verifying_key,
            label=enacted_federated_policy.label,
            treasure_map=treasure_map,
            use_attached_cfrags=False)

    # Check that Bob can't get the treasure map after the policy is expired
    with pytest.raises(TreasureMap.NowhereToBeFound):
        federated_bob.get_treasure_map(alice_verifying_key, label=enacted_federated_policy.label)
