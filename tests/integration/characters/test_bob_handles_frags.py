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
import pytest_twisted
from twisted.internet import threads
from nucypher.crypto.umbral_adapter import pre, CapsuleFrag, KFrag

from nucypher.crypto.kits import PolicyMessageKit
from nucypher.crypto.powers import DecryptingPower
from nucypher.config.constants import TEMPORARY_DOMAIN
from nucypher.datastore.models import PolicyArrangement, Workorder
from tests.utils.middleware import MockRestMiddleware, NodeIsDownMiddleware


def test_bob_cannot_follow_the_treasure_map_in_isolation(enacted_federated_policy, federated_bob):
    # Assume for the moment that Bob has already received a TreasureMap, perhaps via a side channel.
    hrac, treasure_map = enacted_federated_policy.hrac, enacted_federated_policy.treasure_map

    # Bob knows of no Ursulas.
    assert len(federated_bob.known_nodes) == 0

    # He can't successfully follow the TreasureMap until he learns of a node to ask.
    unknown, known = federated_bob.peek_at_treasure_map(treasure_map=treasure_map)
    assert len(known) == 0

    # TODO: Show that even with learning loop going, nothing happens here.
    # Probably use Clock?
    federated_bob.follow_treasure_map(treasure_map=treasure_map)
    assert len(known) == 0


def test_bob_already_knows_all_nodes_in_treasure_map(enacted_federated_policy,
                                                     federated_ursulas,
                                                     federated_bob,
                                                     federated_alice):
    # Bob knows of no Ursulas.
    assert len(federated_bob.known_nodes) == 0

    # Now we'll inform Bob of some Ursulas.
    for ursula in federated_ursulas:
        federated_bob.remember_node(ursula)

    # Now, Bob can get the TreasureMap all by himself, and doesn't need a side channel.
    the_map = federated_bob.get_treasure_map(federated_alice.stamp, enacted_federated_policy.label)
    unknown, known = federated_bob.peek_at_treasure_map(treasure_map=the_map)

    # He finds that he didn't need to discover any new nodes...
    assert len(unknown) == 0

    # ...because he already knew of all the Ursulas on the map.
    assert len(known) == len(enacted_federated_policy.treasure_map)


@pytest_twisted.inlineCallbacks
def test_bob_can_follow_treasure_map_even_if_he_only_knows_of_one_node(enacted_federated_policy,
                                                                       federated_ursulas,
                                                                       certificates_tempdir):
    """
    Similar to above, but this time, we'll show that if Bob can connect to a single node, he can
    learn enough to follow the TreasureMap.

    Also, we'll get the TreasureMap from the hrac alone (ie, not via a side channel).
    """

    from nucypher.characters.lawful import Bob

    bob = Bob(network_middleware=MockRestMiddleware(),
              domain=TEMPORARY_DOMAIN,
              start_learning_now=False,
              abort_on_learning_error=True,
              federated_only=True)

    # Again, let's assume that he received the TreasureMap via a side channel.
    hrac, treasure_map = enacted_federated_policy.hrac, enacted_federated_policy.treasure_map

    # Now, let's create a scenario in which Bob knows of only one node.
    assert len(bob.known_nodes) == 0
    first_ursula = list(federated_ursulas).pop(0)
    bob.remember_node(first_ursula)
    assert len(bob.known_nodes) == 1

    # This time, when he follows the TreasureMap...
    unknown_nodes, known_nodes = bob.peek_at_treasure_map(treasure_map=treasure_map)

    # Bob already knew about one node; the rest are unknown.
    assert len(unknown_nodes) == len(treasure_map) - 1

    # He needs to actually follow the treasure map to get the rest.
    bob.follow_treasure_map(treasure_map=treasure_map)

    # The nodes in the learning loop are now his top target, but he's not learning yet.
    assert not bob._learning_task.running

    # ...so he hasn't learned anything (ie, Bob still knows of just one node).
    assert len(bob.known_nodes) == 1

    # Now, we'll start his learning loop.
    bob.start_learning_loop()

    # ...and block until the unknown_nodes have all been found.
    d = threads.deferToThread(bob.block_until_specific_nodes_are_known, unknown_nodes)
    yield d

    # ...and he now has no more unknown_nodes.
    assert len(bob.known_nodes) == len(treasure_map)
    bob.disenchant()


def test_bob_can_issue_a_work_order_to_a_specific_ursula(enacted_federated_policy, federated_bob,
                                                         federated_alice, federated_ursulas, capsule_side_channel):
    """
    Now that Bob has his list of Ursulas, he can issue a WorkOrder to one. Upon receiving the WorkOrder, Ursula
    saves it and responds by re-encrypting and giving Bob a cFrag.

    This is a multipart test; it shows proper relations between the Characters Ursula and Bob and also proper
    interchange between a KFrag, Capsule, and CFrag object in the context of REST-driven proxy re-encryption.
    """

    # We pick up our story with Bob already having followed the treasure map above, ie:
    hrac, treasure_map = enacted_federated_policy.hrac, enacted_federated_policy.treasure_map
    federated_bob.start_learning_loop()

    federated_bob.follow_treasure_map(treasure_map=treasure_map, block=True, timeout=1)

    assert len(federated_bob.known_nodes) == len(federated_ursulas)

    # Bob has no saved work orders yet, ever.
    assert len(federated_bob._completed_work_orders) == 0

    # We'll test against just a single Ursula - here, we make a WorkOrder for just one.
    # We can pass any number of capsules as args; here we pass just one.
    capsule = capsule_side_channel().capsule
    capsule.set_correctness_keys(delegating=enacted_federated_policy.public_key,
                                 receiving=federated_bob.public_keys(DecryptingPower),
                                 verifying=federated_alice.stamp.as_umbral_pubkey())
    work_orders, _ = federated_bob.work_orders_for_capsules(
        capsule,
        treasure_map=treasure_map,
        alice_verifying_key=federated_alice.stamp.as_umbral_pubkey(),
        num_ursulas=1)

    # Again: one Ursula, one work_order.
    assert len(work_orders) == 1

    # Since we didn't tell Bob to cache the WorkOrders, Bob didn't save it.
    assert len(federated_bob._completed_work_orders) == 0

    # This time, we'll tell Bob to cache it.
    retained_work_orders, _ = federated_bob.work_orders_for_capsules(
        capsule,
        treasure_map=treasure_map,
        alice_verifying_key=federated_alice.stamp.as_umbral_pubkey(),
        num_ursulas=1)

    # The work order we just made is not yet complete, of course.
    address, work_order = list(retained_work_orders.items())[0]
    assert work_order.completed is False

    # **** RE-ENCRYPTION HAPPENS HERE! ****
    _success, cfrags = federated_bob._reencrypt(work_order, retain_cfrags=True)

    # We only gave one Capsule, so we only got one cFrag.
    assert len(cfrags) == 1
    the_cfrag = cfrags[0]

    # ...and the work order is complete.
    assert work_order.completed

    # Attach the CFrag to the Capsule.
    capsule.attach_cfrag(the_cfrag)

    # Having received the cFrag, Bob also saved the WorkOrder as complete.
    assert len(federated_bob._completed_work_orders.by_ursula[address]) == 1

    # OK, so cool - Bob has his cFrag!  Let's make sure everything went properly.  First, we'll show that it is in fact
    # the correct cFrag (ie, that Ursula performed re-encryption properly).
    for u in federated_ursulas:
        if u.rest_interface.port == work_order.ursula.rest_interface.port:
            ursula = u
            break
    else:
        raise RuntimeError("We've lost track of the Ursula that has the WorkOrder. Can't really proceed.")

    with ursula.datastore.describe(PolicyArrangement, work_order.arrangement_id.hex()) as policy_arrangement:
        the_kfrag = policy_arrangement.kfrag
    the_correct_cfrag = pre.reencrypt(the_kfrag, capsule)

    # The first CFRAG_LENGTH_WITHOUT_PROOF bytes (ie, the cfrag proper, not the proof material), are the same:
    assert bytes(the_cfrag)[:CapsuleFrag.expected_bytes_length()] == bytes(
        the_correct_cfrag)[:CapsuleFrag.expected_bytes_length()]  # It's the correct cfrag!

    assert the_correct_cfrag.verify_correctness(capsule)

    # Now we'll show that Ursula saved the correct WorkOrder.
    with ursula.datastore.query_by(Workorder, filter_field='bob_verifying_key',
            filter_func=lambda bob_key: bob_key == federated_bob.stamp.as_umbral_pubkey()) as work_orders_from_bob:
        assert len(work_orders_from_bob) == 1
        assert work_orders_from_bob[0].bob_signature == work_order.receipt_signature


def test_bob_can_use_cfrag_attached_to_completed_workorder(enacted_federated_policy,
                                                           federated_alice,
                                                           federated_bob,
                                                           federated_ursulas,
                                                           capsule_side_channel):
    # In our last episode, Bob made a single WorkOrder...
    work_orders = list(federated_bob._completed_work_orders.by_ursula.values())
    assert len(work_orders) == 1

    # ...and it matched the last capsule that came through the side channel.
    last_capsule_on_side_channel = capsule_side_channel.messages[-1][0].capsule
    old_work_order = work_orders[0][last_capsule_on_side_channel]

    incomplete_work_orders, complete_work_orders = federated_bob.work_orders_for_capsules(
        last_capsule_on_side_channel,
        treasure_map=enacted_federated_policy.treasure_map,
        alice_verifying_key=federated_alice.stamp.as_umbral_pubkey(),
        num_ursulas=1,
    )

    # Here we show that this WorkOrder is still saved, replete with the CFrag.
    work_orders_for_this_capsule = federated_bob._completed_work_orders._latest_replete[last_capsule_on_side_channel]
    new_work_order = list(work_orders_for_this_capsule.values())[0]
    assert old_work_order == new_work_order

    # We already got a CFrag for this WorkOrder, a couple of tests ago.
    assert old_work_order.tasks[last_capsule_on_side_channel].cfrag

    # As such, we will get TypeError if we try to get CFrags again.
    with pytest.raises(TypeError):
        federated_bob._reencrypt(new_work_order)


def test_bob_remembers_that_he_has_cfrags_for_a_particular_capsule(enacted_federated_policy, federated_alice,
                                                                   federated_bob,
                                                                   federated_ursulas, capsule_side_channel):
    # In our last episode, Bob made a single WorkOrder...
    work_orders = list(federated_bob._completed_work_orders.by_ursula.values())
    assert len(work_orders) == 1

    # ...and it matched the last capsule that came through the side channel.
    last_capsule_on_side_channel = capsule_side_channel.messages[-1][0].capsule
    first_and_only_work_order = work_orders[0]
    list_of_one_capsule = list(first_and_only_work_order.keys())
    capsule_as_saved = list_of_one_capsule[0]
    # Indeed, they're the same capsule.
    assert capsule_as_saved == last_capsule_on_side_channel
    assert len(federated_bob._completed_work_orders.by_capsule(last_capsule_on_side_channel)) == 1

    # ...and he used it to obtain a CFrag from Ursula.
    assert len(capsule_as_saved) == 1

    # He can also get a dict of {Ursula:WorkOrder} by looking them up from the capsule.
    work_orders_by_capsule = federated_bob._completed_work_orders.by_capsule(capsule_as_saved)

    # Bob has just one WorkOrder from that one Ursula.
    assert len(work_orders_by_capsule) == 1
    saved_work_order = list(work_orders_by_capsule.values())[0]

    # The rest of this test will show that if Bob generates another WorkOrder, it's for a *different* Ursula.
    incomplete_work_orders, complete_work_orders = federated_bob.work_orders_for_capsules(
        last_capsule_on_side_channel,
        treasure_map=enacted_federated_policy.treasure_map,
        alice_verifying_key=federated_alice.stamp.as_umbral_pubkey(),
        num_ursulas=1)
    id_of_this_new_ursula, new_work_order = list(incomplete_work_orders.items())[0]

    # This new Ursula isn't the same one to whom we've already issued a WorkOrder.
    id_of_ursula_from_whom_we_already_have_a_cfrag = list(work_orders_by_capsule.keys())[0]
    assert id_of_ursula_from_whom_we_already_have_a_cfrag != id_of_this_new_ursula

    # ...and, although this WorkOrder has the same capsules as the saved one...
    for (new_item, saved_item) in zip(new_work_order.tasks.values(), saved_work_order.tasks.values()):
        assert new_item.capsule == saved_item.capsule

    # ...it's not the same WorkOrder.
    assert new_work_order != saved_work_order

    # This WorkOrder has never been completed
    _success, cfrags = federated_bob._reencrypt(new_work_order, retain_cfrags=True)

    # Again: one Capsule, one cFrag.
    assert len(cfrags) == 1
    new_cfrag = cfrags[0]

    # Attach the CFrag to the Capsule.
    last_capsule_on_side_channel.attach_cfrag(new_cfrag)


def test_bob_gathers_and_combines(enacted_federated_policy, federated_bob, federated_alice, capsule_side_channel):
    # The side channel delivers all that Bob needs at this point:
    # - A single MessageKit, containing a Capsule
    # - A representation of the data source
    the_message_kit, the_data_source = capsule_side_channel.messages[-1]

    # Bob has saved two WorkOrders so far.
    assert len(federated_bob._completed_work_orders) == 2

    # ...but the policy requires us to collect more cfrags.
    assert len(federated_bob._completed_work_orders) < enacted_federated_policy.treasure_map.m

    # Bob can't decrypt yet with just two CFrags.  He needs to gather at least m.
    with pytest.raises(pre.GenericUmbralError):
        federated_bob.decrypt(the_message_kit)

    number_left_to_collect = enacted_federated_policy.treasure_map.m - len(federated_bob._completed_work_orders)

    the_message_kit.capsule.set_correctness_keys(
        delegating=the_data_source.policy_pubkey,
        receiving=federated_bob.public_keys(DecryptingPower),
        verifying=federated_alice.stamp.as_umbral_pubkey())

    new_incomplete_work_orders, _ = federated_bob.work_orders_for_capsules(
        the_message_kit.capsule,
        treasure_map=enacted_federated_policy.treasure_map,
        alice_verifying_key=federated_alice.stamp.as_umbral_pubkey(),
        num_ursulas=number_left_to_collect)
    _id_of_yet_another_ursula, new_work_order = list(new_incomplete_work_orders.items())[0]

    _success, cfrags = federated_bob._reencrypt(new_work_order)
    cfrag = cfrags[0]
    assert cfrag not in the_message_kit.capsule._attached_cfrags

    the_message_kit.capsule.attach_cfrag(cfrags[0])

    # Now.
    # At long last.
    cleartext = federated_bob.verify_from(the_data_source,
                                          the_message_kit,
                                          decrypt=True)
    assert cleartext == b'Welcome to flippering number 1.'


def test_federated_bob_retrieves_a_single_message(federated_bob,
                                                  federated_alice,
                                                  capsule_side_channel,
                                                  enacted_federated_policy,
                                                  ):
    # The side channel delivers all that Bob needs at this point:
    # - A single MessageKit, containing a Capsule
    # - A representation of the data source
    capsule_side_channel.reset()
    the_message_kit = capsule_side_channel()

    alices_verifying_key = federated_alice.stamp.as_umbral_pubkey()

    delivered_cleartexts = federated_bob.retrieve(the_message_kit,
                                                  enrico=capsule_side_channel.enrico,
                                                  alice_verifying_key=alices_verifying_key,
                                                  label=enacted_federated_policy.label)

    # We show that indeed this is the passage originally encrypted by the Enrico.
    assert b"Welcome to flippering number 1." == delivered_cleartexts[0]


def test_federated_bob_retrieves_multiple_messages_from_same_enrico(federated_bob,
                                                   federated_alice,
                                                   capsule_side_channel,
                                                   enacted_federated_policy,
                                                   ):
    # The side channel delivers all that Bob needs at this point:
    # - A single MessageKit, containing a Capsule
    # - A representation of the data source
    capsule_side_channel.reset()

    three_message_kits = [capsule_side_channel(), capsule_side_channel(), capsule_side_channel()]

    alices_verifying_key = federated_alice.stamp.as_umbral_pubkey()

    delivered_cleartexts = federated_bob.retrieve(*three_message_kits,
                                                  enrico=capsule_side_channel.enrico,
                                                  alice_verifying_key=alices_verifying_key,
                                                  label=enacted_federated_policy.label)

    assert b"Welcome to flippering number 1." == delivered_cleartexts[0]
    assert b"Welcome to flippering number 2." == delivered_cleartexts[1]
    assert b"Welcome to flippering number 3." == delivered_cleartexts[2]


def test_federated_bob_retrieves_multiple_messages_from_different_enricos(federated_bob,
                                                   federated_alice,
                                                   capsule_side_channel,
                                                   enacted_federated_policy,
                                                   ):
    # The side channel delivers all that Bob needs at this point:
    # - A single MessageKit, containing a Capsule
    # - A representation of the data source
    message1, enrico1 = capsule_side_channel.reset()  # First message
    message2, enrico2 = capsule_side_channel.reset()  # Second message
    message3, enrico3 = capsule_side_channel.reset()  # Third message

    alices_verifying_key = federated_alice.stamp.as_umbral_pubkey()
    message1.sender = enrico1
    message2.sender = enrico2
    message3.sender = enrico3

    delivered_cleartexts = federated_bob.retrieve(message1,
                                                  message2,
                                                  message3,
                                                  alice_verifying_key=alices_verifying_key,
                                                  label=enacted_federated_policy.label)

    assert b"Welcome to flippering number 0." == delivered_cleartexts[0]
    assert b"Welcome to flippering number 0." == delivered_cleartexts[1]
    assert b"Welcome to flippering number 0." == delivered_cleartexts[2]


def test_federated_bob_retrieves_twice_without_retaining_cfrags(federated_bob,
                                                                federated_alice,
                                                                capsule_side_channel,
                                                                enacted_federated_policy,
                                                                ):
    # The side channel delivers all that Bob needs at this point:
    # - A single MessageKit, containing a Capsule
    # - A representation of the data source
    capsule_side_channel.reset()
    the_message_kit = capsule_side_channel()

    alices_verifying_key = federated_alice.stamp.as_umbral_pubkey()

    delivered_cleartexts = federated_bob.retrieve(the_message_kit,
                                                  enrico=capsule_side_channel.enrico,
                                                  alice_verifying_key=alices_verifying_key,
                                                  label=enacted_federated_policy.label)

    # We show that indeed this is the passage originally encrypted by the Enrico.
    assert b"Welcome to flippering number 1." == delivered_cleartexts[0]

    delivered_cleartexts = federated_bob.retrieve(the_message_kit,
                                                  enrico=capsule_side_channel.enrico,
                                                  alice_verifying_key=alices_verifying_key,
                                                  label=enacted_federated_policy.label,
                                                  use_precedent_work_orders=True)

    # We show that indeed this is the passage originally encrypted by the Enrico.
    assert b"Welcome to flippering number 1." == delivered_cleartexts[0]


def test_federated_bob_retrieves_twice_by_retaining_cfrags(federated_bob,
                                                           federated_alice,
                                                           capsule_side_channel,
                                                           enacted_federated_policy,
                                                           ):
    capsule_side_channel.reset()
    the_message_kit = capsule_side_channel()
    alices_verifying_key = federated_alice.stamp.as_umbral_pubkey()

    delivered_cleartexts = federated_bob.retrieve(the_message_kit,
                                                  enrico=capsule_side_channel.enrico,
                                                  alice_verifying_key=alices_verifying_key,
                                                  label=enacted_federated_policy.label,
                                                  retain_cfrags=True)
    assert b"Welcome to flippering number 1." == delivered_cleartexts[0]

    # Can't retrieve this message again.
    # Bob needs to either instantiate the message_kit again or use use_attached_cfrags=True.
    with pytest.raises(TypeError):
        federated_bob.retrieve(the_message_kit,
                               enrico=capsule_side_channel.enrico,
                               alice_verifying_key=alices_verifying_key,
                               label=enacted_federated_policy.label,
                               )

    delivered_cleartexts = federated_bob.retrieve(the_message_kit,
                                                  enrico=capsule_side_channel.enrico,
                                                  alice_verifying_key=alices_verifying_key,
                                                  label=enacted_federated_policy.label,
                                                  use_attached_cfrags=True)

    assert b"Welcome to flippering number 1." == delivered_cleartexts[0]


def test_federated_bob_cannot_resume_retrieval_without_caching(federated_bob,
                                                               federated_alice,
                                                               capsule_side_channel,
                                                               enacted_federated_policy,
                                                               federated_ursulas
                                                               ):
    capsule_side_channel.reset()
    the_message_kit = capsule_side_channel()

    alices_verifying_key = federated_alice.stamp.as_umbral_pubkey()

    # Out of 10 Ursulas, eight are down.
    ursula1 = list(federated_ursulas)[0]
    ursula2 = list(federated_ursulas)[1]
    ursula3 = list(federated_ursulas)[2]
    ursula4 = list(federated_ursulas)[3]
    ursula5 = list(federated_ursulas)[4]
    ursula6 = list(federated_ursulas)[5]
    ursula7 = list(federated_ursulas)[6]
    ursula8 = list(federated_ursulas)[7]

    federated_bob.remember_node(ursula1)

    federated_bob.network_middleware = NodeIsDownMiddleware()
    federated_bob.network_middleware.node_is_down(ursula1)
    federated_bob.network_middleware.node_is_down(ursula2)
    federated_bob.network_middleware.node_is_down(ursula3)
    federated_bob.network_middleware.node_is_down(ursula4)
    federated_bob.network_middleware.node_is_down(ursula5)
    federated_bob.network_middleware.node_is_down(ursula6)
    federated_bob.network_middleware.node_is_down(ursula7)
    federated_bob.network_middleware.node_is_down(ursula8)

    # Since 8 Ursulas are down, Bob can only get 2 CFrags; not enough to complete retrieval.
    with pytest.raises(ursula1.NotEnoughUrsulas):
        federated_bob.retrieve(the_message_kit,
                               enrico=capsule_side_channel.enrico,
                               alice_verifying_key=alices_verifying_key,
                               label=enacted_federated_policy.label)

    # Since we weren't caching, there are no attached Cfrags.
    assert len(the_message_kit.capsule) == 0

    # Now the remaining two Ursulas go down.
    ursula9 = list(federated_ursulas)[8]
    ursula10 = list(federated_ursulas)[9]
    federated_bob.network_middleware.node_is_down(ursula9)
    federated_bob.network_middleware.node_is_down(ursula10)

    # ...but one other comes up.
    federated_bob.network_middleware.node_is_up(ursula4)

    with pytest.raises(ursula1.NotEnoughUrsulas):
        federated_bob.retrieve(the_message_kit,
                               enrico=capsule_side_channel.enrico,
                               alice_verifying_key=alices_verifying_key,
                               label=enacted_federated_policy.label)


def test_federated_retrieves_partially_then_finishes(federated_bob,
                                                     federated_alice,
                                                     capsule_side_channel,
                                                     enacted_federated_policy,
                                                     federated_ursulas
                                                     ):
    # Same setup as last time.
    capsule_side_channel.reset()
    the_message_kit = capsule_side_channel()

    alices_verifying_key = federated_alice.stamp.as_umbral_pubkey()
    ursula1 = list(federated_ursulas)[0]
    ursula2 = list(federated_ursulas)[1]
    ursula3 = list(federated_ursulas)[2]
    ursula4 = list(federated_ursulas)[3]
    ursula5 = list(federated_ursulas)[4]
    ursula6 = list(federated_ursulas)[5]
    ursula7 = list(federated_ursulas)[6]
    ursula8 = list(federated_ursulas)[7]

    federated_bob.remember_node(ursula1)

    federated_bob.network_middleware = NodeIsDownMiddleware()
    federated_bob.network_middleware.node_is_down(ursula1)
    federated_bob.network_middleware.node_is_down(ursula2)
    federated_bob.network_middleware.node_is_down(ursula3)
    federated_bob.network_middleware.node_is_down(ursula4)
    federated_bob.network_middleware.node_is_down(ursula5)
    federated_bob.network_middleware.node_is_down(ursula6)
    federated_bob.network_middleware.node_is_down(ursula7)
    federated_bob.network_middleware.node_is_down(ursula8)

    # Bob can't retrieve; there aren't enough Ursulas up.
    with pytest.raises(ursula1.NotEnoughUrsulas):
        federated_bob.retrieve(the_message_kit,
                               enrico=capsule_side_channel.enrico,
                               alice_verifying_key=alices_verifying_key,
                               label=enacted_federated_policy.label,
                               retain_cfrags=True)

    # Since we were caching, there are now 2 attached cfrags.
    assert len(the_message_kit.capsule) == 2

    # Now the remaining two Ursulas go down.
    ursula9 = list(federated_ursulas)[8]
    ursula10 = list(federated_ursulas)[9]
    federated_bob.network_middleware.node_is_down(ursula9)
    federated_bob.network_middleware.node_is_down(ursula10)

    # ...but one other comes up.
    federated_bob.network_middleware.node_is_up(ursula4)

    # We're not allowed to try again with a Capsule with cached CFrags if we set cache to False.
    with pytest.raises(TypeError):
        federated_bob.retrieve(the_message_kit,
                               enrico=capsule_side_channel.enrico,
                               alice_verifying_key=alices_verifying_key,
                               label=enacted_federated_policy.label,
                               retain_cfrags=False)

    # But now, with just one Ursula up, we can use the cached CFrags to get the message.
    delivered_cleartexts = federated_bob.retrieve(the_message_kit,
                                                  enrico=capsule_side_channel.enrico,
                                                  alice_verifying_key=alices_verifying_key,
                                                  label=enacted_federated_policy.label,
                                                  retain_cfrags=True,
                                                  use_attached_cfrags=True,
                                                  )

    assert b"Welcome to flippering number 1." == delivered_cleartexts[0]

    # In fact, if Bob is totally offline, he can get the message:
    for ursula in federated_ursulas:
        federated_bob.network_middleware.node_is_down(ursula)

    delivered_cleartexts = federated_bob.retrieve(the_message_kit,
                                                  enrico=capsule_side_channel.enrico,
                                                  alice_verifying_key=alices_verifying_key,
                                                  label=enacted_federated_policy.label,
                                                  retain_cfrags=True,
                                                  use_attached_cfrags=True)

    assert b"Welcome to flippering number 1." == delivered_cleartexts[0]

    # Heck, even if we delete the attached CFrags, as might happen if we were loading the Capsule again from disk...
    the_message_kit.capsule.clear_cfrags()

    # ...we can still get the message with the network being down because Bob has the properly completed WorkOrders cached in state.
    delivered_cleartexts = federated_bob.retrieve(the_message_kit,
                                                  enrico=capsule_side_channel.enrico,
                                                  alice_verifying_key=alices_verifying_key,
                                                  label=enacted_federated_policy.label,
                                                  use_precedent_work_orders=True)

    assert b"Welcome to flippering number 1." == delivered_cleartexts[0]
    federated_bob.network_middleware.all_nodes_up()


def test_bob_retrieves_multiple_messages_in_a_single_adventure(federated_bob,
                                                   federated_alice,
                                                   capsule_side_channel,
                                                   enacted_federated_policy,
                                                   ):
    # The side channel delivers all that Bob needs at this point:
    # - A single MessageKit, containing a Capsule
    # - A representation of the data source
    message1, enrico1 = capsule_side_channel.reset()  # First message
    message2, enrico2 = capsule_side_channel.reset()  # Second message
    message3, enrico3 = capsule_side_channel.reset()  # Third message

    # We'll cast the kits to bytes as if to pretend that Bob has stored them to disk or is accessing them via the web extension.
    # This is meaningful as a regression test (as distinct from the single-Capsule tests) because it shows that we are
    # properly adhering the three different sender_verifying_keys.
    message1_bytes = bytes(message1)
    message2_bytes = bytes(message2)
    message3_bytes = bytes(message3)

    alices_verifying_key = federated_alice.stamp.as_umbral_pubkey()

    delivered_cleartexts = federated_bob.retrieve(PolicyMessageKit.from_bytes(message1_bytes),
                                                  PolicyMessageKit.from_bytes(message2_bytes),
                                                  PolicyMessageKit.from_bytes(message3_bytes),
                                                  alice_verifying_key=alices_verifying_key,
                                                  label=enacted_federated_policy.label,
                                                  use_precedent_work_orders=True,
                                                  policy_encrypting_key=enacted_federated_policy.public_key)

    assert b"Welcome to flippering number 0." == delivered_cleartexts[0]
    assert b"Welcome to flippering number 0." == delivered_cleartexts[1]
    assert b"Welcome to flippering number 0." == delivered_cleartexts[2]
