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

from nucypher.acumen.perception import FleetSensor
from nucypher.config.storages import LocalFileBasedNodeStorage


def test_learner_learns_about_domains_separately(lonely_ursula_maker, caplog):
    hero_learner, other_first_domain_learner = lonely_ursula_maker(domain="nucypher1.test_suite", quantity=2)
    _nobody = lonely_ursula_maker(domain="nucypher1.test_suite", quantity=1).pop()
    other_first_domain_learner.remember_node(_nobody)

    second_domain_learners = lonely_ursula_maker(domain="nucypher2.test_suite", know_each_other=True, quantity=3)

    assert len(hero_learner.known_nodes) == 0

    # Learn from a teacher in our domain.
    hero_learner.remember_node(other_first_domain_learner)
    hero_learner.learn_from_teacher_node()

    # All domain 1 nodes
    assert len(hero_learner.known_nodes) == 2

    # Learn about the second domain.
    hero_learner._current_teacher_node = second_domain_learners.pop()
    hero_learner.learn_from_teacher_node()

    # All domain 1 nodes
    assert len(hero_learner.known_nodes) == 2

    new_first_domain_learner = lonely_ursula_maker(domain="nucypher1.test_suite", quantity=1).pop()
    _new_second_domain_learner = lonely_ursula_maker(domain="nucypher2.test_suite", quantity=1).pop()

    new_first_domain_learner.remember_node(hero_learner)

    new_first_domain_learner.learn_from_teacher_node()

    # This node, in the first domain, didn't learn about the second domain.
    assert not set(second_domain_learners).intersection(new_first_domain_learner.known_nodes.get_nodes())

    # However, it learned about *all* of the nodes in its own domain.
    nodes = list(new_first_domain_learner.known_nodes.get_nodes())
    assert hero_learner in nodes
    assert other_first_domain_learner in nodes
    assert _nobody in nodes


def test_learner_restores_metadata_from_storage(lonely_ursula_maker, tmpdir):
    # Create a local file-based node storage
    root = tmpdir.mkdir("known_nodes")
    metadata = root.mkdir("metadata")
    certs = root.mkdir("certs")
    old_storage = LocalFileBasedNodeStorage(federated_only=True,
                                            metadata_dir=metadata,
                                            certificates_dir=certs,
                                            storage_root=root)

    # Use the ursula maker with this storage so it's populated with nodes from one domain
    _some_ursulas = lonely_ursula_maker(domain="fistro",
                                        node_storage=old_storage,
                                        know_each_other=True,
                                        quantity=3,
                                        save_metadata=True)

    # Create a pair of new learners in a different domain, using the previous storage, and learn from it
    new_learners = lonely_ursula_maker(domain="duodenal",
                                       node_storage=old_storage,
                                       quantity=2,
                                       know_each_other=True,
                                       save_metadata=False)
    learner, buddy = new_learners
    buddy._Learner__known_nodes = FleetSensor(domain="fistro")

    # The learner shouldn't learn about any node from the first domain, since it's different.
    learner.learn_from_teacher_node()
    for restored_node in learner.known_nodes.get_nodes():
        assert restored_node.mature().domain == learner.domain

    # In fact, since the storage only contains nodes from a different domain,
    # the learner should only know its buddy from the second domain.
    assert set(learner.known_nodes.get_nodes()) == {buddy}


def test_learner_ignores_stored_nodes_from_other_domains(lonely_ursula_maker, tmpdir):
    learner, other_staker = lonely_ursula_maker(domain="call-it-mainnet",
                                                know_each_other=True,
                                                quantity=2)

    pest, *other_ursulas_from_the_wrong_side_of_the_tracks = lonely_ursula_maker(domain="i-dunno-testt-maybe",
                                                                                 quantity=5,
                                                                                 know_each_other=True)

    assert pest not in learner.known_nodes
    pest._current_teacher_node = learner
    pest.learn_from_teacher_node()

    ##################################
    # Prior to #2423, learner remembered pest because POSTed node metadata was not domain-checked.
    # This is how ibex nodes initially made their way into mainnet fleet states.
    assert pest not in learner.known_nodes  # But not anymore.

    # Once pest made its way into learner, learner taught passed it to other mainnet nodes.

    with pytest.raises(FleetSensor.WrongDomain):
        learner.known_nodes.track(pest)  # This used to happen anyway.
    other_staker._current_teacher_node = learner
    other_staker.learn_from_teacher_node()  # And once it did, the node from the wrong domain spread.
    assert pest not in other_staker.known_nodes  # But not anymore.
