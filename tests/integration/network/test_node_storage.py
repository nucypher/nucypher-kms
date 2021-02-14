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

import maya
import pytest
import pytest_twisted as pt
from twisted.internet.threads import deferToThread


@pt.inlineCallbacks
def test_one_node_stores_a_bunch_of_others(federated_ursulas, lonely_ursula_maker):
    the_chosen_seednode = list(federated_ursulas)[2]  # ...neo?
    seed_node = the_chosen_seednode.seed_node_metadata()

    newcomer = lonely_ursula_maker(
        quantity=1,
        save_metadata=True,
        seed_nodes=[seed_node]).pop()

    assert not newcomer.known_nodes

    newcomer.start_learning_loop(now=True)

    def start_lonely_learning_loop():
        newcomer.start_learning_loop()
        start = maya.now()
        # Loop until the_chosen_seednode is in storage.
        while the_chosen_seednode.checksum_address not in [u.checksum_address for u in newcomer.node_storage.all(federated_only=True)]:
            passed = maya.now() - start
            if passed.seconds > 2:
                pytest.fail("Didn't find the seed node.")

    yield deferToThread(start_lonely_learning_loop)

    nodes = list(newcomer.known_nodes.get_nodes())
    assert nodes
    assert len(nodes) == len(list(newcomer.node_storage.all(True)))
    assert set(nodes) == set(list(newcomer.node_storage.all(True)))
