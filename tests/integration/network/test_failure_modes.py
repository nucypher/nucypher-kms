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
import pytest_twisted
import requests
from bytestring_splitter import BytestringSplittingError
from functools import partial
from twisted.internet import threads

from nucypher.policy.collections import TreasureMap
from nucypher.policy.policies import Policy
from tests.utils.middleware import EvilMiddleWare, NodeIsDownMiddleware
from tests.utils.ursula import make_federated_ursulas


def test_alice_can_grant_even_when_the_first_nodes_she_tries_are_down(federated_alice, federated_bob, federated_ursulas):
    m, n = 2, 3
    policy_end_datetime = maya.now() + datetime.timedelta(days=5)
    label = b"this_is_the_path_to_which_access_is_being_granted"
    federated_alice.known_nodes._FleetSensor__nodes = {}

    federated_alice.network_middleware = NodeIsDownMiddleware()

    # OK, her first and only node is down.
    down_node = list(federated_ursulas)[0]
    federated_alice.remember_node(down_node)
    federated_alice.network_middleware.node_is_down(down_node)

    # Here's the command we want to run.
    alice_grant_action = partial(federated_alice.grant,
                                 federated_bob,
                                 label,
                                 m=m,
                                 n=n,
                                 expiration=policy_end_datetime,
                                 timeout=.1)

    # Go!
    federated_alice.start_learning_loop()

    # Now we'll have a situation where Alice knows about all 10,
    # though only one is up.

    # She'll try to learn about more, but there aren't any.
    # Because she has successfully completed learning, but the nodes about which she learned are down,
    # she'll get a different error.

    more_nodes = list(federated_ursulas)[1:10]
    for node in more_nodes:
        federated_alice.network_middleware.node_is_down(node)

    for node in more_nodes:
        federated_alice.remember_node(node)
    with pytest.raises(Policy.NotEnoughUrsulas):
        alice_grant_action()

    # Now let's let a few of them come up.
    for node in more_nodes[0:4]:
        federated_alice.network_middleware.node_is_up(node)

    # Now the same exact action works.
    # TODO: This action only succeeds here because we are forcing
    #       grant to accept the ursulas that just came back online (handpicked_ursulas).
    #       Since there are now enough Ursulas online, this action *can* succeed without forcing sample.
    policy = alice_grant_action(handpicked_ursulas=more_nodes[:3])

    # TODO: This is how it's actually done. How can we measure such random results?
    #       The below line will fail with ? probability, if more then 2 of the nodes selected
    #       are among those still down.
    # policy = alice_grant_action()

    # The number of actually enacted arrangements is exactly equal to n.
    assert len(policy.treasure_map.destinations) == n


def test_node_has_changed_cert(federated_alice, federated_ursulas):
    federated_alice.known_nodes._FleetSensor__nodes = {}
    federated_alice.network_middleware = NodeIsDownMiddleware()
    federated_alice.network_middleware.client.certs_are_broken = True

    firstula = list(federated_ursulas)[0]
    federated_alice.remember_node(firstula)
    federated_alice.start_learning_loop(now=True)
    federated_alice.learn_from_teacher_node()

    # Cool - we didn't crash because of SSLError.
    # TODO: Assertions and such.


def test_huge_treasure_maps_are_rejected(federated_alice, federated_ursulas):
    federated_alice.network_middleware = EvilMiddleWare()

    firstula = list(federated_ursulas)[0]

    ok_amount = 10 * 1024  # 10k
    ok_data = os.urandom(ok_amount)

    with pytest.raises(BytestringSplittingError):
        federated_alice.network_middleware.upload_arbitrary_data(
            firstula, 'consider_arrangement', ok_data
        )

    """
    TODO:  the following does not work because of this issue: https://github.com/pallets/werkzeug/issues/1513

    it is implemented at a lower level through hendrix
    but would be nice if it could be configurable through
    flask as well and thus, testable here...

    evil_amount = 5000 * 1024
    evil_data = os.urandom(evil_amount)
    with pytest.raises(RequestEntityTooLarge):
        federated_alice.network_middleware.upload_arbitrary_data(
            firstula, 'consider_arrangement', evil_data
        )
    """


@pytest.mark.skip("Hangs forever")
@pytest_twisted.inlineCallbacks
def test_hendrix_handles_content_length_validation(ursula_federated_test_config):
    node = make_federated_ursulas(ursula_config=ursula_federated_test_config, quantity=1).pop()
    node_deployer = node.get_deployer()

    node_deployer.addServices()
    node_deployer.catalogServers(node_deployer.hendrix)
    node_deployer.start()

    def check_node_rejects_large_posts(node):
        too_much_data = os.urandom(100 * 1024)
        response = requests.post(
            "https://{}/consider_arrangement".format(node.rest_url()),
            data=too_much_data, verify=False)
        assert response.status_code > 400
        assert response.reason == "Request Entity Too Large"
        return node

    def check_node_accepts_normal_posts(node):
        a_normal_arrangement = os.urandom(49 * 1024)  # 49K, the limit is 50K
        response = requests.post(
            "https://{}/consider_arrangement".format(node.rest_url()),
            data=a_normal_arrangement, verify=False)
        assert response.status_code >= 500  # it still fails because we are sending random bytes
        assert response.reason != "Request Entity Too Large"  # but now we are running nucypher code
        return node

    yield threads.deferToThread(check_node_rejects_large_posts, node)
    yield threads.deferToThread(check_node_accepts_normal_posts, node)
