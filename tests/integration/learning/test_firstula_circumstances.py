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

import pytest_twisted as pt
from functools import partial
from twisted.internet.threads import deferToThread

from nucypher.network.middleware import RestMiddleware
from tests.utils.ursula import make_federated_ursulas


def test_proper_seed_node_instantiation(lonely_ursula_maker):
    _lonely_ursula_maker = partial(lonely_ursula_maker, quantity=1)
    firstula = _lonely_ursula_maker(domain="this-is-meaningful-now").pop()
    firstula_as_seed_node = firstula.seed_node_metadata()
    any_other_ursula = _lonely_ursula_maker(seed_nodes=[firstula_as_seed_node], domain="this-is-meaningful-now").pop()

    assert not any_other_ursula.known_nodes
    any_other_ursula.start_learning_loop(now=True)
    assert firstula in any_other_ursula.known_nodes


@pt.inlineCallbacks
def test_get_cert_from_running_seed_node(lonely_ursula_maker):

    firstula = lonely_ursula_maker().pop()
    node_deployer = firstula.get_deployer()

    node_deployer.addServices()
    node_deployer.catalogServers(node_deployer.hendrix)
    node_deployer.start()   # If this port happens not to be open, we'll get an error here.  THis might be one of the few sane places to reintroduce a check.

    certificate_as_deployed = node_deployer.cert.to_cryptography()

    firstula_as_seed_node = firstula.seed_node_metadata()
    any_other_ursula = lonely_ursula_maker(seed_nodes=[firstula_as_seed_node],
                                           network_middleware=RestMiddleware()).pop()
    assert not any_other_ursula.known_nodes

    yield deferToThread(any_other_ursula.load_seednodes)
    assert firstula in any_other_ursula.known_nodes

    firstula_as_learned = any_other_ursula.known_nodes.get_node(firstula.checksum_address)
    firstula_as_learned.mature()
    assert certificate_as_deployed == firstula_as_learned.certificate
