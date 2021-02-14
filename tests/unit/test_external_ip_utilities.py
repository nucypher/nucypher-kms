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
from nucypher.characters.lawful import Ursula
from nucypher.network.exceptions import NodeSeemsToBeDown
from nucypher.network.middleware import RestMiddleware, NucypherMiddlewareClient
from nucypher.utilities.networking import (
    determine_external_ip_address,
    get_external_ip_from_centralized_source,
    get_external_ip_from_default_teacher,
    get_external_ip_from_known_nodes,
    CENTRALIZED_IP_ORACLE_URL,
    UnknownIPAddress
)
from tests.constants import MOCK_IP_ADDRESS


class Dummy:  # Teacher
    certificate_filepath = None

    class GoodResponse:
        status_code = 200
        text = MOCK_IP_ADDRESS

    class BadResponse:
        status_code = 404
        text = None
        content = 'DUMMY 404'

    def mature(self):
        return Dummy()

    def verify_node(self, *args, **kwargs):
        pass

    def rest_url(self):
        return MOCK_IP_ADDRESS


@pytest.fixture(autouse=True)
def mock_requests(mocker):
    """prevents making live HTTP requests from this module"""
    make_request = 'nucypher.utilities.networking._request'
    yield mocker.patch(make_request, return_value=None)


@pytest.fixture(autouse=True)
def mock_client(mocker):
    yield mocker.patch.object(NucypherMiddlewareClient, 'invoke_method', return_value=Dummy.GoodResponse)


@pytest.fixture()
def mock_network():
    return 'holodeck'


@pytest.fixture(autouse=True)
def mock_default_teachers(mocker, mock_network):
    teachers = {mock_network: (MOCK_IP_ADDRESS, )}
    mocker.patch.dict(RestMiddleware.TEACHER_NODES, teachers)


def test_get_external_ip_from_centralized_source(mock_requests):
    get_external_ip_from_centralized_source()
    mock_requests.assert_called_once_with(url=CENTRALIZED_IP_ORACLE_URL)


def test_get_external_ip_from_empty_known_nodes(mock_requests, mock_network):
    sensor = FleetSensor(domain=mock_network)
    assert len(sensor) == 0
    get_external_ip_from_known_nodes(known_nodes=sensor)
    # skipped because there are no known nodes
    mock_requests.assert_not_called()


def test_get_external_ip_from_known_nodes_with_one_known_node(mocker, mock_requests, mock_network):
    sensor = FleetSensor(domain=mock_network)
    mocker.patch.dict(sensor._FleetSensor__nodes, {'0xdeadbeef': Dummy()})
    assert len(sensor) == 1
    get_external_ip_from_known_nodes(known_nodes=sensor)
    # skipped because there are too few known nodes
    mock_requests.assert_not_called()


def test_get_external_ip_from_known_nodes(mocker, mock_client, mock_network):

    # Setup FleetSensor
    sensor = FleetSensor(domain=mock_network)
    sample_size = 3
    nodes = {'0xdeadbeef': Dummy(),
             '0xdeadllama': Dummy(),
             '0xdeadmouse': Dummy()}

    mocker.patch.dict(sensor._FleetSensor__nodes, nodes)
    assert len(sensor) == sample_size

    # First sampled node replies
    get_external_ip_from_known_nodes(known_nodes=sensor, sample_size=sample_size)
    assert mock_client.call_count == 1
    mock_client.call_count = 0  # reset

    # All sampled nodes dont respond
    mock_client.return_value = Dummy.BadResponse
    get_external_ip_from_known_nodes(known_nodes=sensor, sample_size=sample_size)
    assert mock_client.call_count == sample_size


def test_get_external_ip_from_known_nodes_client(mocker, mock_client, mock_network):

    # Setup FleetSensor
    sensor = FleetSensor(domain=mock_network)
    sample_size = 3
    nodes = {'0xdeadbeef': Dummy(),
             '0xdeadllama': Dummy(),
             '0xdeadmouse': Dummy()}
    mocker.patch.dict(sensor._FleetSensor__nodes, nodes)
    assert len(sensor) == sample_size

    # Setup HTTP Client
    mocker.patch.object(Ursula, 'from_teacher_uri', return_value=Dummy())
    teacher_uri = RestMiddleware.TEACHER_NODES[mock_network][0]

    get_external_ip_from_known_nodes(known_nodes=sensor, sample_size=sample_size)
    assert mock_client.call_count == 1  # first node responded

    function, endpoint = mock_client.call_args[0]
    assert function.__name__ == 'get'
    assert endpoint == f'https://{teacher_uri}/ping'


def test_get_external_ip_default_teacher_unreachable(mocker, mock_network):
    for error in NodeSeemsToBeDown:
        # Default seednode is down
        mocker.patch.object(Ursula, 'from_teacher_uri', side_effect=error)
        ip = get_external_ip_from_default_teacher(network=mock_network)
        assert ip is None


def test_get_external_ip_from_default_teacher(mocker, mock_client, mock_requests, mock_network):

    mock_client.return_value = Dummy.GoodResponse
    teacher_uri = RestMiddleware.TEACHER_NODES[mock_network][0]
    mocker.patch.object(Ursula, 'from_teacher_uri', return_value=Dummy())

    # "Success"
    ip = get_external_ip_from_default_teacher(network=mock_network)
    assert ip == MOCK_IP_ADDRESS

    # Check that the correct endpoint and function is targeted
    mock_requests.assert_not_called()
    mock_client.assert_called_once()
    function, endpoint = mock_client.call_args[0]
    assert function.__name__ == 'get'
    assert endpoint == f'https://{teacher_uri}/ping'


def test_get_external_ip_default_unknown_network():
    unknown_domain = 'thisisnotarealdomain'

    # Without fleet sensor
    with pytest.raises(UnknownIPAddress):
        determine_external_ip_address(network=unknown_domain)

    # with fleet sensor
    sensor = FleetSensor(domain=unknown_domain)
    with pytest.raises(UnknownIPAddress):
        determine_external_ip_address(known_nodes=sensor, network=unknown_domain)


def test_get_external_ip_cascade_failure(mocker, mock_network, mock_requests):
    first = mocker.patch('nucypher.utilities.networking.get_external_ip_from_known_nodes', return_value=None)
    second = mocker.patch('nucypher.utilities.networking.get_external_ip_from_default_teacher', return_value=None)
    third = mocker.patch('nucypher.utilities.networking.get_external_ip_from_centralized_source', return_value=None)

    sensor = FleetSensor(domain=mock_network)
    mocker.patch.dict(sensor._FleetSensor__nodes, {'0xdeadbeef': Dummy()})

    with pytest.raises(UnknownIPAddress, match='External IP address detection failed'):
        determine_external_ip_address(network=mock_network, known_nodes=sensor)

    first.assert_called_once()
    second.assert_called_once()
    third.assert_called_once()
