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
import os
import pytest
from base64 import b64encode

from nucypher.characters.control.interfaces import AliceInterface
from nucypher.characters.control.interfaces import BobInterface, EnricoInterface
from nucypher.crypto.powers import DecryptingPower
from nucypher.policy.maps import SignedTreasureMap
from tests.utils.controllers import get_fields, validate_json_rpc_response_data


def test_bob_rpc_character_control_join_policy(bob_rpc_controller, join_control_request, enacted_blockchain_policy, blockchain_bob, blockchain_ursulas):
    for ursula in blockchain_ursulas:
        if ursula.checksum_address in enacted_blockchain_policy.treasure_map.destinations:
            # Simulate passing in a teacher-uri
            blockchain_bob.remember_node(ursula)
            break
    else:
        # Shouldn't happen
        raise Exception("No known Ursulas present in the treasure map destinations")

    method_name, params = join_control_request
    request_data = {'method': method_name, 'params': params}
    response = bob_rpc_controller.send(request_data)
    assert validate_json_rpc_response_data(response=response,
                                           method_name=method_name,
                                           interface=BobInterface)


def test_enrico_rpc_character_control_encrypt_message(enrico_rpc_controller_test_client, encrypt_control_request):
    method_name, params = encrypt_control_request
    request_data = {'method': method_name, 'params': params}
    response = enrico_rpc_controller_test_client.send(request_data)
    assert validate_json_rpc_response_data(response=response,
                                           method_name=method_name,
                                           interface=EnricoInterface)


def test_bob_rpc_character_control_retrieve_with_tmap(
        enacted_blockchain_policy, blockchain_bob, blockchain_alice,
        bob_rpc_controller, retrieve_control_request):

    # So that this test can run even independently.
    if not blockchain_bob.done_seeding:
        blockchain_bob.learn_from_teacher_node()

    tmap_64 = b64encode(bytes(enacted_blockchain_policy.treasure_map)).decode()
    method_name, params = retrieve_control_request
    params['treasure_map'] = tmap_64
    request_data = {'method': method_name, 'params': params}
    response = bob_rpc_controller.send(request_data)
    assert response.data['result']['cleartexts'][0] == 'Welcome to flippering number 1.'

    # Make a wrong (empty) treasure map

    wrong_tmap = SignedTreasureMap(m=0)
    wrong_tmap.derive_hrac(alice_stamp=blockchain_alice.stamp, bob_verifying_key=blockchain_bob.stamp, label=b"Wrong")
    wrong_tmap.prepare_for_publication(
        bob_encrypting_key=blockchain_bob.public_keys(DecryptingPower),
        alice_stamp=blockchain_alice.stamp)
    wrong_tmap._blockchain_signature = os.urandom(64)    # ...because it only matters when Ursula looks at it.
    tmap_bytes = bytes(wrong_tmap)
    tmap_64 = b64encode(tmap_bytes).decode()
    request_data['params']['treasure_map'] = tmap_64
    with pytest.raises(SignedTreasureMap.IsDisorienting):
        bob_rpc_controller.send(request_data)


def test_alice_rpc_character_control_create_policy(alice_rpc_test_client, create_policy_control_request):
    alice_rpc_test_client.__class__.MESSAGE_ID = 0
    method_name, params = create_policy_control_request
    request_data = {'method': method_name, 'params': params}
    rpc_response = alice_rpc_test_client.send(request=request_data)
    assert rpc_response.success is True
    assert rpc_response.id == 1

    _input_fields, _optional_fields, required_output_fileds = get_fields(AliceInterface, method_name)

    assert 'jsonrpc' in rpc_response.data
    for output_field in required_output_fileds:
        assert output_field in rpc_response.content

    try:
        bytes.fromhex(rpc_response.content['policy_encrypting_key'])
    except (KeyError, ValueError):
        pytest.fail("Invalid Policy Encrypting Key")

    # Confirm the same message send works again, with a unique ID
    request_data = {'method': method_name, 'params': params}
    rpc_response = alice_rpc_test_client.send(request=request_data)
    assert rpc_response.success is True
    assert rpc_response.id == 2

    # Send a bulk create policy request
    bulk_request = list()
    for i in range(50):
        request_data = {'method': method_name, 'params': params}
        bulk_request.append(request_data)

    rpc_responses = alice_rpc_test_client.send(request=bulk_request)
    for response_id, rpc_response in enumerate(rpc_responses, start=3):
        assert rpc_response.success is True
        assert rpc_response.id == response_id


def test_alice_rpc_character_control_bad_input(alice_rpc_test_client, create_policy_control_request):
    alice_rpc_test_client.__class__.MESSAGE_ID = 0

    # Send bad data to assert error returns (Request #3)
    alice_rpc_test_client.crash_on_error = False

    response = alice_rpc_test_client.send(request={'bogus': 'input'}, malformed=True)
    assert response.error_code == -32600


def test_alice_rpc_character_control_derive_policy_encrypting_key(alice_rpc_test_client):
    method_name = 'derive_policy_encrypting_key'
    request_data = {'method': method_name, 'params': {'label': 'test'}}
    response = alice_rpc_test_client.send(request_data)
    assert response.success is True
    assert validate_json_rpc_response_data(response=response,
                                           method_name=method_name,
                                           interface=AliceInterface)


def test_alice_rpc_character_control_grant(alice_rpc_test_client, grant_control_request):
    method_name, params = grant_control_request
    request_data = {'method': method_name, 'params': params}
    response = alice_rpc_test_client.send(request_data)
    assert validate_json_rpc_response_data(response=response,
                                           method_name=method_name,
                                           interface=AliceInterface)
