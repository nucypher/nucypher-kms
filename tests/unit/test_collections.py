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

from nucypher.crypto.powers import DecryptingPower, SigningPower
from nucypher.policy.maps import TreasureMap
from umbral.kfrags import KFrag


def test_complete_treasure_map_journey(federated_alice, federated_bob, federated_ursulas, mocker):

    treasure_map = TreasureMap(m=1)

    bob_encrypting_key = federated_bob.public_keys(DecryptingPower)
    bob_verifying_key = federated_bob.public_keys(SigningPower)

    mock_kfrag = os.urandom(KFrag.expected_bytes_length())
    make_kfrag_payload_spy = mocker.spy(TreasureMap, '_make_kfrag_payload')

    treasure_map.derive_hrac(alice_stamp=federated_alice.stamp,
                             bob_verifying_key=bob_verifying_key,
                             label="chili con carne 🔥".encode('utf-8'))

    encrypted_kfrags = dict()
    for ursula in federated_ursulas:
        treasure_map.add_kfrag(ursula, mock_kfrag, federated_alice.stamp)
        encrypted_kfrags[ursula.checksum_address] = make_kfrag_payload_spy.spy_return

    treasure_map.prepare_for_publication(bob_encrypting_key=bob_encrypting_key,
                                         alice_stamp=federated_alice.stamp)

    ursula_rolodex = {u.checksum_address: u for u in federated_ursulas}
    for ursula_address, encrypted_kfrag in treasure_map.destinations.items():
        assert ursula_address in ursula_rolodex
        ursula = ursula_rolodex[ursula_address]
        mock_kfrag_payload = encrypted_kfrags[ursula.checksum_address]
        assert mock_kfrag_payload == ursula.verify_from(federated_alice, encrypted_kfrag, decrypt=True)  # FIXME: 2203

    serialized_map = bytes(treasure_map)
    # ...
    deserialized_map = TreasureMap.from_bytes(serialized_map)

    compass = federated_bob.make_compass_for_alice(federated_alice)
    deserialized_map.orient(compass)

    assert treasure_map.m == deserialized_map.m == 1
    assert set(treasure_map.destinations) == set(deserialized_map.destinations)
    assert treasure_map == deserialized_map


def test_treasure_map_versioning(mocker, federated_alice, federated_bob, federated_ursulas):
    kfrags = [os.urandom(32) for _ in range(3)]
    treasure_map = TreasureMap.author(alice=federated_alice,
                                      bob=federated_bob,
                                      label=b'still Bill',
                                      ursulas=list(federated_ursulas)[:len(kfrags)],
                                      kfrags=kfrags,
                                      m=2)

    # Good version (baseline)
    serialized_map = bytes(treasure_map)
    deserialized_map = TreasureMap.from_bytes(serialized_map)
    assert treasure_map == deserialized_map

    # b''.serialized_map.split(b'')[len(TreasureMap._PREFIX)+1] = int(TreasureMap.VERSION_NUMBER+1).to_bytes(1, 'big')
    assert False
