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
import base64

import sha3
from constant_sorrow.constants import PUBLIC_ONLY
from nucypher.crypto.umbral_adapter import UmbralPrivateKey

from nucypher.crypto import keypairs


def test_gen_keypair_if_needed():
    new_dec_keypair = keypairs.DecryptingKeypair()
    assert new_dec_keypair._privkey is not None
    assert new_dec_keypair.pubkey is not None
    assert new_dec_keypair.pubkey == new_dec_keypair._privkey.get_pubkey()

    new_sig_keypair = keypairs.SigningKeypair()
    assert new_sig_keypair._privkey is not None
    assert new_sig_keypair.pubkey is not None
    assert new_sig_keypair.pubkey == new_sig_keypair._privkey.get_pubkey()


def test_keypair_with_umbral_keys():
    umbral_privkey = UmbralPrivateKey.gen_key()
    umbral_pubkey = umbral_privkey.get_pubkey()

    new_keypair_from_priv = keypairs.Keypair(umbral_privkey)
    assert new_keypair_from_priv._privkey == umbral_privkey
    assert new_keypair_from_priv.pubkey.to_bytes() == umbral_pubkey.to_bytes()

    new_keypair_from_pub = keypairs.Keypair(public_key=umbral_pubkey)
    assert new_keypair_from_pub.pubkey.to_bytes() == umbral_pubkey.to_bytes()
    assert new_keypair_from_pub._privkey == PUBLIC_ONLY


def test_keypair_serialization():
    umbral_pubkey = UmbralPrivateKey.gen_key().get_pubkey()
    new_keypair = keypairs.Keypair(public_key=umbral_pubkey)

    pubkey_bytes = new_keypair.serialize_pubkey()
    assert pubkey_bytes == bytes(umbral_pubkey)


def test_keypair_fingerprint():
    umbral_pubkey = UmbralPrivateKey.gen_key().get_pubkey()
    new_keypair = keypairs.Keypair(public_key=umbral_pubkey)

    fingerprint = new_keypair.fingerprint()
    assert fingerprint is not None

    umbral_fingerprint = sha3.keccak_256(bytes(umbral_pubkey)).hexdigest().encode()
    assert fingerprint == umbral_fingerprint


def test_signing():
    umbral_privkey = UmbralPrivateKey.gen_key()
    sig_keypair = keypairs.SigningKeypair(umbral_privkey)

    msg = b'peace at dawn'
    signature = sig_keypair.sign(msg)
    assert signature.verify(msg, sig_keypair.pubkey)

    bad_msg = b'bad message'
    assert not signature.verify(bad_msg, sig_keypair.pubkey)


# TODO: Add test for DecryptingKeypair.decrypt
