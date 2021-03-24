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
from functools import partial
from pathlib import Path

import pytest
from constant_sorrow.constants import FEDERATED_ADDRESS
from cryptography.hazmat.primitives.serialization import Encoding

from nucypher.config.keyring import (
    _assemble_key_data,
    _generate_tls_keys,
    _serialize_private_key,
    _deserialize_private_key,
    _serialize_private_key_to_pem,
    _deserialize_private_key_from_pem,
    _write_private_keyfile,
    _read_keyfile, NucypherKeyring
)
from nucypher.crypto.api import _TLS_CURVE
from nucypher.crypto.powers import DecryptingPower, SigningPower
from nucypher.network.server import TLSHostingPower
from nucypher.utilities.networking import LOOPBACK_ADDRESS
from tests.constants import INSECURE_DEVELOPMENT_PASSWORD


def test_keyring_invalid_password(tmpdir):
    with pytest.raises(NucypherKeyring.AuthenticationFailed):
        _generate_keyring(tmpdir, password='tobeornottobe')  # password less than 16 characters


def test_keyring_lock_unlock(tmpdir):
    keyring = _generate_keyring(tmpdir)
    assert not keyring.is_unlocked

    keyring.unlock(INSECURE_DEVELOPMENT_PASSWORD)
    assert keyring.is_unlocked
    keyring.unlock(INSECURE_DEVELOPMENT_PASSWORD)  # unlock when already unlocked
    assert keyring.is_unlocked

    keyring.lock()
    assert not keyring.is_unlocked
    keyring.lock()  # lock when already locked
    assert not keyring.is_unlocked


def test_keyring_derive_crypto_power_without_unlock(tmpdir):
    keyring = _generate_keyring(tmpdir)
    with pytest.raises(NucypherKeyring.KeyringLocked):
        keyring.derive_crypto_power(power_class=DecryptingPower)


def test_keyring_restoration(tmpdir):
    keyring = _generate_keyring(tmpdir)
    keyring.unlock(password=INSECURE_DEVELOPMENT_PASSWORD)

    account = keyring.account
    checksum_address = keyring.checksum_address
    certificate_filepath = keyring.certificate_filepath
    encrypting_public_key_hex = keyring.encrypting_public_key.hex()
    signing_public_key_hex = keyring.signing_public_key.hex()

    # tls power
    tls_hosting_power = keyring.derive_crypto_power(power_class=TLSHostingPower, host=LOOPBACK_ADDRESS)
    tls_hosting_power_public_key_numbers = tls_hosting_power.public_key().public_numbers()
    tls_hosting_power_certificate_public_bytes = \
        tls_hosting_power.keypair.certificate.public_bytes(encoding=Encoding.PEM)
    tls_hosting_power_certificate_filepath = tls_hosting_power.keypair.certificate_filepath

    # decrypting power
    decrypting_power = keyring.derive_crypto_power(power_class=DecryptingPower)
    decrypting_power_public_key_hex = decrypting_power.public_key().hex()
    decrypting_power_fingerprint = decrypting_power.keypair.fingerprint()

    # signing power
    signing_power = keyring.derive_crypto_power(power_class=SigningPower)
    signing_power_public_key_hex = signing_power.public_key().hex()
    signing_power_fingerprint = signing_power.keypair.fingerprint()

    # get rid of object, but not persistent data
    del keyring

    restored_keyring = NucypherKeyring(keyring_root=tmpdir, account=account)
    restored_keyring.unlock(password=INSECURE_DEVELOPMENT_PASSWORD)

    assert restored_keyring.account == account
    assert restored_keyring.checksum_address == checksum_address
    assert restored_keyring.certificate_filepath == certificate_filepath
    assert restored_keyring.encrypting_public_key.hex() == encrypting_public_key_hex
    assert restored_keyring.signing_public_key.hex() == signing_public_key_hex

    # tls power
    restored_tls_hosting_power = restored_keyring.derive_crypto_power(power_class=TLSHostingPower,
                                                                      host=LOOPBACK_ADDRESS)
    assert restored_tls_hosting_power.public_key().public_numbers() == tls_hosting_power_public_key_numbers
    assert restored_tls_hosting_power.keypair.certificate.public_bytes(encoding=Encoding.PEM) == \
           tls_hosting_power_certificate_public_bytes
    assert restored_tls_hosting_power.keypair.certificate_filepath == tls_hosting_power_certificate_filepath

    # decrypting power
    restored_decrypting_power = restored_keyring.derive_crypto_power(power_class=DecryptingPower)
    assert restored_decrypting_power.public_key().hex() == decrypting_power_public_key_hex
    assert restored_decrypting_power.keypair.fingerprint() == decrypting_power_fingerprint

    # signing power
    restored_signing_power = restored_keyring.derive_crypto_power(power_class=SigningPower)
    assert restored_signing_power.public_key().hex() == signing_power_public_key_hex
    assert restored_signing_power.keypair.fingerprint() == signing_power_fingerprint


def test_keyring_destroy(tmpdir):
    keyring = _generate_keyring(tmpdir)
    keyring.unlock(password=INSECURE_DEVELOPMENT_PASSWORD)

    keyring.destroy()

    with pytest.raises(FileNotFoundError):
        keyring.encrypting_public_key


def test_private_key_serialization():
    key_data = _assemble_key_data(key_data=b'peanuts, get your peanuts',
                                  master_salt=b'sea salt',
                                  wrap_salt=b'red salt')
    key_bytes = _serialize_private_key(key_data)
    deserialized_key_data = _deserialize_private_key(key_bytes)

    assert key_data == deserialized_key_data


def test_write_read_private_keyfile(temp_dir_path):
    temp_filepath = Path(temp_dir_path) / "test_private_key_serialization_file"
    key_data = _assemble_key_data(key_data=b'peanuts, get your peanuts',
                                  master_salt=b'sea salt',
                                  wrap_salt=b'red salt')
    _write_private_keyfile(keypath=temp_filepath,
                           key_data=key_data,
                           serializer=_serialize_private_key)

    deserialized_key_data_from_file = _read_keyfile(keypath=temp_filepath,
                                                    deserializer=_deserialize_private_key)
    assert key_data == deserialized_key_data_from_file


def test_tls_private_key_serialization():
    host = LOOPBACK_ADDRESS
    checksum_address = '0xdeadbeef'

    private_key, _ = _generate_tls_keys(host=host,
                                        checksum_address=checksum_address,
                                        curve=_TLS_CURVE)
    password = b'serialize_deserialized'
    key_bytes = _serialize_private_key_to_pem(private_key, password=password)
    deserialized_private_key = _deserialize_private_key_from_pem(key_bytes, password=password)

    assert private_key.private_numbers() == deserialized_private_key.private_numbers()

    # sanity check just to be certain that a different key doesn't have the same private numbers
    other_private_key, _ = _generate_tls_keys(host=host,
                                              checksum_address=checksum_address,
                                              curve=_TLS_CURVE)
    assert other_private_key.private_numbers() != deserialized_private_key.private_numbers()


def test_tls_write_read_private_keyfile(temp_dir_path):
    temp_filepath = Path(temp_dir_path) / "test_tls_private_key_serialization_file"
    host = LOOPBACK_ADDRESS
    checksum_address = '0xdeadbeef'

    private_key, _ = _generate_tls_keys(host=host,
                                        checksum_address=checksum_address,
                                        curve=_TLS_CURVE)
    password = b'serialize_deserialized'
    tls_serializer = partial(_serialize_private_key_to_pem, password=password)
    _write_private_keyfile(keypath=temp_filepath,
                           key_data=private_key,
                           serializer=tls_serializer)

    tls_deserializer = partial(_deserialize_private_key_from_pem, password=password)
    deserialized_private_key_from_file = _read_keyfile(keypath=temp_filepath,
                                                       deserializer=tls_deserializer)

    assert private_key.private_numbers() == deserialized_private_key_from_file.private_numbers()


def _generate_keyring(root,
                      checksum_address=FEDERATED_ADDRESS,
                      password=INSECURE_DEVELOPMENT_PASSWORD,
                      encrypting=True,
                      rest=True,
                      host=LOOPBACK_ADDRESS):
    keyring = NucypherKeyring.generate(
              checksum_address=checksum_address,
              password=password,
              encrypting=encrypting,
              rest=rest,
              host=host,
              keyring_root=root)
    return keyring
