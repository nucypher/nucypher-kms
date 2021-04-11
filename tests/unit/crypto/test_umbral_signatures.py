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
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives import hashes
from nucypher.crypto.umbral_adapter import UmbralPrivateKey

from nucypher.crypto.api import ecdsa_sign, verify_ecdsa
from nucypher.crypto.signing import Signature, Signer
from nucypher.crypto.utils import get_signature_recovery_value, recover_pubkey_from_signature


def test_signature_can_verify():
    privkey = UmbralPrivateKey.gen_key()
    message = b"peace at dawn"
    der_sig_bytes = ecdsa_sign(message, privkey)
    assert verify_ecdsa(message, der_sig_bytes, privkey.get_pubkey())
    signature = Signature.from_bytes(der_sig_bytes, der_encoded=True)
    assert signature.verify(message, privkey.get_pubkey())


def test_signature_rs_serialization():
    privkey = UmbralPrivateKey.gen_key()
    message = b"peace at dawn"
    der_sig_bytes = ecdsa_sign(message, privkey)

    signature_from_der = Signature.from_bytes(der_sig_bytes, der_encoded=True)
    rs_sig_bytes = bytes(signature_from_der)
    assert len(rs_sig_bytes) == 64

    signature_from_rs = Signature.from_bytes(rs_sig_bytes, der_encoded=False)

    assert signature_from_rs == signature_from_der
    assert bytes(signature_from_rs) == der_sig_bytes
    assert signature_from_rs.verify(message, privkey.get_pubkey())


@pytest.mark.skip("Seems to require DER-formatted signatures")
@pytest.mark.parametrize('execution_number', range(100))  # Run this test 100 times.
def test_ecdsa_signature_recovery(execution_number):
    privkey = UmbralPrivateKey.gen_key()
    pubkey = privkey.get_pubkey()
    signer = Signer(private_key=privkey)
    message = b"peace at dawn"
    signature = signer(message=message)

    assert signature.verify(message, pubkey)

    v_value = 27
    pubkey_bytes = recover_pubkey_from_signature(message=message,
                                                 signature=signature,
                                                 v_value_to_try=v_value)
    if not pubkey_bytes == pubkey.to_bytes():
        v_value = 28
        pubkey_bytes = recover_pubkey_from_signature(message=message,
                                                     signature=signature,
                                                     v_value_to_try=v_value)

    assert pubkey_bytes == pubkey.to_bytes()
    assert bytes([v_value - 27]) == get_signature_recovery_value(message, signature, pubkey)

    hash_function = hashes.Hash(hashes.SHA256(), backend=backend)
    hash_function.update(message)
    prehashed_message = hash_function.finalize()

    v_value = 27
    pubkey_bytes = recover_pubkey_from_signature(message=prehashed_message,
                                                 signature=signature,
                                                 v_value_to_try=v_value,
                                                 is_prehashed=True)
    if not pubkey_bytes == pubkey.to_bytes():
        v_value = 28
        pubkey_bytes = recover_pubkey_from_signature(message=prehashed_message,
                                                     signature=signature,
                                                     v_value_to_try=v_value,
                                                     is_prehashed=True)
    assert pubkey_bytes == pubkey.to_bytes()
    assert bytes([v_value - 27]) == get_signature_recovery_value(prehashed_message,
                                                                 signature,
                                                                 pubkey,
                                                                 is_prehashed=True)
