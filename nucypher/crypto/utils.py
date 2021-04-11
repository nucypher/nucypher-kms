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

from coincurve import PublicKey
from eth_keys import KeyAPI as EthKeyAPI
from typing import Any, Union
from nucypher.crypto.umbral_adapter import UmbralPublicKey, Signature, Point

from nucypher.crypto.api import keccak_digest
from nucypher.crypto.signing import SignatureStamp


def fingerprint_from_key(public_key: Any):
    """
    Hashes a key using keccak-256 and returns the hexdigest in bytes.
    :return: Hexdigest fingerprint of key (keccak-256) in bytes
    """
    return keccak_digest(bytes(public_key)).hex().encode()


def construct_policy_id(label: bytes, stamp: bytes) -> bytes:
    """
    Forms an ID unique to the policy per label and Bob's signing pubkey via
    a keccak hash of the two.
    """
    return keccak_digest(label + stamp)


def canonical_address_from_umbral_key(public_key: UmbralPublicKey) -> bytes:
    # TODO: seems `public_key` like is actually a `SignatureStamp` now.
    pubkey_raw_bytes = bytes(public_key)
    eth_pubkey = EthKeyAPI.PublicKey.from_compressed_bytes(pubkey_raw_bytes)
    canonical_address = eth_pubkey.to_canonical_address()
    return canonical_address


def recover_pubkey_from_signature(message: bytes,
                                  signature: Union[bytes, Signature],
                                  v_value_to_try: int,
                                  is_prehashed: bool = False) -> bytes:
    """
    Recovers a serialized, compressed public key from a signature.
    It allows to specify a potential v value, in which case it assumes the signature
    has the traditional (r,s) raw format. If a v value is not present, it assumes
    the signature has the recoverable format (r, s, v).

    :param message: Signed message
    :param signature: The signature from which the pubkey is recovered
    :param v_value_to_try: A potential v value to try
    :param is_prehashed: True if the message is already pre-hashed. Default is False, and message will be hashed with SHA256
    :return: The compressed byte-serialized representation of the recovered public key
    """
    signature = bytes(signature)
    expected_signature_size = Signature.expected_bytes_length()
    if not len(signature) == expected_signature_size:
        raise ValueError(f"The signature size should be {expected_signature_size} B.")

    if v_value_to_try in (0, 1, 27, 28):
        if v_value_to_try >= 27:
            v_value_to_try -= 27
        signature = signature + v_value_to_try.to_bytes(1, 'big')
    else:
        raise ValueError("Wrong v value. It should be 0, 1, 27 or 28.")

    kwargs = dict(hasher=None) if is_prehashed else {}
    pubkey = PublicKey.from_signature_and_message(serialized_sig=signature,
                                                  message=message,
                                                  **kwargs)
    return pubkey.format(compressed=True)


def get_signature_recovery_value(message: bytes,
                                 signature: Union[bytes, Signature],
                                 public_key: Union[bytes, UmbralPublicKey],
                                 is_prehashed: bool = False) -> bytes:
    """
    Obtains the recovery value of a standard ECDSA signature.

    :param message: Signed message
    :param signature: The signature from which the pubkey is recovered
    :param public_key: The public key for verifying the signature
    :param is_prehashed: True if the message is already pre-hashed. Default is False, and message will be hashed with SHA256
    :return: The compressed byte-serialized representation of the recovered public key
    """

    signature = bytes(signature)
    ecdsa_signature_size = Signature.expected_bytes_length()
    if len(signature) != ecdsa_signature_size:
        raise ValueError(f"The signature size should be {ecdsa_signature_size} B.")

    kwargs = dict(hasher=None) if is_prehashed else {}
    for v in (0, 1):
        v_byte = bytes([v])
        recovered_pubkey = PublicKey.from_signature_and_message(serialized_sig=signature + v_byte,
                                                                message=message,
                                                                **kwargs)
        if bytes(public_key) == recovered_pubkey.format(compressed=True):
            return v_byte
    else:
        raise ValueError("Signature recovery failed. "
                         "Either the message, the signature or the public key is not correct")


def get_coordinates_as_bytes(point: Union[Point, UmbralPublicKey, SignatureStamp],
                             x_coord=True,
                             y_coord=True) -> bytes:
    if isinstance(point, SignatureStamp):
        point = point.as_umbral_pubkey()

    coordinates_as_bytes = point.to_bytes(is_compressed=False)[1:]
    middle = len(coordinates_as_bytes)//2
    if x_coord and y_coord:
        return coordinates_as_bytes
    elif x_coord:
        return coordinates_as_bytes[:middle]
    elif y_coord:
        return coordinates_as_bytes[middle:]
    else:
        raise ValueError("At least one coordinate must be set")
