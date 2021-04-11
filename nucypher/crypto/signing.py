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


from bytestring_splitter import BytestringSplitter
from nucypher.crypto.umbral_adapter import Signature, Signer

from nucypher.crypto.api import keccak_digest

signature_splitter = BytestringSplitter(Signature)


class SignatureStamp(object):
    """
    Can be called to sign something or used to express the signing public
    key as bytes.
    """

    def __init__(self, verifying_key, signer: Signer = None) -> None:
        self.__signer = signer
        self._as_bytes = bytes(verifying_key)
        self._as_umbral_pubkey = verifying_key

    def __bytes__(self):
        return self._as_bytes

    def __call__(self, *args, **kwargs):
        return self.__signer(*args, **kwargs)

    def __hash__(self):
        return int.from_bytes(self, byteorder="big")

    def __eq__(self, other):
        return other == bytes(self)

    def __add__(self, other):
        return bytes(self) + other

    def __radd__(self, other):
        return other + bytes(self)

    def __len__(self):
        return len(bytes(self))

    def __bool__(self):
        return True

    def as_umbral_pubkey(self):
        return self._as_umbral_pubkey

    def fingerprint(self):
        """
        Hashes the key using keccak-256 and returns the hexdigest in bytes.

        :return: Hexdigest fingerprint of key (keccak-256) in bytes
        """
        return keccak_digest(bytes(self)).hex().encode()


class StrangerStamp(SignatureStamp):
    """
    SignatureStamp of a stranger (ie, can only be used to glean public key, not to sign)
    """

    def __call__(self, *args, **kwargs):
        from nucypher.crypto.powers import NoSigningPower
        message = "This isn't your SignatureStamp; it belongs to (a Stranger).  You can't sign with it."
        raise NoSigningPower(message)


class InvalidSignature(Exception):
    """Raised when a Signature is not valid."""
