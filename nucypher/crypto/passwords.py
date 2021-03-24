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

from typing import Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt as CryptographyScrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from nacl.secret import SecretBox
from nacl.bindings.crypto_aead import (
    crypto_aead_xchacha20poly1305_ietf_encrypt as xchacha_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt as xchacha_decrypt,
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES as XCHACHA_KEY_SIZE,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as XCHACHA_NONCE_SIZE,
    crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX as XCHACHA_MESSAGEBYTES_MAX,
    )
from nacl.utils import random as nacl_random

from nucypher.crypto.constants import BLAKE2B


# Keyring
__WRAPPING_KEY_LENGTH = 32 # TODO: should be the same as XCHACHA_KEY_SIZE
__WRAPPING_KEY_INFO = b'NuCypher-KeyWrap'
__HKDF_HASH_ALGORITHM = BLAKE2B


class ChaChaSecretBox:
    """
    A NaCl SecretBox analogue based on ChaCha instead of Salsa, for compatibility with rust-umbral.

    Unlike SecretBox, it also takes key material (password) instead of the full key
    and expands it using SHA256.
    """

    KEY_SIZE = XCHACHA_KEY_SIZE
    NONCE_SIZE = XCHACHA_NONCE_SIZE
    MESSAGEBYTES_MAX = XCHACHA_MESSAGEBYTES_MAX

    @classmethod
    def from_key_material(key_material: bytes, salt: bytes, info: bytes):
        hkdf = HKDF(algorithm=hashes.SHA256(),
                    length=self.KEY_SIZE,
                    salt=salt,
                    info=info,
                    backend=default_backend()
                    )
        return cls(hkdf.derive(key_material))

    def __init__(self, key: bytes):
        assert len(key) == self.KEY_SIZE
        self._key = key

    def encrypt(self, plaintext: bytes, nonce: Optional[bytes] = None) -> bytes:
        if nonce is None:
            nonce = nacl_random(self.NONCE_SIZE)

        if len(nonce) != self.NONCE_SIZE:
            raise ValueError(f"The nonce must be exactly {self.NONCE_SIZE} bytes long")

        ciphertext = xchacha_encrypt(plaintext, b"", nonce, self._key)
        return nonce + ciphertext

    def decrypt(self, nonce_and_ciphertext: bytes) -> bytes:

        if len(nonce_and_ciphertext) < self.NONCE_SIZE:
            raise ValueError(f"The ciphertext must include the nonce")

        nonce = nonce_and_ciphertext[:self.NONCE_SIZE]
        ciphertext = nonce_and_ciphertext[self.NONCE_SIZE:]

        return xchacha_decrypt(ciphertext, b"", nonce, self._key)


def derive_wrapping_key_from_key_material(salt: bytes,
                                          key_material: bytes,
                                          ) -> bytes:
    """
    Uses HKDF to derive a 32 byte wrapping key to encrypt key material with.
    """

    wrapping_key = HKDF(
        algorithm=__HKDF_HASH_ALGORITHM,
        length=__WRAPPING_KEY_LENGTH,
        salt=salt,
        info=__WRAPPING_KEY_INFO,
        backend=default_backend()
    ).derive(key_material)
    return wrapping_key


class Scrypt:
    __DEFAULT_SCRYPT_COST = 20

    def __call__(self,
                 password: bytes,
                 salt: bytes,
                 **kwargs) -> bytes:
        """
        Derives a symmetric encryption key from a pair of password and salt.
        It also accepts an additional _scrypt_cost argument.
        WARNING: RFC7914 recommends that you use a 2^20 cost value for sensitive
        files. It is NOT recommended to change the `_scrypt_cost` value unless
        you know what you are doing.
        :param password: byte-encoded password used to derive a symmetric key
        :param salt: cryptographic salt added during key derivation
        :return:
        """

        _scrypt_cost = kwargs.get('_scrypt_cost', Scrypt.__DEFAULT_SCRYPT_COST)
        try:
            derived_key = CryptographyScrypt(
                salt=salt,
                length=SecretBox.KEY_SIZE,
                n=2 ** _scrypt_cost,
                r=8,
                p=1,
                backend=default_backend()
            ).derive(password)
        except InternalError as e:
            required_memory = 128 * 2**_scrypt_cost * 8 // (10**6)
            if e.err_code[0].reason == 65:
                raise MemoryError(
                    "Scrypt key derivation requires at least {} MB of memory. "
                    "Please free up some memory and try again.".format(required_memory)
                )
            else:
                raise e
        else:
            return derived_key


def derive_key_from_password(password: bytes,
                             salt: bytes,
                             **kwargs) -> bytes:
    """
    Derives a symmetric encryption key from a pair of password and salt.
    It uses Scrypt by default.
    """
    kdf = kwargs.get('kdf', Scrypt)()
    derived_key = kdf(password, salt, **kwargs)
    return derived_key
