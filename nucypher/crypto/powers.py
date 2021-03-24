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


import inspect
from eth_typing.evm import ChecksumAddress
from hexbytes import HexBytes
from typing import List, Optional, Tuple
from nucypher.crypto.umbral_adapter import pre, UmbralKeyingMaterial, UmbralPrivateKey, UmbralPublicKey

from nucypher.blockchain.eth.decorators import validate_checksum_address
from nucypher.blockchain.eth.signers.base import Signer
from nucypher.crypto import keypairs
from nucypher.crypto.keypairs import DecryptingKeypair, SigningKeypair


class PowerUpError(TypeError):
    pass


class NoSigningPower(PowerUpError):
    pass


class NoDecryptingPower(PowerUpError):
    pass


class NoTransactingPower(PowerUpError):
    pass


class CryptoPower(object):
    def __init__(self, power_ups: list = None) -> None:
        self.__power_ups = {}   # type: dict
        # TODO: The keys here will actually be IDs for looking up in a Datastore.
        self.public_keys = {}  # type: dict

        if power_ups is not None:
            for power_up in power_ups:
                self.consume_power_up(power_up)

    def __contains__(self, item):
        try:
            self.power_ups(item)
        except PowerUpError:
            return False
        else:
            return True

    def consume_power_up(self, power_up, *args, **kwargs):
        if isinstance(power_up, CryptoPowerUp):
            power_up_class = power_up.__class__
            power_up.activate(*args, **kwargs)
            power_up_instance = power_up
        elif CryptoPowerUp in inspect.getmro(power_up):
            power_up_class = power_up
            power_up_instance = power_up()
        else:
            raise TypeError(
                ("power_up must be a subclass of CryptoPowerUp or an instance "
                 "of a CryptoPowerUp subclass."))
        self.__power_ups[power_up_class] = power_up_instance

        if power_up.confers_public_key:
            self.public_keys[power_up_class] = power_up_instance.public_key()

    def power_ups(self, power_up_class):
        try:
            return self.__power_ups[power_up_class]
        except KeyError:
            raise power_up_class.not_found_error


class CryptoPowerUp:
    """
    Gives you MORE CryptoPower!
    """
    confers_public_key = False

    def activate(self, *args, **kwargs):
        return


class TransactingPower(CryptoPowerUp):
    """
    The power to sign ethereum transactions as the custodian of a private key through a signing backend.
    """

    not_found_error = NoTransactingPower

    class AccountLocked(PowerUpError):
        """Raised when signing cannot be performed due to a locked account"""
        pass

    @validate_checksum_address
    def __init__(self,
                 account: ChecksumAddress,
                 signer: Signer,
                 password: str = None,
                 cache: bool = False):
        """
        Instantiates a TransactingPower for the given checksum_address.
        """

        # Auth
        if not signer:
            raise ValueError('signer is required to init a TransactingPower.')
        self._signer = signer
        self.__account = account
        self.__password = password

        # Config
        self.__blockchain = None
        self.__cache = cache
        self.__activated = False

    def __enter__(self):
        return self.unlock()

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self.lock_account()

    def __eq__(self, other):
        if not isinstance(other, TransactingPower):
            return False
        result = bool(self.account == other.account)
        return result

    #
    # Properties
    #

    @property
    def account(self) -> ChecksumAddress:
        return self.__account

    @property
    def is_device(self) -> bool:
        return self._signer.is_device(account=self.__account)

    #
    # Power
    #

    def activate(self, password: str = None) -> None:
        """Called during power consumption"""
        self.unlock(password=password)
        if self.__cache is False:
            self.__password = None

    def lock_account(self) -> None:
        self._signer.lock_account(account=self.__account)

    def unlock(self, password: str = None, duration: int = None) -> bool:
        """Unlocks the account with provided or cached password."""
        password = password or self.__password
        result = self._signer.unlock_account(self.__account,
                                             password=password,
                                             duration=duration)
        return result

    def sign_message(self, message: bytes) -> bytes:
        """Signs the message with the private key of the TransactingPower."""
        return self._signer.sign_message(account=self.__account, message=message)

    def sign_transaction(self, transaction_dict: dict) -> HexBytes:
        """Signs the transaction with the private key of the TransactingPower."""
        return self._signer.sign_transaction(transaction_dict=transaction_dict)


class KeyPairBasedPower(CryptoPowerUp):
    confers_public_key = True
    _keypair_class = keypairs.Keypair
    _default_private_key_class = UmbralPrivateKey

    def __init__(self, public_key: UmbralPublicKey = None, keypair: keypairs.Keypair = None):
        if keypair and public_key:
            raise ValueError("Pass keypair or pubkey_bytes (or neither), but not both.")
        elif keypair:
            self.keypair = keypair
        else:
            # They didn't pass a keypair; we'll make one with the bytes or
            # UmbralPublicKey if they provided such a thing.
            if public_key:
                try:
                    public_key = public_key.as_umbral_pubkey()
                except AttributeError:
                    try:
                        public_key = UmbralPublicKey.from_bytes(public_key)
                    except TypeError:
                        public_key = public_key
                self.keypair = self._keypair_class(
                    public_key=public_key)
            else:
                # They didn't even pass a public key.  We have no choice but to generate a keypair.
                self.keypair = self._keypair_class(generate_keys_if_needed=True)

    def __getattr__(self, item):
        if item in self.provides:
            try:
                return getattr(self.keypair, item)
            except AttributeError:
                message = f"This {self.__class__} has a keypair, {self.keypair.__class__}, which doesn't provide {item}."
                raise PowerUpError(message)
        else:
            raise PowerUpError("This {} doesn't provide {}.".format(self.__class__, item))

    def public_key(self) -> 'UmbralPublicKey':
        return self.keypair.pubkey


class SigningPower(KeyPairBasedPower):
    _keypair_class = SigningKeypair
    not_found_error = NoSigningPower
    provides = ("sign", "get_signature_stamp")


class DecryptingPower(KeyPairBasedPower):
    _keypair_class = DecryptingKeypair
    not_found_error = NoDecryptingPower
    provides = ("decrypt",)


class DerivedKeyBasedPower(CryptoPowerUp):
    """
    Rather than rely on an established KeyPair, this type of power
    derives a key at moments defined by the user.
    """


class DelegatingPower(DerivedKeyBasedPower):

    def __init__(self,
                 keying_material: Optional[bytes] = None,
                 password: Optional[bytes] = None) -> None:
        if keying_material is None:
            self.__umbral_keying_material = UmbralKeyingMaterial()
        else:
            self.__umbral_keying_material = UmbralKeyingMaterial.from_bytes(key_bytes=keying_material,
                                                                            password=password)

    def _get_privkey_from_label(self, label):
        return self.__umbral_keying_material.derive_privkey_by_label(label)

    def get_pubkey_from_label(self, label):
        return self._get_privkey_from_label(label).get_pubkey()

    def generate_kfrags(self,
                        bob_pubkey_enc,
                        signer,
                        label: bytes,
                        m: int,
                        n: int
                        ) -> Tuple[UmbralPublicKey, List]:
        """
        Generates re-encryption key frags ("KFrags") and returns them.

        These KFrags can be used by Ursula to re-encrypt a Capsule for Bob so
        that he can activate the Capsule.
        :param bob_pubkey_enc: Bob's public key
        :param m: Minimum number of KFrags needed to rebuild ciphertext
        :param n: Total number of KFrags to generate
        """

        __private_key = self._get_privkey_from_label(label)
        kfrags = pre.generate_kfrags(delegating_privkey=__private_key,
                                     receiving_pubkey=bob_pubkey_enc,
                                     threshold=m,
                                     N=n,
                                     signer=signer,
                                     sign_delegating_key=False,
                                     sign_receiving_key=False,
                                     )
        return __private_key.get_pubkey(), kfrags

    def get_decrypting_power_from_label(self, label):
        label_privkey = self._get_privkey_from_label(label)
        label_keypair = keypairs.DecryptingKeypair(private_key=label_privkey)
        decrypting_power = DecryptingPower(keypair=label_keypair)
        return decrypting_power
