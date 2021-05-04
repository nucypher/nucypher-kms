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


from bytestring_splitter import (
    BytestringSplitter,
    VariableLengthBytestring,
    BytestringKwargifier,
    BytestringSplittingError
)
from constant_sorrow.constants import NO_DECRYPTION_PERFORMED, NOT_SIGNED
from eth_utils.address import to_checksum_address, to_canonical_address
from typing import Optional, Callable, Union, Sequence
from umbral.kfrags import KFrag

from nucypher.blockchain.eth.constants import ETH_ADDRESS_BYTE_LENGTH
from nucypher.characters.base import Character
from nucypher.crypto.api import encrypt_and_sign, keccak_digest, verify_eip_191
from nucypher.crypto.constants import HRAC_LENGTH, WRIT_CHECKSUM_SIZE
from nucypher.crypto.kits import UmbralMessageKit
from nucypher.crypto.powers import DecryptingPower, SigningPower
from nucypher.crypto.signing import SignatureStamp
from nucypher.network.middleware import RestMiddleware
from umbral.keys import UmbralPublicKey
from umbral.signing import Signature


class TreasureMap:

    VERSION_NUMBER = 2  # Increment when serialization format changes.

    _DELIMITER = b':'
    _PREFIX = b'TM' + _DELIMITER
    _VERSION = int(VERSION_NUMBER).to_bytes(1, 'big')
    _HEADER = _PREFIX + _VERSION
    _HEADER_SIZE = len(_HEADER)

    class NowhereToBeFound(RestMiddleware.NotFound):
        """
        Called when no known nodes have it.
        """

    class IsDisorienting(Exception):
        """
        Called when an oriented TreasureMap lists fewer than m destinations, which
        leaves Bob disoriented.
        """

    class OldVersion(Exception):
        """Raised when a treasure map's version is too old or contents are incompatible."""

    ursula_and_kfrag_payload_splitter = BytestringSplitter(
        (to_checksum_address, ETH_ADDRESS_BYTE_LENGTH),
        (UmbralMessageKit, VariableLengthBytestring),
    )

    from nucypher.crypto.signing import \
        InvalidSignature  # Raised when the public signature (typically intended for Ursula) is not valid.

    def __init__(self,
                 m: int = None,
                 destinations=None,
                 message_kit: UmbralMessageKit = None,
                 public_signature: Signature = None,
                 hrac: Optional[bytes] = None,
                 version: bytes = None
                 ) -> None:

        if version is not None:
            self.version = version

        if m is not None:
            if m > 255:
                raise ValueError("Largest allowed value for m is 255.")
            self._m = m

            self._destinations = destinations or {}
        else:
            self._m = NO_DECRYPTION_PERFORMED
            self._destinations = NO_DECRYPTION_PERFORMED

        self._id = None

        self.message_kit = message_kit
        self._public_signature = public_signature
        self._hrac = hrac
        self._payload = None

        if message_kit is not None:
            self.message_kit = message_kit
            self._set_id()
        else:
            self.message_kit = None

    def __eq__(self, other):
        try:
            return self.public_id() == other.public_id()
        except AttributeError:
            raise TypeError(f"Can't compare {type(other).__name__} to a TreasureMap (it needs to implement public_id() )")

    def __iter__(self):
        return iter(self.destinations.items())

    def __len__(self):
        return len(self.destinations)

    def __bytes__(self):
        if self._payload is None:
            self._set_payload()
        return self._payload

    @classmethod
    def splitter(cls):
        return BytestringKwargifier(cls,
                                    version=(bytes, cls._HEADER_SIZE),
                                    public_signature=Signature,
                                    hrac=(bytes, HRAC_LENGTH),
                                    message_kit=(UmbralMessageKit, VariableLengthBytestring))

    @classmethod
    def _check_version(cls, bytes_representation: bytes) -> None:
        """
        Takes a bytes representation of a treasure map and raises OldVersion
        error is the version is incompatible or ValueError if the header is malformed.
        """
        header = bytes_representation[:cls._HEADER_SIZE]
        if header != cls._HEADER:
            if bytes_representation[:len(cls._PREFIX)] != cls._PREFIX:
                # This either is not a treasure map, or predates versioning.
                raise ValueError('Invalid treasure map header.')
            try:
                prefix, version = header.split(cls._DELIMITER)
            except ValueError:
                raise ValueError('Invalid treasure map header.')
            raise cls.OldVersion(f'Treasure map is an old version ({version} but the latest version is {cls.VERSION_NUMBER}')

    @classmethod
    def from_bytes(cls, bytes_representation: bytes, verify: bool = True) -> Union['TreasureMap', 'SignedTreasureMap']:
        cls._check_version(bytes_representation=bytes_representation)
        splitter = cls.splitter()
        treasure_map = splitter(bytes_representation)
        if verify:
            treasure_map.public_verify()
        return treasure_map

    @property
    def _verifying_key(self):
        return self.message_kit.sender_verifying_key

    @property
    def m(self) -> int:
        if self._m == NO_DECRYPTION_PERFORMED:
            raise TypeError("The TreasureMap is probably encrypted. You must decrypt it first.")
        return self._m

    @property
    def destinations(self):
        if self._destinations == NO_DECRYPTION_PERFORMED:
            raise TypeError("The TreasureMap is probably encrypted. You must decrypt it first.")
        return self._destinations

    def _set_id(self) -> None:
        self._id = keccak_digest(bytes(self._verifying_key) + bytes(self._hrac)).hex()

    def _set_payload(self) -> None:
        self._payload = self._HEADER  \
            + self._public_signature  \
            + self._hrac              \
            + bytes(VariableLengthBytestring(self.message_kit.to_bytes()))

    def derive_hrac(self, alice_stamp: SignatureStamp, bob_verifying_key: UmbralPublicKey, label: bytes) -> None:
        """
        Here's our "hashed resource access code".

        A hash of:
        * Alice's public key
        * Bob's public key
        * the label

        Alice and Bob have all the information they need to construct this.
        Ursula does not, so we share it with her.

        This way, Bob can generate it and use it to find the TreasureMap.
        """
        self._hrac = keccak_digest(bytes(alice_stamp) + bytes(bob_verifying_key) + label)[:HRAC_LENGTH]

    def prepare_for_publication(self, bob_encrypting_key, alice_stamp):
        plaintext = self._m.to_bytes(1, "big") + self.nodes_as_bytes()
        self.message_kit, _signature_for_bob = encrypt_and_sign(bob_encrypting_key,
                                                                plaintext=plaintext,
                                                                signer=alice_stamp)
        self._public_signature = alice_stamp(bytes(alice_stamp) + self._hrac)
        self._set_payload()
        self._set_id()

    def nodes_as_bytes(self):
        if self.destinations == NO_DECRYPTION_PERFORMED:
            return NO_DECRYPTION_PERFORMED
        else:
            nodes_as_bytes = b""
            for ursula_address, encrypted_kfrag in self.destinations.items():
                node_id = to_canonical_address(ursula_address)
                kfrag = bytes(VariableLengthBytestring(encrypted_kfrag.to_bytes()))
                nodes_as_bytes += (node_id + kfrag)
            return nodes_as_bytes

    def _make_writ(self, kfrag, alice_stamp) -> bytes:
        """
        Alice makes plain to Ursula that, upon decrypting this message,
        this particular KFrag is authorized for use in the policy identified by this HRAC.
        """
        writ = self._hrac + keccak_digest(bytes(kfrag))[:WRIT_CHECKSUM_SIZE]
        writ_signature = alice_stamp(writ)
        signed_writ = writ + writ_signature
        return signed_writ

    def _make_kfrag_payload(self, kfrag, alice_stamp) -> bytes:
        # The writ and the KFrag together represent a complete kfrag kit: the entirety of
        # the material needed for Ursula to assuredly service this policy.
        signed_writ = self._make_writ(kfrag=kfrag, alice_stamp=alice_stamp)
        kfrag_payload = signed_writ + bytes(kfrag)
        return kfrag_payload

    def add_kfrag(self, ursula, kfrag, alice_stamp: SignatureStamp) -> None:
        if self.destinations == NO_DECRYPTION_PERFORMED:
            # Unsure how this situation can arise, but let's raise an error just in case.
            raise TypeError("This TreasureMap is encrypted.  You can't add another node without decrypting it.")

        if not self._hrac:
            # TODO: Use a better / different exception or encapsulate HRAC derivation with KFrag population.
            raise RuntimeError('Cannot add KFrag to TreasureMap without an HRAC set.  Call "derive_hrac" and try again.')

        # Encrypt this kfrag payload for Ursula.
        kfrag_payload = self._make_kfrag_payload(kfrag=kfrag, alice_stamp=alice_stamp)
        encrypted_kfrag, _signature = encrypt_and_sign(recipient_pubkey_enc=ursula.public_keys(DecryptingPower),
                                                       plaintext=kfrag_payload,
                                                       signer=alice_stamp)

        # Set the encrypted kfrag payload into the map.
        self.destinations[ursula.checksum_address] = encrypted_kfrag

    def public_id(self) -> str:
        """
        We need an ID that Bob can glean from knowledge he already has *and* which Ursula can verify came from Alice.
        Ursula will refuse to propagate this if it she can't prove the payload is signed by Alice's public key,
        which is included in it,
        """
        return self._id

    def public_verify(self) -> bool:
        message = bytes(self._verifying_key) + self._hrac
        verified = self._public_signature.verify(message, self._verifying_key)
        if verified:
            return True
        else:
            raise self.InvalidSignature("This TreasureMap is not properly publicly signed by Alice.")

    def orient(self, compass: Callable):
        """
        When Bob receives the TreasureMap, he'll pass a compass (a callable which can verify and decrypt the
        payload message kit).
        """
        try:
            map_in_the_clear = compass(message_kit=self.message_kit)
        except Character.InvalidSignature:
            raise self.InvalidSignature("This TreasureMap does not contain the correct signature from Alice to Bob.")
        self._m = map_in_the_clear[0]
        try:
            ursula_and_kfrags = self.ursula_and_kfrag_payload_splitter.repeat(map_in_the_clear[1:])
        except BytestringSplittingError:
            raise self.IsDisorienting('Invalid treasure map contents.')
        self._destinations = {u: k for u, k in ursula_and_kfrags}
        self.check_for_sufficient_destinations()  # TODO: Remove this check, how is this even possible?

    def check_for_sufficient_destinations(self):
        if len(self._destinations) < self._m or self._m == 0:
            raise self.IsDisorienting(
                f"TreasureMap lists only {len(self._destinations)} destination, "
                f"but requires interaction with {self._m} nodes.")

    @classmethod
    def author(cls,
               alice: 'Alice',
               bob: 'Bob',
               label: bytes,
               ursulas: Sequence['Ursula'],
               kfrags: Sequence[KFrag],
               m: int
               ) -> 'TreasureMap':
        """Create a new treasure map for a collection of ursulas and kfrags."""

        # The HRAC is needed to produce kfrag writs.
        treasure_map = cls(m=m)
        treasure_map.derive_hrac(alice_stamp=alice.stamp,
                                 bob_verifying_key=bob.public_keys(SigningPower),
                                 label=label)

        # Encrypt each kfrag for an Ursula.
        for ursula, kfrag in zip(ursulas, kfrags):
            treasure_map.add_kfrag(ursula=ursula,
                                   kfrag=kfrag,
                                   alice_stamp=alice.stamp)

        # Sign the map if needed before sending it out into the world.
        treasure_map.prepare_for_publication(bob_encrypting_key=bob.public_keys(DecryptingPower),
                                             alice_stamp=alice.stamp)

        return treasure_map


class SignedTreasureMap(TreasureMap):

    def __init__(self, blockchain_signature=NOT_SIGNED, *args, **kwargs):
        self._blockchain_signature = blockchain_signature
        super().__init__(*args, **kwargs)

    @classmethod
    def splitter(cls):
        return BytestringKwargifier(cls,
                                    version=(bytes, len(cls._PREFIX)),
                                    public_signature=Signature,
                                    hrac=(bytes, HRAC_LENGTH),
                                    message_kit=(UmbralMessageKit, VariableLengthBytestring),
                                    blockchain_signature=65)

    def include_blockchain_signature(self, blockchain_signer):
        self._blockchain_signature = blockchain_signer(super().__bytes__())

    def verify_blockchain_signature(self, checksum_address):
        self._set_payload()
        return verify_eip_191(message=self._payload,
                              signature=self._blockchain_signature,
                              address=checksum_address)

    def __bytes__(self):
        if self._blockchain_signature is NOT_SIGNED:
            raise self.InvalidSignature(
                "Can't cast a SignedTreasureMap to bytes until it has a blockchain signature "
                "(otherwise, is it really a 'SignedTreasureMap'?")
        return super().__bytes__() + self._blockchain_signature
