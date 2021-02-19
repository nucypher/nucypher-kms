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
from constant_sorrow import constants

from cryptography.exceptions import InvalidSignature

from nucypher.characters.lawful import Alice, Bob, Character
from nucypher.crypto import api
from nucypher.crypto.powers import (CryptoPower, NoSigningPower, SigningPower)
from nucypher.crypto.constants import NOT_SIGNED
"""
Chapter 1: SIGNING
"""
def test_actor_without_signing_power_cannot_sign():
    """
    We can create a Character with no real CryptoPower to speak of.
    This Character can't even sign a message.
    """
    cannot_sign = CryptoPower(power_ups=[])
    non_signer = Character(crypto_power=cannot_sign,
                           start_learning_now=False,
                           federated_only=True)

    # The non-signer's stamp doesn't work for signing...
    with pytest.raises(NoSigningPower):
        non_signer.stamp("something")

    # ...or as a way to cast the (non-existent) public key to bytes.
    with pytest.raises(NoSigningPower):
        bytes(non_signer.stamp)


def test_actor_with_signing_power_can_sign():
    """
    However, simply giving that character a PowerUp bestows the power to sign.

    Instead of having a Character verify the signature, we'll use the lower level API.
    """
    message = b"Llamas."

    signer = Character(crypto_power_ups=[SigningPower], is_me=True,
                       start_learning_now=False, federated_only=True)
    stamp_of_the_signer = signer.stamp

    # We can use the signer's stamp to sign a message (since the signer is_me)...
    signature = stamp_of_the_signer(message)

    # ...or to get the signer's public key for verification purposes.
    # (note: we use the private _der_encoded_bytes here to test directly against the API, instead of Character)
    verification = api.verify_ecdsa(message, signature._der_encoded_bytes(),
                                    stamp_of_the_signer.as_umbral_pubkey())

    assert verification is True


def test_anybody_can_verify():
    """
    In the last example, we used the lower-level Crypto API to verify the signature.

    Here, we show that anybody can do it without needing to directly access Crypto.
    """
    # Alice can sign by default, by dint of her _default_crypto_powerups.
    alice = Alice(federated_only=True, start_learning_now=False)

    # So, our story is fairly simple: an everyman meets Alice.
    somebody = Character(start_learning_now=False, federated_only=True)

    # Alice signs a message.
    message = b"A message for all my friends who can only verify and not sign."
    signature = alice.stamp(message)

    # Our everyman can verify it.
    cleartext = somebody.verify_from(alice, message, signature, decrypt=False)
    assert cleartext is constants.NO_DECRYPTION_PERFORMED

    # Of course, verification fails with any fake message
    with pytest.raises(InvalidSignature):
        fake = b"McLovin      892 Momona St.  Honolulu, HI 96820"
        _ = somebody.verify_from(alice, fake, signature, decrypt=False)

    # Signature verification also works when Alice is not living with our
    # everyman in the same process, and he only knows her by her public key
    alice_pubkey_bytes = bytes(alice.stamp)
    hearsay_alice = Character.from_public_keys({SigningPower: alice_pubkey_bytes})

    cleartext = somebody.verify_from(hearsay_alice, message, signature, decrypt=False)
    assert cleartext is constants.NO_DECRYPTION_PERFORMED

    hearsay_alice = Character.from_public_keys(verifying_key=alice_pubkey_bytes)

    cleartext = somebody.verify_from(hearsay_alice, message, signature, decrypt=False)
    assert cleartext is constants.NO_DECRYPTION_PERFORMED
    alice.disenchant()


"""
Chapter 2: ENCRYPTION
"""


def test_anybody_can_encrypt():
    """
    Similar to anybody_can_verify() above; we show that anybody can encrypt.
    """
    someone = Character(start_learning_now=False, federated_only=True)
    bob = Bob(is_me=False, federated_only=True)

    cleartext = b"This is Officer Rod Farva. Come in, Ursula!  Come in Ursula!"

    ciphertext, signature = someone.encrypt_for(bob, cleartext, sign=False)

    assert signature == NOT_SIGNED
    assert ciphertext is not None
