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
from cryptography.exceptions import InvalidSignature

from nucypher.crypto import constants
from nucypher.characters.lawful import Enrico

"""
What follows are various combinations of signing and encrypting, to match
real-world scenarios.
"""


def test_sign_cleartext_and_encrypt(federated_alice, federated_bob):
    """
    Exhibit One: federated_alice signs the cleartext and encrypts her signature inside
    the ciphertext.
    """
    message = b"Have you accepted my answer on StackOverflow yet?"

    message_kit, _signature = federated_alice.encrypt_for(federated_bob, message,
                                                          sign_plaintext=True)

    # Notice that our function still returns the signature here, in case federated_alice
    # wants to do something else with it, such as post it publicly for later
    # public verifiability.

    # However, we can expressly refrain from passing the Signature, and the
    # verification still works:
    cleartext = federated_bob.verify_from(federated_alice, message_kit, signature=None,
                                          decrypt=True)
    assert cleartext == message


def test_encrypt_and_sign_the_ciphertext(federated_alice, federated_bob):
    """
    Now, federated_alice encrypts first and then signs the ciphertext, providing a
    Signature that is completely separate from the message.
    This is useful in a scenario in which federated_bob needs to prove authenticity
    publicly without disclosing contents.
    """
    message = b"We have a reaaall problem."
    message_kit, signature = federated_alice.encrypt_for(federated_bob, message,
                                                         sign_plaintext=False)
    cleartext = federated_bob.verify_from(federated_alice, message_kit, signature, decrypt=True)
    assert cleartext == message


def test_encrypt_and_sign_including_signature_in_both_places(federated_alice, federated_bob):
    """
    Same as above, but showing that we can include the signature in both
    the plaintext (to be found upon decryption) and also passed into
    verify_from() (eg, gleaned over a side-channel).
    """
    message = b"We have a reaaall problem."
    message_kit, signature = federated_alice.encrypt_for(federated_bob, message,
                                                         sign_plaintext=True)
    cleartext = federated_bob.verify_from(federated_alice, message_kit, signature,
                                          decrypt=True)
    assert cleartext == message


def test_encrypt_but_do_not_sign(federated_alice, federated_bob):
    """
    Finally, federated_alice encrypts but declines to sign.
    This is useful in a scenario in which federated_alice wishes to plausibly disavow
    having created this content.
    """
    # TODO: How do we accurately demonstrate this test safely, if at all?
    message = b"If Bonnie comes home and finds an unencrypted private key in her keystore, I'm gonna get divorced."

    # Alice might also want to encrypt a message but *not* sign it, in order
    # to refrain from creating evidence that can prove she was the
    # original sender.
    message_kit, not_signature = federated_alice.encrypt_for(federated_bob, message, sign=False)

    # The message is not signed...
    assert not_signature == constants.NOT_SIGNED

    # ...and thus, the message is not verified.
    with pytest.raises(InvalidSignature):
        federated_bob.verify_from(federated_alice, message_kit, decrypt=True)


def test_alice_can_decrypt(federated_alice):
    label = b"boring test label"

    policy_pubkey = federated_alice.get_policy_encrypting_key_from_label(label)

    enrico = Enrico(policy_encrypting_key=policy_pubkey)

    message = b"boring test message"
    message_kit, signature = enrico.encrypt_message(plaintext=message)

    # Interesting thing: if Alice wants to decrypt, she needs to provide the label directly.
    cleartext = federated_alice.verify_from(stranger=enrico,
                                            message_kit=message_kit,
                                            signature=signature,
                                            decrypt=True,
                                            label=label)
    assert cleartext == message
