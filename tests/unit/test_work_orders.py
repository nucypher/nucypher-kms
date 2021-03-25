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
import os

import pytest
from bytestring_splitter import VariableLengthBytestring
from eth_utils import to_canonical_address
from nucypher.crypto.umbral_adapter import UmbralPrivateKey, Signer

from nucypher.blockchain.eth.constants import ETH_HASH_BYTE_LENGTH, LENGTH_ECDSA_SIGNATURE_WITH_RECOVERY
from nucypher.crypto.signing import SignatureStamp, InvalidSignature
from nucypher.crypto.utils import canonical_address_from_umbral_key
from nucypher.policy.collections import WorkOrder
from nucypher.policy.policies import Arrangement


@pytest.fixture(scope="function")
def ursula(mocker):
    identity_evidence = os.urandom(LENGTH_ECDSA_SIGNATURE_WITH_RECOVERY)
    ursula_privkey = UmbralPrivateKey.gen_key()
    ursula_stamp = SignatureStamp(verifying_key=ursula_privkey.pubkey,
                                  signer=Signer(ursula_privkey))
    ursula = mocker.Mock(stamp=ursula_stamp, decentralized_identity_evidence=identity_evidence)
    ursula.mature = lambda: True
    ursula._stamp_has_valid_signature_by_worker = lambda: True
    return ursula


def test_pre_task(mock_ursula_reencrypts, ursula, get_random_checksum_address):
    identity_evidence = ursula.decentralized_identity_evidence
    evidence = mock_ursula_reencrypts(ursula)
    capsule = evidence.task.capsule
    capsule_bytes = capsule.to_bytes()

    signature = ursula.stamp(capsule_bytes)

    task = WorkOrder.PRETask(capsule=capsule, signature=signature)
    assert capsule == task.capsule
    assert signature == task.signature

    task_bytes = bytes(task)
    assert bytes(capsule) + bytes(signature) == task_bytes

    deserialized_task = WorkOrder.PRETask.from_bytes(task_bytes)
    assert capsule == deserialized_task.capsule
    assert signature == deserialized_task.signature

    # Attaching cfrags to the task
    cfrag = evidence.task.cfrag
    cfrag_bytes = bytes(cfrag.to_bytes())
    cfrag_signature = ursula.stamp(cfrag_bytes)

    task.attach_work_result(cfrag, cfrag_signature)
    assert capsule == task.capsule
    assert signature == task.signature
    assert cfrag == task.cfrag
    assert cfrag_signature == task.cfrag_signature

    task_bytes = bytes(task)
    assert bytes(capsule) + bytes(signature) + cfrag_bytes + bytes(cfrag_signature) == task_bytes

    deserialized_task = WorkOrder.PRETask.from_bytes(task_bytes)
    assert capsule == deserialized_task.capsule
    assert signature == deserialized_task.signature
    assert bytes(cfrag) == bytes(deserialized_task.cfrag)  # We compare bytes as there's no CapsuleFrag.__eq__
    assert cfrag_signature == deserialized_task.cfrag_signature

    # Task specification
    alice_address = to_canonical_address(get_random_checksum_address())
    blockhash = os.urandom(ETH_HASH_BYTE_LENGTH)

    specification = task.get_specification(bytes(ursula.stamp), alice_address, blockhash, identity_evidence)

    expected_specification = bytes(capsule) + bytes(ursula.stamp) + identity_evidence + alice_address + blockhash
    assert expected_specification == specification

    with pytest.raises(ValueError, match=f"blockhash must be of length {ETH_HASH_BYTE_LENGTH}"):
        task.get_specification(bytes(ursula.stamp), alice_address, os.urandom(42), identity_evidence)


@pytest.mark.parametrize('number', (1, 5, 10))
def test_work_order_with_multiple_capsules(mock_ursula_reencrypts,
                                           ursula,
                                           get_random_checksum_address,
                                           federated_bob,
                                           federated_alice,
                                           number):

    tasks = [mock_ursula_reencrypts(ursula).task for _ in range(number)]
    material = [(task.capsule, task.signature, task.cfrag, task.cfrag_signature) for task in tasks]
    capsules, signatures, cfrags, cfrag_signatures = zip(*material)

    arrangement_id = os.urandom(Arrangement.ID_LENGTH)
    alice_address = canonical_address_from_umbral_key(federated_alice.stamp)
    blockhash = b'\0' * ETH_HASH_BYTE_LENGTH  # TODO: Prove freshness of work order - #259
    identity_evidence = ursula.decentralized_identity_evidence

    # Test construction of WorkOrders by Bob
    work_order = WorkOrder.construct_by_bob(arrangement_id=arrangement_id,
                                            bob=federated_bob,
                                            alice_verifying=federated_alice.stamp.as_umbral_pubkey(),
                                            ursula=ursula,
                                            capsules=capsules)

    receipt_input = WorkOrder.HEADER + bytes(ursula.stamp) + b''.join(map(bytes, capsules))
    bob_verifying_pubkey = federated_bob.stamp.as_umbral_pubkey()

    assert work_order.bob == federated_bob
    assert work_order.arrangement_id == arrangement_id
    assert work_order.alice_address == alice_address
    assert len(work_order.tasks) == len(work_order) == number
    for capsule in capsules:
        assert work_order.tasks[capsule].capsule == capsule
        task = WorkOrder.PRETask(capsule, signature=None)
        specification = task.get_specification(ursula.stamp, alice_address, blockhash, identity_evidence)
        assert work_order.tasks[capsule].signature.verify(specification, bob_verifying_pubkey)
    assert work_order.receipt_signature.verify(receipt_input, bob_verifying_pubkey)
    assert work_order.ursula == ursula
    assert work_order.blockhash == blockhash
    assert not work_order.completed

    # Test WorkOrders' payload serialization and deserialization
    tasks_bytes = b''.join(map(bytes, work_order.tasks.values()))
    expected_payload = bytes(work_order.receipt_signature) + bytes(federated_bob.stamp) + blockhash + tasks_bytes

    payload = work_order.payload()
    assert expected_payload == payload

    same_work_order = WorkOrder.from_rest_payload(arrangement_id=arrangement_id,
                                                  rest_payload=payload,
                                                  ursula=ursula,
                                                  alice_address=alice_address)

    assert same_work_order.bob == federated_bob
    assert same_work_order.arrangement_id == arrangement_id
    assert same_work_order.alice_address == alice_address
    assert len(same_work_order.tasks) == len(same_work_order) == number
    for capsule in capsules:
        assert same_work_order.tasks[capsule].capsule == capsule
        assert same_work_order.tasks[capsule].signature == work_order.tasks[capsule].signature
    assert same_work_order.receipt_signature == work_order.receipt_signature
    assert same_work_order.ursula == ursula
    assert same_work_order.blockhash == blockhash
    assert not same_work_order.completed

    tampered_payload = bytearray(payload)
    somewhere_over_the_blockhash = 64+33+5
    tampered_payload[somewhere_over_the_blockhash] = 255 - payload[somewhere_over_the_blockhash]
    with pytest.raises(InvalidSignature):
        _ = WorkOrder.from_rest_payload(arrangement_id=arrangement_id,
                                        rest_payload=bytes(tampered_payload),
                                        ursula=ursula,
                                        alice_address=alice_address)

    # Testing WorkOrder.complete()

    # Let's use the original task signatures in our WorkOrder, instead
    for capsule, task_signature in zip(capsules, signatures):
        work_order.tasks[capsule].signature = task_signature

    # Now, complete() works as intended
    good_cfrags = work_order.complete(list(zip(cfrags, cfrag_signatures)))
    assert work_order.completed
    assert len(good_cfrags) == number

    # Testing some additional expected exceptions
    with pytest.raises(ValueError, match="Ursula gave back the wrong number of cfrags"):
        work_order.complete(list(zip(cfrags, cfrag_signatures))[1:])

    bad_cfrag_signature = ursula.stamp(os.urandom(10))
    with pytest.raises(InvalidSignature, match=f"{cfrags[0]} is not properly signed by Ursula."):
        work_order.complete(list(zip(cfrags, [bad_cfrag_signature] + list(cfrag_signatures[1:]))))
