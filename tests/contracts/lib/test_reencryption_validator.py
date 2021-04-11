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
from eth_tester.exceptions import TransactionFailed
from nucypher.crypto.umbral_adapter import Signer, CurveBN, UmbralPrivateKey, Point, hash_to_curvebn

from nucypher.crypto.signing import SignatureStamp


@pytest.fixture(scope='module')
def reencryption_validator(testerchain, deploy_contract):
    contract, _ = deploy_contract('ReEncryptionValidatorMock')
    return contract


def test_extended_keccak_to_bn(testerchain, reencryption_validator):
    test_data = os.urandom(40)
    h = hash_to_curvebn(test_data, params=default_params(), hash_class=ExtendedKeccak)
    assert int(h) == reencryption_validator.functions.extendedKeccakToBN(test_data).call()


def test_ec_point_operations(testerchain, reencryption_validator):
    valid_point = Point.gen_rand()
    x, y = valid_point.to_affine()

    # Test isOnCurve
    assert reencryption_validator.functions.isOnCurve(x, y).call()

    bad_y = y - 1
    assert not reencryption_validator.functions.isOnCurve(x, bad_y).call()

    # Test checkCompressedPoint
    sign = 2 + (y % 2)
    assert reencryption_validator.functions.checkCompressedPoint(sign, x, y).call()

    bad_sign = 3 - (y % 2)
    assert not reencryption_validator.functions.checkCompressedPoint(bad_sign, x, y).call()

    # Test checkSerializedCoordinates
    coords = valid_point.to_bytes(is_compressed=False)[1:]
    assert reencryption_validator.functions.checkSerializedCoordinates(coords).call()

    coords = coords[:-1] + ((coords[-1] + 42) % 256).to_bytes(1, 'big')
    assert not reencryption_validator.functions.checkSerializedCoordinates(coords).call()

    # Test ecmulVerify
    P = valid_point
    scalar = CurveBN.gen_rand()
    Q = scalar * P
    qx, qy = Q.to_affine()

    assert reencryption_validator.functions.ecmulVerify(x, y, int(scalar), qx, qy).call()
    assert not reencryption_validator.functions.ecmulVerify(x, y, int(scalar), x, y).call()

    # Test eqAffineJacobian
    Q_affine = [qx, qy]
    Q_jacobian = [qx, qy, 1]
    assert reencryption_validator.functions.eqAffineJacobian(Q_affine, Q_jacobian).call()

    P_jacobian = [x, y, 1]
    assert not reencryption_validator.functions.eqAffineJacobian(Q_affine, P_jacobian).call()

    point_at_infinity = [x, y, 0]
    random_point = Point.gen_rand()
    assert not reencryption_validator.functions.eqAffineJacobian(random_point.to_affine(), point_at_infinity).call()

    # Test doubleJacobian
    doubleP = reencryption_validator.functions.doubleJacobian(P_jacobian).call()
    assert reencryption_validator.functions.eqAffineJacobian((P + P).to_affine(), doubleP).call()

    # Test addAffineJacobian
    scalar1 = CurveBN.gen_rand()
    scalar2 = CurveBN.gen_rand()
    R1 = scalar1 * P
    R2 = scalar2 * P

    assert R1 + R2 == (scalar1 + scalar2) * P
    R = reencryption_validator.functions.addAffineJacobian(R1.to_affine(), R2.to_affine()).call()
    assert reencryption_validator.functions.eqAffineJacobian((R1 + R2).to_affine(), R).call()

    P_plus_P = reencryption_validator.functions.addAffineJacobian(P.to_affine(), P.to_affine()).call()
    assert reencryption_validator.functions.eqAffineJacobian((P + P).to_affine(), P_plus_P).call()


def test_umbral_constants(testerchain, reencryption_validator):
    umbral_params = default_params()
    u_xcoord, u_ycoord = umbral_params.u.to_affine()
    u_sign = 2 + (u_ycoord % 2)
    assert u_sign == reencryption_validator.functions.UMBRAL_PARAMETER_U_SIGN().call()
    assert u_xcoord == reencryption_validator.functions.UMBRAL_PARAMETER_U_XCOORD().call()
    assert u_ycoord == reencryption_validator.functions.UMBRAL_PARAMETER_U_YCOORD().call()

    secp256k1_field_order = 2**256 - 0x1000003D1
    assert secp256k1_field_order == reencryption_validator.functions.FIELD_ORDER().call()
    assert secp256k1_field_order - 2 == reencryption_validator.functions.MINUS_2().call()
    assert (secp256k1_field_order - 1) // 2 == reencryption_validator.functions.MINUS_ONE_HALF().call()


def test_compute_proof_challenge_scalar(testerchain, reencryption_validator, mock_ursula_reencrypts, mocker):
    ursula_privkey = UmbralPrivateKey.gen_key()
    ursula_stamp = SignatureStamp(verifying_key=ursula_privkey.pubkey,
                                  signer=Signer(ursula_privkey))
    ursula = mocker.Mock(stamp=ursula_stamp, decentralized_identity_evidence=b'')

    # Bob prepares supporting Evidence
    evidence = mock_ursula_reencrypts(ursula)
    capsule = evidence.task.capsule
    cfrag = evidence.task.cfrag
    capsule_bytes = capsule.to_bytes()
    cfrag_bytes = cfrag.to_bytes()
    proof_challenge_scalar = int(evidence.get_proof_challenge_scalar())
    computeProofChallengeScalar = reencryption_validator.functions.computeProofChallengeScalar
    assert proof_challenge_scalar == computeProofChallengeScalar(capsule_bytes, cfrag_bytes).call()


def test_validate_cfrag(testerchain, reencryption_validator, mock_ursula_reencrypts, mocker):
    ursula_privkey = UmbralPrivateKey.gen_key()
    ursula_stamp = SignatureStamp(verifying_key=ursula_privkey.pubkey,
                                  signer=Signer(ursula_privkey))
    ursula = mocker.Mock(stamp=ursula_stamp, decentralized_identity_evidence=b'')

    ###############################
    # Test: Ursula produces correct proof:
    ###############################

    # Bob prepares supporting Evidence
    evidence = mock_ursula_reencrypts(ursula)
    evidence_data = evidence.precompute_values()
    assert len(evidence_data) == 20 * 32 + 32 + 20 + 5

    # Challenge using good data
    capsule = evidence.task.capsule
    cfrag = evidence.task.cfrag
    capsule_bytes = capsule.to_bytes()
    cfrag_bytes = cfrag.to_bytes()
    args = (capsule_bytes, cfrag_bytes, evidence_data)
    assert reencryption_validator.functions.validateCFrag(*args).call()

    ###############################
    # Test: Ursula produces incorrect proof:
    ###############################
    evidence = mock_ursula_reencrypts(ursula, corrupt_cfrag=True)
    capsule = evidence.task.capsule
    cfrag = evidence.task.cfrag
    capsule_bytes = capsule.to_bytes()
    cfrag_bytes = cfrag.to_bytes()
    assert not cfrag.verify_correctness(capsule)

    evidence_data = evidence.precompute_values()
    args = (capsule_bytes, cfrag_bytes, evidence_data)
    assert not reencryption_validator.functions.validateCFrag(*args).call()

    ###############################
    # Test: Bob produces wrong precomputed data
    ###############################
    evidence = mock_ursula_reencrypts(ursula)
    capsule = evidence.task.capsule
    cfrag = evidence.task.cfrag
    capsule_bytes = capsule.to_bytes()
    cfrag_bytes = cfrag.to_bytes()
    assert cfrag.verify_correctness(capsule)

    evidence_data = evidence.precompute_values()

    # Bob produces a random point and gets the bytes of coords x and y
    random_point_bytes = Point.gen_rand().to_bytes(is_compressed=False)[1:]
    # He uses this garbage instead of correct precomputation of z*E
    evidence_data = bytearray(evidence_data)
    evidence_data[32:32 + 64] = random_point_bytes
    evidence_data = bytes(evidence_data)

    args = (capsule_bytes, cfrag_bytes, evidence_data)

    # Evaluation must fail since Bob precomputed wrong values
    with pytest.raises(TransactionFailed):
        _ = reencryption_validator.functions.validateCFrag(*args).call()
