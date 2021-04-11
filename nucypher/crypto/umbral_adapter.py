import umbral
from umbral.curve_point import CurvePoint as Point
from umbral.curve_scalar import CurveScalar as CurveBN

from nucypher.crypto.passwords import derive_key_from_password, SecretBox


SIGNATURE_DST = b'SIGNATURE'


def hash_to_curvebn():
    raise NotImplementedError


class Signer:

    def __init__(self, private_key):
        assert isinstance(private_key, umbral.SecretKey)
        self._sk = private_key

    def __call__(self, message):
        # TODO: to migrate to PyUmbral?
        from umbral.hashing import Hash
        digest = Hash(SIGNATURE_DST)
        digest.update(message)
        return Signature.from_bytes(bytes(self._sk.sign_digest(digest)))


class CryptographyPrivkey:

    def __init__(self, secret_key):
        self._secret_key = secret_key

    def sign(self, message, ecdsa):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
        assert isinstance(ecdsa.algorithm, hashes.SHA256)

        # NOTE: returns just r and s, not a DER format!
        # change `signature_der_bytes` at the usage locations accordingly if that stays.
        signer = Signer(self._secret_key)
        return bytes(signer(message))


class CryptographyPubkey:

    def __init__(self, public_key):
        assert isinstance(public_key, UmbralPublicKey)
        self._public_key = public_key

    def verify(self, signature, message, ecdsa):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
        assert isinstance(ecdsa.algorithm, hashes.SHA256)

        # NOTE: returns just r and s, not a DER format!
        # change `signature_der_bytes` at the usage locations accordingly if that stays.
        signature = Signature.from_bytes(signature)
        return signature.verify(message, self._public_key)


class AuthenticationFailed(Exception):
    pass


class UmbralPrivateKey(umbral.SecretKey):

    @classmethod
    def gen_key(cls):
        return cls.random()

    def get_pubkey(self):
        return UmbralPublicKey.from_secret_key(self)

    def to_bytes(self, wrapping_key=None):
        if wrapping_key is None:
            return bytes(self)
        else:
            return SecretBox(wrapping_key).encrypt(bytes(self))

    @classmethod
    def from_bytes(cls, key_bytes, wrapping_key=None):
        if wrapping_key is None:
            data = key_bytes
        else:
            try:
                data = SecretBox(wrapping_key).decrypt(key_bytes)
            except CryptoError:
                raise AuthenticationFailed()
        key = super().from_bytes(data)
        key.__class__ = cls
        return key

    @property
    def pubkey(self):
        return self.get_pubkey()

    def to_cryptography_privkey(self):
        return CryptographyPrivkey(self)

    def __eq__(self, other):
        if not isinstance(other, UmbralPrivateKey):
            return False
        return super().__eq__(other)


class UmbralPublicKey(umbral.PublicKey):

    @classmethod
    def expected_bytes_length(cls):
        return 33

    def to_bytes(self):
        return bytes(self)

    def to_cryptography_pubkey(self):
        return CryptographyPubkey(self)

    def hex(self):
        return bytes(self).hex()


class _UmbralKeyingMaterial(umbral.SecretKeyFactory):

    def to_bytes(self):
        return bytes(self)

    def derive_privkey_by_label(self, label):
        pk = self.secret_key_by_label(label)
        pk.__class__ = UmbralPrivateKey
        return pk


def UmbralKeyingMaterial():
    return _UmbralKeyingMaterial.random()


class Signature(umbral.keys.Signature):

    @classmethod
    def expected_bytes_length(cls):
        return 64 # two curve scalars

    @classmethod
    def from_bytes(cls, data, der_encoded=False):
        # NOTE: returns just r and s, not a DER format!
        # change `signature_der_bytes` at the usage locations accordingly if that stays.
        return super(Signature, cls).from_bytes(data)

    def verify(self, message, verifying_key, is_prehashed=False):
        assert not is_prehashed
        # TODO: to migrate to PyUmbral?
        from umbral.hashing import Hash
        digest = Hash(SIGNATURE_DST)
        digest.update(message)
        return self.verify_digest(verifying_key, digest)

    def __add__(self, other):
        return bytes(self) + bytes(other)


class KFrag(umbral.KeyFrag):

    def verify(self, signing_pubkey, delegating_pubkey=None, receiving_pubkey=None):
        return super().verify(
               signing_pk=signing_pubkey,
               delegating_pk=delegating_pubkey,
               receiving_pk=receiving_pubkey,
               )

    def to_bytes(self):
        return bytes(self)


class Capsule:

    def __init__(self, capsule):
        assert isinstance(capsule, umbral.Capsule)
        self._capsule = capsule

    def set_correctness_keys(self, delegating=None, receiving=None, verifying=None):
        assert delegating is None or isinstance(delegating, UmbralPublicKey)
        assert receiving is None or isinstance(receiving, UmbralPublicKey)
        assert verifying is None or isinstance(verifying, UmbralPublicKey)
        self._delegating_key = delegating
        self._receiving_key = receiving
        self._verifying_key = verifying

    def get_correctness_keys(self):
        return dict(delegating=self._delegating_key,
                    receiving=self._receiving_key,
                    verifying=self._verifying_key)

    def __bytes__(self):
        return bytes(self._capsule)

    def to_bytes(self):
        return bytes(self._capsule)

    @classmethod
    def from_bytes(cls, data):
        return cls(umbral.Capsule.from_bytes(data))

    def __eq__(self, other):
        return self._capsule == other._capsule

    def __hash__(self):
        return hash(self._capsule)


class CapsuleFrag(umbral.CapsuleFrag):

    def to_bytes(self):
        return bytes(self)


# Adapter for standalone functions
class PRE:

    @staticmethod
    def reencrypt(kfrag, capsule, metadata=None):
        assert isinstance(capsule, Capsule)
        cf = umbral.reencrypt(capsule._capsule, kfrag, metadata=metadata)
        cf.__class__ = CapsuleFrag
        return cf

    @staticmethod
    def encrypt(pubkey, message):
        capsule, ciphertext = umbral.encrypt(pubkey, message)
        return ciphertext, Capsule(capsule)

    @staticmethod
    def decrypt(ciphertext, capsule, decrypting_key):
        assert isinstance(capsule, Capsule)
        return umbral.decrypt_original(decrypting_key, capsule._capsule, ciphertext)

    @staticmethod
    def generate_kfrags(delegating_privkey,
                        receiving_pubkey,
                        threshold,
                        N,
                        signer,
                        sign_delegating_key=False,
                        sign_receiving_key=False,
                        ):
        if 'SignatureStamp' in str(type(signer)):
            sk = signer._SignatureStamp__signer._sk # TODO: gotta be a better way
        else:
            sk = signer._sk
        kfrags = umbral.generate_kfrags(
            delegating_sk=delegating_privkey,
            receiving_pk=receiving_pubkey,
            signing_sk=sk,
            threshold=threshold,
            num_kfrags=N,
            sign_delegating_key=sign_delegating_key,
            sign_receiving_key=sign_receiving_key)

        for kfrag in kfrags:
            kfrag.__class__ = KFrag
        return kfrags

    @staticmethod
    def _encapsulate(delegating_pubkey):
        capsule, key_seed = umbral.Capsule.from_public_key(delegating_pubkey)
        return bytes(key_seed), Capsule(capsule)


pre = PRE()
