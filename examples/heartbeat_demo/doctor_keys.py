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

import json
import os
from nucypher.crypto.umbral_adapter import UmbralPrivateKey, UmbralPublicKey

DOCTOR_PUBLIC_JSON = 'doctor.public.json'
DOCTOR_PRIVATE_JSON = 'doctor.private.json'


def generate_doctor_keys():
    enc_privkey = UmbralPrivateKey.gen_key()
    sig_privkey = UmbralPrivateKey.gen_key()

    doctor_privkeys = {
        'enc': enc_privkey.to_bytes().hex(),
        'sig': sig_privkey.to_bytes().hex(),
    }

    with open(DOCTOR_PRIVATE_JSON, 'w') as f:
        json.dump(doctor_privkeys, f)

    enc_pubkey = enc_privkey.get_pubkey()
    sig_pubkey = sig_privkey.get_pubkey()
    doctor_pubkeys = {
        'enc': enc_pubkey.to_bytes().hex(),
        'sig': sig_pubkey.to_bytes().hex()
    }
    with open(DOCTOR_PUBLIC_JSON, 'w') as f:
        json.dump(doctor_pubkeys, f)


def _get_keys(file, key_class):
    if not os.path.isfile(file):
        generate_doctor_keys()

    with open(file) as f:
        stored_keys = json.load(f)
    keys = dict()
    for key_type, key_str in stored_keys.items():
        keys[key_type] = key_class.from_bytes(bytes.fromhex(key_str))
    return keys


def get_doctor_pubkeys():
    return _get_keys(DOCTOR_PUBLIC_JSON, UmbralPublicKey)


def get_doctor_privkeys():
    return _get_keys(DOCTOR_PRIVATE_JSON, UmbralPrivateKey)
