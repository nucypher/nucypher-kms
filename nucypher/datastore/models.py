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
from maya import MayaDT
from nucypher.crypto.umbral_adapter import UmbralPublicKey, KFrag

from nucypher.crypto.signing import Signature
from nucypher.datastore.base import DatastoreRecord, RecordField


class PolicyArrangement(DatastoreRecord):
    _arrangement_id = RecordField(bytes)
    _expiration = RecordField(
            MayaDT,
            encode=lambda maya_date: maya_date.iso8601().encode(),
            decode=lambda maya_bytes: MayaDT.from_iso8601(maya_bytes.decode()))
    _kfrag = RecordField(
            KFrag,
            encode=lambda kfrag: kfrag.to_bytes(),
            decode=KFrag.from_bytes)
    _alice_verifying_key = RecordField(
            UmbralPublicKey,
            encode=bytes,
            decode=UmbralPublicKey.from_bytes)


class Workorder(DatastoreRecord):
    _arrangement_id = RecordField(bytes)
    _bob_verifying_key = RecordField(
            UmbralPublicKey,
            encode=bytes,
            decode=UmbralPublicKey.from_bytes)
    _bob_signature = RecordField(
            Signature,
            encode=bytes,
            decode=Signature.from_bytes)


class TreasureMap(DatastoreRecord):
    # Ideally this is a `policy.collections.TreasureMap`, but it causes a huge
    # circular import due to `Bob` and `Character` in `policy.collections`.
    # TODO #2126
    _treasure_map = RecordField(bytes)
    _expiration = RecordField(
            MayaDT,
            encode=lambda maya_date: maya_date.iso8601().encode(),
            decode=lambda maya_bytes: MayaDT.from_iso8601(maya_bytes.decode()))
