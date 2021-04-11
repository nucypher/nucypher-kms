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

from marshmallow import fields
from nucypher.crypto.umbral_adapter import UmbralPublicKey

from nucypher.characters.control.specifications.exceptions import InvalidInputData, InvalidNativeDataTypes
from nucypher.characters.control.specifications.fields.base import BaseField


class Key(BaseField, fields.Field):

    def _serialize(self, value, attr, obj, **kwargs):
        return bytes(value).hex()

    def _deserialize(self, value, attr, data, **kwargs):
        if isinstance(value, bytes):
            return value
        try:
            return bytes.fromhex(value)
        except InvalidNativeDataTypes as e:
            raise InvalidInputData(f"Could not convert input for {self.name} to an Umbral Key: {e}")

    def _validate(self, value):
        try:
            UmbralPublicKey.from_bytes(value)
        except InvalidNativeDataTypes as e:
            raise InvalidInputData(f"Could not convert input for {self.name} to an Umbral Key: {e}")
