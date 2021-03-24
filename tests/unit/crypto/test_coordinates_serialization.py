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
from nucypher.crypto.umbral_adapter import UmbralPrivateKey

from nucypher.crypto.signing import SignatureStamp
from nucypher.crypto.utils import get_coordinates_as_bytes


def test_coordinates_as_bytes():
    pubkey = UmbralPrivateKey.gen_key().pubkey
    point = pubkey.point_key
    stamp = SignatureStamp(verifying_key=pubkey)

    x, y = point.to_affine()
    x = x.to_bytes(32, 'big')
    y = y.to_bytes(32, 'big')

    for p in (point, pubkey, stamp):
        assert get_coordinates_as_bytes(p) == x + y
        assert get_coordinates_as_bytes(p, x_coord=False) == y
        assert get_coordinates_as_bytes(p, y_coord=False) == x
        with pytest.raises(ValueError):
            _ = get_coordinates_as_bytes(p, x_coord=False, y_coord=False)
