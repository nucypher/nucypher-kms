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


from cryptography.hazmat.primitives import hashes

HRAC_LENGTH = 16

# Digest Lengths
KECCAK_DIGEST_LENGTH = 32
BLAKE2B_DIGEST_LENGTH = 64

# Hashes
SHA256 = hashes.SHA256()
BLAKE2B = hashes.BLAKE2b(64)

# SECP256K1
# TODO: Umbral should expose these
CAPSULE_LENGTH = 98
PUBLIC_KEY_LENGTH = 33
CAPSULE_FRAG_LENGTH = 359
