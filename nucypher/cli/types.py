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

import click
from cryptography.exceptions import InternalError
from decimal import Decimal, DecimalException
from eth_utils import to_checksum_address
from ipaddress import ip_address
from nucypher.crypto.umbral_adapter import UmbralPublicKey

from nucypher.blockchain.economics import StandardTokenEconomics
from nucypher.blockchain.eth.interfaces import BlockchainInterface
from nucypher.blockchain.eth.networks import NetworksInventory
from nucypher.blockchain.eth.token import NU
from nucypher.utilities.networking import validate_worker_ip, InvalidWorkerIP


class ChecksumAddress(click.ParamType):
    name = 'checksum_address'

    def convert(self, value, param, ctx):
        try:
            value = to_checksum_address(value=value)
        except ValueError as e:
            self.fail("Invalid ethereum address")
        else:
            return value


class IPv4Address(click.ParamType):
    name = 'ipv4_address'

    def convert(self, value, param, ctx):
        try:
            _address = ip_address(value)
        except ValueError:
            self.fail("Invalid IP Address")
        else:
            return value


class WorkerIPAddress(IPv4Address):
    name = 'worker_ip'

    def convert(self, value, param, ctx):
        _ip = super().convert(value, param, ctx)
        try:
            validate_worker_ip(worker_ip=_ip)
        except InvalidWorkerIP as e:
            self.fail(str(e))
        return value


class DecimalType(click.ParamType):
    name = 'decimal'

    def convert(self, value, param, ctx):
        try:
            return Decimal(value)
        except DecimalException:
            self.fail(f"'{value}' is an invalid decimal number")


class DecimalRange(DecimalType):
    name = 'decimal_range'

    def __init__(self, min=None, max=None, clamp=False):
        self.min = min
        self.max = max
        self.clamp = clamp

    def convert(self, value, param, ctx):
        rv = DecimalType.convert(self, value, param, ctx)
        if self.clamp:
            if self.min is not None and rv < self.min:
                return self.min
            if self.max is not None and rv > self.max:
                return self.max
        if self.min is not None and rv < self.min or \
           self.max is not None and rv > self.max:
            if self.min is None:
                self.fail(f'{rv} is bigger than the maximum valid value {self.max}')
            elif self.max is None:
                self.fail(f'{rv} is smaller than the minimum valid value {self.min}')
            else:
                self.fail(f'{rv} is not in the valid range of {self.min} to {self.max}')
        return rv


class NuCypherNetworkName(click.ParamType):
    name = 'nucypher_network_name'

    def __init__(self, validate: bool = True):
        self.validate = bool(validate)

    def convert(self, value, param, ctx):
        if self.validate:
            network = str(value).lower()
            if network not in NetworksInventory.NETWORKS:
                self.fail(f"'{value}' is not a NuCypher Network. Valid options are: {list(NetworksInventory.NETWORKS)}")
            else:
                return network
        else:
            return value


class UmbralPublicKeyHex(click.ParamType):
    name = 'nucypher_umbral_public_key'

    def __init__(self, validate: bool = True):
        self.validate = bool(validate)

    def convert(self, value, param, ctx):
        if self.validate:
            try:
                _key = UmbralPublicKey.from_hex(value)
            except (InternalError, ValueError):
                self.fail(f"'{value}' is not a valid nucypher public key.")
        return value


# Ethereum
EIP55_CHECKSUM_ADDRESS = ChecksumAddress()
WEI = click.IntRange(min=1, clamp=False)  # TODO: Better validation for ether and wei values?
GWEI = DecimalRange(min=0)

__min_allowed_locked = NU.from_nunits(StandardTokenEconomics._default_minimum_allowed_locked).to_tokens()
MIN_ALLOWED_LOCKED_TOKENS = Decimal(__min_allowed_locked)
STAKED_TOKENS_RANGE = DecimalRange(min=__min_allowed_locked)

# Filesystem
EXISTING_WRITABLE_DIRECTORY = click.Path(exists=True, dir_okay=True, file_okay=False, writable=True)
EXISTING_READABLE_FILE = click.Path(exists=True, dir_okay=False, file_okay=True, readable=True)

# Network
NETWORK_PORT = click.IntRange(min=0, max=65535, clamp=False)
IPV4_ADDRESS = IPv4Address()
WORKER_IP = WorkerIPAddress()

GAS_STRATEGY_CHOICES = click.Choice(list(BlockchainInterface.GAS_STRATEGIES.keys()))
UMBRAL_PUBLIC_KEY_HEX = UmbralPublicKeyHex()
