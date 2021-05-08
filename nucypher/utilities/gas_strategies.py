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
import datetime
import statistics
from typing import Callable, Optional

from web3 import Web3
from web3.exceptions import ValidationError
from web3.gas_strategies import time_based
from web3.gas_strategies.rpc import rpc_gas_price_strategy
from web3.types import Wei, TxParams

from nucypher.utilities.datafeeds import (
    Datafeed,
    EtherchainGasPriceDatafeed,
    UpvestGasPriceDatafeed,
    ZoltuGasPriceDatafeed
)


class GasStrategyError(RuntimeError):
    """
    Generic exception when retrieving a gas price using a gas strategy
    """


#
# Max Price Gas Strategy Wrapper
#

def max_price_gas_strategy_wrapper(gas_strategy: Callable, max_gas_price_wei: int) -> Callable:
    """
    Puts a cap on the prices resulting from a given gas strategy.
    """

    def _wrapper(*args, **kwargs):
        gas_price = gas_strategy(*args, **kwargs)
        if gas_price > max_gas_price_wei:
            gas_price = max_gas_price_wei
        return gas_price

    return _wrapper


#
# Linear Scaling Gas Price Strategy Wrapper
#

def linear_scaling_gas_strategy_wrapper(gas_strategy: Callable, gas_price_factor: float) -> Callable:
    """
    Linearly scales gas price from a given gas strategy for replacement transactions.
    """

    def _wrapper(web3, transaction_params):
        gas_price = gas_strategy(web3, transaction_params)
        if transaction_params.get('_is_replacement_tx', False):
            gas_price = round(gas_price * gas_price_factor)
        return gas_price

    return _wrapper

#
# Datafeed gas strategies
#


# Median

def construct_datafeed_median_strategy(speed: Optional[str] = None) -> Callable:
    def datafeed_median_gas_price_strategy(web3: Web3, transaction_params: TxParams = None) -> Wei:
        feeds = (UpvestGasPriceDatafeed, EtherchainGasPriceDatafeed, ZoltuGasPriceDatafeed)

        prices = []
        for gas_price_feed_class in feeds:
            try:
                gas_strategy = gas_price_feed_class.construct_gas_strategy(speed=speed)
                gas_price = gas_strategy(web3, transaction_params)
            except Datafeed.DatafeedError:
                continue
            else:
                prices.append(gas_price)

        if prices:
            median_price = statistics.median(prices)
            return median_price
        else:  # Worst-case scenario, we get the price from the ETH node itself
            return rpc_gas_price_strategy(web3, transaction_params)
    return datafeed_median_gas_price_strategy


#
# Web3 gas strategies
#

__RAW_WEB3_GAS_STRATEGIES = {
    'slow': time_based.slow_gas_price_strategy,      # 1h
    'medium': time_based.medium_gas_price_strategy,  # 5m
    'fast': time_based.fast_gas_price_strategy       # 60s
}


def web3_gas_strategy_wrapper(web3_gas_strategy, speed):
    """
    Enriches the web3 exceptions thrown by gas strategies
    """
    def _wrapper(*args, **kwargs):
        try:
            return web3_gas_strategy(*args, **kwargs)
        except ValidationError as e:
            raise GasStrategyError(f"Calling the '{speed}' web3 gas strategy failed. "
                                   f"Verify your Ethereum provider connection and syncing status.") from e

    _wrapper.name = speed

    return _wrapper


WEB3_GAS_STRATEGIES = {speed: web3_gas_strategy_wrapper(strategy, speed)
                       for speed, strategy in __RAW_WEB3_GAS_STRATEGIES.items()}

EXPECTED_CONFIRMATION_TIME_IN_SECONDS = {  # TODO: See #2447
    'slow': int(datetime.timedelta(hours=1).total_seconds()),
    'medium': int(datetime.timedelta(minutes=5).total_seconds()),
    'fast': 60
}


#
# Fixed-price gas strategy
#


def construct_fixed_price_gas_strategy(gas_price, denomination: str = "wei") -> Callable:
    gas_price_in_wei = Web3.toWei(gas_price, denomination)

    def _fixed_price_strategy(web3: Web3, transaction_params: TxParams = None) -> Wei:
        return gas_price_in_wei

    _fixed_price_strategy.name = f"{round(Web3.fromWei(gas_price_in_wei, 'gwei'))}gwei"

    return _fixed_price_strategy
