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


import maya
import os
from eth_tester.exceptions import TransactionFailed
from eth_utils import to_canonical_address
from hexbytes import HexBytes
from typing import List, Tuple, Union, Optional
from web3 import Web3

from nucypher.blockchain.economics import BaseEconomics, StandardTokenEconomics
from nucypher.blockchain.eth.actors import ContractAdministrator
from nucypher.blockchain.eth.deployers import StakingEscrowDeployer
from nucypher.blockchain.eth.interfaces import BlockchainDeployerInterface, BlockchainInterfaceFactory
from nucypher.blockchain.eth.registry import InMemoryContractRegistry, BaseContractRegistry
from nucypher.blockchain.eth.sol.compile.constants import TEST_SOLIDITY_SOURCE_ROOT, SOLIDITY_SOURCE_ROOT
from nucypher.blockchain.eth.sol.compile.types import SourceBundle
from nucypher.blockchain.eth.token import NU
from nucypher.blockchain.eth.utils import epoch_to_period
from nucypher.crypto.powers import TransactingPower
from nucypher.utilities.gas_strategies import EXPECTED_CONFIRMATION_TIME_IN_SECONDS
from nucypher.utilities.logging import Logger
from tests.constants import (
    DEVELOPMENT_ETH_AIRDROP_AMOUNT,
    INSECURE_DEVELOPMENT_PASSWORD,
    NUMBER_OF_ETH_TEST_ACCOUNTS,
    NUMBER_OF_STAKERS_IN_BLOCKCHAIN_TESTS,
    NUMBER_OF_URSULAS_IN_BLOCKCHAIN_TESTS,
    PYEVM_DEV_URI
)
from constant_sorrow.constants import INIT


def token_airdrop(token_agent, amount: NU, origin: str, addresses: List[str]):
    """Airdrops tokens from creator address to all other addresses!"""

    token_agent.blockchain.transacting_power.activate(password=INSECURE_DEVELOPMENT_PASSWORD)

    def txs():
        args = {'from': origin, 'gasPrice': token_agent.blockchain.client.gas_price}
        for address in addresses:
            contract_function = token_agent.contract.functions.transfer(address, int(amount))
            _receipt = token_agent.blockchain.send_transaction(contract_function=contract_function,
                                                               sender_address=origin,
                                                               payload=args)
            yield _receipt

    receipts = list()
    for receipt in txs():  # One at a time
        receipts.append(receipt)
    return receipts


def free_gas_price_strategy(w3, transaction_params=None):
    return 0


class TesterBlockchain(BlockchainDeployerInterface):
    """
    Blockchain subclass with additional test utility methods and options.
    """

    __test__ = False  # prohibit pytest from collecting this object as a test

    # Solidity
    SOURCES: List[SourceBundle] = [
        SourceBundle(base_path=SOLIDITY_SOURCE_ROOT,
                     other_paths=(TEST_SOLIDITY_SOURCE_ROOT,))
    ]

    # Web3
    GAS_STRATEGIES = {**BlockchainDeployerInterface.GAS_STRATEGIES, 'free': free_gas_price_strategy}
    PROVIDER_URI = PYEVM_DEV_URI
    DEFAULT_GAS_STRATEGY = 'free'

    # Reserved addresses
    _ETHERBASE = 0
    _ALICE = 1
    _BOB = 2
    _FIRST_STAKER = 5
    _FIRST_URSULA = _FIRST_STAKER + NUMBER_OF_STAKERS_IN_BLOCKCHAIN_TESTS

    # Internal
    __STAKERS_RANGE = range(NUMBER_OF_STAKERS_IN_BLOCKCHAIN_TESTS)
    __WORKERS_RANGE = range(NUMBER_OF_URSULAS_IN_BLOCKCHAIN_TESTS)
    __ACCOUNT_CACHE = list()

    # Defaults
    DEFAULT_ECONOMICS = StandardTokenEconomics()

    def __init__(self,
                 test_accounts: int = NUMBER_OF_ETH_TEST_ACCOUNTS,
                 poa: bool = True,
                 light: bool = False,
                 eth_airdrop: bool = False,
                 free_transactions: bool = False,
                 compile_now: bool = True,
                 *args, **kwargs):

        self.free_transactions = free_transactions

        EXPECTED_CONFIRMATION_TIME_IN_SECONDS['free'] = 5  # Just some upper-limit

        super().__init__(provider_uri=self.PROVIDER_URI,
                         poa=poa,
                         light=light,
                         *args, **kwargs)

        self.log = Logger("test-blockchain")
        self.connect(compile_now=compile_now)

        # Generate additional ethereum accounts for testing
        population = test_accounts
        enough_accounts = len(self.client.accounts) >= population
        if not enough_accounts:
            accounts_to_make = population - len(self.client.accounts)
            self.__generate_insecure_unlocked_accounts(quantity=accounts_to_make)
            assert test_accounts == len(self.w3.eth.accounts)

        if eth_airdrop is True:  # ETH for everyone!
            self.ether_airdrop(amount=DEVELOPMENT_ETH_AIRDROP_AMOUNT)

    def attach_middleware(self):
        if self.free_transactions:
            self.w3.eth.setGasPriceStrategy(free_gas_price_strategy)

    def __generate_insecure_unlocked_accounts(self, quantity: int) -> List[str]:

        #
        # Sanity Check - Only PyEVM can be used.
        #

        # Detect provider platform
        client_version = self.w3.clientVersion

        if 'Geth' in client_version:
            raise RuntimeError("WARNING: Geth providers are not implemented.")
        elif "Parity" in client_version:
            raise RuntimeError("WARNING: Parity providers are not implemented.")

        addresses = list()
        for _ in range(quantity):
            address = self.provider.ethereum_tester.add_account('0x' + os.urandom(32).hex())
            addresses.append(address)
            self.__ACCOUNT_CACHE.append(address)
            self.log.info('Generated new insecure account {}'.format(address))
        return addresses

    def ether_airdrop(self, amount: int) -> List[str]:
        """Airdrops ether from creator address to all other addresses!"""

        coinbase, *addresses = self.w3.eth.accounts

        tx_hashes = list()
        for address in addresses:
            tx = {'to': address, 'from': coinbase, 'value': amount}
            txhash = self.w3.eth.sendTransaction(tx)

            _receipt = self.wait_for_receipt(txhash)
            tx_hashes.append(txhash)
            eth_amount = Web3().fromWei(amount, 'ether')
            self.log.info("Airdropped {} ETH {} -> {}".format(eth_amount, tx['from'], tx['to']))

        return tx_hashes

    def time_travel(self, hours: int = None, seconds: int = None, periods: int = None):
        """
        Wait the specified number of wait_hours by comparing
        block timestamps and mines a single block.
        """

        more_than_one_arg = sum(map(bool, (hours, seconds, periods))) > 1
        if more_than_one_arg:
            raise ValueError("Specify hours, seconds, or periods, not a combination")

        if periods:
            duration = self.DEFAULT_ECONOMICS.seconds_per_period * periods
            base = self.DEFAULT_ECONOMICS.seconds_per_period
        elif hours:
            duration = hours * (60*60)
            base = 60 * 60
        elif seconds:
            duration = seconds
            base = 1
        else:
            raise ValueError("Specify either hours, seconds, or periods.")

        now = self.w3.eth.getBlock('latest').timestamp
        end_timestamp = ((now+duration)//base) * base

        self.w3.eth.web3.testing.timeTravel(timestamp=end_timestamp)
        self.w3.eth.web3.testing.mine(1)

        delta = maya.timedelta(seconds=end_timestamp-now)
        self.log.info(f"Time traveled {delta} "
                      f"| period {epoch_to_period(epoch=end_timestamp, seconds_per_period=self.DEFAULT_ECONOMICS.seconds_per_period)} "
                      f"| epoch {end_timestamp}")

    @classmethod
    def bootstrap_network(cls,
                          registry: Optional[BaseContractRegistry] = None,
                          economics: BaseEconomics = None
                          ) -> Tuple['TesterBlockchain', 'InMemoryContractRegistry']:
        """For use with metric testing scripts"""

        if registry is None:
            registry = InMemoryContractRegistry()
        testerchain = cls()
        if not BlockchainInterfaceFactory.is_interface_initialized(provider_uri=testerchain.provider_uri):
            BlockchainInterfaceFactory.register_interface(interface=testerchain)
        power = TransactingPower(password=INSECURE_DEVELOPMENT_PASSWORD, account=testerchain.etherbase_account)
        power.activate()
        testerchain.transacting_power = power

        origin = testerchain.client.etherbase
        admin = ContractAdministrator(deployer_address=origin,
                                      registry=registry,
                                      economics=economics or cls.DEFAULT_ECONOMICS)

        gas_limit = None  # TODO: Gas management - #842
        for deployer_class in admin.primary_deployer_classes:
            if deployer_class is StakingEscrowDeployer:
                admin.deploy_contract(contract_name=deployer_class.contract_name,
                                      gas_limit=gas_limit,
                                      deployment_mode=INIT)
            else:
                admin.deploy_contract(contract_name=deployer_class.contract_name, gas_limit=gas_limit)
        admin.deploy_contract(contract_name=StakingEscrowDeployer.contract_name, gas_limit=gas_limit)
        return testerchain, registry

    @property
    def etherbase_account(self):
        return self.client.accounts[self._ETHERBASE]

    @property
    def alice_account(self):
        return self.client.accounts[self._ALICE]

    @property
    def bob_account(self):
        return self.client.accounts[self._BOB]

    def ursula_account(self, index):
        if index not in self.__WORKERS_RANGE:
            raise ValueError(f"Ursula index must be lower than {NUMBER_OF_URSULAS_IN_BLOCKCHAIN_TESTS}")
        return self.client.accounts[index + self._FIRST_URSULA]

    def staker_account(self, index):
        if index not in self.__STAKERS_RANGE:
            raise ValueError(f"Staker index must be lower than {NUMBER_OF_STAKERS_IN_BLOCKCHAIN_TESTS}")
        return self.client.accounts[index + self._FIRST_STAKER]

    @property
    def ursulas_accounts(self):
        return list(self.ursula_account(i) for i in self.__WORKERS_RANGE)

    @property
    def stakers_accounts(self):
        return list(self.staker_account(i) for i in self.__STAKERS_RANGE)

    @property
    def unassigned_accounts(self):
        special_accounts = [self.etherbase_account, self.alice_account, self.bob_account]
        assigned_accounts = set(self.stakers_accounts + self.ursulas_accounts + special_accounts)
        accounts = set(self.client.accounts)
        return list(accounts.difference(assigned_accounts))

    def wait_for_receipt(self, txhash: Union[bytes, str, HexBytes], timeout: int = None) -> dict:
        """Wait for a transaction receipt and return it"""
        timeout = timeout or self.TIMEOUT
        result = self.client.wait_for_receipt(transaction_hash=txhash, timeout=timeout)
        if result.status == 0:
            raise TransactionFailed()
        return result

    def get_block_number(self) -> int:
        return self.client.block_number

    def read_storage_slot(self, address, slot):
        # https://github.com/ethereum/web3.py/issues/1490
        address = to_canonical_address(address)
        return self.client.w3.provider.ethereum_tester.backend.chain.get_vm().state.get_storage(address, slot)
