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

import random
from typing import Dict, Iterable, List, Tuple, Type, Union, Any, Optional, cast

import sys
from constant_sorrow.constants import (  # type: ignore
    CONTRACT_CALL,
    NO_CONTRACT_AVAILABLE,
    TRANSACTION,
    CONTRACT_ATTRIBUTE
)
from eth_typing.encoding import HexStr
from eth_typing.evm import ChecksumAddress
from eth_utils.address import to_checksum_address
from hexbytes.main import HexBytes
from web3.contract import Contract, ContractFunction
from web3.types import Wei, Timestamp, TxReceipt, TxParams, Nonce

from nucypher.blockchain.eth.aragon import Artifact
from nucypher.blockchain.eth.constants import (
    ADJUDICATOR_CONTRACT_NAME,
    DISPATCHER_CONTRACT_NAME,
    ETH_ADDRESS_BYTE_LENGTH,
    FORWARDER_INTERFACE_NAME,
    MULTISIG_CONTRACT_NAME,
    NUCYPHER_TOKEN_CONTRACT_NAME,
    NULL_ADDRESS,
    POLICY_MANAGER_CONTRACT_NAME,
    PREALLOCATION_ESCROW_CONTRACT_NAME,
    STAKING_ESCROW_CONTRACT_NAME,
    STAKING_INTERFACE_CONTRACT_NAME,
    STAKING_INTERFACE_ROUTER_CONTRACT_NAME,
    TOKEN_MANAGER_CONTRACT_NAME,
    VOTING_CONTRACT_NAME,
    VOTING_AGGREGATOR_CONTRACT_NAME,
    WORKLOCK_CONTRACT_NAME
)
from nucypher.blockchain.eth.decorators import contract_api, validate_checksum_address
from nucypher.blockchain.eth.events import ContractEvents
from nucypher.blockchain.eth.interfaces import BlockchainInterfaceFactory, VersionedContract
from nucypher.blockchain.eth.registry import AllocationRegistry, BaseContractRegistry
from nucypher.blockchain.eth.utils import epoch_to_period
from nucypher.crypto.api import sha256_digest
from nucypher.types import (
    Agent,
    NuNits,
    SubStakeInfo,
    RawSubStakeInfo,
    Period,
    Work, WorklockParameters,
    StakerFlags,
    StakerInfo,
    PeriodDelta,
    StakingEscrowParameters,
    Evidence
)
from nucypher.utilities.logging import Logger  # type: ignore
from nucypher.utilities.sampler import WeightedSampler


class EthereumContractAgent:
    """
    Base class for ethereum contract wrapper types that interact with blockchain contract instances
    """

    contract_name: str = NotImplemented
    _forward_address: bool = True
    _proxy_name: Optional[str] = None
    _excluded_interfaces: Tuple[str, ...]

    # TODO - #842: Gas Management
    DEFAULT_TRANSACTION_GAS_LIMITS: Dict[str, Optional[Wei]]
    DEFAULT_TRANSACTION_GAS_LIMITS = {'default': None}

    class ContractNotDeployed(Exception):
        """Raised when attempting to access a contract that is not deployed on the current network."""

    class RequirementError(Exception):
        """
        Raised when an agent discovers a failed requirement in an invocation to a contract function,
        usually, a failed `require()`.
        """

    def __init__(self,
                 registry: BaseContractRegistry = None,  # TODO: Consider make it non-optional again. See comment in InstanceAgent.
                 provider_uri: Optional[str] = None,
                 contract: Optional[Contract] = None,
                 transaction_gas: Optional[Wei] = None):

        self.log = Logger(self.__class__.__name__)
        self.registry_str = str(registry)

        self.blockchain = BlockchainInterfaceFactory.get_or_create_interface(provider_uri=provider_uri)

        if not contract:  # Fetch the contract
            contract = self.blockchain.get_contract_by_name(
                registry=registry,
                contract_name=self.contract_name,
                proxy_name=self._proxy_name,
                use_proxy_address=self._forward_address
            )

        self.__contract = contract
        self.events = ContractEvents(contract)
        if not transaction_gas:
            transaction_gas = EthereumContractAgent.DEFAULT_TRANSACTION_GAS_LIMITS['default']
        self.transaction_gas = transaction_gas

        self.log.info("Initialized new {} for {} with {} and {}".format(self.__class__.__name__,
                                                                        self.contract.address,
                                                                        self.blockchain.provider_uri,
                                                                        self.registry_str))

    def __repr__(self) -> str:
        class_name = self.__class__.__name__
        r = "{}(registry={}, contract={})"
        return r.format(class_name, self.registry_str, self.contract_name)

    def __eq__(self, other: Any) -> bool:
        return bool(self.contract.address == other.contract.address)

    @property  # type: ignore
    def contract(self) -> Contract:
        return self.__contract

    @property  # type: ignore
    def contract_address(self) -> ChecksumAddress:
        return self.__contract.address

    @property  # type: ignore
    @contract_api(CONTRACT_ATTRIBUTE)
    def owner(self) -> Optional[ChecksumAddress]:
        if not self._proxy_name:
            # Only upgradeable + ownable contracts can implement ownership transference.
            return None
        return self.contract.functions.owner().call()


class NucypherTokenAgent(EthereumContractAgent):

    contract_name: str = NUCYPHER_TOKEN_CONTRACT_NAME

    @contract_api(CONTRACT_CALL)
    def get_balance(self, address: Optional[ChecksumAddress] = None) -> NuNits:
        """Get the NU balance (in NuNits) of a token holder address, or of this contract address"""
        address = address if address is not None else self.contract_address
        balance: int = self.contract.functions.balanceOf(address).call()
        return NuNits(balance)

    @contract_api(CONTRACT_CALL)
    def get_allowance(self, owner: ChecksumAddress, spender: ChecksumAddress) -> NuNits:
        """Check the amount of tokens that an owner allowed to a spender"""
        allowance: int = self.contract.functions.allowance(owner, spender).call()
        return NuNits(allowance)

    @contract_api(TRANSACTION)
    def increase_allowance(self,
                           sender_address: ChecksumAddress,
                           spender_address: ChecksumAddress,
                           increase: NuNits
                           ) -> TxReceipt:
        """Increase the allowance of a spender address funded by a sender address"""
        contract_function: ContractFunction = self.contract.functions.increaseAllowance(spender_address, increase)
        receipt: TxReceipt = self.blockchain.send_transaction(contract_function=contract_function,
                                                              sender_address=sender_address)
        return receipt

    @contract_api(TRANSACTION)
    def approve_transfer(self,
                         amount: NuNits,
                         spender_address: ChecksumAddress,
                         sender_address: ChecksumAddress
                         ) -> TxReceipt:
        """Approve the spender address to transfer an amount of tokens on behalf of the sender address"""
        payload: TxParams = {'gas': Wei(500_000)}  # TODO #842: gas needed for use with geth! <<<< Is this still open?
        contract_function: ContractFunction = self.contract.functions.approve(spender_address, amount)
        receipt: TxReceipt = self.blockchain.send_transaction(contract_function=contract_function,
                                                              payload=payload,
                                                              sender_address=sender_address)
        return receipt

    @contract_api(TRANSACTION)
    def transfer(self, amount: NuNits, target_address: ChecksumAddress, sender_address: ChecksumAddress) -> TxReceipt:
        """Transfer an amount of tokens from the sender address to the target address."""
        contract_function: ContractFunction = self.contract.functions.transfer(target_address, amount)
        receipt: TxReceipt = self.blockchain.send_transaction(contract_function=contract_function,
                                                              sender_address=sender_address)
        return receipt

    @contract_api(TRANSACTION)
    def approve_and_call(self,
                         amount: NuNits,
                         target_address: ChecksumAddress,
                         sender_address: ChecksumAddress,
                         call_data: bytes = b'',
                         gas_limit: Optional[Wei] = None
                         ) -> TxReceipt:
        payload = None
        if gas_limit:  # TODO: Gas management - #842
            payload = {'gas': gas_limit}
        approve_and_call: ContractFunction = self.contract.functions.approveAndCall(target_address, amount, call_data)
        approve_and_call_receipt: TxReceipt = self.blockchain.send_transaction(contract_function=approve_and_call,
                                                                               sender_address=sender_address,
                                                                               payload=payload)
        return approve_and_call_receipt


class StakingEscrowAgent(EthereumContractAgent):

    contract_name: str = STAKING_ESCROW_CONTRACT_NAME
    _proxy_name: str = DISPATCHER_CONTRACT_NAME
    _excluded_interfaces = (
        'verifyState',
        'finishUpgrade'
    )

    DEFAULT_PAGINATION_SIZE: int = 30    # TODO: Use dynamic pagination size (see #1424)

    class NotEnoughStakers(Exception):
        """Raised when the are not enough stakers available to complete an operation"""

    #
    # Staker Network Status
    #

    @contract_api(CONTRACT_CALL)
    def get_staker_population(self) -> int:
        """Returns the number of stakers on the blockchain"""
        return self.contract.functions.getStakersLength().call()

    @contract_api(CONTRACT_CALL)
    def get_current_period(self) -> Period:
        """Returns the current period"""
        return self.contract.functions.getCurrentPeriod().call()

    @contract_api(CONTRACT_CALL)
    def get_stakers(self) -> List[ChecksumAddress]:
        """Returns a list of stakers"""
        num_stakers: int = self.get_staker_population()
        stakers: List[ChecksumAddress] = [self.contract.functions.stakers(i).call() for i in range(num_stakers)]
        return stakers

    @contract_api(CONTRACT_CALL)
    def partition_stakers_by_activity(self) -> Tuple[List[ChecksumAddress], List[ChecksumAddress], List[ChecksumAddress]]:
        """
        Returns three lists of stakers depending on their commitments:
        The first list contains stakers that already committed to next period.
        The second, stakers that committed to current period but haven't committed to next yet.
        The third contains stakers that have missed commitments before current period
        """

        num_stakers: int = self.get_staker_population()
        current_period: Period = self.get_current_period()
        active_stakers: List[ChecksumAddress] = list()
        pending_stakers: List[ChecksumAddress] = list()
        missing_stakers: List[ChecksumAddress] = list()

        for i in range(num_stakers):
            staker = self.contract.functions.stakers(i).call()
            last_committed_period = self.get_last_committed_period(staker)
            if last_committed_period == current_period + 1:
                active_stakers.append(staker)
            elif last_committed_period == current_period:
                pending_stakers.append(staker)
            else:
                missing_stakers.append(staker)

        return active_stakers, pending_stakers, missing_stakers

    @contract_api(CONTRACT_CALL)
    def get_all_active_stakers(self, periods: int, pagination_size: Optional[int] = None) -> Tuple[NuNits, Dict[ChecksumAddress, NuNits]]:
        """Only stakers which committed to the current period (in the previous period) are used."""
        if not periods > 0:
            raise ValueError("Period must be > 0")

        if pagination_size is None:
            pagination_size = StakingEscrowAgent.DEFAULT_PAGINATION_SIZE if self.blockchain.is_light else 0
        elif pagination_size < 0:
            raise ValueError("Pagination size must be >= 0")

        if pagination_size > 0:
            num_stakers: int = self.get_staker_population()
            start_index: int = 0
            n_tokens: int = 0
            stakers: Dict[int, int] = dict()
            active_stakers: Tuple[NuNits, List[List[int]]]
            while start_index < num_stakers:
                active_stakers = self.contract.functions.getActiveStakers(periods, start_index, pagination_size).call()
                temp_locked_tokens, temp_stakers = active_stakers
                # temp_stakers is a list of length-2 lists (address -> locked tokens)
                temp_stakers_map = {address: locked_tokens for address, locked_tokens in temp_stakers}
                n_tokens = n_tokens + temp_locked_tokens
                stakers.update(temp_stakers_map)
                start_index += pagination_size
        else:
            n_tokens, temp_stakers = self.contract.functions.getActiveStakers(periods, 0, 0).call()
            stakers = {address: locked_tokens for address, locked_tokens in temp_stakers}

        # stakers' addresses are returned as uint256 by getActiveStakers(), convert to address objects
        def checksum_address(address: int) -> ChecksumAddress:
            return ChecksumAddress(to_checksum_address(address.to_bytes(ETH_ADDRESS_BYTE_LENGTH, 'big')))
        typed_stakers = {checksum_address(address): NuNits(locked_tokens) for address, locked_tokens in stakers.items()}

        return NuNits(n_tokens), typed_stakers

    @contract_api(CONTRACT_CALL)
    def get_all_locked_tokens(self, periods: int, pagination_size: Optional[int] = None) -> NuNits:
        all_locked_tokens, _stakers = self.get_all_active_stakers(periods=periods, pagination_size=pagination_size)
        return all_locked_tokens

    #
    # StakingEscrow Contract API
    #

    @contract_api(CONTRACT_CALL)
    def get_global_locked_tokens(self, at_period: Optional[Period] = None) -> NuNits:
        """
        Gets the number of locked tokens for *all* stakers that have
        made a commitment to the specified period.

        `at_period` values can be any valid period number past, present, or future:

            PAST - Calling this function with an `at_period` value in the past will return the number
            of locked tokens whose worker commitment was made to that past period.

            PRESENT - This is the default value, when no `at_period` value is provided.

            FUTURE - Calling this function with an `at_period` value greater than
            the current period + 1 (next period), will result in a zero return value
            because commitment cannot be made beyond the next period.

        Returns an amount of NuNits.
        """
        if at_period is None:  # allow 0, vs default
            # Get the current period on-chain by default.
            at_period = self.contract.functions.getCurrentPeriod().call()
        return NuNits(self.contract.functions.lockedPerPeriod(at_period).call())

    @contract_api(CONTRACT_CALL)
    def get_staker_info(self, staker_address: ChecksumAddress) -> StakerInfo:
        # remove reserved fields
        info: list = self.contract.functions.stakerInfo(staker_address).call()
        return StakerInfo(*info[0:9])

    @contract_api(CONTRACT_CALL)
    def get_locked_tokens(self, staker_address: ChecksumAddress, periods: int = 0) -> NuNits:
        """
        Returns the amount of tokens this staker has locked
        for a given duration in periods measured from the current period forwards.
        """
        if periods < 0:
            raise ValueError(f"Periods value must not be negative, Got '{periods}'.")
        return NuNits(self.contract.functions.getLockedTokens(staker_address, periods).call())

    @contract_api(CONTRACT_CALL)
    def owned_tokens(self, staker_address: ChecksumAddress) -> NuNits:
        """
        Returns all tokens that belong to staker_address, including locked, unlocked and rewards.
        """
        return NuNits(self.contract.functions.getAllTokens(staker_address).call())

    @contract_api(CONTRACT_CALL)
    def get_substake_info(self, staker_address: ChecksumAddress, stake_index: int) -> SubStakeInfo:
        first_period, *others, locked_value = self.contract.functions.getSubStakeInfo(staker_address, stake_index).call()
        last_period: Period = self.contract.functions.getLastPeriodOfSubStake(staker_address, stake_index).call()
        return SubStakeInfo(first_period, last_period, locked_value)

    @contract_api(CONTRACT_CALL)
    def get_raw_substake_info(self, staker_address: ChecksumAddress, stake_index: int) -> RawSubStakeInfo:
        result: RawSubStakeInfo = self.contract.functions.getSubStakeInfo(staker_address, stake_index).call()
        return RawSubStakeInfo(*result)

    @contract_api(CONTRACT_CALL)
    def get_all_stakes(self, staker_address: ChecksumAddress) -> Iterable[SubStakeInfo]:
        stakes_length: int = self.contract.functions.getSubStakesLength(staker_address).call()
        if stakes_length == 0:
            return iter(())  # Empty iterable, There are no stakes
        for stake_index in range(stakes_length):
            yield self.get_substake_info(staker_address=staker_address, stake_index=stake_index)

    @contract_api(TRANSACTION)
    def deposit_tokens(self,
                       staker_address: ChecksumAddress,
                       amount: NuNits,
                       lock_periods: PeriodDelta,
                       sender_address: Optional[ChecksumAddress] = None
                       ) -> TxReceipt:
        """
        Send tokens to the escrow from the sender's address to be locked on behalf of the staker address.
        If the sender address is not provided, the stakers address is used.
        Note that this resolved to two separate contract function signatures.
        """
        if not sender_address:
            sender_address = staker_address
        contract_function: ContractFunction = self.contract.functions.deposit(staker_address, amount, lock_periods)
        receipt: TxReceipt = self.blockchain.send_transaction(contract_function=contract_function,
                                                              sender_address=sender_address)
        return receipt

    @contract_api(TRANSACTION)
    def deposit_and_increase(self,
                             staker_address: ChecksumAddress,
                             amount: NuNits,
                             stake_index: int
                             ) -> TxReceipt:
        """
        Send tokens to the escrow from the sender's address to be locked on behalf of the staker address.
        This method will add tokens to the selected sub-stake.
        Note that this resolved to two separate contract function signatures.
        """
        contract_function: ContractFunction = self.contract.functions.depositAndIncrease(stake_index, amount)
        receipt: TxReceipt = self.blockchain.send_transaction(contract_function=contract_function,
                                                              sender_address=staker_address)
        return receipt

    @contract_api(TRANSACTION)
    def lock_and_create(self,
                        staker_address: ChecksumAddress,
                        amount: NuNits,
                        lock_periods: PeriodDelta
                        ) -> TxReceipt:
        """
        Locks tokens amount and creates new sub-stake
        """
        contract_function: ContractFunction = self.contract.functions.lockAndCreate(amount, lock_periods)
        receipt: TxReceipt = self.blockchain.send_transaction(contract_function=contract_function,
                                                              sender_address=staker_address)
        return receipt

    @contract_api(TRANSACTION)
    def lock_and_increase(self,
                          staker_address: ChecksumAddress,
                          amount: NuNits,
                          stake_index: int
                          ) -> TxReceipt:
        """
        Locks tokens amount and add them to selected sub-stake
        """
        contract_function: ContractFunction = self.contract.functions.lockAndIncrease(stake_index, amount)
        receipt: TxReceipt = self.blockchain.send_transaction(contract_function=contract_function,
                                                              sender_address=staker_address)
        return receipt

    @contract_api(TRANSACTION)
    def divide_stake(self,
                     staker_address: ChecksumAddress,
                     stake_index: int,
                     target_value: NuNits,
                     periods: PeriodDelta
                     ) -> TxReceipt:
        contract_function: ContractFunction = self.contract.functions.divideStake(stake_index, target_value, periods)
        receipt = self.blockchain.send_transaction(contract_function=contract_function, sender_address=staker_address)
        return receipt

    @contract_api(TRANSACTION)
    def prolong_stake(self, staker_address: ChecksumAddress, stake_index: int, periods: PeriodDelta) -> TxReceipt:
        contract_function: ContractFunction = self.contract.functions.prolongStake(stake_index, periods)
        receipt = self.blockchain.send_transaction(contract_function=contract_function, sender_address=staker_address)
        return receipt

    @contract_api(TRANSACTION)
    def merge_stakes(self, staker_address: ChecksumAddress, stake_index_1: int, stake_index_2: int) -> TxReceipt:
        contract_function: ContractFunction = self.contract.functions.mergeStake(stake_index_1, stake_index_2)
        receipt = self.blockchain.send_transaction(contract_function=contract_function, sender_address=staker_address)
        return receipt

    @contract_api(CONTRACT_CALL)
    def get_current_committed_period(self, staker_address: ChecksumAddress) -> Period:
        staker_info: StakerInfo = self.get_staker_info(staker_address)
        period: int = staker_info.current_committed_period
        return Period(period)

    @contract_api(CONTRACT_CALL)
    def get_next_committed_period(self, staker_address: ChecksumAddress) -> Period:
        staker_info: StakerInfo = self.get_staker_info(staker_address)
        period: int = staker_info.next_committed_period
        return Period(period)

    @contract_api(CONTRACT_CALL)
    def get_last_committed_period(self, staker_address: ChecksumAddress) -> Period:
        period: int = self.contract.functions.getLastCommittedPeriod(staker_address).call()
        return Period(period)

    @contract_api(CONTRACT_CALL)
    def get_worker_from_staker(self, staker_address: ChecksumAddress) -> ChecksumAddress:
        worker: str = self.contract.functions.getWorkerFromStaker(staker_address).call()
        return to_checksum_address(worker)

    @contract_api(CONTRACT_CALL)
    def get_staker_from_worker(self, worker_address: ChecksumAddress) -> ChecksumAddress:
        staker = self.contract.functions.stakerFromWorker(worker_address).call()
        return to_checksum_address(staker)

    @contract_api(TRANSACTION)
    def bond_worker(self, staker_address: ChecksumAddress, worker_address: ChecksumAddress) -> TxReceipt:
        contract_function: ContractFunction = self.contract.functions.bondWorker(worker_address)
        receipt: TxReceipt = self.blockchain.send_transaction(contract_function=contract_function,
                                                              sender_address=staker_address)
        return receipt

    @contract_api(TRANSACTION)
    def release_worker(self, staker_address: ChecksumAddress) -> TxReceipt:
        return self.bond_worker(staker_address=staker_address, worker_address=NULL_ADDRESS)

    @contract_api(TRANSACTION)
    def commit_to_next_period(self,
                              worker_address: ChecksumAddress,
                              fire_and_forget: bool = True,  # TODO: make fire_and_forget required? See #2385 too.
                              ) -> Union[TxReceipt, HexBytes]:
        """
        For each period that the worker makes a commitment, the staker is rewarded.
        """
        contract_function: ContractFunction = self.contract.functions.commitToNextPeriod()
        txhash_or_receipt = self.blockchain.send_transaction(contract_function=contract_function,
                                                             sender_address=worker_address,
                                                             gas_estimation_multiplier=1.5, # TODO: Workaround for #2337
                                                             fire_and_forget=fire_and_forget)
        return txhash_or_receipt

    @contract_api(TRANSACTION)
    def mint(self, staker_address: ChecksumAddress) -> TxReceipt:
        """
        Computes reward tokens for the staker's account;
        This is only used to calculate the reward for the final period of a stake,
        when you intend to withdraw 100% of tokens.
        """
        contract_function: ContractFunction = self.contract.functions.mint()
        receipt: TxReceipt = self.blockchain.send_transaction(contract_function=contract_function,
                                                              sender_address=staker_address)
        return receipt

    @contract_api(CONTRACT_CALL)
    def non_withdrawable_stake(self, staker_address: ChecksumAddress) -> NuNits:
        """
        Returns token amount that can not be withdrawn.
        Opposite method for `calculate_staking_reward`.
        Uses maximum of locked tokens in the current and next periods.
        """
        staked_amount: int = max(self.contract.functions.getLockedTokens(staker_address, 0).call(),
                                 self.contract.functions.getLockedTokens(staker_address, 1).call())
        return NuNits(staked_amount)

    @contract_api(CONTRACT_CALL)
    def calculate_staking_reward(self, staker_address: ChecksumAddress) -> NuNits:
        token_amount: NuNits = self.owned_tokens(staker_address)
        reward_amount: int = token_amount - self.non_withdrawable_stake(staker_address)
        return NuNits(reward_amount)

    @contract_api(TRANSACTION)
    def collect_staking_reward(self, staker_address: ChecksumAddress) -> TxReceipt:
        """Withdraw tokens rewarded for staking."""
        reward_amount: NuNits = self.calculate_staking_reward(staker_address=staker_address)
        from nucypher.blockchain.eth.token import NU
        self.log.debug(f"Withdrawing staking reward ({NU.from_nunits(reward_amount)}) to {staker_address}")
        receipt: TxReceipt = self.withdraw(staker_address=staker_address, amount=reward_amount)
        return receipt

    @contract_api(TRANSACTION)
    def withdraw(self, staker_address: ChecksumAddress, amount: NuNits) -> TxReceipt:
        """Withdraw tokens"""
        payload = {'gas': 500_000}  # TODO: #842 Gas Management
        contract_function: ContractFunction = self.contract.functions.withdraw(amount)
        receipt = self.blockchain.send_transaction(contract_function=contract_function,
                                                   payload=payload,
                                                   sender_address=staker_address)
        return receipt

    @contract_api(CONTRACT_CALL)
    def get_flags(self, staker_address: ChecksumAddress) -> StakerFlags:
        flags: tuple = self.contract.functions.getFlags(staker_address).call()
        wind_down_flag, restake_flag, measure_work_flag, snapshot_flag = flags
        return StakerFlags(wind_down_flag, restake_flag, measure_work_flag, snapshot_flag)

    @contract_api(CONTRACT_CALL)
    def is_restaking(self, staker_address: ChecksumAddress) -> bool:
        flags = self.get_flags(staker_address)
        return flags.restake_flag

    @contract_api(TRANSACTION)
    def set_restaking(self, staker_address: ChecksumAddress, value: bool) -> TxReceipt:
        """
        Enable automatic restaking for a fixed duration of lock periods.
        If set to True, then all staking rewards will be automatically added to locked stake.
        """
        contract_function: ContractFunction = self.contract.functions.setReStake(value)
        receipt: TxReceipt = self.blockchain.send_transaction(contract_function=contract_function,
                                                              sender_address=staker_address)
        # TODO: Handle ReStakeSet event (see #1193)
        return receipt

    @contract_api(CONTRACT_CALL)
    def is_winding_down(self, staker_address: ChecksumAddress) -> bool:
        flags = self.get_flags(staker_address)
        return flags.wind_down_flag

    @contract_api(TRANSACTION)
    def set_winding_down(self, staker_address: ChecksumAddress, value: bool) -> TxReceipt:
        """
        Enable wind down for stake.
        If set to True, then stakes duration will decrease in each period with `commitToNextPeriod()`.
        """
        contract_function: ContractFunction = self.contract.functions.setWindDown(value)
        receipt = self.blockchain.send_transaction(contract_function=contract_function,
                                                   sender_address=staker_address)
        # TODO: Handle WindDownSet event (see #1193)
        return receipt

    @contract_api(CONTRACT_CALL)
    def is_taking_snapshots(self, staker_address: ChecksumAddress) -> bool:
        _winddown_flag, _restake_flag, _measure_work_flag, snapshots_flag = self.get_flags(staker_address)
        return snapshots_flag

    @contract_api(TRANSACTION)
    def set_snapshots(self, staker_address: ChecksumAddress, activate: bool) -> TxReceipt:
        """
        Activate/deactivate taking balance snapshots.
        If set to True, then each time the balance changes, a snapshot associated to current block number is stored.
        """
        contract_function: ContractFunction = self.contract.functions.setSnapshots(activate)
        receipt = self.blockchain.send_transaction(contract_function=contract_function, sender_address=staker_address)
        # TODO: Handle SnapshotSet event (see #1193)
        return receipt

    @contract_api(TRANSACTION)
    def remove_unused_stake(self, staker_address: ChecksumAddress, stake_index: int) -> TxReceipt:
        contract_function: ContractFunction = self.contract.functions.removeUnusedSubStake(stake_index)
        receipt: TxReceipt = self.blockchain.send_transaction(contract_function=contract_function,
                                                              sender_address=staker_address)
        return receipt

    @contract_api(CONTRACT_CALL)
    def staking_parameters(self) -> StakingEscrowParameters:
        parameter_signatures = (

            # Period
            'secondsPerPeriod',  # Seconds in single period

            # Coefficients
            'mintingCoefficient',           # Minting coefficient (d * k2)
            'lockDurationCoefficient1',     # Numerator of the lock duration coefficient (k1)
            'lockDurationCoefficient2',     # Denominator of the lock duration coefficient (k2)
            'maximumRewardedPeriods',       # Max periods that will be additionally rewarded (kmax)
            'firstPhaseTotalSupply',        # Total supply for the first phase
            'firstPhaseMaxIssuance',        # Max possible reward for one period for all stakers in the first phase

            # Constraints
            'minLockedPeriods',             # Min amount of periods during which tokens can be locked
            'minAllowableLockedTokens',     # Min amount of tokens that can be locked
            'maxAllowableLockedTokens',     # Max amount of tokens that can be locked
            'minWorkerPeriods'              # Min amount of periods while a worker can't be changed
        )

        def _call_function_by_name(name: str) -> int:
            return getattr(self.contract.functions, name)().call()

        staking_parameters = StakingEscrowParameters(tuple(map(_call_function_by_name, parameter_signatures)))
        return staking_parameters

    #
    # Contract Utilities
    #

    @contract_api(CONTRACT_CALL)
    def swarm(self) -> Iterable[ChecksumAddress]:
        """
        Returns an iterator of all staker addresses via cumulative sum, on-network.
        Staker addresses are returned in the order in which they registered with the StakingEscrow contract's ledger
        """
        for index in range(self.get_staker_population()):
            staker_address: ChecksumAddress = self.contract.functions.stakers(index).call()
            yield staker_address

    def get_stakers_reservoir(self,
                              duration: int,
                              without: Iterable[ChecksumAddress] = [],
                              pagination_size: Optional[int] = None) -> 'StakersReservoir':

        n_tokens, stakers_map = self.get_all_active_stakers(periods=duration,
                                                            pagination_size=pagination_size)

        filtered_out = 0
        for address in without:
            if address in stakers_map:
                n_tokens -= stakers_map[address]
                del stakers_map[address]
                filtered_out += 1

        self.log.debug(f"Got {len(stakers_map)} stakers with {n_tokens} total tokens "
                       f"({filtered_out} filtered out)")

        if n_tokens == 0:
            raise self.NotEnoughStakers(f'There are no locked tokens for duration {duration}.')

        return StakersReservoir(stakers_map)

    @contract_api(CONTRACT_CALL)
    def get_completed_work(self, bidder_address: ChecksumAddress) -> Work:
        total_completed_work = self.contract.functions.getCompletedWork(bidder_address).call()
        return total_completed_work

    @contract_api(CONTRACT_CALL)
    def get_missing_commitments(self, checksum_address: ChecksumAddress) -> int:
        # TODO: Move this up one layer, since it utilizes a combination of contract API methods.
        last_committed_period = self.get_last_committed_period(checksum_address)
        current_period = self.get_current_period()
        missing_commitments = current_period - last_committed_period
        if missing_commitments in (0, -1):
            result = 0
        elif last_committed_period == 0:  # never committed
            stakes = list(self.get_all_stakes(staker_address=checksum_address))
            initial_staking_period = min(stakes, key=lambda s: s[0])[0]
            result = current_period - initial_staking_period
        else:
            result = missing_commitments
        return result

    @property  # type: ignore
    @contract_api(CONTRACT_ATTRIBUTE)
    def worklock(self) -> ChecksumAddress:
        return self.contract.functions.workLock().call()

    @property  # type: ignore
    @contract_api(CONTRACT_ATTRIBUTE)
    def adjudicator(self) -> ChecksumAddress:
        return self.contract.functions.adjudicator().call()

    @property  # type: ignore
    @contract_api(CONTRACT_ATTRIBUTE)
    def policy_manager(self) -> ChecksumAddress:
        return self.contract.functions.policyManager().call()


class PolicyManagerAgent(EthereumContractAgent):

    contract_name: str = POLICY_MANAGER_CONTRACT_NAME
    _proxy_name: str = DISPATCHER_CONTRACT_NAME
    _excluded_interfaces = (
        'verifyState',
        'finishUpgrade'
    )

    @contract_api(TRANSACTION)
    def create_policy(self,
                      policy_id: str,
                      author_address: ChecksumAddress,
                      value: Wei,
                      end_timestamp: Timestamp,
                      node_addresses: List[ChecksumAddress],
                      owner_address: Optional[ChecksumAddress] = None) -> TxReceipt:

        owner_address = owner_address or author_address
        payload = {'value': value}
        contract_function: ContractFunction = self.contract.functions.createPolicy(policy_id,
                                                                 owner_address,
                                                                 end_timestamp,
                                                                 node_addresses)
        receipt = self.blockchain.send_transaction(contract_function=contract_function,
                                                   payload=payload,
                                                   sender_address=author_address)  # TODO: Gas management - #842
        return receipt

    @contract_api(CONTRACT_CALL)
    def fetch_policy(self, policy_id: str, with_owner=False) -> list:
        """
        Fetch raw stored blockchain data regarding the policy with the given policy ID.
        If `with_owner=True`, this method executes the equivalent of `getPolicyOwner`
        to avoid another call.
        """
        blockchain_record = self.contract.functions.policies(policy_id).call()
        if with_owner:
            # If the policyOwner addr is null, we return the sponsor addr instead of the owner.
            owner_checksum_addr = blockchain_record[1] if blockchain_record[2] == NULL_ADDRESS else blockchain_record[2]
            return blockchain_record, owner_checksum_addr
        return blockchain_record

    def fetch_arrangement_addresses_from_policy_txid(self, txhash: Union[str, bytes], timeout: int = 600) -> Iterable:
        # TODO: Won't it be great when this is impossible?  #1274
        _receipt = self.blockchain.client.wait_for_receipt(txhash, timeout=timeout)
        transaction = self.blockchain.client.w3.eth.getTransaction(txhash)
        try:
            _signature, parameters = self.contract.decode_function_input(
                self.blockchain.client.parse_transaction_data(transaction))
        except AttributeError:
            raise RuntimeError(f"Eth Client incompatibility issue: {self.blockchain.client} could not extract data from {transaction}")
        return parameters['_nodes']

    @contract_api(TRANSACTION)
    def revoke_policy(self, policy_id: bytes, author_address: ChecksumAddress) -> TxReceipt:
        """Revoke by arrangement ID; Only the policy's author_address can revoke the policy."""
        contract_function: ContractFunction = self.contract.functions.revokePolicy(policy_id)
        receipt = self.blockchain.send_transaction(contract_function=contract_function, sender_address=author_address)
        return receipt

    @contract_api(TRANSACTION)
    def collect_policy_fee(self, collector_address: ChecksumAddress, staker_address: ChecksumAddress) -> TxReceipt:
        """Collect fees (ETH) earned since last withdrawal"""
        contract_function: ContractFunction = self.contract.functions.withdraw(collector_address)
        receipt = self.blockchain.send_transaction(contract_function=contract_function, sender_address=staker_address)
        return receipt

    @contract_api(CONTRACT_CALL)
    def fetch_policy_arrangements(self, policy_id: str) -> Iterable[Tuple[ChecksumAddress, int, int]]:
        record_count = self.contract.functions.getArrangementsLength(policy_id).call()
        for index in range(record_count):
            arrangement = self.contract.functions.getArrangementInfo(policy_id, index).call()
            yield arrangement

    @contract_api(TRANSACTION)
    def revoke_arrangement(self, policy_id: str, node_address: ChecksumAddress, author_address: ChecksumAddress) -> TxReceipt:
        contract_function: ContractFunction = self.contract.functions.revokeArrangement(policy_id, node_address)
        receipt = self.blockchain.send_transaction(contract_function=contract_function, sender_address=author_address)
        return receipt

    @contract_api(TRANSACTION)
    def calculate_refund(self, policy_id: str, author_address: ChecksumAddress) -> TxReceipt:
        contract_function: ContractFunction = self.contract.functions.calculateRefundValue(policy_id)
        receipt = self.blockchain.send_transaction(contract_function=contract_function, sender_address=author_address)
        return receipt

    @contract_api(TRANSACTION)
    def collect_refund(self, policy_id: str, author_address: ChecksumAddress) -> TxReceipt:
        contract_function: ContractFunction = self.contract.functions.refund(policy_id)
        receipt = self.blockchain.send_transaction(contract_function=contract_function, sender_address=author_address)
        return receipt

    @contract_api(CONTRACT_CALL)
    def get_fee_amount(self, staker_address: ChecksumAddress) -> Wei:
        fee_amount = self.contract.functions.nodes(staker_address).call()[0]
        return fee_amount

    @contract_api(CONTRACT_CALL)
    def get_fee_rate_range(self) -> Tuple[Wei, Wei, Wei]:
        """Check minimum, default & maximum fee rate for all policies ('global fee range')"""
        minimum, default, maximum = self.contract.functions.feeRateRange().call()
        return minimum, default, maximum

    @contract_api(CONTRACT_CALL)
    def get_min_fee_rate(self, staker_address: ChecksumAddress) -> Wei:
        """Check minimum fee rate that staker accepts"""
        min_rate = self.contract.functions.getMinFeeRate(staker_address).call()
        return min_rate

    @contract_api(CONTRACT_CALL)
    def get_raw_min_fee_rate(self, staker_address: ChecksumAddress) -> Wei:
        """Check minimum acceptable fee rate set by staker for their associated worker"""
        min_rate = self.contract.functions.nodes(staker_address).call()[3]
        return min_rate

    @contract_api(TRANSACTION)
    def set_min_fee_rate(self, staker_address: ChecksumAddress, min_rate: Wei) -> TxReceipt:
        contract_function: ContractFunction = self.contract.functions.setMinFeeRate(min_rate)
        receipt = self.blockchain.send_transaction(contract_function=contract_function, sender_address=staker_address)
        return receipt


class PreallocationEscrowAgent(EthereumContractAgent):

    contract_name: str = PREALLOCATION_ESCROW_CONTRACT_NAME
    _proxy_name: str = NotImplemented
    _forward_address: bool = False
    __allocation_registry_class: Type[AllocationRegistry] = AllocationRegistry

    class StakingInterfaceAgent(EthereumContractAgent):
        contract_name: str = STAKING_INTERFACE_CONTRACT_NAME
        _proxy_name: str = STAKING_INTERFACE_ROUTER_CONTRACT_NAME
        _forward_address: bool = False

        @validate_checksum_address
        def _generate_beneficiary_agency(self, principal_address: ChecksumAddress) -> Contract:
            contract = self.blockchain.client.get_contract(address=principal_address, abi=self.contract.abi)
            return contract

    def __init__(self,
                 beneficiary: ChecksumAddress,
                 registry: BaseContractRegistry,
                 allocation_registry: Optional[AllocationRegistry] = None,
                 *args, **kwargs):

        self.__allocation_registry = allocation_registry or PreallocationEscrowAgent.__allocation_registry_class()
        self.__beneficiary = beneficiary
        self.__principal_contract: Contract = NO_CONTRACT_AVAILABLE
        self.__interface_contract = NO_CONTRACT_AVAILABLE

        # Sets the above
        self.__read_principal()
        self.__read_interface(registry)

        self.token_agent: NucypherTokenAgent = ContractAgency.get_agent(NucypherTokenAgent, registry)
        self.staking_agent: StakingEscrowAgent = ContractAgency.get_agent(StakingEscrowAgent, registry)

        super().__init__(contract=self.principal_contract, registry=registry, *args, **kwargs)

    def __read_interface(self, registry: BaseContractRegistry) -> None:
        self.__interface_contract = self.StakingInterfaceAgent(registry=registry)
        contract = self.__interface_contract._generate_beneficiary_agency(principal_address=self.principal_contract.address)
        self.__interface_contract = contract

    @validate_checksum_address
    def __fetch_principal_contract(self, contract_address: Optional[ChecksumAddress] = None) -> None:
        """Fetch the PreallocationEscrow deployment directly from the AllocationRegistry."""
        if contract_address is not None:
            contract_data = self.__allocation_registry.search(contract_address=contract_address)
        else:
            contract_data = self.__allocation_registry.search(beneficiary_address=self.beneficiary)
        address, abi = contract_data
        blockchain = BlockchainInterfaceFactory.get_interface()
        principal_contract: Contract = blockchain.client.get_contract(abi=abi, address=address, ContractFactoryClass=Contract)
        self.__principal_contract = principal_contract

    def __set_owner(self) -> None:
        self.__beneficiary = self.owner

    @validate_checksum_address
    def __read_principal(self, contract_address: Optional[ChecksumAddress] = None) -> None:
        self.__fetch_principal_contract(contract_address=contract_address)
        self.__set_owner()

    @property  # type: ignore
    @contract_api(CONTRACT_ATTRIBUTE)
    def owner(self) -> ChecksumAddress:
        owner = self.principal_contract.functions.owner().call()
        return owner

    @property  # type: ignore
    def beneficiary(self) -> ChecksumAddress:
        return self.__beneficiary

    @property  # type: ignore
    def interface_contract(self) -> VersionedContract:
        if self.__interface_contract is NO_CONTRACT_AVAILABLE:
            raise RuntimeError("{} not available".format(self.contract_name))
        return self.__interface_contract

    @property  # type: ignore
    def principal_contract(self) -> Contract:
        """Directly reference the beneficiary's deployed contract instead of the interface contracts's ABI"""
        if self.__principal_contract is NO_CONTRACT_AVAILABLE:
            raise RuntimeError("{} not available".format(self.contract_name))
        return self.__principal_contract

    @property  # type: ignore
    @contract_api(CONTRACT_ATTRIBUTE)
    def initial_locked_amount(self) -> int:
        return self.principal_contract.functions.lockedValue().call()

    @property  # type: ignore
    @contract_api(CONTRACT_ATTRIBUTE)
    def available_balance(self) -> int:
        overall_balance = self.token_agent.get_balance(self.principal_contract.address)
        seconds_per_period = self.staking_agent.contract.functions.secondsPerPeriod().call()
        current_period = self.staking_agent.get_current_period()
        end_lock_period = epoch_to_period(self.end_timestamp, seconds_per_period=seconds_per_period)

        available_balance = overall_balance
        if current_period <= end_lock_period:
            staked_tokens = self.staking_agent.get_locked_tokens(staker_address=self.principal_contract.address,
                                                                 periods=end_lock_period - current_period)
            if self.unvested_tokens > staked_tokens:
                # The staked amount is deducted from the locked amount
                available_balance -= self.unvested_tokens - staked_tokens

        return available_balance

    @property  # type: ignore
    @contract_api(CONTRACT_ATTRIBUTE)
    def unvested_tokens(self) -> int:
        return self.principal_contract.functions.getLockedTokens().call()

    @property  # type: ignore
    @contract_api(CONTRACT_ATTRIBUTE)
    def end_timestamp(self) -> Timestamp:
        return self.principal_contract.functions.endLockTimestamp().call()

    @contract_api(TRANSACTION)
    def lock(self, amount: NuNits, periods: PeriodDelta) -> TxReceipt:
        contract_function: ContractFunction = self.__interface_contract.functions.lockAndCreate(amount, periods)
        receipt = self.blockchain.send_transaction(contract_function=contract_function, sender_address=self.__beneficiary)
        return receipt

    @contract_api(TRANSACTION)
    def withdraw_tokens(self, value: NuNits) -> TxReceipt:
        contract_function: ContractFunction = self.principal_contract.functions.withdrawTokens(value)
        receipt = self.blockchain.send_transaction(contract_function=contract_function, sender_address=self.__beneficiary)
        return receipt

    @contract_api(TRANSACTION)
    def withdraw_eth(self) -> TxReceipt:
        contract_function: ContractFunction = self.principal_contract.functions.withdrawETH()
        receipt = self.blockchain.send_transaction(contract_function=contract_function, sender_address=self.__beneficiary)
        return receipt

    @contract_api(TRANSACTION)
    def deposit_as_staker(self, amount: NuNits, lock_periods: PeriodDelta) -> TxReceipt:
        contract_function: ContractFunction = self.__interface_contract.functions.depositAsStaker(amount, lock_periods)
        receipt = self.blockchain.send_transaction(contract_function=contract_function, sender_address=self.__beneficiary)
        return receipt

    @contract_api(TRANSACTION)
    def withdraw_as_staker(self, value: NuNits) -> TxReceipt:
        contract_function: ContractFunction = self.__interface_contract.functions.withdrawAsStaker(value)
        receipt = self.blockchain.send_transaction(contract_function=contract_function, sender_address=self.__beneficiary)
        return receipt

    @contract_api(TRANSACTION)
    def bond_worker(self, worker_address: ChecksumAddress) -> TxReceipt:
        contract_function: ContractFunction = self.__interface_contract.functions.bondWorker(worker_address)
        receipt = self.blockchain.send_transaction(contract_function=contract_function, sender_address=self.__beneficiary)
        return receipt

    @contract_api(TRANSACTION)
    def release_worker(self) -> TxReceipt:
        receipt = self.bond_worker(worker_address=NULL_ADDRESS)
        return receipt

    @contract_api(TRANSACTION)
    def mint(self) -> TxReceipt:
        contract_function: ContractFunction = self.__interface_contract.functions.mint()
        receipt = self.blockchain.send_transaction(contract_function=contract_function, sender_address=self.__beneficiary)
        return receipt

    @contract_api(TRANSACTION)
    def collect_policy_fee(self) -> TxReceipt:
        contract_function: ContractFunction = self.__interface_contract.functions.withdrawPolicyFee()
        receipt = self.blockchain.send_transaction(contract_function=contract_function, sender_address=self.__beneficiary)
        return receipt

    @contract_api(TRANSACTION)
    def set_min_fee_rate(self, min_rate: Wei) -> TxReceipt:
        contract_function: ContractFunction = self.__interface_contract.functions.setMinFeeRate(min_rate)
        receipt = self.blockchain.send_transaction(contract_function=contract_function, sender_address=self.__beneficiary)
        return receipt

    @contract_api(TRANSACTION)
    def set_restaking(self, value: bool) -> TxReceipt:
        """
        Enable automatic restaking for a fixed duration of lock periods.
        If set to True, then all staking rewards will be automatically added to locked stake.
        """
        contract_function: ContractFunction = self.__interface_contract.functions.setReStake(value)
        receipt = self.blockchain.send_transaction(contract_function=contract_function, sender_address=self.__beneficiary)
        # TODO: Handle ReStakeSet event (see #1193)
        return receipt

    @contract_api(TRANSACTION)
    def lock_restaking(self, release_period: Period) -> TxReceipt:
        contract_function: ContractFunction = self.__interface_contract.functions.lockReStake(release_period)
        receipt = self.blockchain.send_transaction(contract_function=contract_function, sender_address=self.__beneficiary)
        # TODO: Handle ReStakeLocked event (see #1193)
        return receipt

    @contract_api(TRANSACTION)
    def set_winding_down(self, value: bool) -> TxReceipt:
        """
        Enable wind down for stake.
        If set to True, then the stake's duration will decrease each period with `commitToNextPeriod()`.
        """
        contract_function: ContractFunction = self.__interface_contract.functions.setWindDown(value)
        receipt = self.blockchain.send_transaction(contract_function=contract_function, sender_address=self.__beneficiary)
        # TODO: Handle WindDownSet event (see #1193)
        return receipt


class AdjudicatorAgent(EthereumContractAgent):

    contract_name: str = ADJUDICATOR_CONTRACT_NAME
    _proxy_name: str = DISPATCHER_CONTRACT_NAME

    @contract_api(TRANSACTION)
    def evaluate_cfrag(self, evidence: Evidence, sender_address: ChecksumAddress) -> TxReceipt:
        """Submits proof that a worker created wrong CFrag"""
        payload: TxParams = {'gas': Wei(500_000)}  # TODO #842: gas needed for use with geth.
        contract_function: ContractFunction = self.contract.functions.evaluateCFrag(*evidence.evaluation_arguments())
        receipt = self.blockchain.send_transaction(contract_function=contract_function,
                                                   sender_address=sender_address,
                                                   payload=payload)
        return receipt

    @contract_api(CONTRACT_CALL)
    def was_this_evidence_evaluated(self, evidence: Evidence) -> bool:
        data_hash: bytes = sha256_digest(evidence.task.capsule, evidence.task.cfrag)
        result: bool = self.contract.functions.evaluatedCFrags(data_hash).call()
        return result

    @property  # type: ignore
    @contract_api(CONTRACT_ATTRIBUTE)
    def staking_escrow_contract(self) -> ChecksumAddress:
        return self.contract.functions.escrow().call()

    @property  # type: ignore
    @contract_api(CONTRACT_ATTRIBUTE)
    def hash_algorithm(self) -> int:
        return self.contract.functions.hashAlgorithm().call()

    @property  # type: ignore
    @contract_api(CONTRACT_ATTRIBUTE)
    def base_penalty(self) -> int:
        return self.contract.functions.basePenalty().call()

    @property  # type: ignore
    @contract_api(CONTRACT_ATTRIBUTE)
    def penalty_history_coefficient(self) -> int:
        return self.contract.functions.penaltyHistoryCoefficient().call()

    @property  # type: ignore
    @contract_api(CONTRACT_ATTRIBUTE)
    def percentage_penalty_coefficient(self) -> int:
        return self.contract.functions.percentagePenaltyCoefficient().call()

    @property  # type: ignore
    @contract_api(CONTRACT_ATTRIBUTE)
    def reward_coefficient(self) -> int:
        return self.contract.functions.rewardCoefficient().call()

    @contract_api(CONTRACT_CALL)
    def penalty_history(self, staker_address: str) -> int:
        return self.contract.functions.penaltyHistory(staker_address).call()

    @contract_api(CONTRACT_CALL)
    def slashing_parameters(self) -> Tuple[int, ...]:
        parameter_signatures = (
            'hashAlgorithm',                    # Hashing algorithm
            'basePenalty',                      # Base for the penalty calculation
            'penaltyHistoryCoefficient',        # Coefficient for calculating the penalty depending on the history
            'percentagePenaltyCoefficient',     # Coefficient for calculating the percentage penalty
            'rewardCoefficient',                # Coefficient for calculating the reward
        )

        def _call_function_by_name(name: str) -> int:
            return getattr(self.contract.functions, name)().call()

        staking_parameters = tuple(map(_call_function_by_name, parameter_signatures))
        return staking_parameters


class WorkLockAgent(EthereumContractAgent):

    contract_name: str = WORKLOCK_CONTRACT_NAME
    _excluded_interfaces = ('shutdown', 'tokenDeposit')

    #
    # Transactions
    #

    @contract_api(TRANSACTION)
    def bid(self, value: Wei, checksum_address: ChecksumAddress) -> TxReceipt:
        """Bid for NU tokens with ETH."""
        contract_function: ContractFunction = self.contract.functions.bid()
        receipt = self.blockchain.send_transaction(contract_function=contract_function,
                                                   sender_address=checksum_address,
                                                   payload={'value': value})
        return receipt

    @contract_api(TRANSACTION)
    def cancel_bid(self, checksum_address: ChecksumAddress) -> TxReceipt:
        """Cancel bid and refund deposited ETH."""
        contract_function: ContractFunction = self.contract.functions.cancelBid()
        receipt = self.blockchain.send_transaction(contract_function=contract_function, sender_address=checksum_address)
        return receipt

    @contract_api(TRANSACTION)
    def force_refund(self, checksum_address: ChecksumAddress, addresses: List[ChecksumAddress]) -> TxReceipt:
        """Force refund to bidders who can get tokens more than maximum allowed."""
        addresses = sorted(addresses, key=str.casefold)
        contract_function: ContractFunction = self.contract.functions.forceRefund(addresses)
        receipt = self.blockchain.send_transaction(contract_function=contract_function, sender_address=checksum_address)
        return receipt

    @contract_api(TRANSACTION)
    def verify_bidding_correctness(self,
                                   checksum_address: ChecksumAddress,
                                   gas_limit: Wei,  # TODO - #842: Gas Management
                                   gas_to_save_state: Wei = Wei(30000)) -> TxReceipt:
        """Verify all bids are less than max allowed bid"""
        contract_function: ContractFunction = self.contract.functions.verifyBiddingCorrectness(gas_to_save_state)
        receipt = self.blockchain.send_transaction(contract_function=contract_function,
                                                   sender_address=checksum_address,
                                                   transaction_gas_limit=gas_limit)
        return receipt

    @contract_api(TRANSACTION)
    def claim(self, checksum_address: ChecksumAddress) -> TxReceipt:
        """
        Claim tokens - will be deposited and locked as stake in the StakingEscrow contract.
        """
        contract_function: ContractFunction = self.contract.functions.claim()
        receipt = self.blockchain.send_transaction(contract_function=contract_function,
                                                   sender_address=checksum_address,
                                                   gas_estimation_multiplier=1.5)  # FIXME
        return receipt

    @contract_api(TRANSACTION)
    def refund(self, checksum_address: ChecksumAddress) -> TxReceipt:
        """Refund ETH for completed work."""
        contract_function: ContractFunction = self.contract.functions.refund()
        receipt: TxReceipt = self.blockchain.send_transaction(contract_function=contract_function,
                                                              sender_address=checksum_address)
        return receipt

    @contract_api(TRANSACTION)
    def withdraw_compensation(self, checksum_address: ChecksumAddress) -> TxReceipt:
        """Withdraw compensation after force refund."""
        contract_function: ContractFunction = self.contract.functions.withdrawCompensation()
        receipt: TxReceipt = self.blockchain.send_transaction(contract_function=contract_function,
                                                              sender_address=checksum_address)
        return receipt

    @contract_api(CONTRACT_CALL)
    def check_claim(self, checksum_address: ChecksumAddress) -> bool:
        has_claimed: bool = bool(self.contract.functions.workInfo(checksum_address).call()[2])
        return has_claimed

    #
    # Internal
    #

    @contract_api(CONTRACT_CALL)
    def get_refunded_work(self, checksum_address: ChecksumAddress) -> Work:
        work = self.contract.functions.workInfo(checksum_address).call()[1]
        return Work(work)

    #
    # Calls
    #

    @contract_api(CONTRACT_CALL)
    def get_available_refund(self, checksum_address: ChecksumAddress) -> Wei:
        refund_eth: int = self.contract.functions.getAvailableRefund(checksum_address).call()
        return Wei(refund_eth)

    @contract_api(CONTRACT_CALL)
    def get_available_compensation(self, checksum_address: ChecksumAddress) -> Wei:
        compensation_eth: int = self.contract.functions.compensation(checksum_address).call()
        return Wei(compensation_eth)

    @contract_api(CONTRACT_CALL)
    def get_deposited_eth(self, checksum_address: ChecksumAddress) -> Wei:
        current_bid: int = self.contract.functions.workInfo(checksum_address).call()[0]
        return Wei(current_bid)

    @property  # type: ignore
    @contract_api(CONTRACT_ATTRIBUTE)
    def lot_value(self) -> NuNits:
        """
        Total number of tokens than can be bid for and awarded in or the number of NU
        tokens deposited before the bidding windows begins via tokenDeposit().
        """
        supply: int = self.contract.functions.tokenSupply().call()
        return NuNits(supply)

    @contract_api(CONTRACT_CALL)
    def get_bonus_lot_value(self) -> NuNits:
        """
        Total number of tokens than can be  awarded for bonus part of bid.
        """
        num_bidders: int = self.get_bidders_population()
        supply: int = self.lot_value - num_bidders * self.contract.functions.minAllowableLockedTokens().call()
        return NuNits(supply)

    @contract_api(CONTRACT_CALL)
    def get_remaining_work(self, checksum_address: str) -> Work:
        """Get remaining work periods until full refund for the target address."""
        result = self.contract.functions.getRemainingWork(checksum_address).call()
        return Work(result)

    @contract_api(CONTRACT_CALL)
    def get_bonus_eth_supply(self) -> Wei:
        supply = self.contract.functions.bonusETHSupply().call()
        return Wei(supply)

    @contract_api(CONTRACT_CALL)
    def get_eth_supply(self) -> Wei:
        num_bidders: int = self.get_bidders_population()
        min_bid: int = self.minimum_allowed_bid
        supply: int = num_bidders * min_bid + self.get_bonus_eth_supply()
        return Wei(supply)

    @property  # type: ignore
    @contract_api(CONTRACT_ATTRIBUTE)
    def boosting_refund(self) -> int:
        refund = self.contract.functions.boostingRefund().call()
        return refund

    @property  # type: ignore
    @contract_api(CONTRACT_ATTRIBUTE)
    def slowing_refund(self) -> int:
        refund: int = self.contract.functions.SLOWING_REFUND().call()
        return refund

    @contract_api(CONTRACT_CALL)
    def get_bonus_refund_rate(self) -> float:
        f = self.contract.functions
        slowing_refund: int = f.SLOWING_REFUND().call()
        boosting_refund: int = f.boostingRefund().call()
        refund_rate: float = self.get_bonus_deposit_rate() * slowing_refund / boosting_refund
        return refund_rate

    @contract_api(CONTRACT_CALL)
    def get_base_refund_rate(self) -> int:
        f = self.contract.functions
        slowing_refund = f.SLOWING_REFUND().call()
        boosting_refund = f.boostingRefund().call()
        refund_rate = self.get_base_deposit_rate() * slowing_refund / boosting_refund
        return refund_rate

    @contract_api(CONTRACT_CALL)
    def get_base_deposit_rate(self) -> int:
        min_allowed_locked_tokens: NuNits = self.contract.functions.minAllowableLockedTokens().call()
        deposit_rate: int = min_allowed_locked_tokens // self.minimum_allowed_bid  # should never divide by 0
        return deposit_rate

    @contract_api(CONTRACT_CALL)
    def get_bonus_deposit_rate(self) -> int:
        try:
            deposit_rate: int = self.get_bonus_lot_value() // self.get_bonus_eth_supply()
        except ZeroDivisionError:
            return 0
        return deposit_rate

    @contract_api(CONTRACT_CALL)
    def eth_to_tokens(self, value: Wei) -> NuNits:
        tokens: int = self.contract.functions.ethToTokens(value).call()
        return NuNits(tokens)

    @contract_api(CONTRACT_CALL)
    def eth_to_work(self, value: Wei) -> Work:
        tokens: int = self.contract.functions.ethToWork(value).call()
        return Work(tokens)

    @contract_api(CONTRACT_CALL)
    def work_to_eth(self, value: Work) -> Wei:
        wei: Wei = self.contract.functions.workToETH(value).call()
        return Wei(wei)

    @contract_api(CONTRACT_CALL)
    def get_bidders_population(self) -> int:
        """Returns the number of bidders on the blockchain"""
        return self.contract.functions.getBiddersLength().call()

    @contract_api(CONTRACT_CALL)
    def get_bidders(self) -> List[ChecksumAddress]:
        """Returns a list of bidders"""
        num_bidders: int = self.get_bidders_population()
        bidders: List[ChecksumAddress] = [self.contract.functions.bidders(i).call() for i in range(num_bidders)]
        return bidders

    @contract_api(CONTRACT_CALL)
    def is_claiming_available(self) -> bool:
        """Returns True if claiming is available"""
        result: bool = self.contract.functions.isClaimingAvailable().call()
        return result

    @contract_api(CONTRACT_CALL)
    def estimate_verifying_correctness(self, gas_limit: Wei, gas_to_save_state: Wei = Wei(30000)) -> int:  # TODO - #842: Gas Management
        """Returns how many bidders will be verified using specified gas limit"""
        return self.contract.functions.verifyBiddingCorrectness(gas_to_save_state).call({'gas': gas_limit})

    @contract_api(CONTRACT_CALL)
    def next_bidder_to_check(self) -> int:
        """Returns the index of the next bidder to check as part of the bids verification process"""
        return self.contract.functions.nextBidderToCheck().call()

    @contract_api(CONTRACT_CALL)
    def bidders_checked(self) -> bool:
        """Returns True if bidders have been checked"""
        bidders_population: int = self.get_bidders_population()
        return self.next_bidder_to_check() == bidders_population

    @property  # type: ignore
    @contract_api(CONTRACT_ATTRIBUTE)
    def minimum_allowed_bid(self) -> Wei:
        min_bid: Wei = self.contract.functions.minAllowedBid().call()
        return min_bid

    @property  # type: ignore
    @contract_api(CONTRACT_ATTRIBUTE)
    def start_bidding_date(self) -> Timestamp:
        date: int = self.contract.functions.startBidDate().call()
        return Timestamp(date)

    @property  # type: ignore
    @contract_api(CONTRACT_ATTRIBUTE)
    def end_bidding_date(self) -> Timestamp:
        date: int = self.contract.functions.endBidDate().call()
        return Timestamp(date)

    @property  # type: ignore
    @contract_api(CONTRACT_ATTRIBUTE)
    def end_cancellation_date(self) -> Timestamp:
        date: int = self.contract.functions.endCancellationDate().call()
        return Timestamp(date)

    @contract_api(CONTRACT_CALL)
    def worklock_parameters(self) -> WorklockParameters:
        parameter_signatures = (
            'tokenSupply',
            'startBidDate',
            'endBidDate',
            'endCancellationDate',
            'boostingRefund',
            'stakingPeriods',
            'minAllowedBid',
        )

        def _call_function_by_name(name: str) -> int:
            return getattr(self.contract.functions, name)().call()

        parameters = WorklockParameters(map(_call_function_by_name, parameter_signatures))
        return parameters


class MultiSigAgent(EthereumContractAgent):

    contract_name: str = MULTISIG_CONTRACT_NAME

    @property  # type: ignore
    @contract_api(CONTRACT_ATTRIBUTE)
    def nonce(self) -> Nonce:
        nonce: int = self.contract.functions.nonce().call()
        return Nonce(nonce)

    @contract_api(CONTRACT_CALL)
    def get_owner(self, index: int) -> ChecksumAddress:
        owner: ChecksumAddress = self.contract.functions.owners(index).call()
        return ChecksumAddress(owner)

    @property  # type: ignore
    @contract_api(CONTRACT_ATTRIBUTE)
    def number_of_owners(self) -> int:
        number: int = self.contract.functions.getNumberOfOwners().call()
        return number

    @property  # type: ignore
    def owners(self) -> Tuple[ChecksumAddress, ...]:
        return tuple(ChecksumAddress(self.get_owner(i)) for i in range(self.number_of_owners))

    @property  # type: ignore
    @contract_api(CONTRACT_ATTRIBUTE)
    def threshold(self) -> int:
        threshold: int = self.contract.functions.required().call()
        return threshold

    @contract_api(CONTRACT_CALL)
    def is_owner(self, checksum_address: ChecksumAddress) -> bool:
        result: bool = self.contract.functions.isOwner(checksum_address).call()
        return result

    @contract_api(TRANSACTION)
    def build_add_owner_tx(self, new_owner_address: ChecksumAddress) -> TxParams:
        max_owner_count: int = self.contract.functions.MAX_OWNER_COUNT().call()
        if not self.number_of_owners < max_owner_count:
            raise self.RequirementError(f"MultiSig already has the maximum number of owners")
        if new_owner_address == NULL_ADDRESS:
            raise self.RequirementError(f"Invalid MultiSig owner address (NULL ADDRESS)")
        if self.is_owner(new_owner_address):
            raise self.RequirementError(f"{new_owner_address} is already an owner of the MultiSig.")
        transaction_function: ContractFunction = self.contract.functions.addOwner(new_owner_address)
        transaction: TxParams = self.blockchain.build_contract_transaction(contract_function=transaction_function,
                                                                           sender_address=self.contract_address)
        return transaction

    @contract_api(TRANSACTION)
    def build_remove_owner_tx(self, owner_address: ChecksumAddress) -> TxParams:
        if not self.number_of_owners > self.threshold:
            raise self.RequirementError(f"Need at least one owner above the threshold to remove an owner.")
        if not self.is_owner(owner_address):
            raise self.RequirementError(f"{owner_address} is not owner of the MultiSig.")

        transaction_function: ContractFunction = self.contract.functions.removeOwner(owner_address)
        transaction: TxParams = self.blockchain.build_contract_transaction(contract_function=transaction_function,
                                                                           sender_address=self.contract_address)
        return transaction

    @contract_api(TRANSACTION)
    def build_change_threshold_tx(self, threshold: int) -> TxParams:
        if not 0 < threshold <= self.number_of_owners:
            raise self.RequirementError(f"New threshold {threshold} does not satisfy "
                                        f"0 < threshold ≤ number of owners = {self.number_of_owners}")
        transaction_function: ContractFunction = self.contract.functions.changeRequirement(threshold)
        transaction: TxParams = self.blockchain.build_contract_transaction(contract_function=transaction_function,
                                                                           sender_address=self.contract_address)
        return transaction

    @contract_api(CONTRACT_CALL)
    def get_unsigned_transaction_hash(self,
                                      trustee_address: ChecksumAddress,
                                      target_address: ChecksumAddress,
                                      value: Wei,
                                      data: bytes,
                                      nonce: Nonce
                                      ) -> HexBytes:
        transaction_args = trustee_address, target_address, value, data, nonce
        transaction_hash: bytes = self.contract.functions.getUnsignedTransactionHash(*transaction_args).call()
        return HexBytes(transaction_hash)

    @contract_api(TRANSACTION)
    def execute(self,
                v: List[str],  # TODO: Use bytes?
                r: List[str],
                s: List[str],
                destination: ChecksumAddress,
                value: Wei,
                data: Union[bytes, HexStr],
                sender_address: ChecksumAddress,
                ) -> TxReceipt:
        contract_function: ContractFunction = self.contract.functions.execute(v, r, s, destination, value, data)
        receipt: TxReceipt = self.blockchain.send_transaction(contract_function=contract_function,
                                                              sender_address=sender_address)
        return receipt


class InstanceAgent(EthereumContractAgent):
    """Base class for agents that interact with contracts instantiated by address"""

    # TODO: Consider combine InstanceAgent and EthereumContractAgent
    # see https://github.com/nucypher/nucypher/pull/2119#discussion_r472146989
    def __init__(self, address: str, abi: List[Dict] = None, provider_uri: str = None):
        blockchain = BlockchainInterfaceFactory.get_or_create_interface(provider_uri=provider_uri)
        if abi:
            contract = blockchain.client.w3.eth.contract(abi=abi, address=address)
        else:  # FIXME: This only works if the blockchain is a deployer interface (i.e. has the solidity compiler)
            contract = blockchain.get_contract_instance(contract_name=self.contract_name, address=address)
        super().__init__(contract=contract, provider_uri=provider_uri)


class AragonAgent(InstanceAgent):
    """Base agent for Aragon contracts that uses ABIs from artifact.json files"""

    def __init__(self, address: str, provider_uri: str = None):
        self.artifact = Artifact(name=self.contract_name)
        super().__init__(abi=self.artifact.abi, address=address, provider_uri=provider_uri)


class ForwarderAgent(AragonAgent):
    """Agent for Aragon apps that implement the Forwarder interface"""

    contract_name = FORWARDER_INTERFACE_NAME

    def _forward(self, callscript: bytes) -> ContractFunction:  # TODO: Generalize this approach
        return self.contract.functions.forward(callscript)

    @contract_api(TRANSACTION)
    def forward(self, callscript: bytes, sender_address: ChecksumAddress) -> TxReceipt:
        receipt = self.blockchain.send_transaction(contract_function=self._forward(callscript),
                                                   sender_address=sender_address)
        return TxReceipt(receipt)


class VotingAgent(ForwarderAgent):
    """Agent to interact with Aragon's Voting apps"""

    contract_name = VOTING_CONTRACT_NAME

    def _new_vote(self,
                  callscript: bytes,
                  metadata: str,
                  cast_vote: bool = None,
                  execute_if_decided: bool = None) -> ContractFunction:
        if cast_vote is None and execute_if_decided is None:
            return self.contract.functions.newVote(callscript, metadata)
        elif cast_vote is not None and execute_if_decided is not None:
            return self.contract.functions.newVote(callscript, metadata, cast_vote, execute_if_decided)
        else:
            raise ValueError("'cast_vote' and 'execute_if_decided' parameters need to be used in conjunction: "
                             "either use them both or don't use them.")

    @contract_api(TRANSACTION)
    def new_vote(self,
                 callscript: bytes,
                 metadata: str,
                 sender_address: ChecksumAddress,
                 cast_vote: bool = None,
                 execute_if_decided: bool = None) -> TxReceipt:
        contract_function = self._new_vote(callscript, metadata, cast_vote, execute_if_decided)
        receipt = self.blockchain.send_transaction(contract_function=contract_function, sender_address=sender_address)
        return TxReceipt(receipt)

    @contract_api(TRANSACTION)
    def vote(self, vote_id: int, support_proposal: bool, execute_if_decided: bool, sender_address: ChecksumAddress):
        contract_function = self.contract.functions.vote(vote_id, support_proposal, execute_if_decided)
        receipt = self.blockchain.send_transaction(contract_function=contract_function, sender_address=sender_address)
        return TxReceipt(receipt)


class VotingAggregatorAgent(ForwarderAgent):
    """Agent to interact with Aragon's Voting Aggregator app"""

    contract_name = VOTING_AGGREGATOR_CONTRACT_NAME


class TokenManagerAgent(ForwarderAgent):

    contract_name = TOKEN_MANAGER_CONTRACT_NAME

    def _mint(self, receiver_address: ChecksumAddress, amount: int) -> ContractFunction:
        function_call = self.contract.functions.mint(receiver_address, amount)
        return function_call

    def _issue(self, amount: int) -> ContractFunction:
        function_call = self.contract.functions.issue(amount)
        return function_call

    def _assign(self, receiver_address: ChecksumAddress, amount: int) -> ContractFunction:
        function_call = self.contract.functions.assign(receiver_address, amount)
        return function_call

    def _burn(self, holder_address: ChecksumAddress, amount: int) -> ContractFunction:
        function_call = self.contract.functions.burn(holder_address, amount)
        return function_call


class ContractAgency:
    """Where agents live and die."""

    # TODO: Enforce singleton - #1506 - Okay, actually, make this into a module
    __agents: Dict[str, Dict[Type[EthereumContractAgent], EthereumContractAgent]] = dict()

    @classmethod
    def get_agent(cls,
                  agent_class: Type[Agent],
                  registry: Optional[BaseContractRegistry] = None,
                  provider_uri: Optional[str] = None
                  ) -> Agent:

        if not issubclass(agent_class, EthereumContractAgent):
            raise TypeError(f"Only agent subclasses can be used from the agency.")

        if not registry:
            if len(cls.__agents) == 1:
                registry_id = list(cls.__agents.keys()).pop()
            else:
                raise ValueError("Need to specify a registry in order to get an agent from the ContractAgency")
        else:
            registry_id = registry.id
        try:
            return cast(Agent, cls.__agents[registry_id][agent_class])
        except KeyError:
            agent = cast(Agent, agent_class(registry=registry, provider_uri=provider_uri))
            cls.__agents[registry_id] = cls.__agents.get(registry_id, dict())
            cls.__agents[registry_id][agent_class] = agent
            return agent

    @staticmethod
    def _contract_name_to_agent_name(name: str) -> str:
        if name == NUCYPHER_TOKEN_CONTRACT_NAME:
            # TODO: Perhaps rename NucypherTokenAgent
            name = "NucypherToken"
        agent_name = f"{name}Agent"
        return agent_name

    @classmethod
    def get_agent_by_contract_name(cls,
                                   contract_name: str,
                                   registry: BaseContractRegistry,
                                   provider_uri: Optional[str] = None
                                   ) -> EthereumContractAgent:
        agent_name: str = cls._contract_name_to_agent_name(name=contract_name)
        agents_module = sys.modules[__name__]
        agent_class: Type[EthereumContractAgent] = getattr(agents_module, agent_name)
        agent: EthereumContractAgent = cls.get_agent(agent_class=agent_class, registry=registry, provider_uri=provider_uri)
        return agent


class StakersReservoir:

    def __init__(self, stakers_map: Dict[ChecksumAddress, int]):
        self._sampler = WeightedSampler(stakers_map)
        self._rng = random.SystemRandom()

    def __len__(self):
        return len(self._sampler)

    def draw(self, quantity):
        if quantity > len(self):
            raise StakingEscrowAgent.NotEnoughStakers(f'Cannot sample {quantity} out of {len(self)} total stakers')

        return self._sampler.sample_no_replacement(self._rng, quantity)

    def draw_at_most(self, quantity):
        return self.draw(min(quantity, len(self)))
