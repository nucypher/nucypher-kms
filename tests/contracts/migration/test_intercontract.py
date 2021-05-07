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
import os

import pytest
from eth_tester.exceptions import TransactionFailed
from web3.contract import Contract

from nucypher.blockchain.eth.constants import NULL_ADDRESS


FEE_FIELD = 0
PREVIOUS_FEE_PERIOD_FIELD = 1
FEE_RATE_FIELD = 2
MIN_FEE_RATE_FIELD = 3

POLICY_ID_LENGTH = 16


def test_intercontract_migration(testerchain, token_economics, token, deploy_contract):
    creator, alice, staker1, staker2, staker3, staker4, *everyone_else = testerchain.client.accounts

    # Give some ether to Alice
    tx = testerchain.client.send_transaction(
        {'from': testerchain.client.coinbase, 'to': alice, 'value': int(1e18)})
    testerchain.wait_for_receipt(tx)

    # Deploy Adjudicator and WorkLock mocks
    adjudicator, _ = deploy_contract('AdjudicatorForStakingEscrowMock', token_economics.reward_coefficient)
    worklock, _ = deploy_contract('WorkLockForStakingEscrowMock', token.address)

    # Deploy old StakingEscrow contract
    deploy_args = token_economics.staking_deployment_parameters
    deploy_args = (deploy_args[0], *deploy_args[2:])
    escrow_old_library, _ = deploy_contract(
        'StakingEscrowOld',
        token.address,
        *deploy_args,
        False  # testContract
    )
    escrow_dispatcher, _ = deploy_contract('Dispatcher', escrow_old_library.address)

    escrow = testerchain.client.get_contract(
        abi=escrow_old_library.abi,
        address=escrow_dispatcher.address,
        ContractFactoryClass=Contract)
    assert escrow.functions.secondsPerPeriod().call() == token_economics.genesis_seconds_per_period

    # Deploy old PolicyManager contract
    policy_manager_old_library, _ = deploy_contract(contract_name='PolicyManagerOld', _escrow=escrow.address)
    policy_manager_dispatcher, _ = deploy_contract('Dispatcher', policy_manager_old_library.address)

    policy_manager = testerchain.client.get_contract(
        abi=policy_manager_old_library.abi,
        address=policy_manager_dispatcher.address,
        ContractFactoryClass=Contract)
    assert policy_manager.functions.secondsPerPeriod().call() == token_economics.genesis_seconds_per_period

    tx = adjudicator.functions.setStakingEscrow(escrow.address).transact()
    testerchain.wait_for_receipt(tx)
    tx = worklock.functions.setStakingEscrow(escrow.address).transact()
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.setPolicyManager(policy_manager.address).transact()
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.setAdjudicator(adjudicator.address).transact()
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.setWorkLock(worklock.address).transact()
    testerchain.wait_for_receipt(tx)

    current_period = escrow.functions.getCurrentPeriod().call()
    testerchain.time_travel(hours=token_economics.genesis_hours_per_period)
    assert escrow.functions.getCurrentPeriod().call() == current_period + 1
    assert policy_manager.functions.getCurrentPeriod().call() == current_period + 1
    testerchain.time_travel(hours=token_economics.genesis_hours_per_period)
    assert escrow.functions.getCurrentPeriod().call() == current_period + 2
    assert policy_manager.functions.getCurrentPeriod().call() == current_period + 2

    # Initialize Escrow contract
    tx = token.functions.approve(escrow.address, token_economics.erc20_reward_supply).transact()
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.initialize(token_economics.erc20_reward_supply, creator).transact()
    testerchain.wait_for_receipt(tx)

    # Prepare stakers
    for staker in (staker1, staker2, staker3, staker4):
        max_stake_size = token_economics.maximum_allowed_locked
        tx = token.functions.transfer(staker, max_stake_size).transact()
        testerchain.wait_for_receipt(tx)
        tx = token.functions.approve(escrow.address, max_stake_size).transact({'from': staker})
        testerchain.wait_for_receipt(tx)

    first_period = escrow.functions.getCurrentPeriod().call()
    if first_period % 2 == 1:
        testerchain.time_travel(periods=1, periods_base=token_economics.genesis_seconds_per_period)
        first_period = escrow.functions.getCurrentPeriod().call()

    # First staker: unlocked tokens, minted everything, withdrew everything, cleaned data
    duration = token_economics.minimum_locked_periods
    stake_size = token_economics.minimum_allowed_locked
    tx = escrow.functions.deposit(staker1, stake_size, duration + 1).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.bondWorker(staker1).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.setWindDown(True).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)

    # Second staker: active staker but with downtimes
    tx = escrow.functions.deposit(staker2, stake_size, 4 * duration).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.bondWorker(staker2).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.setReStake(False).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.setWindDown(True).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)

    tx = escrow.functions.commitToNextPeriod().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    testerchain.time_travel(periods=1, periods_base=token_economics.genesis_seconds_per_period)

    # Create policies before migration
    policy_first_period = policy_manager.functions.getCurrentPeriod().call()
    policy_id = os.urandom(POLICY_ID_LENGTH)
    one_period = token_economics.genesis_seconds_per_period
    rate = 100
    current_timestamp = testerchain.w3.eth.getBlock('latest').timestamp
    end_timestamp = current_timestamp + (duration - 1) * one_period
    tx = policy_manager.functions.createPolicy(policy_id, alice, end_timestamp, [staker1])\
        .transact({'from': alice, 'value': duration * rate, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)

    policy_id_2 = os.urandom(POLICY_ID_LENGTH)
    end_timestamp = current_timestamp + (duration + 1 - 1) * one_period
    tx = policy_manager.functions.createPolicy(policy_id_2, alice, end_timestamp, [staker2])\
        .transact({'from': alice, 'value': (duration + 1) * rate, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)

    for i in range(duration):
        tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
        testerchain.wait_for_receipt(tx)
        testerchain.time_travel(periods=1, periods_base=token_economics.genesis_seconds_per_period)

    tx = escrow.functions.commitToNextPeriod().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)

    testerchain.time_travel(hours=token_economics.genesis_hours_per_period)
    current_period = escrow.functions.getCurrentPeriod().call()

    # Create policies to show refund and revoke before migration
    policy_id_3 = os.urandom(POLICY_ID_LENGTH)
    current_timestamp = testerchain.w3.eth.getBlock('latest').timestamp
    end_timestamp = current_timestamp + (duration - 1) * one_period
    tx = policy_manager.functions.createPolicy(policy_id_3, alice, end_timestamp, [staker1, staker2])\
        .transact({'from': alice, 'value': 4 * rate * duration, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)

    # Refund and revoke will work up to upgrade
    tx = policy_manager.functions.refund(policy_id_3, staker1).transact({'from': alice, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)
    tx = policy_manager.functions.revokeArrangement(policy_id_3, staker1).transact({'from': alice, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)

    tx = escrow.functions.mint().transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.removeUnusedSubStake(0).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.bondWorker(NULL_ADDRESS).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    stake_size_1 = escrow.functions.getAllTokens(staker1).call()
    tx = escrow.functions.withdraw(stake_size_1).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    assert escrow.functions.getLockedTokens(staker1, 0).call() == 0
    assert escrow.functions.getPastDowntimeLength(staker1).call() == 1
    assert escrow.functions.getLastCommittedPeriod(staker1).call() == current_period - 1

    tx = escrow.functions.commitToNextPeriod().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    assert escrow.functions.getLockedTokens(staker2, 0).call() == stake_size
    assert escrow.functions.getLockedTokens(staker2, 1).call() == stake_size
    assert escrow.functions.getLockedTokens(staker2, 2).call() == stake_size
    assert escrow.functions.getPastDowntimeLength(staker2).call() == 2
    assert escrow.functions.getLastCommittedPeriod(staker2).call() == current_period + 1

    # Third staker: just deposited before migration
    tx = escrow.functions.deposit(staker3, stake_size, 4 * duration).transact({'from': staker3})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.bondWorker(staker3).transact({'from': staker3})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.setWindDown(True).transact({'from': staker3})
    testerchain.wait_for_receipt(tx)
    assert escrow.functions.getPastDowntimeLength(staker3).call() == 0
    assert escrow.functions.getLastCommittedPeriod(staker3).call() == 0

    assert escrow.functions.lockedPerPeriod(current_period).call() != 0
    current_minting_period = escrow.functions.currentMintingPeriod().call()

    # Check prepared state in PolicyManager
    default_fee_delta = policy_manager.functions.DEFAULT_FEE_DELTA().call()
    some_policy_period = current_period
    assert policy_manager.functions.nodes(staker1).call()[FEE_FIELD] == rate * duration
    assert policy_manager.functions.nodes(staker1).call()[PREVIOUS_FEE_PERIOD_FIELD] == some_policy_period - 1
    assert policy_manager.functions.nodes(staker1).call()[FEE_RATE_FIELD] == 0
    assert policy_manager.functions.getNodeFeeDelta(staker1, policy_first_period).call() == 0
    assert policy_manager.functions.getNodeFeeDelta(staker1, policy_first_period + duration).call() == 0
    assert policy_manager.functions.getNodeFeeDelta(staker1, current_period).call() == 2 * rate
    assert policy_manager.functions.getNodeFeeDelta(staker1, current_period + 1).call() == -2 * rate
    assert policy_manager.functions.getNodeFeeDelta(staker1, current_period + duration).call() == default_fee_delta

    assert policy_manager.functions.nodes(staker2).call()[FEE_FIELD] == rate
    assert policy_manager.functions.nodes(staker2).call()[PREVIOUS_FEE_PERIOD_FIELD] == some_policy_period - 3
    assert policy_manager.functions.nodes(staker2).call()[FEE_RATE_FIELD] == rate
    assert policy_manager.functions.getNodeFeeDelta(staker2, policy_first_period).call() == 0
    assert policy_manager.functions.getNodeFeeDelta(staker2, current_period).call() == rate
    assert policy_manager.functions.getNodeFeeDelta(staker2, current_period + 1).call() == default_fee_delta
    assert policy_manager.functions.getNodeFeeDelta(staker2, current_period + duration).call() == -2 * rate

    assert policy_manager.functions.nodes(staker3).call()[FEE_FIELD] == 0
    assert policy_manager.functions.nodes(staker3).call()[PREVIOUS_FEE_PERIOD_FIELD] == some_policy_period - 1
    assert policy_manager.functions.nodes(staker3).call()[FEE_RATE_FIELD] == 0
    assert policy_manager.functions.getNodeFeeDelta(staker3, current_period + 1).call() == 0

    ##########
    # Deploy new version of contracts
    ##########
    deploy_args = token_economics.staking_deployment_parameters
    escrow_library, _ = deploy_contract(
        'StakingEscrow',
        token.address,
        policy_manager.address,
        adjudicator.address,
        worklock.address,
        *deploy_args)
    escrow = testerchain.client.get_contract(
        abi=escrow_library.abi,
        address=escrow_dispatcher.address,
        ContractFactoryClass=Contract)
    migration_log = escrow.events.Migrated.createFilter(fromBlock='latest')

    policy_manager_library, _ = deploy_contract(contract_name='PolicyManager',
                                                _escrowDispatcher=escrow.address,
                                                _escrowImplementation=escrow_library.address)
    policy_manager = testerchain.client.get_contract(
        abi=policy_manager_library.abi,
        address=policy_manager_dispatcher.address,
        ContractFactoryClass=Contract)

    current_period = escrow.functions.getCurrentPeriod().call()
    tx = escrow_dispatcher.functions.upgrade(escrow_library.address).transact()
    testerchain.wait_for_receipt(tx)
    tx = policy_manager_dispatcher.functions.upgrade(policy_manager_library.address).transact()
    testerchain.wait_for_receipt(tx)

    assert escrow.functions.secondsPerPeriod().call() == token_economics.seconds_per_period
    assert escrow.functions.genesisSecondsPerPeriod().call() == token_economics.genesis_seconds_per_period
    assert escrow.functions.getCurrentPeriod().call() == current_period // 2
    assert policy_manager.functions.secondsPerPeriod().call() == token_economics.seconds_per_period
    assert policy_manager.functions.genesisSecondsPerPeriod().call() == token_economics.genesis_seconds_per_period
    assert policy_manager.functions.getCurrentPeriod().call() == current_period // 2

    reset_timestamp = testerchain.w3.eth.getBlock('latest').timestamp
    assert policy_manager.functions.resetTimestamp().call() == reset_timestamp
    assert policy_manager_library.functions.resetTimestamp().call() == 0

    assert escrow.functions.lockedPerPeriod(current_period).call() == 0
    assert escrow.functions.lockedPerPeriod(current_period - 1).call() == 0
    assert escrow.functions.lockedPerPeriod(current_period + 1).call() == 0
    assert escrow.functions.currentMintingPeriod().call() == current_minting_period // 2
    assert escrow.functions.getActiveStakers(1, 0, 0).call() == [0, []]
    current_period = escrow.functions.getCurrentPeriod().call()
    assert escrow.functions.lockedPerPeriod(current_period).call() == 0
    assert escrow.functions.lockedPerPeriod(current_period - 1).call() == 0
    assert escrow.functions.lockedPerPeriod(current_period + 1).call() == 0

    for staker in (staker1, staker2, staker3):
        for period in range(5 * duration):
            assert policy_manager.functions.getNodeFeeDelta(staker, period).call() == 0
            assert policy_manager.functions.getNodeFeeDelta(staker, period // 2).call() == 0
        assert policy_manager.functions.getNodeFeeDelta(staker, current_period).call() == 0
        assert policy_manager.functions.getNodeFeeDelta(staker, current_period + 1).call() == 0

    # Staker can't do almost anything before migration
    for staker in (staker1, staker2, staker3):
        assert escrow.functions.getLockedTokens(staker, 0).call() == 0
        assert escrow.functions.getLockedTokens(staker, 1).call() == 0
        _wind_down, _re_stake, _measure_work, _snapshots, migrated = escrow.functions.getFlags(staker).call()
        assert not migrated
        with pytest.raises((TransactionFailed, ValueError)):
            tx = escrow.functions.withdraw(1).transact({'from': staker})
            testerchain.wait_for_receipt(tx)
        with pytest.raises((TransactionFailed, ValueError)):
            tx = escrow.functions.deposit(staker, stake_size, duration).transact({'from': staker})
            testerchain.wait_for_receipt(tx)

    # After upgrade can't refund/revoke old policies
    with pytest.raises((TransactionFailed, ValueError)):
        tx = policy_manager.functions.refund(policy_id_3, staker2).transact({'from': alice, 'gas_price': 0})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = policy_manager.functions.revokeArrangement(policy_id_3, staker2).transact({'from': alice, 'gas_price': 0})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = policy_manager.functions.refund(policy_id_3).transact({'from': alice, 'gas_price': 0})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = policy_manager.functions.revokePolicy(policy_id_3).transact({'from': alice, 'gas_price': 0})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = policy_manager.functions.refund(policy_id_2).transact({'from': alice, 'gas_price': 0})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = policy_manager.functions.revokePolicy(policy_id_2).transact({'from': alice, 'gas_price': 0})
        testerchain.wait_for_receipt(tx)

    # And can't create policies for not migrated nodes
    policy_id_4 = os.urandom(POLICY_ID_LENGTH)
    one_period = token_economics.seconds_per_period
    current_timestamp = testerchain.w3.eth.getBlock('latest').timestamp
    end_timestamp = current_timestamp + (duration - 1) * one_period
    with pytest.raises((TransactionFailed, ValueError)):
        tx = policy_manager.functions.createPolicy(policy_id_4, alice, end_timestamp, [staker1, staker2, staker3])\
            .transact({'from': alice, 'value': 3 * rate * duration, 'gas_price': 0})
        testerchain.wait_for_receipt(tx)

    ##########
    # Fresh staker
    ##########

    assert policy_manager.functions.nodes(staker4).call()[PREVIOUS_FEE_PERIOD_FIELD] == 0
    tx = escrow.functions.deposit(staker4, stake_size, duration).transact({'from': staker4})
    testerchain.wait_for_receipt(tx)
    *other_flags, migrated = escrow.functions.getFlags(staker4).call()
    assert migrated
    assert escrow.functions.getSubStakesLength(staker4).call() == 1
    sub_stake = escrow.functions.getSubStakeInfo(staker4, 0).call()
    assert sub_stake == [current_period + 1, 0, duration, stake_size]
    staker_info = escrow.functions.stakerInfo(staker4).call()[0:8]
    assert staker_info == [stake_size, 0, 0, 0, 0, 0, 0, NULL_ADDRESS]

    tx = escrow.functions.bondWorker(staker4).transact({'from': staker4})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker4})
    testerchain.wait_for_receipt(tx)
    assert policy_manager.functions.nodes(staker4).call()[PREVIOUS_FEE_PERIOD_FIELD] == current_period - 1
    assert policy_manager.functions.getNodeFeeDelta(staker4, current_period + 1).call() == default_fee_delta

    tx = escrow.functions.migrate(staker4).transact()
    testerchain.wait_for_receipt(tx)
    assert len(migration_log.get_all_entries()) == 0

    ##########
    # Time to migrate
    ##########
    # Staker who has nothing
    ##########
    wind_down, re_stake, measure_work, snapshots, migrated = escrow.functions.getFlags(staker1).call()
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
        testerchain.wait_for_receipt(tx)

    tx = escrow.functions.migrate(staker1).transact()
    testerchain.wait_for_receipt(tx)
    assert escrow.functions.getFlags(staker1).call() == [wind_down, re_stake, measure_work, snapshots, True]
    assert escrow.functions.getLastCommittedPeriod(staker1).call() == 1
    assert escrow.functions.getPastDowntimeLength(staker1).call() == 0
    assert escrow.functions.getSubStakesLength(staker1).call() == 0
    assert escrow.functions.getLockedTokens(staker1, 0).call() == 0
    staker_info = escrow.functions.stakerInfo(staker1).call()[0:8]
    assert staker_info == [0, 0, 0, 1, 0, 0, (first_period + duration + 2) // 2, NULL_ADDRESS]

    assert policy_manager.functions.nodes(staker1).call()[FEE_FIELD] == rate * duration
    assert policy_manager.functions.nodes(staker1).call()[PREVIOUS_FEE_PERIOD_FIELD] == (some_policy_period - 1) // 2
    assert policy_manager.functions.nodes(staker1).call()[FEE_RATE_FIELD] == 0

    tx = escrow.functions.migrate(staker1).transact()
    testerchain.wait_for_receipt(tx)
    assert escrow.functions.getLastCommittedPeriod(staker1).call() == 1

    events = migration_log.get_all_entries()
    assert len(events) == 1
    event_args = events[0]['args']
    assert event_args['staker'] == staker1
    assert event_args['period'] == current_period

    tx = escrow.functions.deposit(staker1, stake_size, duration).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    _wind_down, _re_stake, _measure_work, _snapshots, migrated = escrow.functions.getFlags(staker1).call()
    assert migrated
    assert policy_manager.functions.nodes(staker1).call()[PREVIOUS_FEE_PERIOD_FIELD] == (some_policy_period - 1) // 2

    # ##########
    # # Active staker with downtimes
    # ##########
    current_period = escrow.functions.getCurrentPeriod().call()

    stake_2 = escrow.functions.getAllTokens(staker2).call()
    wind_down, re_stake, measure_work, snapshots, migrated = escrow.functions.getFlags(staker2).call()
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)

    assert escrow.functions.getFlags(staker2).call() == [wind_down, re_stake, measure_work, snapshots, True]
    assert escrow.functions.getLastCommittedPeriod(staker2).call() == current_period + 1
    assert escrow.functions.getPastDowntimeLength(staker2).call() == 1
    assert escrow.functions.getPastDowntime(staker2, 0).call() == [2, current_period]
    assert escrow.functions.getSubStakesLength(staker2).call() == 1
    sub_stake = escrow.functions.getSubStakeInfo(staker2, 0).call()
    assert sub_stake == [(first_period + 1) // 2, 0, (4 * duration - 3) // 2 - 1, stake_size]
    assert escrow.functions.getLockedTokens(staker2, 0).call() == stake_size
    assert escrow.functions.getLockedTokens(staker2, 1).call() == stake_size
    assert escrow.functions.getLockedTokens(staker2, 2).call() == stake_size
    assert escrow.functions.getLockedTokens(staker2, 3).call() == 0
    staker_info = escrow.functions.stakerInfo(staker2).call()[0:8]
    assert staker_info == [stake_2, 0, current_period + 1, 1, 0, 0, first_period // 2, staker2]

    assert policy_manager.functions.nodes(staker2).call()[FEE_FIELD] == rate
    assert policy_manager.functions.nodes(staker2).call()[PREVIOUS_FEE_PERIOD_FIELD] == current_period - 1
    assert policy_manager.functions.nodes(staker2).call()[FEE_RATE_FIELD] == 0

    tx = escrow.functions.migrate(staker2).transact()
    testerchain.wait_for_receipt(tx)
    assert escrow.functions.getLastCommittedPeriod(staker2).call() == current_period + 1
    assert policy_manager.functions.nodes(staker2).call()[PREVIOUS_FEE_PERIOD_FIELD] == current_period - 1

    events = migration_log.get_all_entries()
    assert len(events) == 2
    event_args = events[1]['args']
    assert event_args['staker'] == staker2
    assert event_args['period'] == current_period

    ##########
    # Semi-fresh staker
    ##########

    stake_3 = escrow.functions.getAllTokens(staker3).call()
    wind_down, re_stake, measure_work, snapshots, migrated = escrow.functions.getFlags(staker3).call()
    tx = escrow.functions.migrate(staker3).transact()
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker3})
    testerchain.wait_for_receipt(tx)

    assert escrow.functions.getFlags(staker3).call() == [wind_down, re_stake, measure_work, snapshots, True]
    assert escrow.functions.getLastCommittedPeriod(staker3).call() == current_period + 1
    assert escrow.functions.getPastDowntimeLength(staker3).call() == 1
    assert escrow.functions.getPastDowntime(staker3, 0).call() == [2, current_period]
    assert escrow.functions.getSubStakesLength(staker3).call() == 1
    sub_stake = escrow.functions.getSubStakeInfo(staker3, 0).call()
    assert sub_stake == [(first_period + 4) // 2, 0, 2 * duration - 1, stake_size]
    assert escrow.functions.getLockedTokens(staker3, 0).call() == stake_size
    assert escrow.functions.getLockedTokens(staker3, 1).call() == stake_size
    assert escrow.functions.getLockedTokens(staker3, 2).call() == stake_size
    staker_info = escrow.functions.stakerInfo(staker3).call()[0:8]
    assert staker_info == [stake_3, 0, current_period + 1, 1, 0, 0, (first_period + 4) // 2, staker3]

    assert policy_manager.functions.nodes(staker3).call()[FEE_FIELD] == 0
    assert policy_manager.functions.nodes(staker3).call()[PREVIOUS_FEE_PERIOD_FIELD] == (some_policy_period - 1) // 2
    assert policy_manager.functions.nodes(staker3).call()[FEE_RATE_FIELD] == 0

    tx = escrow.functions.migrate(staker3).transact()
    testerchain.wait_for_receipt(tx)
    assert escrow.functions.getLastCommittedPeriod(staker3).call() == current_period + 1
    assert policy_manager.functions.nodes(staker3).call()[PREVIOUS_FEE_PERIOD_FIELD] == (some_policy_period - 1) // 2

    events = migration_log.get_all_entries()
    assert len(events) == 3
    event_args = events[2]['args']
    assert event_args['staker'] == staker3
    assert event_args['period'] == current_period

    # Now we can use stakers
    tx = policy_manager.functions.createPolicy(policy_id_4, alice, end_timestamp, [staker1, staker2, staker3]) \
        .transact({'from': alice, 'value': 3 * rate * duration, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)

    # And can revoke new policies
    tx = policy_manager.functions.refund(policy_id_4).transact({'from': alice, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)
    tx = policy_manager.functions.revokePolicy(policy_id_4).transact({'from': alice, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)

    # Time machine test
    testerchain.time_travel(periods=1, periods_base=token_economics.seconds_per_period)
    current_period = escrow.functions.getCurrentPeriod().call()
    testerchain.time_travel(hours=token_economics.genesis_hours_per_period)
    assert escrow.functions.getCurrentPeriod().call() == current_period
    assert policy_manager.functions.getCurrentPeriod().call() == current_period
    testerchain.time_travel(hours=token_economics.genesis_hours_per_period)
    assert escrow.functions.getCurrentPeriod().call() == current_period + 1
    assert policy_manager.functions.getCurrentPeriod().call() == current_period + 1
    testerchain.time_travel(hours=token_economics.hours_per_period)
    assert escrow.functions.getCurrentPeriod().call() == current_period + 2
    assert policy_manager.functions.getCurrentPeriod().call() == current_period + 2

    ##########
    # Upgrade again and check that resetTimestamp won't change
    ##########
    tx = escrow_dispatcher.functions.upgrade(escrow_library.address).transact()
    testerchain.wait_for_receipt(tx)
    assert escrow.functions.genesisSecondsPerPeriod().call() == token_economics.genesis_seconds_per_period
    assert escrow.functions.secondsPerPeriod().call() == token_economics.seconds_per_period

    tx = policy_manager_dispatcher.functions.upgrade(policy_manager_library.address).transact()
    testerchain.wait_for_receipt(tx)
    assert policy_manager.functions.resetTimestamp().call() == reset_timestamp
    assert policy_manager.functions.genesisSecondsPerPeriod().call() == token_economics.genesis_seconds_per_period
    assert policy_manager.functions.secondsPerPeriod().call() == token_economics.seconds_per_period

    deploy_args = token_economics.staking_deployment_parameters
    deploy_args = (token_economics.hours_per_period,
                   2 * token_economics.hours_per_period,
                   *deploy_args[2:])
    escrow_2_library, _ = deploy_contract(
        'StakingEscrow',
        token.address,
        policy_manager.address,
        adjudicator.address,
        worklock.address,
        *deploy_args)
    policy_manager_2_library, _ = deploy_contract(contract_name='PolicyManager',
                                                  _escrowDispatcher=escrow.address,
                                                  _escrowImplementation=escrow_2_library.address)

    current_period = escrow.functions.getCurrentPeriod().call()
    tx = escrow_dispatcher.functions.upgrade(escrow_2_library.address).transact()
    testerchain.wait_for_receipt(tx)
    tx = policy_manager_dispatcher.functions.upgrade(policy_manager_2_library.address).transact()
    testerchain.wait_for_receipt(tx)

    assert escrow.functions.genesisSecondsPerPeriod().call() == token_economics.seconds_per_period
    assert escrow.functions.secondsPerPeriod().call() == 2 * token_economics.seconds_per_period
    assert escrow.functions.getCurrentPeriod().call() == current_period // 2
    assert policy_manager.functions.resetTimestamp().call() == reset_timestamp
    assert policy_manager.functions.genesisSecondsPerPeriod().call() == token_economics.seconds_per_period
    assert policy_manager.functions.secondsPerPeriod().call() == 2 * token_economics.seconds_per_period
    assert policy_manager.functions.getCurrentPeriod().call() == current_period // 2
