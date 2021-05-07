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
from eth_tester.exceptions import TransactionFailed
from web3.contract import Contract

from nucypher.blockchain.eth.constants import NULL_ADDRESS


def test_minting(testerchain, token, escrow_contract, token_economics):

    escrow = escrow_contract(1500)
    policy_manager_interface = testerchain.get_contract_factory('PolicyManagerForStakingEscrowMock')
    policy_manager = testerchain.client.get_contract(
        abi=policy_manager_interface.abi,
        address=escrow.functions.policyManager().call(),
        ContractFactoryClass=Contract)
    creator = testerchain.client.accounts[0]
    staker1 = testerchain.client.accounts[1]
    staker2 = testerchain.client.accounts[2]

    current_supply = token_economics.erc20_initial_supply

    def calculate_reward(locked, total_locked, locked_periods):
        return token_economics.first_phase_max_issuance * locked * \
               (locked_periods + token_economics.lock_duration_coefficient_1) // \
               (total_locked * token_economics.lock_duration_coefficient_2)

    staking_log = escrow.events.Minted.createFilter(fromBlock='latest')
    deposit_log = escrow.events.Deposited.createFilter(fromBlock='latest')
    lock_log = escrow.events.Locked.createFilter(fromBlock='latest')
    commitments_log = escrow.events.CommitmentMade.createFilter(fromBlock='latest')
    divides_log = escrow.events.Divided.createFilter(fromBlock='latest')
    withdraw_log = escrow.events.Withdrawn.createFilter(fromBlock='latest')
    worker_log = escrow.events.WorkerBonded.createFilter(fromBlock='latest')

    # Give Escrow tokens for reward and initialize contract
    tx = token.functions.approve(escrow.address, token_economics.erc20_reward_supply).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.initialize(token_economics.erc20_reward_supply, creator).transact({'from': creator})
    testerchain.wait_for_receipt(tx)

    # Give Staker and Staker(2) some coins
    tx = token.functions.transfer(staker1, 10000).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    tx = token.functions.transfer(staker2, 850).transact({'from': creator})
    testerchain.wait_for_receipt(tx)

    # Staker can't make a commitment and mint because no locked tokens
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.mint().transact({'from': staker1})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
        testerchain.wait_for_receipt(tx)

    # Staker and Staker(2) give Escrow rights to transfer
    tx = token.functions.approve(escrow.address, 2000).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tx = token.functions.approve(escrow.address, 750).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)

    # Staker and Staker(2) transfer some tokens to the escrow and lock them
    current_period = escrow.functions.getCurrentPeriod().call()
    staker1_stake = 1000
    staker2_stake = 500
    tx = escrow.functions.deposit(staker1, staker1_stake, 2).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.bondWorker(staker1).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.setReStake(False).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.setWindDown(True).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.deposit(staker2, staker2_stake, 2).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.bondWorker(staker2).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.setReStake(False).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.setWindDown(True).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    assert 0 == escrow.functions.findIndexOfPastDowntime(staker2, 0).call()
    assert 0 == escrow.functions.findIndexOfPastDowntime(staker2, current_period + 1).call()
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    assert 0 == escrow.functions.findIndexOfPastDowntime(staker2, 0).call()
    assert 1 == escrow.functions.findIndexOfPastDowntime(staker2, current_period + 1).call()
    # Check parameters in call of the policy manager mock
    assert policy_manager.functions.getPeriodsLength(staker1).call() == 4
    assert policy_manager.functions.getPeriodsLength(staker2).call() == 4
    assert policy_manager.functions.getPeriod(staker1, 0).call() == current_period - 1
    assert policy_manager.functions.getPeriod(staker2, 0).call() == current_period - 1
    assert policy_manager.functions.getPeriod(staker1, 1).call() == 0
    assert policy_manager.functions.getPeriod(staker2, 1).call() == 0
    assert policy_manager.functions.getPeriod(staker1, 2).call() == 0
    assert policy_manager.functions.getPeriod(staker2, 2).call() == 0
    assert policy_manager.functions.getPeriod(staker1, 3).call() == current_period + 1
    assert policy_manager.functions.getPeriod(staker2, 3).call() == current_period + 1
    # Check downtime parameters
    assert 1 == escrow.functions.getPastDowntimeLength(staker1).call()
    downtime = escrow.functions.getPastDowntime(staker1, 0).call()
    assert 1 == downtime[0]
    assert current_period == downtime[1]
    assert 1 == escrow.functions.getPastDowntimeLength(staker2).call()
    downtime = escrow.functions.getPastDowntime(staker2, 0).call()
    assert 1 == downtime[0]
    assert current_period == downtime[1]
    assert current_period + 1 == escrow.functions.getLastCommittedPeriod(staker1).call()
    assert current_period + 1 == escrow.functions.getLastCommittedPeriod(staker2).call()

    # Staker divides her stake
    tx = escrow.functions.divideStake(0, 500, 1).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)

    # Can't use methods from Issuer contract directly
    with pytest.raises(Exception):
        tx = escrow.functions.mint(1, 1, 1, 1).transact({'from': staker1})
        testerchain.wait_for_receipt(tx)
    with pytest.raises(Exception):
        tx = escrow.functions.unMint(1).transact({'from': staker1})
        testerchain.wait_for_receipt(tx)

    # Only Staker makes a commitment to next period
    testerchain.time_travel(hours=10)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    current_period = escrow.functions.getCurrentPeriod().call()
    assert 1 == escrow.functions.getPastDowntimeLength(staker1).call()
    assert policy_manager.functions.getPeriodsLength(staker1).call() == 7
    assert policy_manager.functions.getPeriod(staker1, 4).call() == 0
    assert policy_manager.functions.getPeriod(staker1, 5).call() == 0
    assert policy_manager.functions.getPeriod(staker1, 6).call() == current_period + 1

    # Can't commit more than once
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
        testerchain.wait_for_receipt(tx)
    assert policy_manager.functions.getPeriodsLength(staker1).call() == 7

    # Staker and Staker(2) mint tokens for last periods
    # And only Staker make a commitment to next period
    testerchain.time_travel(hours=10)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    current_period = escrow.functions.getCurrentPeriod().call()
    assert policy_manager.functions.getPeriodsLength(staker1).call() == 10
    assert policy_manager.functions.getPeriod(staker1, 7).call() == current_period - 1
    assert policy_manager.functions.getPeriod(staker1, 8).call() == 0
    assert policy_manager.functions.getPeriod(staker1, 9).call() == current_period + 1

    tx = escrow.functions.mint(staker2).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    assert policy_manager.functions.getPeriodsLength(staker2).call() == 7
    assert policy_manager.functions.getPeriod(staker2, 4).call() == 0
    assert policy_manager.functions.getPeriod(staker2, 5).call() == current_period - 1
    assert policy_manager.functions.getPeriod(staker2, 6).call() == 0

    # Check result of minting
    total_locked = staker1_stake + staker2_stake
    ursula1_reward = calculate_reward(500, total_locked, 1) + calculate_reward(500, total_locked, 2)
    assert staker1_stake + ursula1_reward == escrow.functions.getAllTokens(staker1).call()
    ursula2_reward = calculate_reward(500, total_locked, 2)
    assert staker2_stake + ursula2_reward == escrow.functions.getAllTokens(staker2).call()
    # Check that downtime value has not changed
    assert 1 == escrow.functions.getPastDowntimeLength(staker1).call()
    assert 1 == escrow.functions.getPastDowntimeLength(staker2).call()
    assert current_period + 1 == escrow.functions.getLastCommittedPeriod(staker1).call()
    assert current_period - 1 == escrow.functions.getLastCommittedPeriod(staker2).call()

    events = staking_log.get_all_entries()
    assert 2 == len(events)
    event_args = events[0]['args']
    assert staker1 == event_args['staker']
    assert ursula1_reward == event_args['value']
    assert escrow.functions.getCurrentPeriod().call() - 1 == event_args['period']
    event_args = events[1]['args']
    assert staker2 == event_args['staker']
    assert ursula2_reward == event_args['value']
    assert escrow.functions.getCurrentPeriod().call() - 1 == event_args['period']

    # Staker tries to mint again and doesn't receive a reward
    # There are no more committed periods that are ready to mint
    staker1_stake += ursula1_reward
    staker2_stake += ursula2_reward
    tx = escrow.functions.mint().transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    assert staker1_stake == escrow.functions.getAllTokens(staker1).call()
    events = staking_log.get_all_entries()
    assert 2 == len(events)
    assert policy_manager.functions.getPeriodsLength(staker1).call() == 10

    # Staker can't make a commitment to next period because stake is unlocked in current period
    testerchain.time_travel(hours=10)
    current_supply += ursula1_reward + ursula2_reward
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
        testerchain.wait_for_receipt(tx)
    # But Staker(2) can
    current_period = escrow.functions.getCurrentPeriod().call()
    assert current_period - 2 == escrow.functions.getLastCommittedPeriod(staker2).call()
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)

    assert current_period + 1 == escrow.functions.getLastCommittedPeriod(staker2).call()
    assert 2 == escrow.functions.getPastDowntimeLength(staker2).call()
    downtime = escrow.functions.getPastDowntime(staker2, 1).call()
    assert current_period - 1 == downtime[0]
    assert current_period == downtime[1]

    assert policy_manager.functions.getPeriodsLength(staker2).call() == 10
    assert policy_manager.functions.getPeriod(staker2, 7).call() == 0
    assert policy_manager.functions.getPeriod(staker2, 8).call() == 0
    assert policy_manager.functions.getPeriod(staker2, 9).call() == current_period + 1

    # Staker mints tokens
    testerchain.time_travel(hours=10)
    tx = escrow.functions.mint(staker1).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    # But Staker(2) can't get reward because she did not make a commitment
    tx = escrow.functions.mint().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    ursula1_reward = calculate_reward(500, 1000, 0) + calculate_reward(500, 1000, 1) + calculate_reward(500, 500, 0)
    assert staker1_stake + ursula1_reward == escrow.functions.getAllTokens(staker1).call()
    assert staker2_stake == escrow.functions.getAllTokens(staker2).call()
    staker1_stake += ursula1_reward

    events = staking_log.get_all_entries()
    assert 3 == len(events)
    event_args = events[2]['args']
    assert staker1 == event_args['staker']
    assert ursula1_reward == event_args['value']
    assert current_period == event_args['period']

    current_period = escrow.functions.getCurrentPeriod().call()
    assert policy_manager.functions.getPeriodsLength(staker2).call() == 10
    assert policy_manager.functions.getPeriodsLength(staker1).call() == 13
    assert policy_manager.functions.getPeriod(staker1, 10).call() == current_period - 2
    assert policy_manager.functions.getPeriod(staker1, 11).call() == current_period - 1
    assert policy_manager.functions.getPeriod(staker1, 12).call() == 0

    # Staker(2) mints tokens
    testerchain.time_travel(hours=10)
    current_supply += ursula1_reward
    tx = escrow.functions.mint().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    ursula2_reward = calculate_reward(500, 500, 0)
    assert staker1_stake == escrow.functions.getAllTokens(staker1).call()
    assert staker2_stake + ursula2_reward == escrow.functions.getAllTokens(staker2).call()
    staker2_stake += ursula2_reward

    events = staking_log.get_all_entries()
    assert 4 == len(events)
    event_args = events[3]['args']
    assert staker2 == event_args['staker']
    assert ursula2_reward == event_args['value']
    assert escrow.functions.getCurrentPeriod().call() - 1 == event_args['period']

    current_period = escrow.functions.getCurrentPeriod().call()
    assert policy_manager.functions.getPeriodsLength(staker1).call() == 13
    assert policy_manager.functions.getPeriodsLength(staker2).call() == 13
    assert policy_manager.functions.getPeriod(staker2, 10).call() == 0
    assert policy_manager.functions.getPeriod(staker2, 11).call() == current_period - 1
    assert policy_manager.functions.getPeriod(staker2, 12).call() == 0

    # Staker(2) can't make a commitment because stake is unlocked
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.commitToNextPeriod().transact({'from': staker2})
        testerchain.wait_for_receipt(tx)

    # Staker can't make a commitment and get reward because no locked tokens
    tx = escrow.functions.mint().transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    current_period = escrow.functions.getCurrentPeriod().call()
    assert current_period - 2 == escrow.functions.getLastCommittedPeriod(staker1).call()
    assert staker1_stake == escrow.functions.getAllTokens(staker1).call()
    # Staker still can't make a commitment
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
        testerchain.wait_for_receipt(tx)

    assert policy_manager.functions.getPeriodsLength(staker1).call() == 13

    # Staker(2) deposits and locks more tokens
    tx = escrow.functions.deposit(staker2, 250, 4).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.lockAndCreate(500, 2).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    staker2_stake += 250

    assert 3 == escrow.functions.getPastDowntimeLength(staker2).call()
    downtime = escrow.functions.getPastDowntime(staker2, 2).call()
    assert current_period == downtime[0]
    assert current_period == downtime[1]

    # Staker(2) mints only one period
    testerchain.time_travel(hours=50)
    current_supply += ursula2_reward
    current_period = escrow.functions.getCurrentPeriod().call()
    assert current_period - 4 == escrow.functions.getLastCommittedPeriod(staker2).call()
    tx = token.functions.approveAndCall(escrow.address, 100, testerchain.w3.toBytes(2))\
        .transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    staker2_stake += 100
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)

    ursula2_reward = calculate_reward(250, 750, 4) + calculate_reward(500, 750, 4)
    assert staker1_stake == escrow.functions.getAllTokens(staker1).call()
    assert staker2_stake + ursula2_reward == escrow.functions.getAllTokens(staker2).call()
    assert 4 == escrow.functions.getPastDowntimeLength(staker2).call()
    downtime = escrow.functions.getPastDowntime(staker2, 3).call()
    assert current_period - 3 == downtime[0]
    assert current_period == downtime[1]
    staker2_stake += ursula2_reward

    assert policy_manager.functions.getPeriodsLength(staker2).call() == 19
    assert policy_manager.functions.getPeriod(staker2, 16).call() == 0
    assert policy_manager.functions.getPeriod(staker2, 17).call() == current_period - 4
    assert policy_manager.functions.getPeriod(staker2, 18).call() == current_period + 1

    events = staking_log.get_all_entries()
    assert 5 == len(events)
    event_args = events[4]['args']
    assert staker2 == event_args['staker']
    assert ursula2_reward == event_args['value']
    assert current_period - 1 == event_args['period']

    # Staker(2) makes a commitment to remaining periods
    testerchain.time_travel(hours=10)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    assert 4 == escrow.functions.getPastDowntimeLength(staker2).call()
    testerchain.time_travel(hours=20)
    current_period = escrow.functions.getCurrentPeriod().call()
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    assert policy_manager.functions.getPeriodsLength(staker2).call() == 25
    assert policy_manager.functions.getPeriod(staker2, 22).call() == current_period - 2
    assert policy_manager.functions.getPeriod(staker2, 23).call() == current_period - 1
    assert policy_manager.functions.getPeriod(staker2, 24).call() == current_period + 1

    # Staker(2) withdraws all
    testerchain.time_travel(hours=20)
    worker_log_length = len(worker_log.get_all_entries())
    staker2_stake = escrow.functions.getAllTokens(staker2).call()
    assert 0 == escrow.functions.getLockedTokens(staker2, 0).call()
    assert escrow.functions.getWorkerFromStaker(staker2).call() == staker2
    assert escrow.functions.stakerFromWorker(staker2).call() == staker2
    tx = escrow.functions.withdraw(staker2_stake).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    assert 0 == escrow.functions.getAllTokens(staker2).call()
    assert staker2_stake == token.functions.balanceOf(staker2).call()
    assert escrow.functions.getWorkerFromStaker(staker2).call() == staker2
    assert escrow.functions.stakerFromWorker(staker2).call() == staker2

    events = withdraw_log.get_all_entries()
    assert 1 == len(events)
    event_args = events[0]['args']
    assert staker2 == event_args['staker']
    assert staker2_stake == event_args['value']

    # Staker(2) still can mint tokens for last two periods
    assert escrow.functions.getAllTokens(staker2).call() == 0
    assert escrow.functions.getLockedTokens(staker2, 0).call() == 0
    assert escrow.functions.stakerInfo(staker2).call()[2] > 0  # nextCommittedPeriod
    tx = escrow.functions.mint().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    staker2_stake = escrow.functions.getAllTokens(staker2).call()
    assert staker2_stake > 0
    assert escrow.functions.getLockedTokens(staker2, 0).call() == 0
    assert escrow.functions.stakerInfo(staker2).call()[2] == 0  # nextCommittedPeriod
    assert escrow.functions.getWorkerFromStaker(staker2).call() == staker2
    assert escrow.functions.stakerFromWorker(staker2).call() == staker2

    # Calling mint() again do nothing
    tx = escrow.functions.mint().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    assert escrow.functions.getAllTokens(staker2).call() == staker2_stake

    # Withdraw reward
    assert len(worker_log.get_all_entries()) == worker_log_length
    tx = escrow.functions.withdraw(staker2_stake).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    assert escrow.functions.getAllTokens(staker2).call() == 0
    assert escrow.functions.getWorkerFromStaker(staker2).call() == NULL_ADDRESS
    assert escrow.functions.stakerFromWorker(staker2).call() == NULL_ADDRESS

    events = worker_log.get_all_entries()
    assert len(events) == worker_log_length + 1
    event_args = events[-1]['args']
    assert event_args['staker'] == staker2
    assert event_args['worker'] == NULL_ADDRESS

    # Now Staker(2) can't even call mint() because she is not staker anymore
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.mint().transact({'from': staker2})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.mint(staker2).transact({'from': staker1})
        testerchain.wait_for_receipt(tx)

    assert 4 == len(deposit_log.get_all_entries())
    assert 6 == len(lock_log.get_all_entries())
    assert 1 == len(divides_log.get_all_entries())
    assert 10 == len(commitments_log.get_all_entries())

    # Check searching downtime index
    current_period = escrow.functions.getCurrentPeriod().call()
    assert 0 == escrow.functions.findIndexOfPastDowntime(staker2, 0).call()
    assert 0 == escrow.functions.findIndexOfPastDowntime(staker2, current_period - 15).call()
    assert 1 == escrow.functions.findIndexOfPastDowntime(staker2, current_period - 14).call()
    assert 1 == escrow.functions.findIndexOfPastDowntime(staker2, current_period - 12).call()
    assert 2 == escrow.functions.findIndexOfPastDowntime(staker2, current_period - 11).call()
    assert 2 == escrow.functions.findIndexOfPastDowntime(staker2, current_period - 10).call()
    assert 3 == escrow.functions.findIndexOfPastDowntime(staker2, current_period - 9).call()
    assert 3 == escrow.functions.findIndexOfPastDowntime(staker2, current_period - 5).call()
    assert 4 == escrow.functions.findIndexOfPastDowntime(staker2, current_period - 4).call()
    assert 4 == escrow.functions.findIndexOfPastDowntime(staker2, current_period - 2).call()
    assert 5 == escrow.functions.findIndexOfPastDowntime(staker2, current_period - 1).call()
    assert 5 == escrow.functions.findIndexOfPastDowntime(staker2, current_period).call()
    assert 5 == escrow.functions.findIndexOfPastDowntime(staker2, current_period + 100).call()


def test_slashing(testerchain, token, adjudicator, escrow_contract, token_economics):
    escrow = escrow_contract(1500)
    creator = testerchain.client.accounts[0]
    staker = testerchain.client.accounts[1]
    investigator = testerchain.client.accounts[2]

    slashing_log = escrow.events.Slashed.createFilter(fromBlock='latest')

    # Give Escrow tokens for reward and initialize contract
    tx = token.functions.approve(escrow.address, token_economics.erc20_reward_supply).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.initialize(token_economics.erc20_reward_supply, creator).transact({'from': creator})
    testerchain.wait_for_receipt(tx)

    # Give Ursula deposit some tokens
    tx = token.functions.transfer(staker, 10000).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    tx = token.functions.approve(escrow.address, 10000).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.deposit(staker, 100, 2).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.bondWorker(staker).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.setReStake(False).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.setWindDown(True).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    testerchain.time_travel(hours=10)
    current_period = escrow.functions.getCurrentPeriod().call()
    assert 100 == escrow.functions.getAllTokens(staker).call()
    assert 100 == escrow.functions.getLockedTokens(staker, 0).call()
    assert 100 == escrow.functions.lockedPerPeriod(current_period).call()
    assert 0 == escrow.functions.lockedPerPeriod(current_period + 1).call()

    # Can't slash directly using the escrow contract
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.slashStaker(staker, 100, investigator, 10).transact()
        testerchain.wait_for_receipt(tx)
    # Penalty must be greater than zero
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.slashStaker(staker, 0, investigator, 0).transact()
        testerchain.wait_for_receipt(tx)

    # Slash the whole stake
    reward = escrow.functions.getReservedReward().call()
    tx = adjudicator.functions.slashStaker(staker, 100, investigator, 10).transact()
    testerchain.wait_for_receipt(tx)
    # Staker has no more sub stakes
    assert 0 == escrow.functions.getAllTokens(staker).call()
    assert 0 == escrow.functions.getLockedTokens(staker, 0).call()
    assert 10 == token.functions.balanceOf(investigator).call()
    assert 0 == escrow.functions.lockedPerPeriod(current_period).call()
    assert reward + 90 == escrow.functions.getReservedReward().call()

    events = slashing_log.get_all_entries()
    assert 1 == len(events)
    event_args = events[0]['args']
    assert staker == event_args['staker']
    assert 100 == event_args['penalty']
    assert investigator == event_args['investigator']
    assert 10 == event_args['reward']

    # New deposit and making a commitment
    tx = escrow.functions.deposit(staker, 100, 5).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    testerchain.time_travel(hours=10)
    current_period += 1
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    assert 100 == escrow.functions.getAllTokens(staker).call()
    assert 100 == escrow.functions.getLockedTokens(staker, 0).call()
    assert 100 == escrow.functions.getLockedTokens(staker, 1).call()
    assert 100 == escrow.functions.lockedPerPeriod(current_period).call()
    assert 100 == escrow.functions.lockedPerPeriod(current_period + 1).call()

    # Slash part of one sub stake (there is only one sub stake)
    reward = escrow.functions.getReservedReward().call()
    tx = adjudicator.functions.slashStaker(staker, 10, investigator, 11).transact()
    testerchain.wait_for_receipt(tx)
    assert 90 == escrow.functions.getAllTokens(staker).call()
    assert 90 == escrow.functions.getLockedTokens(staker, 0).call()
    assert 90 == escrow.functions.getLockedTokens(staker, 1).call()
    # The reward will be equal to the penalty (can't be more then penalty)
    assert 20 == token.functions.balanceOf(investigator).call()
    assert 90 == escrow.functions.lockedPerPeriod(current_period).call()
    assert 90 == escrow.functions.lockedPerPeriod(current_period + 1).call()
    assert reward == escrow.functions.getReservedReward().call()

    events = slashing_log.get_all_entries()
    assert 2 == len(events)
    event_args = events[1]['args']
    assert staker == event_args['staker']
    assert 10 == event_args['penalty']
    assert investigator == event_args['investigator']
    assert 10 == event_args['reward']

    # New deposit of a longer sub stake
    tx = escrow.functions.deposit(staker, 100, 6).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    testerchain.time_travel(hours=10)
    current_period += 1
    assert 90 == escrow.functions.getLockedTokensInPast(staker, 1).call()
    assert 190 == escrow.functions.getLockedTokens(staker, 0).call()
    assert 100 == escrow.functions.getLockedTokens(staker, 4).call()
    assert 190 == escrow.functions.getAllTokens(staker).call()
    assert 90 == escrow.functions.lockedPerPeriod(current_period - 1).call()
    assert 190 == escrow.functions.lockedPerPeriod(current_period).call()
    assert 0 == escrow.functions.lockedPerPeriod(current_period + 1).call()

    # Slash again part of the first sub stake because new sub stake is longer (there are two main sub stakes)
    reward = escrow.functions.getReservedReward().call()
    tx = adjudicator.functions.slashStaker(staker, 10, investigator, 0).transact()
    testerchain.wait_for_receipt(tx)
    assert 180 == escrow.functions.getAllTokens(staker).call()
    assert 90 == escrow.functions.getLockedTokensInPast(staker, 1).call()
    assert 180 == escrow.functions.getLockedTokens(staker, 0).call()
    assert 100 == escrow.functions.getLockedTokens(staker, 4).call()
    assert 20 == token.functions.balanceOf(investigator).call()
    assert 90 == escrow.functions.lockedPerPeriod(current_period - 1).call()
    assert 180 == escrow.functions.lockedPerPeriod(current_period).call()
    assert reward + 10 == escrow.functions.getReservedReward().call()

    events = slashing_log.get_all_entries()
    assert 3 == len(events)
    event_args = events[2]['args']
    assert staker == event_args['staker']
    assert 10 == event_args['penalty']
    assert investigator == event_args['investigator']
    assert 0 == event_args['reward']

    # New deposit of a shorter sub stake
    tx = escrow.functions.deposit(staker, 110, 2).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    testerchain.time_travel(hours=20)
    current_period += 2
    assert 290 == escrow.functions.getLockedTokensInPast(staker, 1).call()
    assert 290 == escrow.functions.getLockedTokens(staker, 0).call()
    assert 180 == escrow.functions.getLockedTokens(staker, 2).call()
    deposit = escrow.functions.getAllTokens(staker).call()  # Some reward is already minted
    assert 290 == escrow.functions.lockedPerPeriod(current_period - 1).call()
    assert 0 == escrow.functions.lockedPerPeriod(current_period).call()

    # Slash only free amount of tokens
    reward = escrow.functions.getReservedReward().call()
    tx = adjudicator.functions.slashStaker(staker, deposit - 290, investigator, 0).transact()
    testerchain.wait_for_receipt(tx)
    assert 290 == escrow.functions.getAllTokens(staker).call()
    assert 290 == escrow.functions.getLockedTokensInPast(staker, 1).call()
    assert 290 == escrow.functions.getLockedTokens(staker, 0).call()
    assert 180 == escrow.functions.getLockedTokens(staker, 2).call()
    assert 20 == token.functions.balanceOf(investigator).call()
    assert 290 == escrow.functions.lockedPerPeriod(current_period - 1).call()
    assert 0 == escrow.functions.lockedPerPeriod(current_period).call()
    assert reward + deposit - 290 == escrow.functions.getReservedReward().call()

    events = slashing_log.get_all_entries()
    assert 4 == len(events)
    event_args = events[3]['args']
    assert staker == event_args['staker']
    assert deposit - 290 == event_args['penalty']
    assert investigator == event_args['investigator']
    assert 0 == event_args['reward']

    # Slash only the new sub stake because it's the shortest one (there are three main sub stakes)
    tx = adjudicator.functions.slashStaker(staker, 20, investigator, 0).transact()
    testerchain.wait_for_receipt(tx)
    assert 270 == escrow.functions.getAllTokens(staker).call()
    assert 290 == escrow.functions.getLockedTokensInPast(staker, 1).call()
    assert 270 == escrow.functions.getLockedTokens(staker, 0).call()
    assert 180 == escrow.functions.getLockedTokens(staker, 2).call()
    assert 20 == token.functions.balanceOf(investigator).call()
    assert 290 == escrow.functions.lockedPerPeriod(current_period - 1).call()
    assert 0 == escrow.functions.lockedPerPeriod(current_period).call()
    assert reward + deposit - 270 == escrow.functions.getReservedReward().call()

    events = slashing_log.get_all_entries()
    assert 5 == len(events)
    event_args = events[4]['args']
    assert staker == event_args['staker']
    assert 20 == event_args['penalty']
    assert investigator == event_args['investigator']
    assert 0 == event_args['reward']

    # Slash the whole new sub stake and part of the next shortest (there are three main sub stakes)
    reward = escrow.functions.getReservedReward().call()
    tx = adjudicator.functions.slashStaker(staker, 100, investigator, 0).transact()
    testerchain.wait_for_receipt(tx)
    assert 170 == escrow.functions.getAllTokens(staker).call()
    assert 290 == escrow.functions.getLockedTokensInPast(staker, 1).call()
    assert 170 == escrow.functions.getLockedTokens(staker, 0).call()
    assert 170 == escrow.functions.getLockedTokens(staker, 2).call()
    assert 20 == token.functions.balanceOf(investigator).call()
    assert 290 == escrow.functions.lockedPerPeriod(current_period - 1).call()
    assert 0 == escrow.functions.lockedPerPeriod(current_period).call()
    assert reward + 100 == escrow.functions.getReservedReward().call()

    events = slashing_log.get_all_entries()
    assert 6 == len(events)
    event_args = events[5]['args']
    assert staker == event_args['staker']
    assert 100 == event_args['penalty']
    assert investigator == event_args['investigator']
    assert 0 == event_args['reward']

    # Making a commitment must handle correctly inactive sub stakes after slashing
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker})
    testerchain.wait_for_receipt(tx)

    # New deposit
    tx = escrow.functions.deposit(staker, 100, 2).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    assert 170 == escrow.functions.getLockedTokens(staker, 0).call()
    assert 270 == escrow.functions.getLockedTokens(staker, 1).call()
    assert 270 == escrow.functions.lockedPerPeriod(current_period + 1).call()
    deposit = escrow.functions.getAllTokens(staker).call()  # Some reward is already minted
    unlocked_deposit = deposit - 270
    reward = escrow.functions.getReservedReward().call()

    # Slash the new sub stake which starts in the next period
    # Because locked value is more in the next period than in the current period
    tx = adjudicator.functions.slashStaker(staker, unlocked_deposit + 10, investigator, 0).transact()
    testerchain.wait_for_receipt(tx)
    assert 170 == escrow.functions.getLockedTokens(staker, 0).call()
    assert 260 == escrow.functions.getLockedTokens(staker, 1).call()
    assert 260 == escrow.functions.getAllTokens(staker).call()
    assert 260 == escrow.functions.lockedPerPeriod(current_period + 1).call()
    assert reward + unlocked_deposit + 10 == escrow.functions.getReservedReward().call()

    events = slashing_log.get_all_entries()
    assert 7 == len(events)
    event_args = events[6]['args']
    assert staker == event_args['staker']
    assert unlocked_deposit + 10 == event_args['penalty']
    assert investigator == event_args['investigator']
    assert 0 == event_args['reward']

    # After two periods two shortest sub stakes will be unlocked, lock again and slash after this
    testerchain.time_travel(hours=10)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    testerchain.time_travel(hours=10)

    current_period += 2
    assert 260 == escrow.functions.getLockedTokens(staker, 0).call()
    assert 100 == escrow.functions.getLockedTokens(staker, 1).call()
    assert 0 == escrow.functions.getLockedTokens(staker, 3).call()
    assert 260 == escrow.functions.lockedPerPeriod(current_period - 1).call()
    assert 260 == escrow.functions.lockedPerPeriod(current_period).call()
    assert 0 == escrow.functions.lockedPerPeriod(current_period + 1).call()
    tx = escrow.functions.lockAndCreate(160, 2).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    assert 260 == escrow.functions.getLockedTokens(staker, 0).call()
    assert 260 == escrow.functions.getLockedTokens(staker, 1).call()
    assert 0 == escrow.functions.getLockedTokens(staker, 3).call()
    assert 260 == escrow.functions.lockedPerPeriod(current_period - 1).call()
    assert 260 == escrow.functions.lockedPerPeriod(current_period).call()
    assert 260 == escrow.functions.lockedPerPeriod(current_period + 1).call()
    deposit = escrow.functions.getAllTokens(staker).call()  # Some reward is already minted
    unlocked_deposit = deposit - 260

    # Slash two sub stakes:
    # one which will be unlocked after current period and new sub stake
    reward = escrow.functions.getReservedReward().call()
    tx = adjudicator.functions.slashStaker(staker, unlocked_deposit + 10, investigator, 0).transact()
    testerchain.wait_for_receipt(tx)
    assert 250 == escrow.functions.getLockedTokens(staker, 0).call()
    assert 250 == escrow.functions.getLockedTokens(staker, 1).call()
    assert 0 == escrow.functions.getLockedTokens(staker, 3).call()
    assert 250 == escrow.functions.getAllTokens(staker).call()
    assert 260 == escrow.functions.lockedPerPeriod(current_period - 1).call()
    assert 250 == escrow.functions.lockedPerPeriod(current_period).call()
    assert 250 == escrow.functions.lockedPerPeriod(current_period + 1).call()
    assert reward + unlocked_deposit + 10 == escrow.functions.getReservedReward().call()

    events = slashing_log.get_all_entries()
    assert 8 == len(events)
    event_args = events[7]['args']
    assert staker == event_args['staker']
    assert unlocked_deposit + 10 == event_args['penalty']
    assert investigator == event_args['investigator']
    assert 0 == event_args['reward']

    # Slash four sub stakes:
    # two that will be unlocked after current period, new sub stake and another short sub stake
    tx = adjudicator.functions.slashStaker(staker, 90, investigator, 0).transact()
    testerchain.wait_for_receipt(tx)
    assert 160 == escrow.functions.getLockedTokens(staker, 0).call()
    assert 160 == escrow.functions.getLockedTokens(staker, 1).call()
    assert 0 == escrow.functions.getLockedTokens(staker, 3).call()
    assert 160 == escrow.functions.getAllTokens(staker).call()
    assert 260 == escrow.functions.lockedPerPeriod(current_period - 1).call()
    assert 160 == escrow.functions.lockedPerPeriod(current_period).call()
    assert 160 == escrow.functions.lockedPerPeriod(current_period + 1).call()
    assert reward + unlocked_deposit + 100 == escrow.functions.getReservedReward().call()

    events = slashing_log.get_all_entries()
    assert 9 == len(events)
    event_args = events[8]['args']
    assert staker == event_args['staker']
    assert 90 == event_args['penalty']
    assert investigator == event_args['investigator']
    assert 0 == event_args['reward']

    # Prepare second Ursula for tests
    staker2 = testerchain.client.accounts[3]
    tx = token.functions.transfer(staker2, 10000).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    tx = token.functions.approve(escrow.address, 10000).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)

    # Two deposits in consecutive periods
    tx = escrow.functions.deposit(staker2, 100, 4).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.bondWorker(staker2).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.setWindDown(True).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    testerchain.time_travel(hours=10)
    tx = escrow.functions.deposit(staker2, 100, 2).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.setReStake(False).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    testerchain.time_travel(hours=20)
    assert 100 == escrow.functions.getLockedTokensInPast(staker2, 2).call()
    assert 200 == escrow.functions.getLockedTokensInPast(staker2, 1).call()
    assert 200 == escrow.functions.getLockedTokens(staker2, 0).call()
    assert 200 == escrow.functions.getLockedTokens(staker2, 1).call()

    # Slash one sub stake to set the last period of this sub stake to the previous period
    tx = adjudicator.functions.slashStaker(staker2, 100, investigator, 0).transact()
    testerchain.wait_for_receipt(tx)
    assert 100 == escrow.functions.getLockedTokensInPast(staker2, 2).call()
    assert 200 == escrow.functions.getLockedTokensInPast(staker2, 1).call()
    assert 100 == escrow.functions.getLockedTokens(staker2, 0).call()
    assert 100 == escrow.functions.getLockedTokens(staker2, 1).call()

    events = slashing_log.get_all_entries()
    assert 10 == len(events)
    event_args = events[9]['args']
    assert staker2 == event_args['staker']
    assert 100 == event_args['penalty']
    assert investigator == event_args['investigator']
    assert 0 == event_args['reward']

    # Slash the first sub stake
    # and check that the second sub stake will not combine with the slashed amount of the first one
    tx = adjudicator.functions.slashStaker(staker2, 50, investigator, 0).transact()
    testerchain.wait_for_receipt(tx)
    assert 100 == escrow.functions.getLockedTokensInPast(staker2, 2).call()
    assert 200 == escrow.functions.getLockedTokensInPast(staker2, 1).call()
    assert 50 == escrow.functions.getLockedTokens(staker2, 0).call()
    assert 50 == escrow.functions.getLockedTokens(staker2, 1).call()

    events = slashing_log.get_all_entries()
    assert 11 == len(events)
    event_args = events[10]['args']
    assert staker2 == event_args['staker']
    assert 50 == event_args['penalty']
    assert investigator == event_args['investigator']
    assert 0 == event_args['reward']

    # Prepare next case: new deposit is longer than previous sub stake
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    testerchain.time_travel(hours=10)
    tx = escrow.functions.deposit(staker2, 100, 3).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    assert 50 == escrow.functions.getLockedTokens(staker2, 0).call()
    assert 150 == escrow.functions.getLockedTokens(staker2, 1).call()
    assert 100 == escrow.functions.getLockedTokens(staker2, 2).call()

    # Withdraw all not locked tokens
    deposit = escrow.functions.getAllTokens(staker2).call()  # Some reward is already minted
    unlocked_deposit = deposit - 150
    tx = escrow.functions.withdraw(unlocked_deposit).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)

    # Slash the previous sub stake
    # Stake in the current period should not change, because overflow starts from the next period
    tx = adjudicator.functions.slashStaker(staker2, 10, investigator, 0).transact()
    testerchain.wait_for_receipt(tx)
    assert 50 == escrow.functions.getLockedTokens(staker2, 0).call()
    assert 140 == escrow.functions.getLockedTokens(staker2, 1).call()
    assert 100 == escrow.functions.getLockedTokens(staker2, 2).call()

    events = slashing_log.get_all_entries()
    assert 12 == len(events)
    event_args = events[11]['args']
    assert staker2 == event_args['staker']
    assert 10 == event_args['penalty']
    assert investigator == event_args['investigator']
    assert 0 == event_args['reward']

    # Next test: optimization does not break saving old sub stake
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    testerchain.time_travel(hours=10)
    assert 50 == escrow.functions.getLockedTokensInPast(staker2, 1).call()
    assert 140 == escrow.functions.getLockedTokens(staker2, 0).call()
    assert 100 == escrow.functions.getLockedTokens(staker2, 1).call()
    tx = adjudicator.functions.slashStaker(staker2, 10, investigator, 0).transact()
    testerchain.wait_for_receipt(tx)
    assert 50 == escrow.functions.getLockedTokensInPast(staker2, 1).call()
    assert 130 == escrow.functions.getLockedTokens(staker2, 0).call()
    assert 100 == escrow.functions.getLockedTokens(staker2, 1).call()
