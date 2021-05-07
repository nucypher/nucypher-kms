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
from eth_utils import to_checksum_address
from web3.contract import Contract

MAX_SUB_STAKES = 30
MAX_UINT16 = 65535


def test_staking(testerchain, token, escrow_contract):
    """
    Tests for staking methods: deposit, lock and stake division
    """

    escrow = escrow_contract(1500, disable_reward=True)
    creator = testerchain.client.accounts[0]
    staker1 = testerchain.client.accounts[1]
    staker2 = testerchain.client.accounts[2]
    deposit_log = escrow.events.Deposited.createFilter(fromBlock='latest')
    lock_log = escrow.events.Locked.createFilter(fromBlock='latest')
    commitments_log = escrow.events.CommitmentMade.createFilter(fromBlock='latest')
    divides_log = escrow.events.Divided.createFilter(fromBlock='latest')
    prolong_log = escrow.events.Prolonged.createFilter(fromBlock='latest')
    withdraw_log = escrow.events.Withdrawn.createFilter(fromBlock='latest')
    wind_down_log = escrow.events.WindDownSet.createFilter(fromBlock='latest')

    # Give Staker and Staker(2) some coins
    tx = token.functions.transfer(staker1, 10000).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    tx = token.functions.transfer(staker2, 10000).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    assert 10000 == token.functions.balanceOf(staker1).call()
    assert 10000 == token.functions.balanceOf(staker2).call()

    # Staker and Staker(2) give Escrow rights to transfer
    tx = token.functions.approve(escrow.address, 1000).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    assert 1000 == token.functions.allowance(staker1, escrow.address).call()
    tx = token.functions.approve(escrow.address, 500).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    assert 500 == token.functions.allowance(staker2, escrow.address).call()

    # Staker's withdrawal attempt won't succeed because nothing to withdraw
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.withdraw(100).transact({'from': staker1})
        testerchain.wait_for_receipt(tx)

    # Can't lock because nothing to lock
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.lockAndCreate(500, 2).transact({'from': staker1})
        testerchain.wait_for_receipt(tx)

    # Check that nothing is locked
    assert 0 == escrow.functions.getLockedTokens(staker1, 0).call()
    assert 0 == escrow.functions.getLockedTokens(staker2, 0).call()
    assert 0 == escrow.functions.getLockedTokens(testerchain.client.accounts[3], 0).call()

    # Can't deposit for too short a period (less than _minLockedPeriods coefficient)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.deposit(staker1, 1000, 1).transact({'from': staker1})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = token.functions.approveAndCall(escrow.address, 1000, testerchain.w3.toBytes(1))\
            .transact({'from': staker1})
        testerchain.wait_for_receipt(tx)

    # Staker transfers some tokens to the escrow and locks them before initialization
    current_period = escrow.functions.getCurrentPeriod().call()
    tx = escrow.functions.deposit(staker1, 1000, 2).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.bondWorker(staker1).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.setWindDown(True).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    assert 1000 == token.functions.balanceOf(escrow.address).call()
    assert 9000 == token.functions.balanceOf(staker1).call()
    assert 0 == escrow.functions.getLockedTokens(staker1, 0).call()
    assert 1000 == escrow.functions.getLockedTokens(staker1, 1).call()
    assert 1000 == escrow.functions.getLockedTokens(staker1, 2).call()
    assert 0 == escrow.functions.getLockedTokens(staker1, 3).call()

    # Check that all events are emitted
    events = deposit_log.get_all_entries()
    assert 1 == len(events)
    event_args = events[0]['args']
    assert staker1 == event_args['staker']
    assert 1000 == event_args['value']
    assert 2 == event_args['periods']
    events = lock_log.get_all_entries()
    assert 1 == len(events)
    event_args = events[0]['args']
    assert staker1 == event_args['staker']
    assert 1000 == event_args['value']
    assert current_period + 1 == event_args['firstPeriod']
    assert 2 == event_args['periods']
    events = wind_down_log.get_all_entries()
    assert 1 == len(events)
    event_args = events[0]['args']
    assert staker1 == event_args['staker']
    assert event_args['windDown']

    # Can't make a commitment before initialization
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
        testerchain.wait_for_receipt(tx)

    # Initialize Escrow contract
    tx = escrow.functions.initialize(0, creator).transact({'from': creator})
    testerchain.wait_for_receipt(tx)

    # Ursula(2) stakes tokens also
    tx = escrow.functions.deposit(staker2, 500, 2).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.bondWorker(staker2).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.setWindDown(True).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    assert 1500 == token.functions.balanceOf(escrow.address).call()
    assert 9500 == token.functions.balanceOf(staker2).call()
    assert 0 == escrow.functions.getLockedTokens(staker2, 0).call()
    assert 500 == escrow.functions.getLockedTokens(staker2, 1).call()

    events = deposit_log.get_all_entries()
    assert 2 == len(events)
    event_args = events[1]['args']
    assert staker2 == event_args['staker']
    assert 500 == event_args['value']
    assert 2 == event_args['periods']
    events = lock_log.get_all_entries()
    assert 2 == len(events)
    event_args = events[1]['args']
    assert staker2 == event_args['staker']
    assert 500 == event_args['value']
    assert current_period + 1 == event_args['firstPeriod']
    assert 2 == event_args['periods']
    events = wind_down_log.get_all_entries()
    assert 2 == len(events)
    event_args = events[1]['args']
    assert staker2 == event_args['staker']
    assert event_args['windDown']

    # Staker and Staker(2) make a commitment
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    assert current_period + 1 == escrow.functions.getLastCommittedPeriod(staker1).call()
    assert current_period + 1 == escrow.functions.getLastCommittedPeriod(staker2).call()

    # No active stakers before next period
    all_locked, stakers = escrow.functions.getActiveStakers(1, 0, 0).call()
    assert 0 == all_locked
    assert 0 == len(stakers)

    events = commitments_log.get_all_entries()
    assert 2 == len(events)
    event_args = events[0]['args']
    assert staker1 == event_args['staker']
    assert current_period + 1 == event_args['period']
    assert 1000 == event_args['value']
    events = commitments_log.get_all_entries()
    event_args = events[1]['args']
    assert staker2 == event_args['staker']
    assert current_period + 1 == event_args['period']
    assert 500 == event_args['value']

    # Checks locked tokens in the next period
    testerchain.time_travel(hours=10)
    current_period = escrow.functions.getCurrentPeriod().call()
    assert 1000 == escrow.functions.getLockedTokens(staker1, 0).call()
    assert 500 == escrow.functions.getLockedTokens(staker2, 0).call()

    # Both stakers are active and have locked tokens in next period
    all_locked, stakers = escrow.functions.getActiveStakers(1, 0, 0).call()
    assert 1500 == all_locked
    assert 2 == len(stakers)
    assert staker1 == to_checksum_address(stakers[0][0])
    assert 1000 == stakers[0][1]
    assert staker2 == to_checksum_address(stakers[1][0])
    assert 500 == stakers[1][1]

    # Test parameters of getActiveStakers method
    same_all_locked, same_stakers = escrow.functions.getActiveStakers(1, 0, 2).call()
    assert all_locked == same_all_locked
    assert stakers == same_stakers
    same_all_locked, same_stakers = escrow.functions.getActiveStakers(1, 0, 10).call()
    assert all_locked == same_all_locked
    assert stakers == same_stakers
    all_locked_1, stakers_1 = escrow.functions.getActiveStakers(1, 0, 1).call()
    all_locked_2, stakers_2 = escrow.functions.getActiveStakers(1, 1, 1).call()
    assert all_locked == all_locked_1 + all_locked_2
    assert stakers == stakers_1 + stakers_2
    same_all_locked, same_stakers = escrow.functions.getActiveStakers(1, 1, 0).call()
    assert all_locked_2 == same_all_locked
    assert stakers_2 == same_stakers
    with pytest.raises((TransactionFailed, ValueError)):
        escrow.functions.getActiveStakers(1, 2, 1).call()

    # But in two periods their sub stakes will be unlocked
    all_locked, stakers = escrow.functions.getActiveStakers(2, 0, 0).call()
    assert 0 == all_locked
    assert 0 == len(stakers)

    # Staker's withdrawal attempt won't succeed because everything is locked
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.withdraw(100).transact({'from': staker1})
        testerchain.wait_for_receipt(tx)
    assert 1500 == token.functions.balanceOf(escrow.address).call()
    assert 9000 == token.functions.balanceOf(staker1).call()

    # Staker can deposit more tokens
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    assert current_period + 1 == escrow.functions.getLastCommittedPeriod(staker1).call()
    assert 1000 == escrow.functions.getLockedTokens(staker1, 1).call()
    assert 0 == escrow.functions.getLockedTokens(staker1, 2).call()

    events = commitments_log.get_all_entries()
    assert 3 == len(events)
    event_args = events[2]['args']
    assert staker1 == event_args['staker']
    assert current_period + 1 == event_args['period']
    assert 1000 == event_args['value']

    locked_next_period = escrow.functions.lockedPerPeriod(current_period + 1).call()
    tx = token.functions.approveAndCall(escrow.address, 500, testerchain.w3.toBytes(2))\
        .transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    assert 2000 == token.functions.balanceOf(escrow.address).call()
    assert 8500 == token.functions.balanceOf(staker1).call()
    assert 1500 == escrow.functions.getLockedTokens(staker1, 1).call()
    assert 500 == escrow.functions.getLockedTokens(staker1, 2).call()
    assert 0 == escrow.functions.getLockedTokens(staker1, 3).call()
    assert locked_next_period + 500 == escrow.functions.lockedPerPeriod(current_period + 1).call()

    events = commitments_log.get_all_entries()
    assert 4 == len(events)
    event_args = events[3]['args']
    assert staker1 == event_args['staker']
    assert current_period + 1 == event_args['period']
    assert 500 == event_args['value']

    # Both stakers are active and only the first one locked tokens for two more periods
    all_locked, stakers = escrow.functions.getActiveStakers(2, 0, 0).call()
    assert 500 == all_locked
    assert 1 == len(stakers)
    assert staker1 == to_checksum_address(stakers[0][0])
    assert 500 == stakers[0][1]
    _, stakers = escrow.functions.getActiveStakers(2, 0, 2).call()
    assert 1 == len(stakers)
    same_all_locked, same_stakers = escrow.functions.getActiveStakers(2, 0, 1).call()
    assert all_locked == same_all_locked
    assert stakers == same_stakers
    all_locked, stakers = escrow.functions.getActiveStakers(2, 1, 1).call()
    assert 0 == all_locked
    assert 0 == len(stakers)

    # Wait 1 period and checks locking
    testerchain.time_travel(hours=10)
    assert 1500 == escrow.functions.getLockedTokens(staker1, 0).call()

    # Only one staker is active
    all_locked, stakers = escrow.functions.getActiveStakers(1, 0, 0).call()
    assert 500 == all_locked
    assert 1 == len(stakers)
    assert staker1 == to_checksum_address(stakers[0][0])
    assert 500 == stakers[0][1]

    # Make a commitment and wait 1 period, locking will be decreased because of end of one stake
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    testerchain.time_travel(hours=10)
    current_period = escrow.functions.getCurrentPeriod().call()
    assert 500 == escrow.functions.getLockedTokens(staker1, 0).call()
    assert 0 == escrow.functions.getLockedTokens(staker1, 1).call()

    events = commitments_log.get_all_entries()
    assert 5 == len(events)
    event_args = events[4]['args']
    assert staker1 == event_args['staker']
    assert current_period == event_args['period']
    assert 500 == event_args['value']

    # Stake is unlocked and Staker can withdraw some tokens
    tx = escrow.functions.withdraw(100).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    assert 1900 == token.functions.balanceOf(escrow.address).call()
    assert 8600 == token.functions.balanceOf(staker1).call()
    events = withdraw_log.get_all_entries()
    assert 1 == len(events)
    event_args = events[0]['args']
    assert staker1 == event_args['staker']
    assert 100 == event_args['value']

    # But Staker can't withdraw all without unlocking other stakes
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.withdraw(1400).transact({'from': staker1})
        testerchain.wait_for_receipt(tx)

    # Staker can deposit and lock more tokens
    tx = token.functions.approveAndCall(escrow.address, 500, testerchain.w3.toBytes(2))\
        .transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
    testerchain.wait_for_receipt(tx)

    events = commitments_log.get_all_entries()
    assert 6 == len(events)
    event_args = events[5]['args']
    assert staker1 == event_args['staker']
    assert current_period + 1 == event_args['period']
    assert 500 == event_args['value']

    tx = escrow.functions.lockAndCreate(100, 2).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)

    events = commitments_log.get_all_entries()
    assert 7 == len(events)
    event_args = events[6]['args']
    assert staker1 == event_args['staker']
    assert current_period + 1 == event_args['period']
    assert 100 == event_args['value']

    # Value of locked tokens will be updated in next period
    assert 500 == escrow.functions.getLockedTokens(staker1, 0).call()
    assert 600 == escrow.functions.getLockedTokens(staker1, 1).call()
    assert 600 == escrow.functions.getLockedTokens(staker1, 2).call()
    assert 0 == escrow.functions.getLockedTokens(staker1, 3).call()
    testerchain.time_travel(hours=10)
    assert 600 == escrow.functions.getLockedTokens(staker1, 0).call()
    assert 600 == escrow.functions.getLockedTokens(staker1, 1).call()
    assert 0 == escrow.functions.getLockedTokens(staker1, 2).call()

    # Staker increases lock
    tx = escrow.functions.lockAndCreate(500, 2).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    assert 600 == escrow.functions.getLockedTokens(staker1, 0).call()
    assert 1100 == escrow.functions.getLockedTokens(staker1, 1).call()
    assert 500 == escrow.functions.getLockedTokens(staker1, 2).call()
    assert 0 == escrow.functions.getLockedTokens(staker1, 3).call()
    testerchain.time_travel(hours=10)
    assert 1100 == escrow.functions.getLockedTokens(staker1, 0).call()

    # Staker(2) increases lock by deposit more tokens using approveAndCall
    tx = token.functions.approveAndCall(escrow.address, 500, testerchain.w3.toBytes(2))\
        .transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    assert 500 == escrow.functions.getLockedTokens(staker2, 0).call()
    assert 1000 == escrow.functions.getLockedTokens(staker2, 1).call()
    assert 500 == escrow.functions.getLockedTokens(staker2, 2).call()
    assert 0 == escrow.functions.getLockedTokens(staker2, 3).call()
    testerchain.time_travel(hours=10)

    # And increases locked time by dividing stake into two parts
    current_period = escrow.functions.getCurrentPeriod().call()
    assert 2 == escrow.functions.getSubStakesLength(staker2).call()
    assert current_period + 1 == escrow.functions.getLastPeriodOfSubStake(staker2, 1).call()
    tx = escrow.functions.divideStake(1, 200, 1).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    assert 1000 == escrow.functions.getLockedTokens(staker2, 0).call()
    assert 500 == escrow.functions.getLockedTokens(staker2, 1).call()
    assert 200 == escrow.functions.getLockedTokens(staker2, 2).call()
    assert 0 == escrow.functions.getLockedTokens(staker2, 3).call()

    events = lock_log.get_all_entries()
    assert 8 == len(events)
    event_args = events[7]['args']
    assert staker2 == event_args['staker']
    assert 200 == event_args['value']
    assert current_period == event_args['firstPeriod']
    assert 2 == event_args['periods']
    events = divides_log.get_all_entries()
    assert 1 == len(events)
    event_args = events[0]['args']
    assert staker2 == event_args['staker']
    assert 500 == event_args['oldValue']
    assert current_period + 1 == event_args['lastPeriod']
    assert 200 == event_args['newValue']
    assert 1 == event_args['periods']

    tx = escrow.functions.commitToNextPeriod().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    testerchain.time_travel(hours=10)
    # Check number of stakes and last stake parameters
    current_period = escrow.functions.getCurrentPeriod().call()
    assert 3 == escrow.functions.getSubStakesLength(staker2).call()
    assert current_period == escrow.functions.getLastPeriodOfSubStake(staker2, 1).call()

    # Can't divide stake again because current period is the last periods for this sub stake
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.divideStake(1, 200, 2).transact({'from': staker2})
        testerchain.wait_for_receipt(tx)
    # But can lock
    tx = escrow.functions.lockAndCreate(200, 2).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    assert 500 == escrow.functions.getLockedTokens(staker2, 0).call()
    assert 400 == escrow.functions.getLockedTokens(staker2, 1).call()
    assert 200 == escrow.functions.getLockedTokens(staker2, 2).call()
    assert 0 == escrow.functions.getLockedTokens(staker2, 3).call()

    # Check number of stakes and last stake parameters
    assert 4 == escrow.functions.getSubStakesLength(staker2).call()
    assert current_period + 1 == escrow.functions.getLastPeriodOfSubStake(staker2, 2).call()

    # Divide stake again
    tx = escrow.functions.divideStake(2, 100, 1).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    assert 500 == escrow.functions.getLockedTokens(staker2, 0).call()
    assert 400 == escrow.functions.getLockedTokens(staker2, 1).call()
    assert 300 == escrow.functions.getLockedTokens(staker2, 2).call()
    assert 0 == escrow.functions.getLockedTokens(staker2, 3).call()

    events = divides_log.get_all_entries()
    assert 2 == len(events)
    event_args = events[1]['args']
    assert staker2 == event_args['staker']
    assert 200 == event_args['oldValue']
    assert current_period + 1 == event_args['lastPeriod']
    assert 100 == event_args['newValue']
    assert 1 == event_args['periods']

    # Prolong some sub stake
    tx = escrow.functions.prolongStake(3, 1).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    assert 500 == escrow.functions.getLockedTokens(staker2, 0).call()
    assert 400 == escrow.functions.getLockedTokens(staker2, 1).call()
    assert 300 == escrow.functions.getLockedTokens(staker2, 2).call()
    assert 200 == escrow.functions.getLockedTokens(staker2, 3).call()
    assert 0 == escrow.functions.getLockedTokens(staker2, 4).call()

    events = lock_log.get_all_entries()
    assert 11 == len(events)
    event_args = events[10]['args']
    assert staker2 == event_args['staker']
    assert 200 == event_args['value']
    assert current_period + 3 == event_args['firstPeriod']
    assert 1 == event_args['periods']

    events = prolong_log.get_all_entries()
    assert len(events) == 1
    event_args = events[0]['args']
    assert staker2 == event_args['staker']
    assert 200 == event_args['value']
    assert current_period + 2 == event_args['lastPeriod']
    assert 1 == event_args['periods']

    # Prolong sub stake that will end in the next period
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.prolongStake(2, 1).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    assert 500 == escrow.functions.getLockedTokens(staker2, 0).call()
    assert 400 == escrow.functions.getLockedTokens(staker2, 1).call()
    assert 400 == escrow.functions.getLockedTokens(staker2, 2).call()
    assert 200 == escrow.functions.getLockedTokens(staker2, 3).call()
    assert 0 == escrow.functions.getLockedTokens(staker2, 4).call()

    # Check overflow in prolong stake
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.prolongStake(2, MAX_UINT16).transact({'from': staker2})
        testerchain.wait_for_receipt(tx)

    events = lock_log.get_all_entries()
    assert 12 == len(events)
    event_args = events[11]['args']
    assert staker2 == event_args['staker']
    assert 100 == event_args['value']
    assert current_period + 2 == event_args['firstPeriod']
    assert 1 == event_args['periods']

    events = prolong_log.get_all_entries()
    assert len(events) == 2
    event_args = events[1]['args']
    assert staker2 == event_args['staker']
    assert 100 == event_args['value']
    assert current_period + 1 == event_args['lastPeriod']
    assert 1 == event_args['periods']

    # Can't prolong sub stake that will end in the current period
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.prolongStake(1, 2).transact({'from': staker2})
        testerchain.wait_for_receipt(tx)

    # Just wait and make a commitment
    testerchain.time_travel(hours=10)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    testerchain.time_travel(hours=10)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)

    # Can't divide old stake because it's already unlocked
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.divideStake(0, 200, 10).transact({'from': staker2})
        testerchain.wait_for_receipt(tx)
    # Can't divide nonexistent stake
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.divideStake(10, 100, 1).transact({'from': staker2})
        testerchain.wait_for_receipt(tx)
    # And can't prolong old stake
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.prolongStake(0, 10).transact({'from': staker2})
        testerchain.wait_for_receipt(tx)

    current_period = escrow.functions.getCurrentPeriod().call()
    events = commitments_log.get_all_entries()
    assert 13 == len(events)
    event_args = events[11]['args']
    assert staker2 == event_args['staker']
    assert current_period == event_args['period']
    assert 400 == event_args['value']
    event_args = events[12]['args']
    assert staker2 == event_args['staker']
    assert current_period + 1 == event_args['period']
    assert 200 == event_args['value']

    assert 5 == len(deposit_log.get_all_entries())
    assert 1 == len(withdraw_log.get_all_entries())

    # Test max locking duration
    tx = escrow.functions.lockAndCreate(200, MAX_UINT16).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    assert 200 == escrow.functions.getLockedTokens(staker2, MAX_UINT16 - current_period).call()


def test_increase_lock(testerchain, token, escrow_contract, token_economics):
    minimum_allowed_locked = token_economics.minimum_allowed_locked
    maximum_allowed_locked = 1500
    minimum_locked_periods = token_economics.minimum_locked_periods

    escrow = escrow_contract(maximum_allowed_locked, disable_reward=True)
    creator = testerchain.client.accounts[0]
    staker = testerchain.client.accounts[1]
    someone_else = testerchain.client.accounts[2]
    deposit_log = escrow.events.Deposited.createFilter(fromBlock='latest')
    lock_log = escrow.events.Locked.createFilter(fromBlock='latest')
    commitments_log = escrow.events.CommitmentMade.createFilter(fromBlock='latest')

    # Initialize Escrow contract
    tx = escrow.functions.initialize(0, creator).transact({'from': creator})
    testerchain.wait_for_receipt(tx)

    # Can't use depositAndIncrease without active sub-stakes
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.depositAndIncrease(0, minimum_allowed_locked).transact({'from': staker})
        testerchain.wait_for_receipt(tx)

    # Check that nothing is locked
    assert escrow.functions.getLockedTokens(staker, 0).call() == 0
    assert escrow.functions.getSubStakesLength(staker).call() == 0

    # Staker transfers some tokens to the escrow and locks them
    stake = minimum_allowed_locked
    duration = 2 * minimum_locked_periods
    current_period = escrow.functions.getCurrentPeriod().call()
    tx = token.functions.transfer(staker, 2 * maximum_allowed_locked).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    tx = token.functions.approve(escrow.address, 2 * maximum_allowed_locked).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.deposit(staker, stake, duration).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    assert escrow.functions.getAllTokens(staker).call() == stake
    assert escrow.functions.getSubStakesLength(staker).call() == 1
    assert escrow.functions.getLockedTokens(staker, 0).call() == 0
    assert escrow.functions.getLockedTokens(staker, 1).call() == stake
    assert escrow.functions.getLockedTokens(staker, duration - 1).call() == stake
    assert escrow.functions.getLockedTokens(staker, duration).call() == stake
    assert escrow.functions.getLockedTokens(staker, duration + 1).call() == 0

    # Now Staker can deposit to the first sub-stake
    tx = escrow.functions.depositAndIncrease(0, minimum_allowed_locked // 2).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    stake += minimum_allowed_locked // 2
    assert escrow.functions.getAllTokens(staker).call() == stake
    assert escrow.functions.getSubStakesLength(staker).call() == 1
    assert escrow.functions.getLockedTokens(staker, 0).call() == 0
    assert escrow.functions.getLockedTokens(staker, 1).call() == stake
    assert escrow.functions.getLockedTokens(staker, duration - 1).call() == stake
    assert escrow.functions.getLockedTokens(staker, duration).call() == stake
    assert escrow.functions.getLockedTokens(staker, duration + 1).call() == 0

    events = deposit_log.get_all_entries()
    assert len(events) == 2
    event_args = events[-1]['args']
    assert event_args['staker'] == staker
    assert event_args['value'] == minimum_allowed_locked // 2
    assert event_args['periods'] == duration
    events = lock_log.get_all_entries()
    assert len(events) == 2
    event_args = events[-1]['args']
    assert event_args['staker'] == staker
    assert event_args['value'] == minimum_allowed_locked // 2
    assert event_args['firstPeriod'] == current_period + 1
    assert event_args['periods'] == duration
    assert len(commitments_log.get_all_entries()) == 0

    # Can't use depositAndIncrease without active sub-stakes
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.depositAndIncrease(0, minimum_allowed_locked).transact({'from': someone_else})
        testerchain.wait_for_receipt(tx)
    # Can't deposit zero amount of tokens
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.depositAndIncrease(0, 0).transact({'from': staker})
        testerchain.wait_for_receipt(tx)

    # Commit to next period and deposit again to the first sub-stake
    tx = escrow.functions.bondWorker(staker).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.setWindDown(True).transact({'from': staker})
    testerchain.wait_for_receipt(tx)

    assert escrow.functions.lockedPerPeriod(current_period).call() == 0
    assert escrow.functions.lockedPerPeriod(current_period + 1).call() == 0
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    assert escrow.functions.lockedPerPeriod(current_period).call() == 0
    assert escrow.functions.lockedPerPeriod(current_period + 1).call() == stake

    tx = escrow.functions.depositAndIncrease(0, minimum_allowed_locked // 4).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    stake += minimum_allowed_locked // 4
    assert escrow.functions.getAllTokens(staker).call() == stake
    assert escrow.functions.getSubStakesLength(staker).call() == 1
    assert escrow.functions.getLockedTokens(staker, 0).call() == 0
    assert escrow.functions.getLockedTokens(staker, 1).call() == stake
    assert escrow.functions.getLockedTokens(staker, duration - 1).call() == stake
    assert escrow.functions.getLockedTokens(staker, duration).call() == stake
    assert escrow.functions.getLockedTokens(staker, duration + 1).call() == 0
    assert escrow.functions.lockedPerPeriod(current_period).call() == 0
    assert escrow.functions.lockedPerPeriod(current_period + 1).call() == stake

    events = deposit_log.get_all_entries()
    assert len(events) == 3
    event_args = events[-1]['args']
    assert event_args['staker'] == staker
    assert event_args['value'] == minimum_allowed_locked // 4
    assert event_args['periods'] == duration
    events = lock_log.get_all_entries()
    assert len(events) == 3
    event_args = events[-1]['args']
    assert event_args['staker'] == staker
    assert event_args['value'] == minimum_allowed_locked // 4
    assert event_args['firstPeriod'] == current_period + 1
    assert event_args['periods'] == duration
    events = commitments_log.get_all_entries()
    assert len(events) == 2
    event_args = events[-1]['args']
    assert event_args['staker'] == staker
    assert event_args['period'] == current_period + 1
    assert event_args['value'] == minimum_allowed_locked // 4

    # Wait next period and try to increase again to check creation of temporary sub-stake
    testerchain.time_travel(hours=10)
    duration -= 1
    current_period = escrow.functions.getCurrentPeriod().call()
    assert escrow.functions.getLockedTokens(staker, 0).call() == stake
    assert escrow.functions.getLockedTokens(staker, 1).call() == stake
    assert escrow.functions.getLockedTokens(staker, duration - 1).call() == stake
    assert escrow.functions.getLockedTokens(staker, duration).call() == stake
    assert escrow.functions.getLockedTokens(staker, duration + 1).call() == 0
    assert escrow.functions.lockedPerPeriod(current_period).call() == stake
    assert escrow.functions.lockedPerPeriod(current_period + 1).call() == 0

    tx = escrow.functions.depositAndIncrease(0, minimum_allowed_locked).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    current_stake = stake
    next_stake = stake + minimum_allowed_locked
    assert escrow.functions.getAllTokens(staker).call() == next_stake
    assert escrow.functions.getSubStakesLength(staker).call() == 2
    assert escrow.functions.getLockedTokens(staker, 0).call() == current_stake
    assert escrow.functions.getLockedTokens(staker, 1).call() == next_stake
    assert escrow.functions.getLockedTokens(staker, duration - 1).call() == next_stake
    assert escrow.functions.getLockedTokens(staker, duration).call() == next_stake
    assert escrow.functions.getLockedTokens(staker, duration + 1).call() == 0
    assert escrow.functions.lockedPerPeriod(current_period).call() == current_stake
    assert escrow.functions.lockedPerPeriod(current_period + 1).call() == 0

    events = deposit_log.get_all_entries()
    assert len(events) == 4
    event_args = events[-1]['args']
    assert event_args['staker'] == staker
    assert event_args['value'] == minimum_allowed_locked
    assert event_args['periods'] == duration
    events = lock_log.get_all_entries()
    assert len(events) == 4
    event_args = events[-1]['args']
    assert event_args['staker'] == staker
    assert event_args['value'] == minimum_allowed_locked
    assert event_args['firstPeriod'] == current_period + 1
    assert event_args['periods'] == duration
    events = commitments_log.get_all_entries()
    assert len(events) == 2

    # Can't use temporary sub-stake because it ends in the current period
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.depositAndIncrease(1, minimum_allowed_locked).transact({'from': staker})
        testerchain.wait_for_receipt(tx)

    # Wait next period and check that temporary sub-stake is active until minting
    testerchain.time_travel(hours=10)
    stake = next_stake
    assert escrow.functions.getLockedTokens(staker, 0).call() == stake
    assert escrow.functions.getLockedTokens(staker, 1).call() == stake

    tx = escrow.functions.deposit(staker, minimum_allowed_locked, 3 * minimum_locked_periods).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    assert escrow.functions.getSubStakesLength(staker).call() == 3
    stake += minimum_allowed_locked

    tx = escrow.functions.mint().transact({'from': staker})
    testerchain.wait_for_receipt(tx)

    tx = escrow.functions.deposit(staker, minimum_allowed_locked, 3 * minimum_locked_periods).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    assert escrow.functions.getSubStakesLength(staker).call() == 3
    stake += minimum_allowed_locked

    # Unlock some tokens
    for i in range(duration):
        tx = escrow.functions.commitToNextPeriod().transact({'from': staker})
        testerchain.wait_for_receipt(tx)
        testerchain.time_travel(hours=10)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker})
    testerchain.wait_for_receipt(tx)

    current_period = escrow.functions.getCurrentPeriod().call()
    next_stake = 2 * minimum_allowed_locked
    duration = 3 * minimum_locked_periods - duration
    assert escrow.functions.getAllTokens(staker).call() == stake
    assert escrow.functions.getSubStakesLength(staker).call() == 3
    assert escrow.functions.getLockedTokens(staker, 0).call() == stake
    assert escrow.functions.getLockedTokens(staker, 1).call() == next_stake
    assert escrow.functions.getLockedTokens(staker, duration - 1).call() == next_stake
    assert escrow.functions.getLockedTokens(staker, duration).call() == next_stake
    assert escrow.functions.getLockedTokens(staker, duration + 1).call() == 0
    assert escrow.functions.lockedPerPeriod(current_period).call() == stake
    assert escrow.functions.lockedPerPeriod(current_period + 1).call() == next_stake

    # Can't lock more than staker has
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.lockAndIncrease(1, stake - next_stake + 1).transact({'from': staker})
        testerchain.wait_for_receipt(tx)
    # Can't ue zero value
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.lockAndIncrease(1, 0).transact({'from': staker})
        testerchain.wait_for_receipt(tx)

    # Lock and increase
    deposits = len(deposit_log.get_all_entries())
    locks = len(lock_log.get_all_entries())
    commitments = len(commitments_log.get_all_entries())

    tx = escrow.functions.lockAndIncrease(1, stake - next_stake - 1).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    assert escrow.functions.getAllTokens(staker).call() == stake
    assert escrow.functions.getSubStakesLength(staker).call() == 4
    assert escrow.functions.getLockedTokens(staker, 0).call() == stake
    assert escrow.functions.getLockedTokens(staker, 1).call() == stake - 1
    assert escrow.functions.getLockedTokens(staker, duration - 1).call() == stake - 1
    assert escrow.functions.getLockedTokens(staker, duration).call() == stake - 1
    assert escrow.functions.getLockedTokens(staker, duration + 1).call() == 0
    assert escrow.functions.lockedPerPeriod(current_period).call() == stake
    assert escrow.functions.lockedPerPeriod(current_period + 1).call() == stake - 1

    assert len(deposit_log.get_all_entries()) == deposits
    events = lock_log.get_all_entries()
    assert len(events) == locks + 1
    event_args = events[-1]['args']
    assert event_args['staker'] == staker
    assert event_args['value'] == stake - next_stake - 1
    assert event_args['firstPeriod'] == current_period + 1
    assert event_args['periods'] == duration
    events = commitments_log.get_all_entries()
    assert len(events) == commitments + 1
    event_args = events[-1]['args']
    assert event_args['staker'] == staker
    assert event_args['period'] == current_period + 1
    assert event_args['value'] == stake - next_stake - 1


def test_merge(testerchain, token, escrow_contract, token_economics):
    minimum_allowed_locked = token_economics.minimum_allowed_locked
    maximum_allowed_locked = 1500
    minimum_locked_periods = token_economics.minimum_locked_periods

    escrow = escrow_contract(maximum_allowed_locked, disable_reward=True)
    creator = testerchain.client.accounts[0]
    staker = testerchain.client.accounts[1]
    merge_log = escrow.events.Merged.createFilter(fromBlock='latest')

    # Initialize Escrow contract
    tx = escrow.functions.initialize(0, creator).transact({'from': creator})
    testerchain.wait_for_receipt(tx)

    # Can merge only two active sub-stakes
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.mergeStake(0, 1).transact({'from': staker})
        testerchain.wait_for_receipt(tx)

    # Check that nothing is locked
    assert escrow.functions.getLockedTokens(staker, 0).call() == 0
    assert escrow.functions.getSubStakesLength(staker).call() == 0

    # Staker transfers some tokens to the escrow and locks them
    stake = minimum_allowed_locked
    duration_1 = minimum_locked_periods
    current_period = escrow.functions.getCurrentPeriod().call()
    tx = token.functions.transfer(staker, 2 * maximum_allowed_locked).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    tx = token.functions.approve(escrow.address, 2 * maximum_allowed_locked).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.deposit(staker, stake, duration_1).transact({'from': staker})
    testerchain.wait_for_receipt(tx)

    # Can merge only two active sub-stakes
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.mergeStake(0, 1).transact({'from': staker})
        testerchain.wait_for_receipt(tx)

    # Create second sub-stake
    tx = escrow.functions.deposit(staker, 2 * minimum_allowed_locked, duration_1).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    stake += 2 * minimum_allowed_locked
    assert escrow.functions.getAllTokens(staker).call() == stake
    assert escrow.functions.getSubStakesLength(staker).call() == 2
    assert escrow.functions.getLockedTokens(staker, 0).call() == 0
    assert escrow.functions.getLockedTokens(staker, 1).call() == stake
    assert escrow.functions.getLockedTokens(staker, duration_1 - 1).call() == stake
    assert escrow.functions.getLockedTokens(staker, duration_1).call() == stake
    assert escrow.functions.getLockedTokens(staker, duration_1 + 1).call() == 0
    assert escrow.functions.getLastPeriodOfSubStake(staker, 0).call() == current_period + duration_1
    assert escrow.functions.getLastPeriodOfSubStake(staker, 1).call() == current_period + duration_1

    # Can't merge non existent sub-stakes
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.mergeStake(0, 2).transact({'from': staker})
        testerchain.wait_for_receipt(tx)

    # Can't merge sub-stake with itself
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.mergeStake(0, 0).transact({'from': staker})
        testerchain.wait_for_receipt(tx)

    # Merge two equal sub-stakes
    tx = escrow.functions.mergeStake(1, 0).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    assert escrow.functions.getAllTokens(staker).call() == stake
    assert escrow.functions.getSubStakesLength(staker).call() == 2
    assert escrow.functions.getLockedTokens(staker, 0).call() == 0
    assert escrow.functions.getLockedTokens(staker, 1).call() == stake
    assert escrow.functions.getLockedTokens(staker, duration_1 - 1).call() == stake
    assert escrow.functions.getLockedTokens(staker, duration_1).call() == stake
    assert escrow.functions.getLockedTokens(staker, duration_1 + 1).call() == 0
    assert escrow.functions.getLastPeriodOfSubStake(staker, 0).call() == 1
    assert escrow.functions.getLastPeriodOfSubStake(staker, 1).call() == current_period + duration_1

    events = merge_log.get_all_entries()
    assert len(events) == 1
    event_args = events[-1]['args']
    assert event_args['staker'] == staker
    assert event_args['value1'] == 2 * minimum_allowed_locked
    assert event_args['value2'] == minimum_allowed_locked
    assert event_args['lastPeriod'] == current_period + duration_1

    # Both sub-stakes must have last period in the next period or later
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.mergeStake(0, 1).transact({'from': staker})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.mergeStake(1, 0).transact({'from': staker})
        testerchain.wait_for_receipt(tx)

    # Deposit again, inactive sub-stake will be reused
    duration_2 = 3 * minimum_locked_periods
    tx = escrow.functions.deposit(staker, 3 * minimum_allowed_locked, duration_2).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    stake_2 = stake + 3 * minimum_allowed_locked
    assert escrow.functions.getAllTokens(staker).call() == stake_2
    assert escrow.functions.getSubStakesLength(staker).call() == 2
    assert escrow.functions.getLockedTokens(staker, 0).call() == 0
    assert escrow.functions.getLockedTokens(staker, 1).call() == stake_2
    assert escrow.functions.getLockedTokens(staker, duration_1 - 1).call() == stake_2
    assert escrow.functions.getLockedTokens(staker, duration_1).call() == stake_2
    assert escrow.functions.getLockedTokens(staker, duration_1 + 1).call() == stake_2 - stake
    assert escrow.functions.getLockedTokens(staker, duration_2 - 1).call() == stake_2 - stake
    assert escrow.functions.getLockedTokens(staker, duration_2).call() == stake_2 - stake
    assert escrow.functions.getLockedTokens(staker, duration_2 + 1).call() == 0

    # Both sub-stakes must have equal last period to be mergeable
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.mergeStake(0, 1).transact({'from': staker})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.mergeStake(1, 0).transact({'from': staker})
        testerchain.wait_for_receipt(tx)

    # Make a commitments and unlock shortest sub-stake
    tx = escrow.functions.bondWorker(staker).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.setWindDown(True).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    testerchain.time_travel(hours=10)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    testerchain.time_travel(hours=10)

    # Both sub-stakes must have last period in the next period or later
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.mergeStake(0, 1).transact({'from': staker})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.mergeStake(1, 0).transact({'from': staker})
        testerchain.wait_for_receipt(tx)

    tx = escrow.functions.commitToNextPeriod().transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    testerchain.time_travel(hours=10)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    duration_2 -= 3

    # Deposit again
    current_period = escrow.functions.getCurrentPeriod().call()
    tx = escrow.functions.deposit(staker, minimum_allowed_locked, duration_2).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    all_tokens = stake_2 + minimum_allowed_locked
    stake = 3 * minimum_allowed_locked
    stake_2 = stake + minimum_allowed_locked
    assert escrow.functions.getAllTokens(staker).call() == all_tokens
    assert escrow.functions.getSubStakesLength(staker).call() == 2
    assert escrow.functions.getLockedTokens(staker, 0).call() == stake
    assert escrow.functions.getLockedTokens(staker, 1).call() == stake_2
    assert escrow.functions.getLockedTokens(staker, duration_2 - 1).call() == stake_2
    assert escrow.functions.getLockedTokens(staker, duration_2).call() == stake_2
    assert escrow.functions.getLockedTokens(staker, duration_2 + 1).call() == 0
    assert escrow.functions.getLastPeriodOfSubStake(staker, 0).call() == current_period + duration_2
    assert escrow.functions.getLastPeriodOfSubStake(staker, 1).call() == current_period + duration_2

    # Merge two sub-stakes with different first period
    tx = escrow.functions.mergeStake(0, 1).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    assert escrow.functions.getAllTokens(staker).call() == all_tokens
    assert escrow.functions.getSubStakesLength(staker).call() == 2
    assert escrow.functions.getLockedTokens(staker, 0).call() == stake
    assert escrow.functions.getLockedTokens(staker, 1).call() == stake_2
    assert escrow.functions.getLockedTokens(staker, duration_2 - 1).call() == stake_2
    assert escrow.functions.getLockedTokens(staker, duration_2).call() == stake_2
    assert escrow.functions.getLockedTokens(staker, duration_2 + 1).call() == 0
    assert escrow.functions.getLastPeriodOfSubStake(staker, 0).call() == current_period
    assert escrow.functions.getLastPeriodOfSubStake(staker, 1).call() == current_period + duration_2

    events = merge_log.get_all_entries()
    assert len(events) == 2
    event_args = events[-1]['args']
    assert event_args['staker'] == staker
    assert event_args['value1'] == 3 * minimum_allowed_locked
    assert event_args['value2'] == minimum_allowed_locked
    assert event_args['lastPeriod'] == current_period + duration_2

    # Deposit again, both sub-stakes are still active and new one will be created
    testerchain.time_travel(hours=10)
    duration_2 -= 1
    current_period = escrow.functions.getCurrentPeriod().call()
    tx = escrow.functions.deposit(staker, 2 * minimum_allowed_locked, duration_2).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    all_tokens += 2 * minimum_allowed_locked
    stake += minimum_allowed_locked
    stake_2 += 2 * minimum_allowed_locked
    assert escrow.functions.getAllTokens(staker).call() == all_tokens
    assert escrow.functions.getSubStakesLength(staker).call() == 3
    assert escrow.functions.getLockedTokens(staker, 0).call() == stake
    assert escrow.functions.getLockedTokens(staker, 1).call() == stake_2
    assert escrow.functions.getLockedTokens(staker, duration_2 - 1).call() == stake_2
    assert escrow.functions.getLockedTokens(staker, duration_2).call() == stake_2
    assert escrow.functions.getLockedTokens(staker, duration_2 + 1).call() == 0
    assert escrow.functions.getLastPeriodOfSubStake(staker, 0).call() == current_period - 1
    assert escrow.functions.getLastPeriodOfSubStake(staker, 1).call() == current_period + duration_2
    assert escrow.functions.getLastPeriodOfSubStake(staker, 2).call() == current_period + duration_2

    # One of the sub-stake become inactive after minting
    tx = escrow.functions.mint(staker).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.deposit(staker, minimum_allowed_locked, duration_2).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    all_tokens += minimum_allowed_locked
    stake_2 += minimum_allowed_locked
    assert escrow.functions.getAllTokens(staker).call() == all_tokens
    assert escrow.functions.getSubStakesLength(staker).call() == 3
    assert escrow.functions.getLockedTokens(staker, 0).call() == stake
    assert escrow.functions.getLockedTokens(staker, 1).call() == stake_2
    assert escrow.functions.getLockedTokens(staker, duration_2 - 1).call() == stake_2
    assert escrow.functions.getLockedTokens(staker, duration_2).call() == stake_2
    assert escrow.functions.getLockedTokens(staker, duration_2 + 1).call() == 0
    assert escrow.functions.getLastPeriodOfSubStake(staker, 0).call() == current_period + duration_2
    assert escrow.functions.getLastPeriodOfSubStake(staker, 1).call() == current_period + duration_2
    assert escrow.functions.getLastPeriodOfSubStake(staker, 2).call() == current_period + duration_2

    # Test merge again to check other branch in if...else clause
    tx = escrow.functions.mergeStake(2, 1).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    assert escrow.functions.getAllTokens(staker).call() == all_tokens
    assert escrow.functions.getSubStakesLength(staker).call() == 3
    assert escrow.functions.getLockedTokens(staker, 0).call() == stake
    assert escrow.functions.getLockedTokens(staker, 1).call() == stake_2
    assert escrow.functions.getLockedTokens(staker, duration_2 - 1).call() == stake_2
    assert escrow.functions.getLockedTokens(staker, duration_2).call() == stake_2
    assert escrow.functions.getLockedTokens(staker, duration_2 + 1).call() == 0
    assert escrow.functions.getLastPeriodOfSubStake(staker, 0).call() == current_period + duration_2
    assert escrow.functions.getLastPeriodOfSubStake(staker, 1).call() == current_period
    assert escrow.functions.getLastPeriodOfSubStake(staker, 2).call() == current_period + duration_2

    events = merge_log.get_all_entries()
    assert len(events) == 3
    event_args = events[-1]['args']
    assert event_args['staker'] == staker
    assert event_args['value1'] == 2 * minimum_allowed_locked
    assert event_args['value2'] == 4 * minimum_allowed_locked
    assert event_args['lastPeriod'] == current_period + duration_2


def test_max_sub_stakes(testerchain, token, escrow_contract):
    escrow = escrow_contract(10000, disable_reward=True)
    creator = testerchain.client.accounts[0]
    staker = testerchain.client.accounts[1]

    # Initialize Escrow contract
    tx = escrow.functions.initialize(0, creator).transact({'from': creator})
    testerchain.wait_for_receipt(tx)

    # Prepare before deposit
    tx = token.functions.transfer(staker, 4000).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    tx = token.functions.approve(escrow.address, 4000).transact({'from': staker})
    testerchain.wait_for_receipt(tx)

    # Lock one sub stake from current period and others from next one
    tx = escrow.functions.deposit(staker, 100, 2).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.bondWorker(staker).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.setWindDown(True).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    assert 1 == escrow.functions.getSubStakesLength(staker).call()

    tx = escrow.functions.commitToNextPeriod().transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    testerchain.time_travel(hours=10)
    for index in range(MAX_SUB_STAKES - 1):
        tx = escrow.functions.deposit(staker, 100, 2).transact({'from': staker})
        testerchain.wait_for_receipt(tx)
    assert MAX_SUB_STAKES == escrow.functions.getSubStakesLength(staker).call()
    assert 3000 == escrow.functions.getLockedTokens(staker, 1).call()

    # Can't lock more because of reaching the maximum number of active sub stakes
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.deposit(staker, 100, 2).transact({'from': staker})
        testerchain.wait_for_receipt(tx)

    # After two periods first sub stake will be unlocked and we can lock again
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    testerchain.time_travel(hours=10)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    testerchain.time_travel(hours=10)
    assert 2900 == escrow.functions.getLockedTokens(staker, 0).call()
    assert 0 == escrow.functions.getLockedTokens(staker, 1).call()
    assert MAX_SUB_STAKES == escrow.functions.getSubStakesLength(staker).call()
    # Before sub stake will be inactive it must be rewarded
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.deposit(staker, 100, 2).transact({'from': staker})
        testerchain.wait_for_receipt(tx)
    tx = escrow.functions.mint().transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.deposit(staker, 100, 2).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    assert 2900 == escrow.functions.getLockedTokens(staker, 0).call()
    assert 100 == escrow.functions.getLockedTokens(staker, 1).call()
    assert MAX_SUB_STAKES == escrow.functions.getSubStakesLength(staker).call()

    # Can't lock more because of reaching the maximum number of active sub stakes and they are not rewarded yet
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.deposit(staker, 100, 2).transact({'from': staker})
        testerchain.wait_for_receipt(tx)


def test_allowable_locked_tokens(testerchain, token_economics, token, escrow_contract, deploy_contract):
    maximum_allowed = 2000
    minimum_allowed = token_economics.minimum_allowed_locked
    escrow = escrow_contract(maximum_allowed, disable_reward=True)
    creator, staker1, staker2, staker3, *everyone_else = testerchain.client.accounts

    # Initialize Escrow contract
    tx = escrow.functions.initialize(0, creator).transact({'from': creator})
    testerchain.wait_for_receipt(tx)

    # Prepare before deposit
    duration = token_economics.minimum_locked_periods
    tx = token.functions.transfer(staker1, 2 * maximum_allowed).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    tx = token.functions.transfer(staker2, 2 * maximum_allowed).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    tx = token.functions.transfer(staker3, 2 * maximum_allowed).transact({'from': creator})
    testerchain.wait_for_receipt(tx)

    # Staker can't deposit and lock too low value (less than _minAllowableLockedTokens coefficient)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = token.functions.approveAndCall(escrow.address, minimum_allowed - 1, testerchain.w3.toBytes(duration))\
            .transact({'from': staker1})
        testerchain.wait_for_receipt(tx)
    # And can't deposit and lock too high value (more than _maxAllowableLockedTokens coefficient)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = token.functions.approveAndCall(escrow.address, maximum_allowed + 1, testerchain.w3.toBytes(duration))\
            .transact({'from': staker1})
        testerchain.wait_for_receipt(tx)

    tx = token.functions.approve(escrow.address, maximum_allowed + 1).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    # Staker can't deposit and lock too low value (less than _minAllowableLockedTokens coefficient)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.deposit(staker1, minimum_allowed - 1, duration).transact({'from': staker1})
        testerchain.wait_for_receipt(tx)
    # And can't deposit and lock too high value (more than _maxAllowableLockedTokens coefficient)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.deposit(staker1, maximum_allowed + 1, duration).transact({'from': staker1})
        testerchain.wait_for_receipt(tx)

    tx = escrow.functions.deposit(staker1, minimum_allowed, duration).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    staker1_lock = minimum_allowed
    tx = token.functions.approve(escrow.address, 0).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tx = token.functions.approveAndCall(escrow.address, minimum_allowed, testerchain.w3.toBytes(duration)) \
        .transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    staker1_lock += minimum_allowed

    # Staker can't use depositAndIncrease with zero value
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.depositAndIncrease(0, 0).transact({'from': staker1})
        testerchain.wait_for_receipt(tx)

    # Preparation for next cases
    tx = token.functions.approveAndCall(escrow.address, minimum_allowed, testerchain.w3.toBytes(duration))\
        .transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    staker1_lock += minimum_allowed
    tx = token.functions.approveAndCall(escrow.address, maximum_allowed, testerchain.w3.toBytes(duration))\
        .transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    tx = token.functions.approveAndCall(escrow.address, maximum_allowed - 1, testerchain.w3.toBytes(duration))\
        .transact({'from': staker3})
    testerchain.wait_for_receipt(tx)

    # Can't deposit or lock too high value (more than _maxAllowableLockedTokens value)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = token.functions.approveAndCall(escrow.address, minimum_allowed, testerchain.w3.toBytes(2 * duration))\
            .transact({'from': staker2})
        testerchain.wait_for_receipt(tx)
    tx = token.functions.approve(escrow.address, minimum_allowed).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.deposit(staker2, minimum_allowed, 2 * duration).transact({'from': staker2})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.depositAndIncrease(0, 1).transact({'from': staker2})
        testerchain.wait_for_receipt(tx)

    # Can't deposit too high value using depositAndIncrease
    tx = token.functions.approve(escrow.address, maximum_allowed).transact({'from': staker3})
    testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.depositAndIncrease(0, 2).transact({'from': staker3})
        testerchain.wait_for_receipt(tx)
    tx = escrow.functions.depositAndIncrease(0, 1).transact({'from': staker3})
    testerchain.wait_for_receipt(tx)

    # Prepare for testing `lock()`: staker makes new sub-stake and unlocks first sub-stake
    tx = token.functions\
        .approveAndCall(escrow.address, maximum_allowed - staker1_lock, testerchain.w3.toBytes(2 * duration)) \
        .transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.setWindDown(True).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.bondWorker(staker1).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    for _ in range(duration):
        tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
        testerchain.wait_for_receipt(tx)
        testerchain.time_travel(hours=10)
    testerchain.time_travel(hours=20)
    staker1_lock = maximum_allowed - staker1_lock
    assert escrow.functions.getLockedTokens(staker1, 0).call() == staker1_lock

    # Staker can't lock again too low or too high value
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.lockAndCreate(minimum_allowed - 1, duration).transact({'from': staker1})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.lockAndCreate(maximum_allowed - staker1_lock + 1, duration).transact({'from': staker1})
        testerchain.wait_for_receipt(tx)
    sub_stake_index = escrow.functions.getSubStakesLength(staker1).call() - 1
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.lockAndIncrease(sub_stake_index, maximum_allowed - staker1_lock + 1).transact({'from': staker1})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.lockAndIncrease(sub_stake_index, 0).transact({'from': staker1})
        testerchain.wait_for_receipt(tx)

    tx = escrow.functions.lockAndIncrease(sub_stake_index, minimum_allowed // 2).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    staker1_lock += minimum_allowed // 2
    tx = escrow.functions.lockAndCreate(minimum_allowed, duration).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    staker1_lock += minimum_allowed

    # Check that still can lock up to maximum
    tx = escrow.functions.lockAndCreate(maximum_allowed - staker1_lock, duration + 1).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)

    # Unlock some tokens to check maximum for lockAndIncrease function
    for _ in range(duration):
        tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
        testerchain.wait_for_receipt(tx)
        testerchain.time_travel(hours=10)
    testerchain.time_travel(hours=20)
    staker1_lock = escrow.functions.getLockedTokens(staker1, 0).call()
    assert staker1_lock < maximum_allowed
    sub_stake_index = escrow.functions.getSubStakesLength(staker1).call() - 1
    tx = escrow.functions.lockAndIncrease(sub_stake_index, maximum_allowed - staker1_lock).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)


def test_staking_from_worklock(testerchain, token, worklock, escrow_contract, token_economics):
    """
    Tests for staking method: depositFromWorkLock
    """

    maximum_allowed_locked = 1500
    escrow = escrow_contract(maximum_allowed_locked, disable_reward=True)
    creator, staker1, staker2, staker3 = testerchain.client.accounts[0:4]
    deposit_log = escrow.events.Deposited.createFilter(fromBlock='latest')
    lock_log = escrow.events.Locked.createFilter(fromBlock='latest')
    wind_down_log = escrow.events.WindDownSet.createFilter(fromBlock='latest')

    # Give WorkLock and Staker some coins
    tx = token.functions.transfer(staker1, maximum_allowed_locked).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    tx = token.functions.transfer(worklock.address, maximum_allowed_locked).transact({'from': creator})
    testerchain.wait_for_receipt(tx)

    # Can't use method not from WorkLock
    value = token_economics.minimum_allowed_locked
    duration = token_economics.minimum_locked_periods
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.depositFromWorkLock(staker1, value, duration).transact({'from': staker1})
        testerchain.wait_for_receipt(tx)
    assert token.functions.balanceOf(escrow.address).call() == 0

    # Can claim before initialization
    wind_down, _re_stake, _measure_work, _snapshots, _migrated = escrow.functions.getFlags(staker1).call()
    assert not wind_down
    current_period = escrow.functions.getCurrentPeriod().call()
    tx = worklock.functions.depositFromWorkLock(staker1, value, duration).transact()
    testerchain.wait_for_receipt(tx)
    assert token.functions.balanceOf(escrow.address).call() == value
    assert escrow.functions.getLockedTokens(staker1, 0).call() == 0
    assert escrow.functions.getLockedTokens(staker1, 1).call() == value
    assert escrow.functions.getLockedTokens(staker1, duration).call() == value
    assert escrow.functions.getLockedTokens(staker1, duration + 1).call() == 0
    wind_down, _re_stake, _measure_work, _snapshots, _migrated = escrow.functions.getFlags(staker1).call()
    assert wind_down

    # Check that all events are emitted
    events = deposit_log.get_all_entries()
    assert len(events) == 1
    event_args = events[-1]['args']
    assert event_args['staker'] == staker1
    assert event_args['value'] == value
    assert event_args['periods'] == duration

    events = lock_log.get_all_entries()
    assert len(events) == 1
    event_args = events[-1]['args']
    assert event_args['staker'] == staker1
    assert event_args['value'] == value
    assert event_args['firstPeriod'] == current_period + 1
    assert event_args['periods'] == duration

    events = wind_down_log.get_all_entries()
    assert len(events) == 1
    event_args = events[-1]['args']
    assert event_args['staker'] == staker1
    assert event_args['windDown']

    # Deposit directly and then through WorkLock
    tx = token.functions.transfer(staker2, maximum_allowed_locked).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    tx = token.functions.approve(escrow.address, maximum_allowed_locked).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.deposit(staker2, value, duration).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)

    tx = escrow.functions.initialize(0, creator).transact({'from': creator})
    testerchain.wait_for_receipt(tx)

    wind_down, _re_stake, _measure_work, _snapshots, _migrated = escrow.functions.getFlags(staker2).call()
    assert not wind_down
    current_period = escrow.functions.getCurrentPeriod().call()
    tx = worklock.functions.depositFromWorkLock(staker2, value, duration).transact()
    testerchain.wait_for_receipt(tx)
    assert token.functions.balanceOf(escrow.address).call() == 3 * value
    assert escrow.functions.getLockedTokens(staker2, 0).call() == 0
    assert escrow.functions.getLockedTokens(staker2, 1).call() == 2 * value
    assert escrow.functions.getLockedTokens(staker2, duration).call() == 2 * value
    assert escrow.functions.getLockedTokens(staker2, duration + 1).call() == 0
    wind_down, _re_stake, _measure_work, _snapshots, _migrated = escrow.functions.getFlags(staker2).call()
    assert not wind_down

    # Check that all events are emitted
    events = deposit_log.get_all_entries()
    assert len(events) == 3
    event_args = events[-1]['args']
    assert event_args['staker'] == staker2
    assert event_args['value'] == value
    assert event_args['periods'] == duration

    events = lock_log.get_all_entries()
    assert len(events) == 3
    event_args = events[-1]['args']
    assert event_args['staker'] == staker2
    assert event_args['value'] == value
    assert event_args['firstPeriod'] == current_period + 1
    assert event_args['periods'] == duration

    events = wind_down_log.get_all_entries()
    assert len(events) == 1

    # Enable wind down before deposit from WorkLock
    tx = token.functions.transfer(staker3, maximum_allowed_locked).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    tx = token.functions.approve(escrow.address, maximum_allowed_locked).transact({'from': staker3})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.deposit(staker3, value, duration).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)

    tx = escrow.functions.setWindDown(True).transact({'from': staker3})
    testerchain.wait_for_receipt(tx)
    wind_down, _re_stake, _measure_work, _snapshots, _migrated = escrow.functions.getFlags(staker3).call()
    assert wind_down
    events = wind_down_log.get_all_entries()
    assert len(events) == 2

    current_period = escrow.functions.getCurrentPeriod().call()
    tx = worklock.functions.depositFromWorkLock(staker3, value, duration).transact()
    testerchain.wait_for_receipt(tx)
    assert token.functions.balanceOf(escrow.address).call() == 5 * value
    assert escrow.functions.getLockedTokens(staker3, 0).call() == 0
    assert escrow.functions.getLockedTokens(staker3, 1).call() == 2 * value
    assert escrow.functions.getLockedTokens(staker3, duration).call() == 2 * value
    assert escrow.functions.getLockedTokens(staker3, duration + 1).call() == 0
    wind_down, _re_stake, _measure_work, _snapshots, _migrated = escrow.functions.getFlags(staker3).call()
    assert wind_down

    # Check that all events are emitted
    events = deposit_log.get_all_entries()
    assert len(events) == 5
    event_args = events[-1]['args']
    assert event_args['staker'] == staker3
    assert event_args['value'] == value
    assert event_args['periods'] == duration

    events = lock_log.get_all_entries()
    assert len(events) == 5
    event_args = events[-1]['args']
    assert event_args['staker'] == staker3
    assert event_args['value'] == value
    assert event_args['firstPeriod'] == current_period + 1
    assert event_args['periods'] == duration

    events = wind_down_log.get_all_entries()
    assert len(events) == 2
