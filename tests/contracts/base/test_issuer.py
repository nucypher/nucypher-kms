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

from nucypher.blockchain.economics import BaseEconomics

INITIAL_SUPPLY = 10 ** 26
TOTAL_SUPPLY = 2 * 10 ** 36


@pytest.fixture()
def token(testerchain, deploy_contract):
    # Create an ERC20 token
    token, _ = deploy_contract('NuCypherToken', _totalSupplyOfTokens=TOTAL_SUPPLY)
    return token


def test_issuer(testerchain, token, deploy_contract):
    economics = BaseEconomics(initial_supply=INITIAL_SUPPLY,
                              first_phase_supply=INITIAL_SUPPLY + 1000,
                              total_supply=TOTAL_SUPPLY,
                              first_phase_max_issuance=333,
                              issuance_decay_coefficient=5 * 10 ** 34,
                              lock_duration_coefficient_1=10 ** 4,
                              lock_duration_coefficient_2=2 * 10 ** 4,
                              maximum_rewarded_periods=10 ** 4,
                              genesis_hours_per_period=10,
                              hours_per_period=10)

    def calculate_first_phase_reward(locked, total_locked, locked_periods):
        return economics.first_phase_max_issuance * locked * \
               (locked_periods + economics.lock_duration_coefficient_1) // \
               (total_locked * economics.lock_duration_coefficient_2)

    def calculate_second_phase_reward(locked, total_locked, locked_periods):
        return (economics.erc20_reward_supply - INITIAL_SUPPLY) * locked * \
               (locked_periods + economics.lock_duration_coefficient_1) // \
               (total_locked * economics.issuance_decay_coefficient * economics.lock_duration_coefficient_2)

    creator = testerchain.client.accounts[0]
    staker = testerchain.client.accounts[1]
    owner = testerchain.client.accounts[2]

    # Only token contract is allowed in Issuer constructor
    bad_args = dict(_token=staker,
                    _genesisHoursPerPeriod=economics.genesis_hours_per_period,
                    _hoursPerPeriod=economics.hours_per_period,
                    _issuanceDecayCoefficient=economics.issuance_decay_coefficient,
                    _lockDurationCoefficient1=economics.lock_duration_coefficient_1,
                    _lockDurationCoefficient2=economics.lock_duration_coefficient_2,
                    _maximumRewardedPeriods=economics.maximum_rewarded_periods,
                    _firstPhaseTotalSupply=economics.first_phase_supply,
                    _firstPhaseMaxIssuance=economics.first_phase_max_issuance)
    with pytest.raises((TransactionFailed, ValueError)):
        deploy_contract(contract_name='IssuerMock', **bad_args)

    # Creator deploys the issuer
    args = bad_args
    args.update(_token=token.address)
    issuer, _ = deploy_contract(contract_name='IssuerMock', **args)
    events = issuer.events.Initialized.createFilter(fromBlock='latest')

    # Approve issuer contract to get funds when initializing
    tx = token.functions.approve(issuer.address, economics.erc20_reward_supply).transact({'from': creator})
    testerchain.wait_for_receipt(tx)

    # Transfer ownership of contracts from the creator to the expected owner
    tx = issuer.functions.transferOwnership(owner).transact({'from': creator})
    testerchain.wait_for_receipt(tx)

    # Can't donate tokens before initialization
    with pytest.raises((TransactionFailed, ValueError)):
        tx = issuer.functions.donate(1).transact({'from': creator})
        testerchain.wait_for_receipt(tx)

    # Only owner can initialize, not even the original creator
    with pytest.raises((TransactionFailed, ValueError)):
        tx = issuer.functions.initialize(0, staker).transact({'from': creator})
        testerchain.wait_for_receipt(tx)

    # Can't initialize if the funding address doesn't have enough tokens
    with pytest.raises((TransactionFailed, ValueError)):
        tx = issuer.functions.initialize(economics.erc20_reward_supply, staker).transact({'from': owner})
        testerchain.wait_for_receipt(tx)

    # Initialization must be performed by the owner, and requires amount and funding address
    tx = issuer.functions.initialize(economics.erc20_reward_supply, creator).transact({'from': owner})
    testerchain.wait_for_receipt(tx)

    events = events.get_all_entries()
    assert 1 == len(events)
    assert economics.erc20_reward_supply == events[0]['args']['reservedReward']
    balance = token.functions.balanceOf(issuer.address).call()

    # Can't initialize second time
    with pytest.raises((TransactionFailed, ValueError)):
        tx = issuer.functions.initialize(0, owner).transact({'from': owner})
        testerchain.wait_for_receipt(tx)

    # First phase

    # Check result of minting tokens
    tx = issuer.functions.testMint(0, 1000, 2000, 0).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    reward = calculate_first_phase_reward(1000, 2000, 0)
    assert calculate_second_phase_reward(1000, 2000, 0) != reward
    assert token.functions.balanceOf(staker).call() == reward
    assert token.functions.balanceOf(issuer.address).call() == balance - reward

    # The result must be more because of a different proportion of lockedValue and totalLockedValue
    tx = issuer.functions.testMint(0, 500, 500, 0).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    reward += calculate_first_phase_reward(500, 500, 0)
    assert token.functions.balanceOf(staker).call() == reward
    assert token.functions.balanceOf(issuer.address).call() == balance - reward

    # The result must be more because of bigger value of allLockedPeriods
    tx = issuer.functions.testMint(0, 500, 500, 10 ** 4).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    reward += calculate_first_phase_reward(500, 500, 10 ** 4)
    assert token.functions.balanceOf(staker).call() == reward
    assert token.functions.balanceOf(issuer.address).call() == balance - reward

    # The result is the same because allLockedPeriods more then specified coefficient _rewardedPeriods
    period = issuer.functions.getCurrentPeriod().call()
    tx = issuer.functions.testMint(period, 500, 500, 2 * 10 ** 4).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    reward += calculate_first_phase_reward(500, 500, 10 ** 4)
    assert token.functions.balanceOf(staker).call() == reward
    assert token.functions.balanceOf(issuer.address).call() == balance - reward

    # Still the first phase because minting period didn't change
    assert issuer.functions.previousPeriodSupply().call() + economics.first_phase_max_issuance < economics.first_phase_supply
    assert issuer.functions.currentPeriodSupply().call() < economics.first_phase_supply
    assert issuer.functions.currentPeriodSupply().call() + economics.first_phase_max_issuance >= economics.first_phase_supply

    tx = issuer.functions.testMint(0, 100, 500, 10 ** 4).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    reward += calculate_first_phase_reward(100, 500, 10 ** 4)
    assert token.functions.balanceOf(staker).call() == reward
    assert token.functions.balanceOf(issuer.address).call() == balance - reward

    # Second phase
    assert issuer.functions.previousPeriodSupply().call() + economics.first_phase_max_issuance < economics.first_phase_supply
    assert issuer.functions.currentPeriodSupply().call() < economics.first_phase_supply
    assert issuer.functions.currentPeriodSupply().call() + economics.first_phase_max_issuance >= economics.first_phase_supply
    # Check result of minting tokens
    tx = issuer.functions.testMint(period + 1, 1000, 2000, 0).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    current_reward = calculate_second_phase_reward(1000, 2000, 0)
    assert calculate_first_phase_reward(500, 500, 10 ** 4) != current_reward
    reward += current_reward
    assert reward == token.functions.balanceOf(staker).call()
    assert balance - reward == token.functions.balanceOf(issuer.address).call()

    # The result must be more because of a different proportion of lockedValue and totalLockedValue
    tx = issuer.functions.testMint(1, 500, 500, 0).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    reward += calculate_second_phase_reward(500, 500, 0)
    assert reward == token.functions.balanceOf(staker).call()
    assert balance - reward == token.functions.balanceOf(issuer.address).call()

    # The result must be more because of bigger value of allLockedPeriods
    tx = issuer.functions.testMint(1, 500, 500, 10 ** 4).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    reward += calculate_second_phase_reward(500, 500, 10 ** 4)
    assert reward == token.functions.balanceOf(staker).call()
    assert balance - reward == token.functions.balanceOf(issuer.address).call()

    # The result is the same because allLockedPeriods more then specified coefficient _rewardedPeriods
    tx = issuer.functions.testMint(1, 500, 500, 2 * 10 ** 4).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    reward += calculate_second_phase_reward(500, 500, 10 ** 4)
    assert reward == token.functions.balanceOf(staker).call()
    assert balance - reward == token.functions.balanceOf(issuer.address).call()


def test_issuance_first_phase(testerchain, token, deploy_contract):
    """
    Checks stable issuance in the first phase
    """
    economics = BaseEconomics(initial_supply=INITIAL_SUPPLY,
                              first_phase_supply=INITIAL_SUPPLY + 1000,
                              total_supply=TOTAL_SUPPLY,
                              first_phase_max_issuance=1000 // 5,
                              issuance_decay_coefficient=10 ** 35,
                              lock_duration_coefficient_1=1,
                              lock_duration_coefficient_2=2,
                              maximum_rewarded_periods=1,
                              genesis_hours_per_period=10,
                              hours_per_period=10)

    creator = testerchain.client.accounts[0]
    staker = testerchain.client.accounts[1]

    # Creator deploys the contract
    issuer, _ = deploy_contract(contract_name='IssuerMock',
                                _token=token.address,
                                _genesisHoursPerPeriod=economics.genesis_hours_per_period,
                                _hoursPerPeriod=economics.hours_per_period,
                                _issuanceDecayCoefficient=economics.issuance_decay_coefficient,
                                _lockDurationCoefficient1=economics.lock_duration_coefficient_1,
                                _lockDurationCoefficient2=economics.lock_duration_coefficient_2,
                                _maximumRewardedPeriods=economics.maximum_rewarded_periods,
                                _firstPhaseTotalSupply=economics.first_phase_supply,
                                _firstPhaseMaxIssuance=economics.first_phase_max_issuance)

    # Give staker tokens for reward and initialize contract
    tx = token.functions.approve(issuer.address, economics.erc20_reward_supply).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    tx = issuer.functions.initialize(economics.erc20_reward_supply, creator).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    reward = issuer.functions.getReservedReward().call()

    # Mint some tokens and save result of minting
    period = issuer.functions.getCurrentPeriod().call()
    tx = issuer.functions.testMint(period + 1, 1, 1, economics.maximum_rewarded_periods).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    one_period = token.functions.balanceOf(staker).call()
    assert one_period == economics.first_phase_max_issuance

    # Inflation rate must be the same in all periods of the first phase
    # Mint more tokens in the same period
    tx = issuer.functions.testMint(period + 1, 1, 1, economics.maximum_rewarded_periods).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    assert 2 * one_period == token.functions.balanceOf(staker).call()
    assert reward - token.functions.balanceOf(staker).call() == issuer.functions.getReservedReward().call()

    # Mint tokens in the next period
    tx = issuer.functions.testMint(period + 2, 1, 1, economics.maximum_rewarded_periods).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    assert 3 * one_period == token.functions.balanceOf(staker).call()
    assert reward - token.functions.balanceOf(staker).call() == issuer.functions.getReservedReward().call()

    # Mint tokens in the first period again
    tx = issuer.functions.testMint(period + 1, 1, 1, economics.maximum_rewarded_periods).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    assert 4 * one_period == token.functions.balanceOf(staker).call()
    assert reward - token.functions.balanceOf(staker).call() == issuer.functions.getReservedReward().call()

    # Mint tokens in the next period
    tx = issuer.functions.testMint(period + 3, 1, 1, economics.maximum_rewarded_periods).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    assert 5 * one_period == token.functions.balanceOf(staker).call()
    assert reward - token.functions.balanceOf(staker).call() == issuer.functions.getReservedReward().call()

    # Switch to the second phase
    assert issuer.functions.previousPeriodSupply().call() < economics.first_phase_supply
    assert issuer.functions.currentPeriodSupply().call() == economics.first_phase_supply

    tx = issuer.functions.testMint(period + 4, 1, 1, economics.maximum_rewarded_periods).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    assert 6 * one_period > token.functions.balanceOf(staker).call()
    assert reward - token.functions.balanceOf(staker).call() == issuer.functions.getReservedReward().call()
    minted_amount_second_phase = token.functions.balanceOf(staker).call() - 5 * one_period

    # Return some tokens as a reward
    reward = issuer.functions.getReservedReward().call()
    amount_to_donate = 4 * one_period + minted_amount_second_phase
    tx = token.functions.approve(issuer.address, amount_to_donate).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    tx = issuer.functions.donate(amount_to_donate).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    assert reward + amount_to_donate == issuer.functions.getReservedReward().call()
    assert one_period == token.functions.balanceOf(staker).call()

    events = issuer.events.Donated.createFilter(fromBlock=0).get_all_entries()
    assert 1 == len(events)
    event_args = events[0]['args']
    assert staker == event_args['sender']
    assert amount_to_donate == event_args['value']

    # Switch back to the first phase
    reward += amount_to_donate
    tx = issuer.functions.testMint(period + 5, 1, 1, economics.maximum_rewarded_periods).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    assert 2 * one_period == token.functions.balanceOf(staker).call()
    assert reward - one_period == issuer.functions.getReservedReward().call()


def test_issuance_second_phase(testerchain, token, deploy_contract):
    """
    Check for decreasing of issuance after minting in the second phase.
    During one period inflation rate must be the same
    """

    economics = BaseEconomics(initial_supply=INITIAL_SUPPLY,
                              first_phase_supply=0,
                              total_supply=TOTAL_SUPPLY,
                              first_phase_max_issuance=0,
                              issuance_decay_coefficient=10 ** 15,
                              lock_duration_coefficient_1=1,
                              lock_duration_coefficient_2=2,
                              maximum_rewarded_periods=1,
                              genesis_hours_per_period=10,
                              hours_per_period=10)

    creator = testerchain.client.accounts[0]
    staker = testerchain.client.accounts[1]

    # Creator deploys the contract
    issuer, _ = deploy_contract(contract_name='IssuerMock',
                                _token=token.address,
                                _genesisHoursPerPeriod=economics.genesis_hours_per_period,
                                _hoursPerPeriod=economics.hours_per_period,
                                _issuanceDecayCoefficient=economics.issuance_decay_coefficient,
                                _lockDurationCoefficient1=economics.lock_duration_coefficient_1,
                                _lockDurationCoefficient2=economics.lock_duration_coefficient_2,
                                _maximumRewardedPeriods=economics.maximum_rewarded_periods,
                                _firstPhaseTotalSupply=economics.first_phase_supply,
                                _firstPhaseMaxIssuance=economics.first_phase_max_issuance)

    # Give staker tokens for reward and initialize contract
    tx = token.functions.approve(issuer.address, economics.erc20_reward_supply).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    tx = issuer.functions.initialize(economics.erc20_reward_supply, creator).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    reward = issuer.functions.getReservedReward().call()

    # Mint some tokens and save result of minting
    period = issuer.functions.getCurrentPeriod().call()
    tx = issuer.functions.testMint(period + 1, 1, 1, 0).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    one_period = token.functions.balanceOf(staker).call()

    # Mint more tokens in the same period, inflation rate must be the same as in previous minting
    tx = issuer.functions.testMint(period + 1, 1, 1, 0).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    assert 2 * one_period == token.functions.balanceOf(staker).call()
    assert reward - token.functions.balanceOf(staker).call() == issuer.functions.getReservedReward().call()

    # Mint tokens in the next period, inflation rate must be lower than in previous minting
    tx = issuer.functions.testMint(period + 2, 1, 1, 0).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    assert 3 * one_period > token.functions.balanceOf(staker).call()
    assert reward - token.functions.balanceOf(staker).call() == issuer.functions.getReservedReward().call()
    minted_amount = token.functions.balanceOf(staker).call() - 2 * one_period

    # Mint tokens in the first period again, inflation rate must be the same as in previous minting
    # but can't be equals as in first minting because rate can't be increased
    tx = issuer.functions.testMint(period + 1, 1, 1, 0).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    assert 2 * one_period + 2 * minted_amount == token.functions.balanceOf(staker).call()
    assert reward - token.functions.balanceOf(staker).call() == issuer.functions.getReservedReward().call()

    # Mint tokens in the next period, inflation rate must be lower than in previous minting
    tx = issuer.functions.testMint(period + 3, 1, 1, 0).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    assert 2 * one_period + 3 * minted_amount > token.functions.balanceOf(staker).call()
    assert reward - token.functions.balanceOf(staker).call() == issuer.functions.getReservedReward().call()

    # Return some tokens as a reward
    balance = token.functions.balanceOf(staker).call()
    reward = issuer.functions.getReservedReward().call()
    amount_to_donate = 2 * one_period + 2 * minted_amount
    tx = token.functions.transfer(staker, amount_to_donate).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    tx = token.functions.approve(issuer.address, amount_to_donate).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    tx = issuer.functions.donate(amount_to_donate).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    assert reward + amount_to_donate == issuer.functions.getReservedReward().call()

    events = issuer.events.Donated.createFilter(fromBlock=0).get_all_entries()
    assert 1 == len(events)
    event_args = events[0]['args']
    assert staker == event_args['sender']
    assert amount_to_donate == event_args['value']

    # Rate will be increased because some tokens were returned
    tx = issuer.functions.testMint(period + 3, 1, 1, 0).transact({'from': staker})
    testerchain.wait_for_receipt(tx)
    assert balance + one_period == token.functions.balanceOf(staker).call()
    assert reward + one_period + 2 * minted_amount == issuer.functions.getReservedReward().call()


def test_upgrading(testerchain, token, deploy_contract):
    creator = testerchain.client.accounts[0]

    # Deploy contract
    contract_library_v1, _ = deploy_contract(
        contract_name='IssuerMock',
        _token=token.address,
        _genesisHoursPerPeriod=10,
        _hoursPerPeriod=10,
        _issuanceDecayCoefficient=1,
        _lockDurationCoefficient1=1,
        _lockDurationCoefficient2=2,
        _maximumRewardedPeriods=1,
        _firstPhaseTotalSupply=1,
        _firstPhaseMaxIssuance=1
    )
    dispatcher, _ = deploy_contract('Dispatcher', contract_library_v1.address)

    # Deploy second version of the contract
    contract_library_v2, _ = deploy_contract(
        contract_name='IssuerV2Mock',
        _token=token.address,
        _genesisHoursPerPeriod=20,
        _hoursPerPeriod=20,
        _issuanceDecayCoefficient=2,
        _lockDurationCoefficient1=2,
        _lockDurationCoefficient2=4,
        _maximumRewardedPeriods=2,
        _firstPhaseTotalSupply=2,
        _firstPhaseMaxIssuance=2
    )
    contract = testerchain.client.get_contract(
        abi=contract_library_v2.abi,
        address=dispatcher.address,
        ContractFactoryClass=Contract)

    # Can't call `finishUpgrade` and `verifyState` methods outside upgrade lifecycle
    with pytest.raises((TransactionFailed, ValueError)):
        tx = contract_library_v1.functions.finishUpgrade(contract.address).transact({'from': creator})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = contract_library_v1.functions.verifyState(contract.address).transact({'from': creator})
        testerchain.wait_for_receipt(tx)

    # Give tokens for reward and initialize contract
    tx = token.functions.approve(contract.address, 10000).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    tx = contract.functions.initialize(10000, creator).transact({'from': creator})
    testerchain.wait_for_receipt(tx)

    # Upgrade to the second version, check new and old values of variables
    period = contract.functions.currentMintingPeriod().call()
    assert 2 == contract.functions.mintingCoefficient().call()
    tx = dispatcher.functions.upgrade(contract_library_v2.address).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    assert contract_library_v2.address == dispatcher.functions.target().call()
    assert 8 == contract.functions.mintingCoefficient().call()
    assert 20 * 3600 == contract.functions.secondsPerPeriod().call()
    assert 20 * 3600 == contract.functions.genesisSecondsPerPeriod().call()
    assert 2 == contract.functions.lockDurationCoefficient1().call()
    assert 4 == contract.functions.lockDurationCoefficient2().call()
    assert 2 == contract.functions.maximumRewardedPeriods().call()
    assert 2 == contract.functions.firstPhaseTotalSupply().call()
    assert 2 == contract.functions.firstPhaseMaxIssuance().call()
    assert period == contract.functions.currentMintingPeriod().call()
    assert TOTAL_SUPPLY == contract.functions.totalSupply().call()
    # Check method from new ABI
    tx = contract.functions.setValueToCheck(3).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    assert 3 == contract.functions.valueToCheck().call()

    # Can't upgrade to the previous version or to the bad version
    contract_library_bad, _ = deploy_contract(
        contract_name='IssuerBad',
        _token=token.address,
        _genesisHoursPerPeriod=20,
        _hoursPerPeriod=20,
        _issuanceDecayCoefficient=2,
        _lockDurationCoefficient1=2,
        _lockDurationCoefficient2=4,
        _maximumRewardedPeriods=2,
        _firstPhaseTotalSupply=2,
        _firstPhaseMaxIssuance=2
    )
    with pytest.raises((TransactionFailed, ValueError)):
        tx = dispatcher.functions.upgrade(contract_library_v1.address).transact({'from': creator})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = dispatcher.functions.upgrade(contract_library_bad.address).transact({'from': creator})
        testerchain.wait_for_receipt(tx)

    # But can rollback
    tx = dispatcher.functions.rollback().transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    # Check old values
    assert contract_library_v1.address == dispatcher.functions.target().call()
    assert 2 == contract.functions.mintingCoefficient().call()
    assert 10 * 3600 == contract.functions.secondsPerPeriod().call()
    assert 10 * 3600 == contract.functions.genesisSecondsPerPeriod().call()
    assert 1 == contract.functions.lockDurationCoefficient1().call()
    assert 2 == contract.functions.lockDurationCoefficient2().call()
    assert 1 == contract.functions.maximumRewardedPeriods().call()
    assert 1 == contract.functions.firstPhaseTotalSupply().call()
    assert 1 == contract.functions.firstPhaseMaxIssuance().call()
    assert period == contract.functions.currentMintingPeriod().call()
    assert TOTAL_SUPPLY == contract.functions.totalSupply().call()
    # After rollback can't use new ABI
    with pytest.raises((TransactionFailed, ValueError)):
        tx = contract.functions.setValueToCheck(2).transact({'from': creator})
        testerchain.wait_for_receipt(tx)

    # Try to upgrade to the bad version again
    with pytest.raises((TransactionFailed, ValueError)):
        tx = dispatcher.functions.upgrade(contract_library_bad.address).transact({'from': creator})
        testerchain.wait_for_receipt(tx)

    events = dispatcher.events.StateVerified.createFilter(fromBlock=0).get_all_entries()
    assert 4 == len(events)
    event_args = events[0]['args']
    assert contract_library_v1.address == event_args['testTarget']
    assert creator == event_args['sender']
    event_args = events[1]['args']
    assert contract_library_v2.address == event_args['testTarget']
    assert creator == event_args['sender']
    assert event_args == events[2]['args']
    event_args = events[3]['args']
    assert contract_library_v2.address == event_args['testTarget']
    assert creator == event_args['sender']

    events = dispatcher.events.UpgradeFinished.createFilter(fromBlock=0).get_all_entries()
    assert 3 == len(events)
    event_args = events[0]['args']
    assert contract_library_v1.address == event_args['target']
    assert creator == event_args['sender']
    event_args = events[1]['args']
    assert contract_library_v2.address == event_args['target']
    assert creator == event_args['sender']
    event_args = events[2]['args']
    assert contract_library_v1.address == event_args['target']
    assert creator == event_args['sender']
