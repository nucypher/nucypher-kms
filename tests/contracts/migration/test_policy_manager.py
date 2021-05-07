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

FEE_FIELD = 0
PREVIOUS_FEE_PERIOD_FIELD = 1
FEE_RATE_FIELD = 2
MIN_FEE_RATE_FIELD = 3

POLICY_ID_LENGTH = 16


def test_policy_manager_migration(testerchain, token_economics, deploy_contract):
    creator, alice, node1, node2, node3, node4, node5, *everyone_else = testerchain.client.accounts

    # Give some ether to Alice
    tx = testerchain.client.send_transaction(
        {'from': testerchain.client.coinbase, 'to': alice, 'value': int(1e18)})
    testerchain.wait_for_receipt(tx)

    # Deploy StakingEscrow mock
    escrow, _ = deploy_contract(
        contract_name='StakingEscrowForPolicyMock',
        _genesisHoursPerPeriod=token_economics.genesis_hours_per_period,
        _hoursPerPeriod=token_economics.genesis_hours_per_period
    )

    # Deploy old contract
    policy_manager_old_library, _ = deploy_contract(contract_name='PolicyManagerOld', _escrow=escrow.address)
    dispatcher, _ = deploy_contract('Dispatcher', policy_manager_old_library.address)

    contract = testerchain.client.get_contract(
        abi=policy_manager_old_library.abi,
        address=dispatcher.address,
        ContractFactoryClass=Contract)
    assert contract.functions.secondsPerPeriod().call() == token_economics.genesis_seconds_per_period

    current_period = contract.functions.getCurrentPeriod().call()
    testerchain.time_travel(hours=token_economics.genesis_hours_per_period)
    assert contract.functions.getCurrentPeriod().call() == current_period + 1
    testerchain.time_travel(hours=token_economics.genesis_hours_per_period)
    assert contract.functions.getCurrentPeriod().call() == current_period + 2

    # Register some nodes
    tx = escrow.functions.setPolicyManager(contract.address).transact()
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.register(node1).transact()
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.register(node2).transact()
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.register(node3).transact()
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.register(node4).transact()
    testerchain.wait_for_receipt(tx)

    # Create policies before migration
    policy_id = os.urandom(POLICY_ID_LENGTH)
    number_of_periods = 10
    one_period = token_economics.genesis_seconds_per_period
    rate = 100
    value = number_of_periods * rate
    current_timestamp = testerchain.w3.eth.getBlock('latest').timestamp
    end_timestamp = current_timestamp + (number_of_periods - 1) * one_period
    tx = contract.functions.createPolicy(policy_id, alice, end_timestamp, [node1, node2, node3])\
        .transact({'from': alice, 'value': 3 * value, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)

    testerchain.time_travel(hours=token_economics.genesis_hours_per_period)
    current_period = contract.functions.getCurrentPeriod().call()
    tx = escrow.functions.ping(node3, current_period - 1, 0, current_period + 1).transact()
    testerchain.wait_for_receipt(tx)
    testerchain.time_travel(hours=token_economics.genesis_hours_per_period)
    current_period = contract.functions.getCurrentPeriod().call()
    tx = escrow.functions.ping(node3, current_period - 1, 0, current_period + 1).transact()
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.ping(node4, current_period - 2, current_period - 1, current_period + 1).transact()
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.pushDowntimePeriod(current_period - 2, current_period - 1).transact()
    testerchain.wait_for_receipt(tx)

    # Refund and revoke will work up to upgrade
    tx = contract.functions.refund(policy_id, node1).transact({'from': alice, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)
    tx = contract.functions.revokeArrangement(policy_id, node1).transact({'from': alice, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)

    default_fee_delta = contract.functions.DEFAULT_FEE_DELTA().call()
    policy_first_period = current_period - 2

    assert contract.functions.nodes(node1).call()[FEE_FIELD] == 0
    assert contract.functions.nodes(node1).call()[PREVIOUS_FEE_PERIOD_FIELD] == policy_first_period - 1
    assert contract.functions.nodes(node1).call()[FEE_RATE_FIELD] == 0
    assert contract.functions.getNodeFeeDelta(node1, policy_first_period).call() == rate
    assert contract.functions.getNodeFeeDelta(node1, policy_first_period + 3).call() == -rate
    assert contract.functions.getNodeFeeDelta(node1, policy_first_period + number_of_periods).call() == default_fee_delta

    assert contract.functions.nodes(node2).call()[FEE_FIELD] == 0
    assert contract.functions.nodes(node2).call()[PREVIOUS_FEE_PERIOD_FIELD] == policy_first_period - 1
    assert contract.functions.nodes(node2).call()[FEE_RATE_FIELD] == 0
    assert contract.functions.getNodeFeeDelta(node2, policy_first_period).call() == rate
    assert contract.functions.getNodeFeeDelta(node2, policy_first_period + 3).call() == 0
    assert contract.functions.getNodeFeeDelta(node2, policy_first_period + number_of_periods).call() == -rate

    assert contract.functions.nodes(node3).call()[FEE_FIELD] == 2 * rate
    assert contract.functions.nodes(node3).call()[PREVIOUS_FEE_PERIOD_FIELD] == policy_first_period + 1
    assert contract.functions.nodes(node3).call()[FEE_RATE_FIELD] == rate
    assert contract.functions.getNodeFeeDelta(node3, policy_first_period).call() == 0
    assert contract.functions.getNodeFeeDelta(node3, policy_first_period + 3).call() == default_fee_delta
    assert contract.functions.getNodeFeeDelta(node3, policy_first_period + number_of_periods).call() == -rate

    assert contract.functions.nodes(node4).call()[FEE_FIELD] == 0
    assert contract.functions.nodes(node4).call()[PREVIOUS_FEE_PERIOD_FIELD] == policy_first_period + 1
    assert contract.functions.nodes(node4).call()[FEE_RATE_FIELD] == 0
    assert contract.functions.getNodeFeeDelta(node4, policy_first_period).call() == 0
    assert contract.functions.getNodeFeeDelta(node4, policy_first_period + 3).call() == default_fee_delta
    assert contract.functions.getNodeFeeDelta(node4, policy_first_period + number_of_periods).call() == 0

    # Redeploy StakingEscrow mock
    escrow, _ = deploy_contract(
        contract_name='StakingEscrowForPolicyMock',
        _genesisHoursPerPeriod=token_economics.genesis_hours_per_period,
        _hoursPerPeriod=token_economics.hours_per_period
    )
    tx = escrow.functions.setPolicyManager(dispatcher.address).transact()
    testerchain.wait_for_receipt(tx)

    # Deploy new version of the contract
    policy_manager_library, _ = deploy_contract(contract_name='PolicyManager',
                                                _escrowDispatcher=escrow.address,
                                                _escrowImplementation=escrow.address)
    contract = testerchain.client.get_contract(
        abi=policy_manager_library.abi,
        address=dispatcher.address,
        ContractFactoryClass=Contract)

    tx = dispatcher.functions.upgrade(policy_manager_library.address).transact()
    testerchain.wait_for_receipt(tx)
    assert contract.functions.secondsPerPeriod().call() == token_economics.seconds_per_period
    assert contract.functions.genesisSecondsPerPeriod().call() == token_economics.genesis_seconds_per_period
    assert contract.functions.getCurrentPeriod().call() == current_period // 2
    assert policy_manager_library.functions.resetTimestamp().call() == 0
    reset_timestamp = testerchain.w3.eth.getBlock('latest').timestamp
    assert contract.functions.resetTimestamp().call() == reset_timestamp

    # After upgrade can't refund/revoke old policies
    with pytest.raises((TransactionFailed, ValueError)):
        tx = contract.functions.refund(policy_id, node2).transact({'from': alice, 'gas_price': 0})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = contract.functions.revokeArrangement(policy_id, node2).transact({'from': alice, 'gas_price': 0})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = contract.functions.refund(policy_id).transact({'from': alice, 'gas_price': 0})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = contract.functions.revokePolicy(policy_id).transact({'from': alice, 'gas_price': 0})
        testerchain.wait_for_receipt(tx)

    # And can't create policies for not migrated nodes
    policy_id = os.urandom(POLICY_ID_LENGTH)
    number_of_periods = 10
    one_period = token_economics.seconds_per_period
    current_timestamp = testerchain.w3.eth.getBlock('latest').timestamp
    end_timestamp = current_timestamp + (number_of_periods - 1) * one_period
    with pytest.raises((TransactionFailed, ValueError)):
        tx = contract.functions.createPolicy(policy_id, alice, end_timestamp, [node1, node2, node3])\
            .transact({'from': alice, 'value': 3 * value, 'gas_price': 0})
        testerchain.wait_for_receipt(tx)

    testerchain.time_travel(periods=1, periods_base=token_economics.seconds_per_period)
    current_period = contract.functions.getCurrentPeriod().call()
    testerchain.time_travel(hours=token_economics.genesis_hours_per_period)
    assert contract.functions.getCurrentPeriod().call() == current_period
    testerchain.time_travel(hours=token_economics.genesis_hours_per_period)
    assert contract.functions.getCurrentPeriod().call() == current_period + 1
    testerchain.time_travel(hours=token_economics.hours_per_period)
    assert contract.functions.getCurrentPeriod().call() == current_period + 2

    # Node can't call ping before migration
    current_period = contract.functions.getCurrentPeriod().call()
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.ping(node1, current_period - 1, 0, current_period + 1).transact()
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.ping(node2, current_period - 1, 0, current_period + 1).transact()
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.ping(node3, current_period - 1, 0, current_period + 1).transact()
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.ping(node4, current_period - 1, 0, current_period + 1).transact()
        testerchain.wait_for_receipt(tx)

    # But new node will work ok
    tx = escrow.functions.register(node5).transact()
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.ping(node5, current_period - 1, 0, current_period + 1).transact()
    testerchain.wait_for_receipt(tx)

    # Nodes migration
    tx = escrow.functions.migrate(node1).transact()
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.migrate(node2).transact()
    testerchain.wait_for_receipt(tx)

    # All nodes must migrate to be able take policies
    current_timestamp = testerchain.w3.eth.getBlock('latest').timestamp
    end_timestamp = current_timestamp + (number_of_periods - 1) * one_period
    with pytest.raises((TransactionFailed, ValueError)):
        tx = contract.functions.createPolicy(policy_id, alice, end_timestamp, [node1, node2, node3])\
            .transact({'from': alice, 'value': 3 * value, 'gas_price': 0})
        testerchain.wait_for_receipt(tx)

    tx = escrow.functions.migrate(node3).transact()
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.migrate(node4).transact()
    testerchain.wait_for_receipt(tx)

    for node in (node1, node2, node3, node4):
        assert contract.functions.getNodeFeeDelta(node, policy_first_period).call() == 0
        assert contract.functions.getNodeFeeDelta(node, policy_first_period + 3).call() == 0
        assert contract.functions.getNodeFeeDelta(node, policy_first_period + number_of_periods).call() == 0
        assert contract.functions.getNodeFeeDelta(node, policy_first_period // 2).call() == 0
        assert contract.functions.getNodeFeeDelta(node, (policy_first_period + 3) // 2).call() == 0
        assert contract.functions.getNodeFeeDelta(node, (policy_first_period + number_of_periods) // 2).call() == 0

    assert contract.functions.nodes(node1).call()[FEE_FIELD] == 0
    assert contract.functions.nodes(node1).call()[PREVIOUS_FEE_PERIOD_FIELD] == current_period - 1
    assert contract.functions.nodes(node1).call()[FEE_RATE_FIELD] == 0

    assert contract.functions.nodes(node2).call()[FEE_FIELD] == 0
    assert contract.functions.nodes(node2).call()[PREVIOUS_FEE_PERIOD_FIELD] == current_period - 1
    assert contract.functions.nodes(node2).call()[FEE_RATE_FIELD] == 0

    assert contract.functions.nodes(node3).call()[FEE_FIELD] == 2 * rate
    assert contract.functions.nodes(node3).call()[PREVIOUS_FEE_PERIOD_FIELD] == current_period - 1
    assert contract.functions.nodes(node3).call()[FEE_RATE_FIELD] == 0

    assert contract.functions.nodes(node4).call()[FEE_FIELD] == 0
    assert contract.functions.nodes(node4).call()[PREVIOUS_FEE_PERIOD_FIELD] == current_period - 1
    assert contract.functions.nodes(node4).call()[FEE_RATE_FIELD] == 0

    tx = escrow.functions.ping(node1, current_period - 1, 0, current_period + 1).transact()
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.ping(node2, current_period - 1, 0, current_period + 1).transact()
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.ping(node3, current_period - 1, 0, current_period + 1).transact()
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.ping(node4, current_period - 1, 0, current_period + 1).transact()
    testerchain.wait_for_receipt(tx)

    current_timestamp = testerchain.w3.eth.getBlock('latest').timestamp
    end_timestamp = current_timestamp + (number_of_periods - 1) * one_period
    tx = contract.functions.createPolicy(policy_id, alice, end_timestamp, [node1, node2, node3, node4, node5])\
        .transact({'from': alice, 'value': 5 * value, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)

    # Migration can happen only once
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.migrate(node1).transact()
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.migrate(node2).transact()
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.migrate(node3).transact()
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.migrate(node4).transact()
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.migrate(node5).transact()
        testerchain.wait_for_receipt(tx)

    # Revoke of new policies will work
    tx = contract.functions.refund(policy_id).transact({'from': alice, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)
    tx = contract.functions.revokePolicy(policy_id).transact({'from': alice, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)

    # Upgrade again and check that resetTimestamp won't change
    tx = dispatcher.functions.upgrade(policy_manager_library.address).transact()
    testerchain.wait_for_receipt(tx)
    assert contract.functions.resetTimestamp().call() == reset_timestamp
    assert contract.functions.genesisSecondsPerPeriod().call() == token_economics.genesis_seconds_per_period
    assert contract.functions.secondsPerPeriod().call() == token_economics.seconds_per_period

    escrow, _ = deploy_contract(
        contract_name='StakingEscrowForPolicyMock',
        _genesisHoursPerPeriod=token_economics.hours_per_period,
        _hoursPerPeriod=2 * token_economics.hours_per_period
    )
    policy_manager_2_library, _ = deploy_contract(contract_name='PolicyManager',
                                                  _escrowDispatcher=escrow.address,
                                                  _escrowImplementation=escrow.address)
    current_period = contract.functions.getCurrentPeriod().call()
    tx = dispatcher.functions.upgrade(policy_manager_2_library.address).transact()
    testerchain.wait_for_receipt(tx)
    assert contract.functions.resetTimestamp().call() == reset_timestamp
    assert contract.functions.genesisSecondsPerPeriod().call() == token_economics.seconds_per_period
    assert contract.functions.secondsPerPeriod().call() == 2 * token_economics.seconds_per_period
    assert contract.functions.getCurrentPeriod().call() == current_period // 2


def test_previous_fee_period(testerchain, token_economics, deploy_contract):
    creator, node1, *everyone_else = testerchain.client.accounts

    # Deploy StakingEscrow mock
    escrow, _ = deploy_contract(
        contract_name='StakingEscrowForPolicyMock',
        _genesisHoursPerPeriod=token_economics.genesis_hours_per_period,
        _hoursPerPeriod=token_economics.genesis_hours_per_period
    )

    # Deploy old contract
    policy_manager_old_library, _ = deploy_contract(contract_name='PolicyManagerOld', _escrow=escrow.address)
    dispatcher, _ = deploy_contract('Dispatcher', policy_manager_old_library.address)

    contract = testerchain.client.get_contract(
        abi=policy_manager_old_library.abi,
        address=dispatcher.address,
        ContractFactoryClass=Contract)
    assert contract.functions.secondsPerPeriod().call() == token_economics.genesis_seconds_per_period

    current_period = contract.functions.getCurrentPeriod().call()
    if current_period % 2 == 0:
        testerchain.time_travel(hours=token_economics.genesis_hours_per_period)

    # Register some nodes
    current_period = contract.functions.getCurrentPeriod().call()
    tx = escrow.functions.setPolicyManager(contract.address).transact()
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.register(node1).transact()
    testerchain.wait_for_receipt(tx)

    assert contract.functions.nodes(node1).call()[FEE_FIELD] == 0
    assert contract.functions.nodes(node1).call()[PREVIOUS_FEE_PERIOD_FIELD] == current_period - 1
    assert contract.functions.nodes(node1).call()[FEE_RATE_FIELD] == 0

    # Redeploy StakingEscrow mock
    escrow, _ = deploy_contract(
        contract_name='StakingEscrowForPolicyMock',
        _genesisHoursPerPeriod=token_economics.genesis_hours_per_period,
        _hoursPerPeriod=token_economics.hours_per_period
    )
    tx = escrow.functions.setPolicyManager(dispatcher.address).transact()
    testerchain.wait_for_receipt(tx)

    # Deploy new version of the contract
    policy_manager_library, _ = deploy_contract(contract_name='PolicyManager',
                                                _escrowDispatcher=escrow.address,
                                                _escrowImplementation=escrow.address)
    contract = testerchain.client.get_contract(
        abi=policy_manager_library.abi,
        address=dispatcher.address,
        ContractFactoryClass=Contract)

    tx = dispatcher.functions.upgrade(policy_manager_library.address).transact()
    testerchain.wait_for_receipt(tx)

    # Node migration
    tx = escrow.functions.migrate(node1).transact()
    testerchain.wait_for_receipt(tx)

    current_period = contract.functions.getCurrentPeriod().call()
    assert contract.functions.nodes(node1).call()[FEE_FIELD] == 0
    assert contract.functions.nodes(node1).call()[PREVIOUS_FEE_PERIOD_FIELD] == current_period - 1
    assert contract.functions.nodes(node1).call()[FEE_RATE_FIELD] == 0

    # Check ping() method
    tx = escrow.functions.ping(node1, 0, 0, 0).transact()
    testerchain.wait_for_receipt(tx)
