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
from nucypher.blockchain.eth.agents import ContractAgency, PolicyManagerAgent
from nucypher.blockchain.eth.constants import POLICY_MANAGER_CONTRACT_NAME
from nucypher.blockchain.eth.deployers import (DispatcherDeployer, PolicyManagerDeployer)


def test_policy_manager_deployment(policy_manager_deployer, staking_escrow_stub_deployer, deployment_progress):

    assert policy_manager_deployer.contract_name == POLICY_MANAGER_CONTRACT_NAME

    deployment_receipts = policy_manager_deployer.deploy(progress=deployment_progress)

    # deployment steps must match expected number of steps
    steps = policy_manager_deployer.deployment_steps
    assert deployment_progress.num_steps == len(steps) == len(deployment_receipts) == 2

    for step_title in steps:
        assert deployment_receipts[step_title]['status'] == 1

    staking_escrow_address = policy_manager_deployer.contract.functions.escrow().call()
    assert staking_escrow_stub_deployer.contract_address == staking_escrow_address


def test_make_agent(policy_manager_deployer, test_registry):

    # Create a PolicyManagerAgent
    policy_agent = policy_manager_deployer.make_agent()

    # Retrieve the PolicyManagerAgent singleton
    some_policy_agent = PolicyManagerAgent(registry=test_registry)
    assert policy_agent == some_policy_agent  # __eq__

    # Compare the contract address for equality
    assert policy_agent.contract_address == some_policy_agent.contract_address


def test_policy_manager_has_dispatcher(policy_manager_deployer, testerchain, test_registry):

    # Let's get the "bare" PolicyManager contract (i.e., unwrapped, no dispatcher)
    existing_bare_contract = testerchain.get_contract_by_name(registry=test_registry,
                                                              contract_name=policy_manager_deployer.contract_name,
                                                              proxy_name=DispatcherDeployer.contract_name,
                                                              use_proxy_address=False)

    # This contract shouldn't be accessible directly through the deployer or the agent
    assert policy_manager_deployer.contract_address != existing_bare_contract.address
    policy_manager_agent = PolicyManagerAgent(registry=test_registry)
    assert policy_manager_agent.contract_address != existing_bare_contract

    # The wrapped contract, on the other hand, points to the bare one.
    target = policy_manager_deployer.contract.functions.target().call()
    assert target == existing_bare_contract.address


def test_upgrade(testerchain, test_registry):
    deployer = PolicyManagerDeployer(registry=test_registry,
                                     deployer_address=testerchain.etherbase_account)

    bare_contract = testerchain.get_contract_by_name(registry=test_registry,
                                                     contract_name=PolicyManagerDeployer.contract_name,
                                                     proxy_name=DispatcherDeployer.contract_name,
                                                     use_proxy_address=False)
    old_address = bare_contract.address

    receipts = deployer.upgrade(ignore_deployed=True, confirmations=0)

    bare_contract = testerchain.get_contract_by_name(registry=test_registry,
                                                     contract_name=PolicyManagerDeployer.contract_name,
                                                     proxy_name=DispatcherDeployer.contract_name,
                                                     use_proxy_address=False)

    new_address = bare_contract.address
    assert old_address != new_address

    # TODO: Contract ABI is not updated in Agents when upgrade/rollback #1184

    transactions = ('deploy', 'retarget')
    assert len(receipts) == len(transactions)
    for tx in transactions:
        assert receipts[tx]['status'] == 1


def test_rollback(testerchain, test_registry):
    deployer = PolicyManagerDeployer(registry=test_registry,
                                     deployer_address=testerchain.etherbase_account)

    policy_manager_agent = PolicyManagerAgent(registry=test_registry)
    current_target = policy_manager_agent.contract.functions.target().call()

    # Let's do one more upgrade
    receipts = deployer.upgrade(ignore_deployed=True, confirmations=0)
    for title, receipt in receipts.items():
        assert receipt['status'] == 1

    old_target = current_target
    current_target = policy_manager_agent.contract.functions.target().call()
    assert current_target != old_target

    # It's time to rollback.
    receipt = deployer.rollback()
    assert receipt['status'] == 1

    new_target = policy_manager_agent.contract.functions.target().call()
    assert new_target != current_target
    assert new_target == old_target


def test_set_fee_range(policy_manager_deployer, test_registry):
    policy_agent = ContractAgency.get_agent(PolicyManagerAgent, registry=test_registry)  # type: PolicyManagerAgent
    assert policy_agent.get_fee_rate_range() == (0, 0, 0)

    minimum, default, maximum = 10, 20, 30
    receipt = policy_manager_deployer.set_fee_rate_range(minimum, default, maximum)
    assert receipt['status'] == 1
    assert policy_agent.get_fee_rate_range() == (minimum, default, maximum)
