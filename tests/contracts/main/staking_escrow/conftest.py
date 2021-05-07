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
from web3.contract import Contract

from nucypher.blockchain.economics import BaseEconomics
from nucypher.blockchain.eth.constants import NULL_ADDRESS

VALUE_FIELD = 0


@pytest.fixture()
def token_economics():
    economics = BaseEconomics(initial_supply=10 ** 9,
                              first_phase_supply=int(0.5 * 10 ** 9),
                              total_supply=2 * 10 ** 9,
                              first_phase_max_issuance=1500,
                              issuance_decay_coefficient=10 ** 7,
                              lock_duration_coefficient_1=4,
                              lock_duration_coefficient_2=8,
                              maximum_rewarded_periods=4,
                              genesis_hours_per_period=10,
                              hours_per_period=10,
                              minimum_locked_periods=2,
                              minimum_allowed_locked=100,
                              minimum_worker_periods=1)
    return economics


@pytest.fixture()
def token(deploy_contract, token_economics):
    # Create an ERC20 token
    token, _ = deploy_contract('NuCypherToken', _totalSupplyOfTokens=token_economics.erc20_total_supply)
    return token


@pytest.fixture()
def policy_manager(deploy_contract, token_economics):
    policy_manager, _ = deploy_contract(
        'PolicyManagerForStakingEscrowMock', NULL_ADDRESS, token_economics.seconds_per_period)
    return policy_manager


@pytest.fixture()
def adjudicator(deploy_contract, token_economics):
    adjudicator, _ = deploy_contract('AdjudicatorForStakingEscrowMock', token_economics.reward_coefficient)
    return adjudicator


@pytest.fixture()
def worklock(deploy_contract, token):
    worklock, _ = deploy_contract('WorkLockForStakingEscrowMock', token.address)
    return worklock


@pytest.fixture(params=[False, True])
def escrow_contract(testerchain,
                    token,
                    policy_manager,
                    adjudicator,
                    worklock,
                    token_economics,
                    request,
                    deploy_contract):
    def make_escrow(max_allowed_locked_tokens, disable_reward: bool = False):
        # Creator deploys the escrow
        deploy_parameters = list(token_economics.staking_deployment_parameters)
        deploy_parameters[-2] = max_allowed_locked_tokens
        if disable_reward:
            deploy_parameters[6] = 0
            deploy_parameters[7] = 0

        contract, _ = deploy_contract('EnhancedStakingEscrow',
                                      token.address,
                                      policy_manager.address,
                                      adjudicator.address,
                                      worklock.address,
                                      *deploy_parameters)

        if request.param:
            dispatcher, _ = deploy_contract('Dispatcher', contract.address)
            contract = testerchain.client.get_contract(
                abi=contract.abi,
                address=dispatcher.address,
                ContractFactoryClass=Contract)

        tx = policy_manager.functions.setStakingEscrow(contract.address).transact()
        testerchain.wait_for_receipt(tx)
        tx = adjudicator.functions.setStakingEscrow(contract.address).transact()
        testerchain.wait_for_receipt(tx)
        tx = worklock.functions.setStakingEscrow(contract.address).transact()
        testerchain.wait_for_receipt(tx)

        assert policy_manager.address == contract.functions.policyManager().call()
        assert adjudicator.address == contract.functions.adjudicator().call()
        assert worklock.address == contract.functions.workLock().call()

        # Travel to the start of the next period to prevent problems with unexpected overflow first period
        testerchain.time_travel(hours=1)
        return contract

    return make_escrow
