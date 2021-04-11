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
from eth_utils import to_canonical_address, to_wei
from nucypher.crypto.umbral_adapter import UmbralPrivateKey, Signer
from web3.contract import Contract

from nucypher.blockchain.economics import BaseEconomics
from nucypher.blockchain.eth.constants import NULL_ADDRESS
from nucypher.crypto.api import sha256_digest
from nucypher.crypto.signing import SignatureStamp
from nucypher.utilities.ethereum import to_32byte_hex


DISABLED_FIELD = 0


def pytest_namespace():
    return {'escrow_supply': 0,
            'staker1_tokens': 0,
            'staker4_tokens': 0,
            'staker1_completed_work': 0,
            'staker2_completed_work': 0}


@pytest.fixture(scope='module')
def token_economics():
    economics = BaseEconomics(
        initial_supply=10 ** 9,
        first_phase_supply=int(0.5 * 10 ** 9),
        total_supply=2 * 10 ** 9,
        first_phase_max_issuance=200,
        issuance_decay_coefficient=10 ** 7,
        lock_duration_coefficient_1=4,
        lock_duration_coefficient_2=8,
        maximum_rewarded_periods=4,
        hours_per_period=1,
        minimum_locked_periods=6,
        minimum_allowed_locked=200,
        maximum_allowed_locked=2000,
        minimum_worker_periods=2,
        base_penalty=300,
        percentage_penalty_coefficient=2)
    return economics


@pytest.fixture(scope='module')
def token(token_economics, deploy_contract):
    # Create an ERC20 token
    contract, _ = deploy_contract('NuCypherToken', _totalSupplyOfTokens=token_economics.erc20_total_supply)
    return contract


@pytest.fixture(scope='module')
def escrow_dispatcher(testerchain, token, token_economics, deploy_contract):
    escrow_stub, _ = deploy_contract('StakingEscrowStub',
                                     token.address,
                                     token_economics.hours_per_period,
                                     token_economics.minimum_locked_periods,
                                     token_economics.minimum_allowed_locked,
                                     token_economics.maximum_allowed_locked)
    dispatcher, _ = deploy_contract('Dispatcher', escrow_stub.address)
    return dispatcher


@pytest.fixture(scope='module')
def policy_manager_bare(testerchain, escrow_dispatcher, deploy_contract):
    contract, _ = deploy_contract('PolicyManager', escrow_dispatcher.address)
    return contract


@pytest.fixture(scope='module')
def policy_manager_dispatcher(testerchain, policy_manager_bare, deploy_contract):
    dispatcher, _ = deploy_contract('Dispatcher', policy_manager_bare.address)

    return dispatcher


@pytest.fixture(scope='module')
def policy_manager(testerchain, policy_manager_bare, policy_manager_dispatcher):
    # Wrap dispatcher contract
    contract = testerchain.client.get_contract(
        abi=policy_manager_bare.abi,
        address=policy_manager_dispatcher.address,
        ContractFactoryClass=Contract)

    return contract


@pytest.fixture(scope='module')
def adjudicator_bare(testerchain, token_economics, escrow_dispatcher, deploy_contract):
    contract, _ = deploy_contract(
        'Adjudicator',
        escrow_dispatcher.address,
        *token_economics.slashing_deployment_parameters)
    return contract


@pytest.fixture(scope='module')
def adjudicator_dispatcher(testerchain, adjudicator_bare, deploy_contract):
    dispatcher, _ = deploy_contract('Dispatcher', adjudicator_bare.address)
    return dispatcher


@pytest.fixture(scope='module')
def adjudicator(testerchain, adjudicator_bare, adjudicator_dispatcher):
    # Wrap dispatcher contract
    contract = testerchain.client.get_contract(
        abi=adjudicator_bare.abi,
        address=adjudicator_dispatcher.address,
        ContractFactoryClass=Contract)

    return contract


@pytest.fixture(scope='module')
def worklock(testerchain, token, escrow_dispatcher, token_economics, deploy_contract):
    # Creator deploys the worklock using test values
    now = testerchain.w3.eth.getBlock('latest').timestamp
    start_bid_date = ((now + 3600) // 3600 + 1) * 3600  # beginning of the next hour plus 1 hour
    end_bid_date = start_bid_date + 3600
    end_cancellation_date = end_bid_date + 3600
    boosting_refund = 100
    staking_periods = token_economics.minimum_locked_periods
    min_allowed_bid = to_wei(1, 'ether')
    contract, _ = deploy_contract(
        contract_name='WorkLock',
        _token=token.address,
        _escrow=escrow_dispatcher.address,
        _startBidDate=start_bid_date,
        _endBidDate=end_bid_date,
        _endCancellationDate=end_cancellation_date,
        _boostingRefund=boosting_refund,
        _stakingPeriods=staking_periods,
        _minAllowedBid=min_allowed_bid
    )

    return contract


@pytest.fixture(scope='module')
def escrow_bare(testerchain,
                token,
                policy_manager,
                adjudicator,
                worklock,
                token_economics,
                escrow_dispatcher,
                deploy_contract):
    # Creator deploys the escrow
    contract, _ = deploy_contract(
        'EnhancedStakingEscrow',
        token.address,
        policy_manager.address,
        adjudicator.address,
        worklock.address,
        *token_economics.staking_deployment_parameters
    )

    tx = escrow_dispatcher.functions.upgrade(contract.address).transact()
    testerchain.wait_for_receipt(tx)

    return contract


@pytest.fixture(scope='module')
def escrow(testerchain, escrow_bare, escrow_dispatcher):
    # Wrap dispatcher contract
    contract = testerchain.client.get_contract(
        abi=escrow_bare.abi,
        address=escrow_dispatcher.address,
        ContractFactoryClass=Contract)
    return contract


def mock_ursula(testerchain, account, mocker):
    ursula_privkey = UmbralPrivateKey.gen_key()
    ursula_stamp = SignatureStamp(verifying_key=ursula_privkey.pubkey,
                                  signer=Signer(ursula_privkey))

    signed_stamp = testerchain.client.sign_message(account=account,
                                                   message=bytes(ursula_stamp))

    ursula = mocker.Mock(stamp=ursula_stamp, decentralized_identity_evidence=signed_stamp)
    return ursula


# TODO organize support functions
def generate_args_for_slashing(mock_ursula_reencrypts, ursula):
    evidence = mock_ursula_reencrypts(ursula, corrupt_cfrag=True)
    args = list(evidence.evaluation_arguments())
    data_hash = sha256_digest(evidence.task.capsule, evidence.task.cfrag)
    return data_hash, args


@pytest.fixture(scope='module')
def staking_interface(testerchain, token, escrow, policy_manager, worklock, deploy_contract):
    # Creator deploys the staking interface
    staking_interface, _ = deploy_contract(
        'StakingInterface', token.address, escrow.address, policy_manager.address, worklock.address)
    return staking_interface


@pytest.fixture(scope='module')
def staking_interface_router(testerchain, staking_interface, deploy_contract):
    router, _ = deploy_contract('StakingInterfaceRouter', staking_interface.address)
    return router


@pytest.fixture(scope='module')
def multisig(testerchain, escrow, policy_manager, adjudicator, staking_interface_router, deploy_contract):
    creator, _staker1, _staker2, _staker3, _staker4, _alice1, _alice2, *contract_owners =\
        testerchain.client.accounts
    contract_owners = sorted(contract_owners)
    contract, _ = deploy_contract('MultiSig', 2, contract_owners)
    tx = escrow.functions.transferOwnership(contract.address).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    tx = policy_manager.functions.transferOwnership(contract.address).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    tx = adjudicator.functions.transferOwnership(contract.address).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    tx = staking_interface_router.functions.transferOwnership(contract.address).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    return contract


def execute_multisig_transaction(testerchain, multisig, accounts, tx):

    def sign_hash(testerchain, account: str, data_hash: bytes) -> dict:
        provider = testerchain.provider
        address = to_canonical_address(account)
        key = provider.ethereum_tester.backend._key_lookup[address]._raw_key
        signed_data = testerchain.w3.eth.account.signHash(data_hash, key)
        return signed_data

    nonce = multisig.functions.nonce().call()
    tx_hash = multisig.functions.getUnsignedTransactionHash(accounts[0], tx['to'], 0, tx['data'], nonce).call()
    signatures = [sign_hash(testerchain, account, tx_hash) for account in accounts]
    w3 = testerchain.w3
    tx = multisig.functions.execute(
        [signature.v for signature in signatures],
        [to_32byte_hex(signature.r) for signature in signatures],
        [to_32byte_hex(signature.s) for signature in signatures],
        tx['to'],
        0,
        tx['data']
    ).transact({'from': accounts[0]})
    testerchain.wait_for_receipt(tx)


@pytest.fixture(scope='module')
def preallocation_escrow_1(testerchain, staking_interface, staking_interface_router, deploy_contract):
    creator = testerchain.w3.eth.accounts[0]
    staker3 = testerchain.client.accounts[3]

    # Create the first preallocation escrow
    contract, _ = deploy_contract('PreallocationEscrow', staking_interface_router.address)
    tx = contract.functions.transferOwnership(staker3).transact({'from': creator})
    testerchain.wait_for_receipt(tx)

    return contract


@pytest.fixture(scope='module')
def preallocation_escrow_interface_1(testerchain, staking_interface, preallocation_escrow_1):
    contract = testerchain.client.get_contract(
        abi=staking_interface.abi,
        address=preallocation_escrow_1.address,
        ContractFactoryClass=Contract)

    return contract


@pytest.fixture(scope='module')
def preallocation_escrow_2(testerchain, token, staking_interface, staking_interface_router, deploy_contract):
    creator = testerchain.w3.eth.accounts[0]
    staker4 = testerchain.client.accounts[4]

    # Deploy one more preallocation escrow
    pytest.staker4_tokens = 10000
    contract, _ = deploy_contract('PreallocationEscrow', staking_interface_router.address)
    tx = contract.functions.transferOwnership(staker4).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    tx = token.functions.approve(contract.address, pytest.staker4_tokens).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    tx = contract.functions.initialDeposit(pytest.staker4_tokens, 20 * 60 * 60).transact({'from': creator})
    testerchain.wait_for_receipt(tx)

    return contract


def test_staking_before_initialization(testerchain,
                                       token_economics,
                                       token,
                                       escrow,
                                       multisig,
                                       preallocation_escrow_1,
                                       preallocation_escrow_interface_1,
                                       preallocation_escrow_2):
    creator, staker1, staker2, staker3, staker4, _alice1, _alice2, *contracts_owners =\
        testerchain.client.accounts
    contracts_owners = sorted(contracts_owners)

    # Travel to the start of the next period to prevent problems with unexpected overflow first period
    testerchain.time_travel(hours=1)

    # Give staker some coins
    tx = token.functions.transfer(staker1, 10000).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    assert 10000 == token.functions.balanceOf(staker1).call()

    # Check that nothing is locked
    assert 0 == escrow.functions.getLockedTokens(staker1, 0).call()
    assert 0 == escrow.functions.getLockedTokens(staker2, 0).call()
    assert 0 == escrow.functions.getLockedTokens(staker3, 0).call()
    assert 0 == escrow.functions.getLockedTokens(staker4, 0).call()

    # Deposit tokens for 1 staker
    tx = token.functions.approve(escrow.address, 10000).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    pytest.staker1_tokens = token_economics.minimum_allowed_locked
    staker1_tokens = pytest.staker1_tokens
    duration = token_economics.minimum_locked_periods
    tx = escrow.functions.deposit(staker1, staker1_tokens, duration).transact({'from': creator})
    testerchain.wait_for_receipt(tx)

    pytest.escrow_supply = token_economics.minimum_allowed_locked
    assert token.functions.balanceOf(escrow.address).call() == pytest.escrow_supply
    assert escrow.functions.getAllTokens(staker1).call() == staker1_tokens
    assert escrow.functions.getLockedTokens(staker1, 0).call() == 0
    assert escrow.functions.getLockedTokens(staker1, 1).call() == staker1_tokens
    assert escrow.functions.getLockedTokens(staker1, duration).call() == staker1_tokens
    assert escrow.functions.getLockedTokens(staker1, duration + 1).call() == 0

    tx = token.functions.approve(escrow.address, 0).transact({'from': creator})
    testerchain.wait_for_receipt(tx)

    # Set and lock re-stake parameter in first preallocation escrow
    _wind_down, re_stake, _measure_work, _snapshots = escrow.functions.getFlags(preallocation_escrow_1.address).call()
    assert re_stake
    current_period = escrow.functions.getCurrentPeriod().call()

    # Deposit some tokens to the preallocation escrow and lock them
    tx = token.functions.approve(preallocation_escrow_1.address, 10000).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    tx = preallocation_escrow_1.functions.initialDeposit(10000, 20 * 60 * 60).transact({'from': creator})
    testerchain.wait_for_receipt(tx)

    assert 10000 == token.functions.balanceOf(preallocation_escrow_1.address).call()
    assert staker3 == preallocation_escrow_1.functions.owner().call()
    assert 10000 >= preallocation_escrow_1.functions.getLockedTokens().call()
    assert 9500 <= preallocation_escrow_1.functions.getLockedTokens().call()

    assert token.functions.balanceOf(staker4).call() == 0
    assert token.functions.balanceOf(preallocation_escrow_2.address).call() == pytest.staker4_tokens
    assert preallocation_escrow_2.functions.owner().call() == staker4
    assert preallocation_escrow_2.functions.getLockedTokens().call() == pytest.staker4_tokens

    # Staker's withdrawal attempt won't succeed because nothing to withdraw
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.withdraw(100).transact({'from': staker1})
        testerchain.wait_for_receipt(tx)

    # And can't lock because nothing to lock
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.lockAndCreate(500, 2).transact({'from': staker1})
        testerchain.wait_for_receipt(tx)

    # Check that nothing is locked
    assert 0 == escrow.functions.getLockedTokens(preallocation_escrow_1.address, 0).call()
    assert 0 == escrow.functions.getLockedTokens(preallocation_escrow_2.address, 0).call()
    assert 0 == escrow.functions.getLockedTokens(contracts_owners[0], 0).call()

    # Staker can't deposit and lock too low value
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.deposit(staker1, 1, 1).transact({'from': staker1})
        testerchain.wait_for_receipt(tx)

    # And can't deposit and lock too high value
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.deposit(staker1, 2001, 1).transact({'from': staker1})
        testerchain.wait_for_receipt(tx)

    # Can't make a commitment before initialization
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.commitToNextPeriod().transact({'from': staker2})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.commitToNextPeriod().transact({'from': staker3})
        testerchain.wait_for_receipt(tx)

    tx = escrow.functions.setWindDown(True).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)


def test_worklock_phases(testerchain,
                         token_economics,
                         token,
                         escrow,
                         preallocation_escrow_1,
                         preallocation_escrow_interface_1,
                         worklock,
                         multisig):
    creator, staker1, staker2, staker3, staker4, alice1, alice2, *contracts_owners =\
        testerchain.client.accounts

    # Initialize worklock
    worklock_supply = 3 * token_economics.minimum_allowed_locked + token_economics.maximum_allowed_locked
    tx = token.functions.approve(worklock.address, worklock_supply).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    tx = worklock.functions.tokenDeposit(worklock_supply).transact({'from': creator})
    testerchain.wait_for_receipt(tx)

    # Give staker some ether
    tx = testerchain.w3.eth.sendTransaction(
        {'from': testerchain.w3.eth.coinbase, 'to': staker2, 'value': 10 ** 10})
    testerchain.wait_for_receipt(tx)

    # Can't do anything before start date
    deposited_eth_1 = to_wei(18, 'ether')
    deposited_eth_2 = to_wei(1, 'ether')
    with pytest.raises((TransactionFailed, ValueError)):
        tx = worklock.functions.bid().transact({'from': staker2, 'value': deposited_eth_1, 'gas_price': 0})
        testerchain.wait_for_receipt(tx)

    # Wait for the start of the bidding
    testerchain.time_travel(hours=1)

    # Staker does bid
    min_stake = token_economics.minimum_allowed_locked
    bonus_worklock_supply = worklock_supply - min_stake
    assert worklock.functions.workInfo(staker2).call()[0] == 0
    assert testerchain.w3.eth.getBalance(worklock.address) == 0
    tx = worklock.functions.bid().transact({'from': staker2, 'value': deposited_eth_1, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)
    assert worklock.functions.workInfo(staker2).call()[0] == deposited_eth_1
    worklock_balance = deposited_eth_1
    assert testerchain.w3.eth.getBalance(worklock.address) == worklock_balance
    assert worklock.functions.ethToTokens(deposited_eth_1).call() == min_stake + bonus_worklock_supply

    # Can't claim while bidding phase
    with pytest.raises((TransactionFailed, ValueError)):
        tx = worklock.functions.claim().transact({'from': staker2, 'gas_price': 0})
        testerchain.wait_for_receipt(tx)

    # Other stakers do bid
    assert worklock.functions.workInfo(preallocation_escrow_1.address).call()[0] == 0
    tx = testerchain.client.send_transaction(
        {'from': testerchain.client.coinbase, 'to': preallocation_escrow_1.address, 'value': deposited_eth_2})
    testerchain.wait_for_receipt(tx)
    assert testerchain.w3.eth.getBalance(preallocation_escrow_1.address) == deposited_eth_2
    tx = preallocation_escrow_interface_1.functions.bid(deposited_eth_2).transact({'from': staker3, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)
    assert testerchain.w3.eth.getBalance(preallocation_escrow_1.address) == 0
    assert worklock.functions.workInfo(preallocation_escrow_1.address).call()[0] == deposited_eth_2
    worklock_balance += deposited_eth_2
    bonus_worklock_supply -= min_stake
    assert testerchain.w3.eth.getBalance(worklock.address) == worklock_balance
    assert worklock.functions.ethToTokens(deposited_eth_2).call() == min_stake
    assert worklock.functions.ethToTokens(deposited_eth_1).call() == min_stake + bonus_worklock_supply

    assert worklock.functions.workInfo(staker1).call()[0] == 0
    tx = worklock.functions.bid().transact({'from': staker1, 'value': 2 * deposited_eth_2, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)
    assert worklock.functions.workInfo(staker1).call()[0] == 2 * deposited_eth_2
    worklock_balance += 2 * deposited_eth_2
    bonus_worklock_supply -= min_stake
    assert testerchain.w3.eth.getBalance(worklock.address) == worklock_balance
    assert worklock.functions.ethToTokens(deposited_eth_2).call() == min_stake
    assert worklock.functions.ethToTokens(2 * deposited_eth_2).call() == min_stake + bonus_worklock_supply // 18

    # Wait for the end of the bidding
    testerchain.time_travel(hours=1)

    # Can't bid after the end of bidding
    with pytest.raises((TransactionFailed, ValueError)):
        tx = worklock.functions.bid().transact({'from': staker2, 'value': 1, 'gas_price': 0})
        testerchain.wait_for_receipt(tx)

    # One of stakers cancels bid
    assert worklock.functions.getBiddersLength().call() == 3
    tx = preallocation_escrow_interface_1.functions.cancelBid().transact({'from': staker3, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)
    assert worklock.functions.workInfo(preallocation_escrow_1.address).call()[0] == 0
    worklock_balance -= deposited_eth_2
    bonus_worklock_supply += min_stake
    assert testerchain.w3.eth.getBalance(preallocation_escrow_1.address) == deposited_eth_2
    assert testerchain.w3.eth.getBalance(worklock.address) == worklock_balance
    assert worklock.functions.ethToTokens(deposited_eth_2).call() == min_stake
    assert worklock.functions.ethToTokens(2 * deposited_eth_2).call() == min_stake + bonus_worklock_supply // 18
    assert worklock.functions.getBiddersLength().call() == 2
    assert worklock.functions.bidders(1).call() == staker1
    assert worklock.functions.workInfo(staker1).call()[3] == 1

    # Wait for the end of the cancellation window
    testerchain.time_travel(hours=1)

    # Can't cancel after the end of cancellation window
    with pytest.raises((TransactionFailed, ValueError)):
        tx = worklock.functions.cancelBid().transact({'from': staker1, 'gas_price': 0})
        testerchain.wait_for_receipt(tx)
    # Can't claim before check
    with pytest.raises((TransactionFailed, ValueError)):
        tx = worklock.functions.claim().transact({'from': staker2, 'gas_price': 0})
        testerchain.wait_for_receipt(tx)

    # Do force refund to whale
    assert worklock.functions.ethToTokens(deposited_eth_1).call() > token_economics.maximum_allowed_locked
    staker2_balance = testerchain.w3.eth.getBalance(staker2)
    tx = worklock.functions.forceRefund([staker2]).transact()
    testerchain.wait_for_receipt(tx)
    staker2_bid = worklock.functions.workInfo(staker2).call()[0]
    refund = deposited_eth_1 - staker2_bid
    assert refund > 0
    staker2_tokens = worklock.functions.ethToTokens(staker2_bid).call()
    assert staker2_tokens <= token_economics.maximum_allowed_locked
    assert testerchain.w3.eth.getBalance(worklock.address) == worklock_balance
    assert testerchain.w3.eth.getBalance(staker2) == staker2_balance
    assert worklock.functions.compensation(staker2).call() == refund

    tx = worklock.functions.withdrawCompensation().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    worklock_balance -= refund
    assert testerchain.w3.eth.getBalance(worklock.address) == worklock_balance
    assert testerchain.w3.eth.getBalance(staker2) == staker2_balance + refund
    assert worklock.functions.compensation(staker2).call() == 0

    # Check all bidders
    assert worklock.functions.getBiddersLength().call() == 2
    assert worklock.functions.nextBidderToCheck().call() == 0
    tx = worklock.functions.verifyBiddingCorrectness(30000).transact()
    testerchain.wait_for_receipt(tx)
    assert worklock.functions.nextBidderToCheck().call() == 2

    # Stakers claim tokens before initialization
    assert not worklock.functions.workInfo(staker2).call()[2]
    tx = worklock.functions.claim().transact({'from': staker2, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)
    assert worklock.functions.workInfo(staker2).call()[2]
    wind_down, _re_stake, _measure_work, _snapshots = escrow.functions.getFlags(staker2).call()
    assert wind_down

    assert token.functions.balanceOf(staker2).call() == 0
    assert escrow.functions.getLockedTokens(staker2, 0).call() == 0
    assert escrow.functions.getLockedTokens(staker2, 1).call() == staker2_tokens
    assert escrow.functions.getLockedTokens(staker2, token_economics.minimum_locked_periods).call() == staker2_tokens
    assert escrow.functions.getLockedTokens(staker2, token_economics.minimum_locked_periods + 1).call() == 0
    staker2_remaining_work = staker2_tokens
    assert worklock.functions.ethToWork(staker2_bid).call() == staker2_remaining_work
    assert worklock.functions.workToETH(staker2_remaining_work, staker2_bid).call() == staker2_bid
    assert worklock.functions.getRemainingWork(staker2).call() == staker2_remaining_work
    assert token.functions.balanceOf(worklock.address).call() == worklock_supply - staker2_tokens
    tx = escrow.functions.bondWorker(staker2).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    pytest.escrow_supply += staker2_tokens
    assert escrow.functions.getAllTokens(staker2).call() == staker2_tokens
    assert escrow.functions.getCompletedWork(staker2).call() == 0
    wind_down, _re_stake, _measure_work, _snapshots = escrow.functions.getFlags(staker2).call()
    assert wind_down

    # Initialize escrow
    tx = token.functions.transfer(multisig.address, token_economics.erc20_reward_supply).transact({'from': creator})
    testerchain.wait_for_receipt(tx)
    tx = token.functions.approve(escrow.address, token_economics.erc20_reward_supply) \
        .buildTransaction({'from': multisig.address, 'gasPrice': 0})
    execute_multisig_transaction(testerchain, multisig, [contracts_owners[0], contracts_owners[1]], tx)
    tx = escrow.functions.initialize(token_economics.erc20_reward_supply, multisig.address) \
        .buildTransaction({'from': multisig.address, 'gasPrice': 0})
    execute_multisig_transaction(testerchain, multisig, [contracts_owners[0], contracts_owners[1]], tx)
    pytest.escrow_supply += token_economics.erc20_reward_supply

    tx = worklock.functions.claim().transact({'from': staker1, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)
    assert worklock.functions.workInfo(staker1).call()[2]
    staker1_claims = worklock.functions.ethToTokens(2 * deposited_eth_2).call()
    pytest.staker1_tokens += staker1_claims
    assert escrow.functions.getLockedTokens(staker1, 1).call() == pytest.staker1_tokens
    pytest.escrow_supply += staker1_claims
    wind_down, _re_stake, _measure_work, _snapshots = escrow.functions.getFlags(staker1).call()
    assert not wind_down

    # Staker prolongs lock duration
    tx = escrow.functions.prolongStake(0, 3).transact({'from': staker2, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)
    assert escrow.functions.getLockedTokens(staker2, 0).call() == 0
    assert escrow.functions.getLockedTokens(staker2, 1).call() == staker2_tokens
    assert escrow.functions.getLockedTokens(staker2, 9).call() == staker2_tokens
    assert escrow.functions.getLockedTokens(staker2, 10).call() == 0
    assert escrow.functions.getCompletedWork(staker2).call() == 0

    # Can't claim more than once
    with pytest.raises((TransactionFailed, ValueError)):
        tx = worklock.functions.claim().transact({'from': staker2, 'gas_price': 0})
        testerchain.wait_for_receipt(tx)
    # Can't refund without work
    with pytest.raises((TransactionFailed, ValueError)):
        tx = worklock.functions.refund().transact({'from': staker2, 'gas_price': 0})
        testerchain.wait_for_receipt(tx)


def test_staking_after_worklock(testerchain,
                                token_economics,
                                token,
                                escrow,
                                multisig,
                                preallocation_escrow_1,
                                preallocation_escrow_interface_1,
                                preallocation_escrow_2):
    creator, staker1, staker2, staker3, staker4, _alice1, _alice2, *contracts_owners =\
        testerchain.client.accounts

    # Grant access to transfer tokens
    tx = token.functions.approve(escrow.address, 10000).transact({'from': creator})
    testerchain.wait_for_receipt(tx)

    # Staker transfers some tokens to the escrow and lock them
    tx = token.functions.approve(escrow.address, 1000).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.deposit(staker1, 1000, 10).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.bondWorker(staker1).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.setWindDown(True).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    wind_down, _re_stake, _measure_work, _snapshots = escrow.functions.getFlags(staker1).call()
    assert wind_down
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    pytest.escrow_supply += 1000
    second_sub_stake = 1000
    pytest.staker1_tokens += second_sub_stake
    assert token.functions.balanceOf(escrow.address).call() == pytest.escrow_supply
    assert token.functions.balanceOf(staker1).call() == 9000
    assert escrow.functions.getLockedTokens(staker1, 0).call() == token_economics.minimum_allowed_locked
    assert escrow.functions.getLockedTokens(staker1, 1).call() == pytest.staker1_tokens
    assert escrow.functions.getLockedTokens(staker1, token_economics.minimum_locked_periods).call() == pytest.staker1_tokens
    assert escrow.functions.getLockedTokens(staker1, token_economics.minimum_locked_periods + 1).call() == second_sub_stake
    assert escrow.functions.getLockedTokens(staker1, 10).call() == second_sub_stake
    assert escrow.functions.getLockedTokens(staker1, 11).call() == 0


def test_policy(testerchain,
                token_economics,
                token,
                escrow,
                policy_manager,
                preallocation_escrow_interface_1,
                preallocation_escrow_1):
    creator, staker1, staker2, staker3, staker4, alice1, alice2, *contracts_owners =\
        testerchain.client.accounts

    # Give clients some ether
    tx = testerchain.client.send_transaction(
        {'from': testerchain.client.coinbase, 'to': alice1, 'value': 10 ** 10})
    testerchain.wait_for_receipt(tx)
    tx = testerchain.client.send_transaction(
        {'from': testerchain.client.coinbase, 'to': alice2, 'value': 10 ** 10})
    testerchain.wait_for_receipt(tx)

    # Create first policy
    # In the same period as staker's deposit
    policy_id_1 = os.urandom(16)
    number_of_periods = 5
    one_period = 60 * 60
    rate = 200
    one_node_value = number_of_periods * rate
    value = 2 * one_node_value
    current_timestamp = testerchain.w3.eth.getBlock('latest').timestamp
    end_timestamp = current_timestamp + (number_of_periods - 1) * one_period
    tx = policy_manager.functions.createPolicy(policy_id_1, alice1, end_timestamp, [staker1]) \
        .transact({'from': alice1, 'value': one_node_value, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)
    policy_manager_balance = one_node_value

    # Wait 1 period and deposit from one more staker
    testerchain.time_travel(hours=1)
    tx = preallocation_escrow_interface_1.functions.depositAsStaker(1000, 10).transact({'from': staker3})
    testerchain.wait_for_receipt(tx)
    tx = preallocation_escrow_interface_1.functions.bondWorker(staker3).transact({'from': staker3})
    testerchain.wait_for_receipt(tx)
    tx = preallocation_escrow_interface_1.functions.setWindDown(True).transact({'from': staker3})
    testerchain.wait_for_receipt(tx)
    wind_down, _re_stake, _measure_work, _snapshots = escrow.functions.getFlags(preallocation_escrow_interface_1.address).call()
    assert wind_down
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker3})
    testerchain.wait_for_receipt(tx)
    pytest.escrow_supply += 1000
    assert 1000 == escrow.functions.getAllTokens(preallocation_escrow_1.address).call()
    assert 0 == escrow.functions.getLockedTokens(preallocation_escrow_1.address, 0).call()
    assert 1000 == escrow.functions.getLockedTokens(preallocation_escrow_1.address, 1).call()
    assert 1000 == escrow.functions.getLockedTokens(preallocation_escrow_1.address, 10).call()
    assert 0 == escrow.functions.getLockedTokens(preallocation_escrow_1.address, 11).call()
    assert pytest.escrow_supply == token.functions.balanceOf(escrow.address).call()
    assert 9000 == token.functions.balanceOf(preallocation_escrow_1.address).call()

    # Only owner can deposit tokens to the staking escrow
    with pytest.raises((TransactionFailed, ValueError)):
        tx = preallocation_escrow_interface_1.functions.depositAsStaker(1000, 5).transact({'from': creator})
        testerchain.wait_for_receipt(tx)
    # Can't deposit more than amount in the preallocation escrow
    with pytest.raises((TransactionFailed, ValueError)):
        tx = preallocation_escrow_interface_1.functions.depositAsStaker(10000, 5).transact({'from': staker3})
        testerchain.wait_for_receipt(tx)

    # Divide stakes
    tx = escrow.functions.divideStake(0, 500, 6).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.divideStake(2, 500, 9).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tx = preallocation_escrow_interface_1.functions.divideStake(0, 500, 6).transact({'from': staker3})
    testerchain.wait_for_receipt(tx)

    # Make a commitment
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
    testerchain.wait_for_receipt(tx)

    testerchain.time_travel(hours=1)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker3})
    testerchain.wait_for_receipt(tx)

    testerchain.time_travel(hours=1)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker3})
    testerchain.wait_for_receipt(tx)

    # Create other policies
    policy_id_1 = os.urandom(16)
    current_timestamp = testerchain.w3.eth.getBlock('latest').timestamp
    end_timestamp = current_timestamp + (number_of_periods - 1) * one_period
    tx = policy_manager.functions.createPolicy(policy_id_1, alice1, end_timestamp, [staker1, staker2]) \
        .transact({'from': alice1, 'value': value, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)
    policy_manager_balance += value

    policy_id_2 = os.urandom(16)
    tx = policy_manager.functions.createPolicy(
        policy_id_2, alice2, end_timestamp, [staker2, preallocation_escrow_1.address]) \
        .transact({'from': alice1, 'value': value, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)
    policy_manager_balance += value

    policy_id_3 = os.urandom(16)
    tx = policy_manager.functions.createPolicy(
        policy_id_3, NULL_ADDRESS, end_timestamp, [staker1, preallocation_escrow_1.address]) \
        .transact({'from': alice2, 'value': value, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)
    policy_manager_balance += value

    policy_id_4 = os.urandom(16)
    tx = policy_manager.functions.createPolicy(
        policy_id_4, alice1, end_timestamp, [staker2, preallocation_escrow_1.address]) \
        .transact({'from': alice2, 'value': value, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)
    policy_manager_balance += value

    policy_id_5 = os.urandom(16)
    tx = policy_manager.functions.createPolicy(
        policy_id_5, alice1, end_timestamp, [staker1, staker2]) \
        .transact({'from': alice2, 'value': value, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)
    policy_manager_balance += value
    assert testerchain.client.get_balance(policy_manager.address) == policy_manager_balance

    # Only Alice can revoke policy
    with pytest.raises((TransactionFailed, ValueError)):
        tx = policy_manager.functions.revokePolicy(policy_id_5).transact({'from': staker1})
        testerchain.wait_for_receipt(tx)
    alice2_balance = testerchain.client.get_balance(alice2)
    tx = policy_manager.functions.revokePolicy(policy_id_5).transact({'from': alice1, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)
    two_nodes_rate = 2 * rate
    refund = value - two_nodes_rate
    policy_manager_balance -= refund
    assert testerchain.client.get_balance(policy_manager.address) == policy_manager_balance
    assert alice2_balance + refund == testerchain.client.get_balance(alice2)
    assert policy_manager.functions.policies(policy_id_5).call()[DISABLED_FIELD]

    # Can't revoke again
    with pytest.raises((TransactionFailed, ValueError)):
        tx = policy_manager.functions.revokePolicy(policy_id_5).transact({'from': alice2})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = policy_manager.functions.revokeArrangement(policy_id_5, staker1).transact({'from': alice2})
        testerchain.wait_for_receipt(tx)

    alice1_balance = testerchain.client.get_balance(alice1)
    tx = policy_manager.functions.revokeArrangement(policy_id_2, staker2).transact({'from': alice2, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)
    refund = one_node_value - rate
    policy_manager_balance -= refund
    assert testerchain.client.get_balance(policy_manager.address) == policy_manager_balance
    assert alice1_balance + refund == testerchain.client.get_balance(alice1)
    assert not policy_manager.functions.policies(policy_id_2).call()[DISABLED_FIELD]

    # Can't revoke again
    with pytest.raises((TransactionFailed, ValueError)):
        tx = policy_manager.functions.revokeArrangement(policy_id_2, staker2)\
            .transact({'from': alice1})
        testerchain.wait_for_receipt(tx)

    # Wait, make a commitment, mint
    testerchain.time_travel(hours=1)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker3})
    testerchain.wait_for_receipt(tx)

    # Check work measurement
    staker2_completed_work = escrow.functions.getCompletedWork(staker2).call()
    assert staker2_completed_work > 0
    assert escrow.functions.getCompletedWork(preallocation_escrow_1.address).call() == 0
    staker1_completed_work = escrow.functions.getCompletedWork(staker1).call()
    assert staker1_completed_work > 0
    pytest.staker1_completed_work = staker1_completed_work
    pytest.staker2_completed_work = staker2_completed_work

    testerchain.time_travel(hours=1)
    tx = policy_manager.functions.revokeArrangement(policy_id_3, preallocation_escrow_1.address) \
        .transact({'from': alice2, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)

    tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker3})
    testerchain.wait_for_receipt(tx)

    testerchain.time_travel(hours=1)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
    testerchain.wait_for_receipt(tx)

    testerchain.time_travel(hours=1)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
    testerchain.wait_for_receipt(tx)

    # Withdraw fee and refund
    testerchain.time_travel(hours=3)
    staker1_balance = testerchain.client.get_balance(staker1)
    tx = policy_manager.functions.withdraw().transact({'from': staker1, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)
    assert staker1_balance < testerchain.client.get_balance(staker1)
    staker2_balance = testerchain.client.get_balance(staker2)
    tx = policy_manager.functions.withdraw().transact({'from': staker2, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)
    assert staker2_balance < testerchain.client.get_balance(staker2)
    staker3_balance = testerchain.client.get_balance(staker3)
    tx = preallocation_escrow_interface_1.functions.withdrawPolicyFee().transact({'from': staker3, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)
    tx = preallocation_escrow_1.functions.withdrawETH().transact({'from': staker3, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)
    assert staker3_balance < testerchain.client.get_balance(staker3)

    alice1_balance = testerchain.client.get_balance(alice1)
    tx = policy_manager.functions.refund(policy_id_1).transact({'from': alice1, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)
    assert alice1_balance < testerchain.client.get_balance(alice1)
    alice1_balance = testerchain.client.get_balance(alice1)
    tx = policy_manager.functions.refund(policy_id_2).transact({'from': alice1, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)
    assert alice1_balance < testerchain.client.get_balance(alice1)
    alice2_balance = testerchain.client.get_balance(alice2)
    tx = policy_manager.functions.refund(policy_id_3).transact({'from': alice2, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)
    assert alice2_balance == testerchain.client.get_balance(alice2)
    tx = policy_manager.functions.refund(policy_id_4).transact({'from': alice1, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)
    assert alice2_balance < testerchain.client.get_balance(alice2)


def test_upgrading_and_rollback(testerchain,
                                token_economics,
                                token,
                                escrow,
                                escrow_dispatcher,
                                policy_manager,
                                policy_manager_dispatcher,
                                staking_interface_router,
                                multisig,
                                adjudicator,
                                worklock,
                                deploy_contract):
    creator, staker1, staker2, staker3, staker4, alice1, alice2, *contracts_owners =\
        testerchain.client.accounts
    contracts_owners = sorted(contracts_owners)

    # Upgrade main contracts
    escrow_v1 = escrow.functions.target().call()
    policy_manager_v1 = policy_manager.functions.target().call()
    # Creator deploys the contracts as the second versions
    escrow_v2, _ = deploy_contract(
        'StakingEscrow',
        token.address,
        policy_manager.address,
        adjudicator.address,
        worklock.address,
        *token_economics.staking_deployment_parameters
    )
    policy_manager_v2, _ = deploy_contract('PolicyManager', escrow.address)
    # Staker and Alice can't upgrade contracts, only owner can
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow_dispatcher.functions.upgrade(escrow_v2.address).transact({'from': alice1})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow_dispatcher.functions.upgrade(escrow_v2.address).transact({'from': staker1})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = policy_manager_dispatcher.functions.upgrade(policy_manager_v2.address).transact({'from': alice1})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = policy_manager_dispatcher.functions.upgrade(policy_manager_v2.address).transact({'from': staker1})
        testerchain.wait_for_receipt(tx)

    # Prepare transactions to upgrade contracts
    tx1 = escrow_dispatcher.functions.upgrade(escrow_v2.address).buildTransaction({'from': multisig.address,
                                                                                   'gasPrice': 0})
    tx2 = policy_manager_dispatcher.functions.upgrade(policy_manager_v2.address).\
        buildTransaction({'from': multisig.address, 'gasPrice': 0})
    # Staker and Alice can't sign this transactions
    with pytest.raises((TransactionFailed, ValueError)):
        execute_multisig_transaction(testerchain, multisig, [contracts_owners[0], staker1], tx1)
    with pytest.raises((TransactionFailed, ValueError)):
        execute_multisig_transaction(testerchain, multisig, [contracts_owners[0], alice1], tx1)
    with pytest.raises((TransactionFailed, ValueError)):
        execute_multisig_transaction(testerchain, multisig, [contracts_owners[0], staker1], tx2)
    with pytest.raises((TransactionFailed, ValueError)):
        execute_multisig_transaction(testerchain, multisig, [contracts_owners[0], alice1], tx2)

    # Execute transactions
    execute_multisig_transaction(testerchain, multisig, [contracts_owners[0], contracts_owners[1]], tx1)
    execute_multisig_transaction(testerchain, multisig, [contracts_owners[0], contracts_owners[1]], tx2)
    assert escrow_v2.address == escrow.functions.target().call()
    assert policy_manager_v2.address == policy_manager.functions.target().call()

    # Staker and Alice can't rollback contracts, only owner can
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow_dispatcher.functions.rollback().transact({'from': alice1})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow_dispatcher.functions.rollback().transact({'from': staker1})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = policy_manager_dispatcher.functions.rollback().transact({'from': alice1})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = policy_manager_dispatcher.functions.rollback().transact({'from': staker1})
        testerchain.wait_for_receipt(tx)

    # Prepare transactions to rollback contracts
    tx1 = escrow_dispatcher.functions.rollback().buildTransaction({'from': multisig.address, 'gasPrice': 0})
    tx2 = policy_manager_dispatcher.functions.rollback().buildTransaction({'from': multisig.address, 'gasPrice': 0})
    # Staker and Alice can't sign this transactions
    with pytest.raises((TransactionFailed, ValueError)):
        execute_multisig_transaction(testerchain, multisig, [contracts_owners[0], staker1], tx1)
    with pytest.raises((TransactionFailed, ValueError)):
        execute_multisig_transaction(testerchain, multisig, [contracts_owners[0], alice1], tx1)
    with pytest.raises((TransactionFailed, ValueError)):
        execute_multisig_transaction(testerchain, multisig, [contracts_owners[0], staker1], tx2)
    with pytest.raises((TransactionFailed, ValueError)):
        execute_multisig_transaction(testerchain, multisig, [contracts_owners[0], alice1], tx2)

    # Execute transactions
    execute_multisig_transaction(testerchain, multisig, [contracts_owners[1], contracts_owners[2]], tx1)
    execute_multisig_transaction(testerchain, multisig, [contracts_owners[1], contracts_owners[2]], tx2)
    assert escrow_v1 == escrow.functions.target().call()
    assert policy_manager_v1 == policy_manager.functions.target().call()

    # Upgrade the staking interface
    # Deploy the same contract as the second version
    staking_interface_v2, _ = deploy_contract(
        'StakingInterface', token.address, escrow.address, policy_manager.address, worklock.address)
    # Staker and Alice can't upgrade library, only owner can
    with pytest.raises((TransactionFailed, ValueError)):
        tx = staking_interface_router.functions.upgrade(staking_interface_v2.address).transact({'from': alice1})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = staking_interface_router.functions.upgrade(staking_interface_v2.address).transact({'from': staker1})
        testerchain.wait_for_receipt(tx)

    # Prepare transactions to upgrade library
    tx = staking_interface_router.functions.upgrade(staking_interface_v2.address)\
        .buildTransaction({'from': multisig.address, 'gasPrice': 0})
    # Staker and Alice can't sign this transactions
    with pytest.raises((TransactionFailed, ValueError)):
        execute_multisig_transaction(testerchain, multisig, [contracts_owners[0], staker1], tx)
    with pytest.raises((TransactionFailed, ValueError)):
        execute_multisig_transaction(testerchain, multisig, [contracts_owners[0], alice1], tx)

    # Execute transactions
    execute_multisig_transaction(testerchain, multisig, [contracts_owners[1], contracts_owners[2]], tx)
    assert staking_interface_v2.address == staking_interface_router.functions.target().call()


def test_slashing(testerchain,
                  token_economics,
                  token,
                  escrow,
                  adjudicator,
                  preallocation_escrow_1,
                  mock_ursula_reencrypts,
                  mocker):
    creator, staker1, staker2, staker3, staker4, alice1, alice2, *contracts_owners =\
        testerchain.client.accounts
    ursula1_with_stamp = mock_ursula(testerchain, staker1, mocker=mocker)
    ursula2_with_stamp = mock_ursula(testerchain, staker2, mocker=mocker)
    ursula3_with_stamp = mock_ursula(testerchain, staker3, mocker=mocker)

    # Slash stakers
    # Make a commitment to two periods
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker3})
    testerchain.wait_for_receipt(tx)
    testerchain.time_travel(hours=1)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.commitToNextPeriod().transact({'from': staker3})
    testerchain.wait_for_receipt(tx)
    testerchain.time_travel(hours=1)

    # Can't slash directly using the escrow contract
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.slashStaker(staker1, 100, alice1, 10).transact()
        testerchain.wait_for_receipt(tx)

    # Slash part of the free amount of tokens
    current_period = escrow.functions.getCurrentPeriod().call()
    tokens_amount = escrow.functions.getAllTokens(staker1).call()
    previous_lock = escrow.functions.getLockedTokensInPast(staker1, 1).call()
    lock = escrow.functions.getLockedTokens(staker1, 0).call()
    next_lock = escrow.functions.getLockedTokens(staker1, 1).call()
    total_previous_lock = escrow.functions.lockedPerPeriod(current_period - 1).call()
    total_lock = escrow.functions.lockedPerPeriod(current_period).call()
    alice1_balance = token.functions.balanceOf(alice1).call()

    algorithm_sha256, base_penalty, *coefficients = token_economics.slashing_deployment_parameters
    penalty_history_coefficient, percentage_penalty_coefficient, reward_coefficient = coefficients

    data_hash, slashing_args = generate_args_for_slashing(mock_ursula_reencrypts, ursula1_with_stamp)
    assert not adjudicator.functions.evaluatedCFrags(data_hash).call()
    tx = adjudicator.functions.evaluateCFrag(*slashing_args).transact({'from': alice1})
    testerchain.wait_for_receipt(tx)
    assert adjudicator.functions.evaluatedCFrags(data_hash).call()
    assert tokens_amount - base_penalty == escrow.functions.getAllTokens(staker1).call()
    assert previous_lock == escrow.functions.getLockedTokensInPast(staker1, 1).call()
    assert lock == escrow.functions.getLockedTokens(staker1, 0).call()
    assert next_lock == escrow.functions.getLockedTokens(staker1, 1).call()
    assert total_previous_lock == escrow.functions.lockedPerPeriod(current_period - 1).call()
    assert total_lock == escrow.functions.lockedPerPeriod(current_period).call()
    assert 0 == escrow.functions.lockedPerPeriod(current_period + 1).call()
    assert alice1_balance + base_penalty / reward_coefficient == token.functions.balanceOf(alice1).call()

    # Slash part of the one sub stake
    tokens_amount = escrow.functions.getAllTokens(staker2).call()
    unlocked_amount = tokens_amount - escrow.functions.getLockedTokens(staker2, 0).call()
    tx = escrow.functions.withdraw(unlocked_amount).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    previous_lock = escrow.functions.getLockedTokensInPast(staker2, 1).call()
    lock = escrow.functions.getLockedTokens(staker2, 0).call()
    next_lock = escrow.functions.getLockedTokens(staker2, 1).call()
    data_hash, slashing_args = generate_args_for_slashing(mock_ursula_reencrypts, ursula2_with_stamp)
    assert not adjudicator.functions.evaluatedCFrags(data_hash).call()
    tx = adjudicator.functions.evaluateCFrag(*slashing_args).transact({'from': alice1})
    testerchain.wait_for_receipt(tx)
    assert adjudicator.functions.evaluatedCFrags(data_hash).call()
    assert lock - base_penalty == escrow.functions.getAllTokens(staker2).call()
    assert previous_lock == escrow.functions.getLockedTokensInPast(staker2, 1).call()
    assert lock - base_penalty == escrow.functions.getLockedTokens(staker2, 0).call()
    assert next_lock - base_penalty == escrow.functions.getLockedTokens(staker2, 1).call()
    assert total_previous_lock == escrow.functions.lockedPerPeriod(current_period - 1).call()
    assert total_lock - base_penalty == escrow.functions.lockedPerPeriod(current_period).call()
    assert 0 == escrow.functions.lockedPerPeriod(current_period + 1).call()
    assert alice1_balance + base_penalty == token.functions.balanceOf(alice1).call()

    # Slash preallocation escrow
    tokens_amount = escrow.functions.getAllTokens(preallocation_escrow_1.address).call()
    previous_lock = escrow.functions.getLockedTokensInPast(preallocation_escrow_1.address, 1).call()
    lock = escrow.functions.getLockedTokens(preallocation_escrow_1.address, 0).call()
    next_lock = escrow.functions.getLockedTokens(preallocation_escrow_1.address, 1).call()
    total_previous_lock = escrow.functions.lockedPerPeriod(current_period - 1).call()
    total_lock = escrow.functions.lockedPerPeriod(current_period).call()
    alice1_balance = token.functions.balanceOf(alice1).call()

    data_hash, slashing_args = generate_args_for_slashing(mock_ursula_reencrypts, ursula3_with_stamp)
    assert not adjudicator.functions.evaluatedCFrags(data_hash).call()
    tx = adjudicator.functions.evaluateCFrag(*slashing_args).transact({'from': alice1})
    testerchain.wait_for_receipt(tx)
    assert adjudicator.functions.evaluatedCFrags(data_hash).call()
    assert tokens_amount - base_penalty == escrow.functions.getAllTokens(preallocation_escrow_1.address).call()
    assert previous_lock == escrow.functions.getLockedTokensInPast(preallocation_escrow_1.address, 1).call()
    assert lock - base_penalty == escrow.functions.getLockedTokens(preallocation_escrow_1.address, 0).call()
    assert next_lock - base_penalty == escrow.functions.getLockedTokens(preallocation_escrow_1.address, 1).call()
    assert total_previous_lock == escrow.functions.lockedPerPeriod(current_period - 1).call()
    assert total_lock - base_penalty == escrow.functions.lockedPerPeriod(current_period).call()
    assert 0 == escrow.functions.lockedPerPeriod(current_period + 1).call()
    assert alice1_balance + base_penalty / reward_coefficient == token.functions.balanceOf(alice1).call()


def test_upgrading_adjudicator(testerchain,
                               token_economics,
                               escrow,
                               adjudicator,
                               adjudicator_dispatcher,
                               multisig,
                               deploy_contract):
    creator, staker1, staker2, staker3, staker4, alice1, alice2, *contracts_owners =\
        testerchain.client.accounts
    contracts_owners = sorted(contracts_owners)

    # Upgrade the adjudicator
    # Deploy the same contract as the second version
    adjudicator_v1 = adjudicator.functions.target().call()
    adjudicator_v2, _ = deploy_contract(
        'Adjudicator',
        escrow.address,
        *token_economics.slashing_deployment_parameters)
    # Staker and Alice can't upgrade library, only owner can
    with pytest.raises((TransactionFailed, ValueError)):
        tx = adjudicator_dispatcher.functions.upgrade(adjudicator_v2.address).transact({'from': alice1})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = adjudicator_dispatcher.functions.upgrade(adjudicator_v2.address).transact({'from': staker1})
        testerchain.wait_for_receipt(tx)

    # Prepare transactions to upgrade contracts
    tx = adjudicator_dispatcher.functions.upgrade(adjudicator_v2.address) \
        .buildTransaction({'from': multisig.address, 'gasPrice': 0})
    # Staker and Alice can't sign this transactions
    with pytest.raises((TransactionFailed, ValueError)):
        execute_multisig_transaction(testerchain, multisig, [contracts_owners[0], staker1], tx)
    with pytest.raises((TransactionFailed, ValueError)):
        execute_multisig_transaction(testerchain, multisig, [contracts_owners[0], alice1], tx)

    # Execute transactions
    execute_multisig_transaction(testerchain, multisig, [contracts_owners[0], contracts_owners[1]], tx)
    assert adjudicator_v2.address == adjudicator.functions.target().call()

    # Staker and Alice can't rollback contract, only owner can
    with pytest.raises((TransactionFailed, ValueError)):
        tx = adjudicator_dispatcher.functions.rollback().transact({'from': alice1})
        testerchain.wait_for_receipt(tx)
    with pytest.raises((TransactionFailed, ValueError)):
        tx = adjudicator_dispatcher.functions.rollback().transact({'from': staker1})
        testerchain.wait_for_receipt(tx)

    # Prepare transactions to rollback contracts
    tx = adjudicator_dispatcher.functions.rollback().buildTransaction({'from': multisig.address, 'gasPrice': 0})
    # Staker and Alice can't sign this transactions
    with pytest.raises((TransactionFailed, ValueError)):
        execute_multisig_transaction(testerchain, multisig, [contracts_owners[0], staker1], tx)
    with pytest.raises((TransactionFailed, ValueError)):
        execute_multisig_transaction(testerchain, multisig, [contracts_owners[0], alice1], tx)

    # Execute transactions
    execute_multisig_transaction(testerchain, multisig, [contracts_owners[1], contracts_owners[2]], tx)
    assert adjudicator_v1 == adjudicator.functions.target().call()


def test_withdraw(testerchain,
                  token_economics,
                  token,
                  escrow,
                  preallocation_escrow_interface_1,
                  preallocation_escrow_1,
                  preallocation_escrow_2):
    staker1, staker2, staker3, staker4 = testerchain.client.accounts[1:5]

    # Can't prolong stake by too low duration
    with pytest.raises((TransactionFailed, ValueError)):
        tx = escrow.functions.prolongStake(0, 1).transact({'from': staker2, 'gas_price': 0})
        testerchain.wait_for_receipt(tx)

    # Unlock and withdraw all tokens
    for index in range(9):
        tx = escrow.functions.commitToNextPeriod().transact({'from': staker1})
        testerchain.wait_for_receipt(tx)
        tx = escrow.functions.commitToNextPeriod().transact({'from': staker2})
        testerchain.wait_for_receipt(tx)
        tx = escrow.functions.commitToNextPeriod().transact({'from': staker3})
        testerchain.wait_for_receipt(tx)
        testerchain.time_travel(hours=1)

    testerchain.time_travel(hours=1)
    # Now can turn off re-stake
    tx = preallocation_escrow_interface_1.functions.setReStake(False).transact({'from': staker3})
    testerchain.wait_for_receipt(tx)
    _wind_down, re_stake, _measure_work, _snapshots = escrow.functions.getFlags(preallocation_escrow_1.address).call()
    assert not re_stake

    tx = escrow.functions.mint().transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tx = escrow.functions.mint().transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    tx = preallocation_escrow_interface_1.functions.mint().transact({'from': staker3})
    testerchain.wait_for_receipt(tx)

    assert 0 == escrow.functions.getLockedTokens(staker1, 0).call()
    assert 0 == escrow.functions.getLockedTokens(staker2, 0).call()
    assert 0 == escrow.functions.getLockedTokens(staker3, 0).call()
    assert 0 == escrow.functions.getLockedTokens(staker4, 0).call()
    assert 0 == escrow.functions.getLockedTokens(preallocation_escrow_1.address, 0).call()
    assert 0 == escrow.functions.getLockedTokens(preallocation_escrow_2.address, 0).call()

    staker1_balance = token.functions.balanceOf(staker1).call()
    staker2_balance = token.functions.balanceOf(staker2).call()
    preallocation_escrow_1_balance = token.functions.balanceOf(preallocation_escrow_1.address).call()
    tokens_amount = escrow.functions.getAllTokens(staker1).call()
    tx = escrow.functions.withdraw(tokens_amount).transact({'from': staker1})
    testerchain.wait_for_receipt(tx)
    tokens_amount = escrow.functions.getAllTokens(staker2).call()
    tx = escrow.functions.withdraw(tokens_amount).transact({'from': staker2})
    testerchain.wait_for_receipt(tx)
    tokens_amount = escrow.functions.getAllTokens(preallocation_escrow_1.address).call()
    tx = preallocation_escrow_interface_1.functions.withdrawAsStaker(tokens_amount).transact({'from': staker3})
    testerchain.wait_for_receipt(tx)
    assert staker1_balance < token.functions.balanceOf(staker1).call()
    assert staker2_balance < token.functions.balanceOf(staker2).call()
    assert preallocation_escrow_1_balance < token.functions.balanceOf(preallocation_escrow_1.address).call()

    # Unlock and withdraw all tokens in PreallocationEscrow
    testerchain.time_travel(hours=1)
    assert 0 == preallocation_escrow_1.functions.getLockedTokens().call()
    assert 0 == preallocation_escrow_2.functions.getLockedTokens().call()
    staker3_balance = token.functions.balanceOf(staker3).call()
    staker4_balance = token.functions.balanceOf(staker4).call()
    tokens_amount = token.functions.balanceOf(preallocation_escrow_1.address).call()
    tx = preallocation_escrow_1.functions.withdrawTokens(tokens_amount).transact({'from': staker3})
    testerchain.wait_for_receipt(tx)
    tokens_amount = token.functions.balanceOf(preallocation_escrow_2.address).call()
    tx = preallocation_escrow_2.functions.withdrawTokens(tokens_amount).transact({'from': staker4})
    testerchain.wait_for_receipt(tx)
    assert staker3_balance < token.functions.balanceOf(staker3).call()
    assert staker4_balance < token.functions.balanceOf(staker4).call()


def test_refund(testerchain, escrow, worklock, preallocation_escrow_1):
    staker1, staker2, staker3, staker4 = testerchain.client.accounts[1:5]
    deposited_eth_2 = to_wei(1, 'ether')
    worklock_balance = testerchain.w3.eth.getBalance(worklock.address)
    staker2_bid = worklock.functions.workInfo(staker2).call()[0]

    # Partial refund for staker
    new_completed_work = escrow.functions.getCompletedWork(staker2).call()
    assert pytest.staker2_completed_work < new_completed_work
    remaining_work = worklock.functions.getRemainingWork(staker2).call()
    assert 0 < remaining_work
    staker2_balance = testerchain.w3.eth.getBalance(staker2)
    tx = worklock.functions.refund().transact({'from': staker2, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)
    refund = worklock.functions.workToETH(new_completed_work, staker2_bid).call()
    assert staker2_bid - refund == worklock.functions.workInfo(staker2).call()[0]
    assert refund + staker2_balance == testerchain.w3.eth.getBalance(staker2)
    worklock_balance -= refund
    assert testerchain.w3.eth.getBalance(worklock.address) == worklock_balance

    # Full refund for staker
    new_completed_work = escrow.functions.getCompletedWork(staker1).call()
    assert new_completed_work > pytest.staker1_completed_work
    remaining_work = worklock.functions.getRemainingWork(staker1).call()
    assert remaining_work == 0
    assert worklock.functions.workInfo(staker1).call()[0] == 2 * deposited_eth_2
    staker1_balance = testerchain.w3.eth.getBalance(staker1)
    tx = worklock.functions.refund().transact({'from': staker1, 'gas_price': 0})
    testerchain.wait_for_receipt(tx)
    assert worklock.functions.workInfo(staker1).call()[0] == 0
    assert testerchain.w3.eth.getBalance(staker1) == staker1_balance + 2 * deposited_eth_2
    worklock_balance -= 2 * deposited_eth_2
    assert testerchain.w3.eth.getBalance(worklock.address) == worklock_balance

    assert 0 == escrow.functions.getCompletedWork(preallocation_escrow_1.address).call()
