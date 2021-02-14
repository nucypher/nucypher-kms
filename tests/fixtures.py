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


import json

import contextlib
import maya
import os
import pytest
import random
import shutil
import tempfile
from click.testing import CliRunner
from datetime import datetime, timedelta
from eth_utils import to_checksum_address
from functools import partial
from typing import Tuple, Callable
from web3 import Web3
from web3.contract import Contract
from web3.types import TxReceipt

from nucypher.blockchain.economics import BaseEconomics, StandardTokenEconomics
from nucypher.blockchain.eth.actors import StakeHolder, Staker
from nucypher.blockchain.eth.agents import NucypherTokenAgent, PolicyManagerAgent, StakingEscrowAgent
from nucypher.blockchain.eth.deployers import (
    AdjudicatorDeployer,
    NucypherTokenDeployer,
    PolicyManagerDeployer,
    StakingEscrowDeployer,
    StakingInterfaceDeployer,
    WorklockDeployer
)
from nucypher.blockchain.eth.interfaces import BlockchainInterfaceFactory
from nucypher.blockchain.eth.registry import InMemoryContractRegistry, LocalContractRegistry
from nucypher.blockchain.eth.signers.software import Web3Signer
from nucypher.blockchain.eth.token import NU
from nucypher.characters.control.emitters import StdoutEmitter
from nucypher.characters.lawful import Enrico
from nucypher.config.characters import (
    AliceConfiguration,
    BobConfiguration,
    StakeHolderConfiguration,
    UrsulaConfiguration
)
from nucypher.config.constants import TEMPORARY_DOMAIN
from nucypher.crypto.powers import TransactingPower
from nucypher.datastore import datastore
from nucypher.utilities.logging import GlobalLoggerSettings, Logger
from tests.constants import (
    BASE_TEMP_DIR,
    BASE_TEMP_PREFIX,
    BONUS_TOKENS_FOR_TESTS,
    DATETIME_FORMAT,
    DEVELOPMENT_ETH_AIRDROP_AMOUNT,
    DEVELOPMENT_TOKEN_AIRDROP_AMOUNT,
    FEE_RATE_RANGE,
    INSECURE_DEVELOPMENT_PASSWORD,
    MIN_STAKE_FOR_TESTS,
    MOCK_ALLOCATION_INFILE,
    MOCK_CUSTOM_INSTALLATION_PATH,
    MOCK_CUSTOM_INSTALLATION_PATH_2,
    MOCK_POLICY_DEFAULT_M,
    MOCK_REGISTRY_FILEPATH,
    NUMBER_OF_URSULAS_IN_DEVELOPMENT_NETWORK,
    TEST_GAS_LIMIT,
    TEST_PROVIDER_URI
)
from tests.mock.interfaces import MockBlockchain, mock_registry_source_manager
from tests.mock.performance_mocks import (
    mock_cert_generation,
    mock_cert_loading,
    mock_cert_storage,
    mock_keep_learning,
    mock_message_verification,
    mock_record_fleet_state,
    mock_remember_node,
    mock_rest_app_creation,
    mock_secret_source,
    mock_verify_node
)
from tests.utils.blockchain import TesterBlockchain, token_airdrop
from tests.utils.config import (
    make_alice_test_configuration,
    make_bob_test_configuration,
    make_ursula_test_configuration
)
from tests.utils.middleware import MockRestMiddleware, MockRestMiddlewareForLargeFleetTests
from tests.utils.policy import generate_random_label
from tests.utils.ursula import (
    MOCK_URSULA_STARTING_PORT,
    make_decentralized_ursulas,
    make_federated_ursulas,
    MOCK_KNOWN_URSULAS_CACHE,
    _mock_ursula_reencrypts
)
from constant_sorrow.constants import (FULL, INIT)

test_logger = Logger("test-logger")

# defer.setDebugging(True)

#
# Temporary
#


@pytest.fixture(scope="session", autouse=True)
def mock_reserved_ip(session_mocker):
    session_mocker.patch('nucypher.network.nodes.RESERVED_IP_ADDRESSES', return_value=tuple())
    yield


@pytest.fixture(scope="function")
def tempfile_path():
    fd, path = tempfile.mkstemp()
    yield path
    os.close(fd)
    os.remove(path)


@pytest.fixture(scope="module")
def temp_dir_path():
    temp_dir = tempfile.TemporaryDirectory(prefix='nucypher-test-')
    yield temp_dir.name
    temp_dir.cleanup()


@pytest.fixture(scope="module")
def test_datastore():
    test_datastore = datastore.Datastore(tempfile.mkdtemp())
    yield test_datastore


@pytest.fixture(scope='function')
def certificates_tempdir():
    custom_filepath = '/tmp/nucypher-test-certificates-'
    cert_tmpdir = tempfile.TemporaryDirectory(prefix=custom_filepath)
    yield cert_tmpdir.name
    cert_tmpdir.cleanup()


#
# Federated Configuration
#


@pytest.fixture(scope="module")
def ursula_federated_test_config(test_registry):
    config = make_ursula_test_configuration(federated=True, rest_port=MOCK_URSULA_STARTING_PORT)
    yield config
    config.cleanup()


@pytest.fixture(scope="module")
def alice_federated_test_config(federated_ursulas):
    config = make_alice_test_configuration(federated=True, known_nodes=federated_ursulas)
    yield config
    config.cleanup()


@pytest.fixture(scope="module")
def bob_federated_test_config():
    config = make_bob_test_configuration(federated=True)
    yield config
    config.cleanup()


#
# Decentralized Configuration
#


@pytest.fixture(scope="module")
def ursula_decentralized_test_config(test_registry):
    config = make_ursula_test_configuration(federated=False,
                                            provider_uri=TEST_PROVIDER_URI,
                                            test_registry=test_registry,
                                            rest_port=MOCK_URSULA_STARTING_PORT)
    yield config
    config.cleanup()
    for k in list(MOCK_KNOWN_URSULAS_CACHE.keys()):
        del MOCK_KNOWN_URSULAS_CACHE[k]


@pytest.fixture(scope="module")
def alice_blockchain_test_config(blockchain_ursulas, testerchain, test_registry):
    config = make_alice_test_configuration(federated=False,
                                           provider_uri=TEST_PROVIDER_URI,
                                           known_nodes=blockchain_ursulas,
                                           checksum_address=testerchain.alice_account,
                                           test_registry=test_registry)
    yield config
    config.cleanup()


@pytest.fixture(scope="module")
def bob_blockchain_test_config(testerchain, test_registry):
    config = make_bob_test_configuration(federated=False,
                                         provider_uri=TEST_PROVIDER_URI,
                                         test_registry=test_registry,
                                         checksum_address=testerchain.bob_account,
                                         )
    yield config
    config.cleanup()


#
# Policies
#


@pytest.fixture(scope="module")
def idle_federated_policy(federated_alice, federated_bob):
    """
    Creates a Policy, in a manner typical of how Alice might do it, with a unique label
    """
    m = MOCK_POLICY_DEFAULT_M
    n = NUMBER_OF_URSULAS_IN_DEVELOPMENT_NETWORK
    random_label = generate_random_label()
    policy = federated_alice.create_policy(federated_bob,
                                           label=random_label,
                                           m=m,
                                           n=n,
                                           expiration=maya.now() + timedelta(days=5))
    return policy


@pytest.fixture(scope="module")
def enacted_federated_policy(idle_federated_policy, federated_ursulas):
    # Alice has a policy in mind and knows of enough qualifies Ursulas; she crafts an offer for them.
    network_middleware = MockRestMiddleware()

    # REST call happens here, as does population of TreasureMap.
    enacted_policy = idle_federated_policy.enact(network_middleware=network_middleware,
                                                 handpicked_ursulas=federated_ursulas)
    enacted_policy.treasure_map_publisher.block_until_complete()

    return enacted_policy


@pytest.fixture(scope="module")
def idle_blockchain_policy(testerchain, blockchain_alice, blockchain_bob, token_economics):
    """
    Creates a Policy, in a manner typical of how Alice might do it, with a unique label
    """
    random_label = generate_random_label()
    days = token_economics.minimum_locked_periods // 2
    now = testerchain.w3.eth.getBlock('latest').timestamp
    expiration = maya.MayaDT(now).add(days=days - 1)
    n = 3
    m = 2
    policy = blockchain_alice.create_policy(blockchain_bob,
                                            label=random_label,
                                            m=m, n=n,
                                            value=n * days * 100,
                                            expiration=expiration)
    return policy


@pytest.fixture(scope="module")
def enacted_blockchain_policy(idle_blockchain_policy, blockchain_ursulas):
    # Alice has a policy in mind and knows of enough qualified Ursulas; she crafts an offer for them.

    # value and expiration were set when creating idle_blockchain_policy already
    # cannot set them again
    # deposit = NON_PAYMENT(b"0000000")
    # contract_end_datetime = maya.now() + datetime.timedelta(days=5)
    network_middleware = MockRestMiddleware()

    # REST call happens here, as does population of TreasureMap.
    enacted_policy = idle_blockchain_policy.enact(network_middleware=network_middleware,
                                                  handpicked_ursulas=list(blockchain_ursulas))
    enacted_policy.treasure_map_publisher.block_until_complete()
    return enacted_policy


@pytest.fixture(scope="module")
def capsule_side_channel(enacted_federated_policy):
    class _CapsuleSideChannel:
        def __init__(self):
            self.reset()

        def __call__(self):
            message = "Welcome to flippering number {}.".format(len(self.messages)).encode()
            message_kit, _signature = self.enrico.encrypt_message(message)
            self.messages.append((message_kit, self.enrico))
            if self.plaintext_passthrough:
                self.plaintexts.append(message)
            return message_kit

        def reset(self, plaintext_passthrough=False):
            self.enrico = Enrico(policy_encrypting_key=enacted_federated_policy.public_key)
            self.messages = []
            self.plaintexts = []
            self.plaintext_passthrough = plaintext_passthrough
            return self(), self.enrico

    return _CapsuleSideChannel()


@pytest.fixture(scope="module")
def capsule_side_channel_blockchain(enacted_blockchain_policy):
    class _CapsuleSideChannel:
        def __init__(self):
            self.reset()

        def __call__(self):
            message = "Welcome to flippering number {}.".format(len(self.messages)).encode()
            message_kit, _signature = self.enrico.encrypt_message(message)
            self.messages.append((message_kit, self.enrico))
            if self.plaintext_passthrough:
                self.plaintexts.append(message)
            return message_kit

        def reset(self, plaintext_passthrough=False):
            self.enrico = Enrico(policy_encrypting_key=enacted_blockchain_policy.public_key)
            self.messages = []
            self.plaintexts = []
            self.plaintext_passthrough = plaintext_passthrough
            return self(), self.enrico

    return _CapsuleSideChannel()


@pytest.fixture(scope="module")
def random_policy_label():
    yield generate_random_label()


#
# Alice, Bob, and Ursula
#

@pytest.fixture(scope="module")
def federated_alice(alice_federated_test_config):
    alice = alice_federated_test_config.produce()
    yield alice
    alice.disenchant()


@pytest.fixture(scope="module")
def blockchain_alice(alice_blockchain_test_config, testerchain):
    alice = alice_blockchain_test_config.produce()
    yield alice
    alice.disenchant()


@pytest.fixture(scope="module")
def federated_bob(bob_federated_test_config):
    bob = bob_federated_test_config.produce()
    yield bob
    bob.disenchant()


@pytest.fixture(scope="module")
def blockchain_bob(bob_blockchain_test_config, testerchain):
    bob = bob_blockchain_test_config.produce()
    yield bob
    bob.disenchant()


@pytest.fixture(scope="module")
def federated_ursulas(ursula_federated_test_config):
    if MOCK_KNOWN_URSULAS_CACHE:
        # raise RuntimeError("Ursulas cache was unclear at fixture loading time.  Did you use one of the ursula maker functions without cleaning up?")
        MOCK_KNOWN_URSULAS_CACHE.clear()

    _ursulas = make_federated_ursulas(ursula_config=ursula_federated_test_config,
                                      quantity=NUMBER_OF_URSULAS_IN_DEVELOPMENT_NETWORK)

    # Since we mutate this list in some tests, it's not enough to remember and remove the Ursulas; we have to remember them by port.
    # The same is true of blockchain_ursulas below.
    _ports_to_remove = [ursula.rest_interface.port for ursula in _ursulas]
    yield _ursulas

    for port in _ports_to_remove:
        if port in MOCK_KNOWN_URSULAS_CACHE:
            test_logger.debug(f"Removing {port} ({MOCK_KNOWN_URSULAS_CACHE[port]}).")
            del MOCK_KNOWN_URSULAS_CACHE[port]

    for u in _ursulas:
        u.stop()
        u._finalize()

    # Pytest will hold on to this object, need to clear it manually.
    # See https://github.com/pytest-dev/pytest/issues/5642
    _ursulas.clear()


@pytest.fixture(scope="function")
def lonely_ursula_maker(ursula_federated_test_config):
    class _PartialUrsulaMaker:
        _partial = partial(make_federated_ursulas,
                           ursula_config=ursula_federated_test_config,
                           know_each_other=False,
                           )
        _made = []

        def __call__(self, *args, **kwargs):
            ursulas = self._partial(*args, **kwargs)
            self._made.extend(ursulas)
            return ursulas

        def clean(self):
            for ursula in self._made:
                ursula.stop()
            for ursula in self._made:
                del MOCK_KNOWN_URSULAS_CACHE[ursula.rest_interface.port]
            for ursula in self._made:
                ursula._finalize()
    _maker = _PartialUrsulaMaker()
    yield _maker
    _maker.clean()



#
# Blockchain
#

def make_token_economics(blockchain):
    # Get current blocktime
    now = blockchain.w3.eth.getBlock('latest').timestamp

    # Calculate instant start time
    one_hour_in_seconds = (60 * 60)
    start_date = now
    bidding_start_date = start_date

    # Ends in one hour
    bidding_end_date = start_date + one_hour_in_seconds
    cancellation_end_date = bidding_end_date + one_hour_in_seconds

    economics = StandardTokenEconomics(
        worklock_boosting_refund_rate=200,
        worklock_commitment_duration=60,  # periods
        worklock_supply=10 * BaseEconomics._default_maximum_allowed_locked,
        bidding_start_date=bidding_start_date,
        bidding_end_date=bidding_end_date,
        cancellation_end_date=cancellation_end_date,
        worklock_min_allowed_bid=Web3.toWei(1, "ether")
    )
    return economics


@pytest.fixture(scope='module')
def token_economics(testerchain):
    return make_token_economics(blockchain=testerchain)


@pytest.fixture(scope='module')
def test_registry():
    registry = InMemoryContractRegistry()
    return registry


def _make_testerchain(mock_backend: bool = False) -> TesterBlockchain:
    """
    https://github.com/ethereum/eth-tester     # available-backends
    """
    # Monkey patch to prevent gas adjustment
    import eth
    eth._utils.headers.GAS_LIMIT_MINIMUM = TEST_GAS_LIMIT
    eth._utils.headers.GENESIS_GAS_LIMIT = TEST_GAS_LIMIT
    eth.vm.forks.frontier.headers.GENESIS_GAS_LIMIT = TEST_GAS_LIMIT

    # Monkey patch to prevent gas estimates
    def _get_buffered_gas_estimate(web3, transaction, gas_buffer=100000):
        return TEST_GAS_LIMIT

    import web3
    web3.eth.get_buffered_gas_estimate = _get_buffered_gas_estimate

    # Create the blockchain
    if mock_backend:
        testerchain = MockBlockchain()
    else:
        testerchain = TesterBlockchain(eth_airdrop=True, free_transactions=True)

    return testerchain


@pytest.fixture(scope='session')
def _testerchain() -> TesterBlockchain:
    testerchain = _make_testerchain()
    yield testerchain


@pytest.fixture(scope='module')
def testerchain(_testerchain) -> TesterBlockchain:
    testerchain = _testerchain

    # Reset chain state
    pyevm_backend = testerchain.provider.ethereum_tester.backend
    snapshot = pyevm_backend.chain.get_canonical_block_by_number(0).hash
    pyevm_backend.revert_to_snapshot(snapshot)

    coinbase, *addresses = testerchain.client.accounts

    for address in addresses:
        balance = testerchain.client.get_balance(address)
        spent = DEVELOPMENT_ETH_AIRDROP_AMOUNT - balance

        if spent > 0:
            tx = {'to': address, 'from': coinbase, 'value': spent}
            txhash = testerchain.w3.eth.sendTransaction(tx)

            _receipt = testerchain.wait_for_receipt(txhash)
            eth_amount = Web3().fromWei(spent, 'ether')
            testerchain.log.info("Airdropped {} ETH {} -> {}".format(eth_amount, tx['from'], tx['to']))

    BlockchainInterfaceFactory.register_interface(interface=testerchain, force=True)
    # Mock TransactingPower Consumption (Deployer)
    testerchain.transacting_power = TransactingPower(password=INSECURE_DEVELOPMENT_PASSWORD,
                                                     signer=Web3Signer(client=testerchain.client),
                                                     account=testerchain.etherbase_account)
    testerchain.transacting_power.activate()
    yield testerchain


@pytest.fixture(scope='module')
def _mock_testerchain() -> MockBlockchain:
    BlockchainInterfaceFactory._interfaces = dict()
    testerchain = _make_testerchain(mock_backend=True)
    BlockchainInterfaceFactory.register_interface(interface=testerchain)
    yield testerchain


def _make_agency(testerchain,
                 test_registry,
                 token_economics) -> Tuple[NucypherTokenAgent, StakingEscrowAgent, PolicyManagerAgent]:
    """
    Launch the big three contracts on provided chain,
    make agents for each and return them.
    """

    # Mock TransactingPower Consumption (Deployer)
    testerchain.transacting_power = TransactingPower(password=INSECURE_DEVELOPMENT_PASSWORD,
                                                     signer=Web3Signer(client=testerchain.client),
                                                     account=testerchain.etherbase_account)
    testerchain.transacting_power.activate()

    origin = testerchain.etherbase_account

    token_deployer = NucypherTokenDeployer(deployer_address=origin,
                                           economics=token_economics,
                                           registry=test_registry)
    token_deployer.deploy()

    staking_escrow_deployer = StakingEscrowDeployer(deployer_address=origin,
                                                    economics=token_economics,
                                                    registry=test_registry)
    staking_escrow_deployer.deploy(deployment_mode=INIT)

    policy_manager_deployer = PolicyManagerDeployer(deployer_address=origin,
                                                    economics=token_economics,
                                                    registry=test_registry)
    policy_manager_deployer.deploy()

    adjudicator_deployer = AdjudicatorDeployer(deployer_address=origin,
                                               economics=token_economics,
                                               registry=test_registry)
    adjudicator_deployer.deploy()

    staking_interface_deployer = StakingInterfaceDeployer(deployer_address=origin,
                                                          economics=token_economics,
                                                          registry=test_registry)
    staking_interface_deployer.deploy()

    worklock_deployer = WorklockDeployer(deployer_address=origin,
                                         economics=token_economics,
                                         registry=test_registry)
    worklock_deployer.deploy()

    staking_escrow_deployer = StakingEscrowDeployer(deployer_address=origin,
                                                    economics=token_economics,
                                                    registry=test_registry)
    staking_escrow_deployer.deploy(deployment_mode=FULL)

    token_agent = token_deployer.make_agent()                           # 1 Token
    staking_agent = staking_escrow_deployer.make_agent()                # 2 Staking Escrow
    policy_agent = policy_manager_deployer.make_agent()                 # 3 Policy Agent
    _adjudicator_agent = adjudicator_deployer.make_agent()              # 4 Adjudicator
    _worklock_agent = worklock_deployer.make_agent()                    # 5 Worklock

    # Set additional parameters
    minimum, default, maximum = FEE_RATE_RANGE
    txhash = policy_agent.contract.functions.setFeeRateRange(minimum, default, maximum).transact()
    _receipt = testerchain.wait_for_receipt(txhash)

    # TODO: Get rid of returning these agents here.
    # What's important is deploying and creating the first agent for each contract,
    # and since agents are singletons, in tests it's only necessary to call the agent
    # constructor again to receive the existing agent.
    #
    # For example:
    #     staking_agent = StakingEscrowAgent()
    #
    # This is more clear than how we currently obtain an agent instance in tests:
    #     _, staking_agent, _ = agency
    #
    # Other advantages is that it's closer to how agents should be use (i.e., there
    # are no fixtures IRL) and it's more extensible (e.g., AdjudicatorAgent)

    return token_agent, staking_agent, policy_agent


@pytest.fixture(scope='module')
def test_registry_source_manager(testerchain, test_registry):
    with mock_registry_source_manager(blockchain=testerchain, test_registry=test_registry):
        yield


@pytest.fixture(scope='module')
def agency(testerchain,
           test_registry,
           token_economics,
           test_registry_source_manager) -> Tuple[NucypherTokenAgent, StakingEscrowAgent, PolicyManagerAgent]:
    agents = _make_agency(testerchain=testerchain,
                          test_registry=test_registry,
                          token_economics=token_economics)
    yield agents


@pytest.fixture(scope='module')
def agency_local_registry(testerchain, agency, test_registry):
    registry = LocalContractRegistry(filepath=MOCK_REGISTRY_FILEPATH)
    registry.write(test_registry.read())
    yield registry
    if os.path.exists(MOCK_REGISTRY_FILEPATH):
        os.remove(MOCK_REGISTRY_FILEPATH)


@pytest.fixture(scope="module")
def stakers(testerchain, agency, token_economics, test_registry):
    token_agent, _staking_agent, _policy_agent = agency
    blockchain = token_agent.blockchain

    # Mock Powerup consumption (Deployer)
    blockchain.transacting_power = TransactingPower(password=INSECURE_DEVELOPMENT_PASSWORD,
                                                    signer=Web3Signer(client=testerchain.client),
                                                    account=blockchain.etherbase_account)
    blockchain.transacting_power.activate()

    token_airdrop(origin=blockchain.etherbase_account,
                  addresses=blockchain.stakers_accounts,
                  token_agent=token_agent,
                  amount=DEVELOPMENT_TOKEN_AIRDROP_AMOUNT)

    stakers = list()
    for index, account in enumerate(blockchain.stakers_accounts):
        staker = Staker(is_me=True, checksum_address=account, registry=test_registry)

        # Mock TransactingPower consumption
        staker.transacting_power = TransactingPower(password=INSECURE_DEVELOPMENT_PASSWORD,
                                                    signer=Web3Signer(client=testerchain.client),
                                                    account=account)
        staker.transacting_power.activate()

        amount = MIN_STAKE_FOR_TESTS + random.randrange(BONUS_TOKENS_FOR_TESTS)

        # for a random lock duration
        min_locktime, max_locktime = token_economics.minimum_locked_periods, token_economics.maximum_rewarded_periods
        periods = random.randint(min_locktime, max_locktime)

        staker.initialize_stake(amount=amount, lock_periods=periods)

        # We assume that the staker knows in advance the account of her worker
        worker_address = blockchain.ursula_account(index)
        staker.bond_worker(worker_address=worker_address)

        stakers.append(staker)

    # Stake starts next period (or else signature validation will fail)
    blockchain.time_travel(periods=1)

    yield stakers


@pytest.fixture(scope="module")
def blockchain_ursulas(testerchain, stakers, ursula_decentralized_test_config):
    if MOCK_KNOWN_URSULAS_CACHE:
        # TODO: Is this a safe assumption / test behaviour?
        # raise RuntimeError("Ursulas cache was unclear at fixture loading time.  Did you use one of the ursula maker functions without cleaning up?")
        MOCK_KNOWN_URSULAS_CACHE.clear()

    _ursulas = make_decentralized_ursulas(ursula_config=ursula_decentralized_test_config,
                                          stakers_addresses=testerchain.stakers_accounts,
                                          workers_addresses=testerchain.ursulas_accounts,
                                          commit_now=True)
    for u in _ursulas:
        u.synchronous_query_timeout = .01  # We expect to never have to wait for content that is actually on-chain during tests.
    testerchain.time_travel(periods=1)

    # Bootstrap the network
    for ursula_to_teach in _ursulas:
        for ursula_to_learn_about in _ursulas:
            ursula_to_teach.remember_node(ursula_to_learn_about)

    _ports_to_remove = [ursula.rest_interface.port for ursula in _ursulas]
    yield _ursulas

    for port in _ports_to_remove:
        del MOCK_KNOWN_URSULAS_CACHE[port]

    for u in _ursulas:
        u.stop()
        u._finalize()

    # Pytest will hold on to this object, need to clear it manually.
    # See https://github.com/pytest-dev/pytest/issues/5642
    _ursulas.clear()


@pytest.fixture(scope="module")
def idle_staker(testerchain, agency):
    token_agent, _staking_agent, _policy_agent = agency

    idle_staker_account = testerchain.unassigned_accounts[-2]

    # Mock Powerup consumption (Deployer)
    testerchain.transacting_power = TransactingPower(account=testerchain.etherbase_account)

    token_airdrop(origin=testerchain.etherbase_account,
                  addresses=[idle_staker_account],
                  token_agent=token_agent,
                  amount=DEVELOPMENT_TOKEN_AIRDROP_AMOUNT)

    # Prepare idle staker
    idle_staker = Staker(is_me=True,
                         checksum_address=idle_staker_account,
                         blockchain=testerchain)
    yield idle_staker


@pytest.fixture(scope='module')
def stake_value(token_economics):
    value = NU(token_economics.minimum_allowed_locked * 2, 'NuNit')
    return value


@pytest.fixture(scope='module')
def policy_rate():
    rate = Web3.toWei(21, 'gwei')
    return rate


@pytest.fixture(scope='module')
def policy_value(token_economics, policy_rate):
    value = policy_rate * token_economics.minimum_locked_periods
    return value


@pytest.fixture(scope='module')
def funded_blockchain(testerchain, agency, token_economics, test_registry):
    # Who are ya'?
    deployer_address, *everyone_else, staking_participant = testerchain.client.accounts

    # Free ETH!!!
    testerchain.ether_airdrop(amount=DEVELOPMENT_ETH_AIRDROP_AMOUNT)

    # Free Tokens!!!
    token_airdrop(token_agent=NucypherTokenAgent(registry=test_registry),
                  origin=deployer_address,
                  addresses=everyone_else,
                  amount=token_economics.minimum_allowed_locked * 5)

    # HERE YOU GO
    yield testerchain, deployer_address


#
# Re-Encryption
#


@pytest.fixture(scope='session')
def mock_ursula_reencrypts():
    return _mock_ursula_reencrypts


@pytest.fixture(scope='session')
def stakeholder_config_file_location():
    path = os.path.join('/', 'tmp', 'nucypher-test-stakeholder.json')
    if os.path.exists(path):
        os.remove(path)
    yield path
    if os.path.exists(path):
        os.remove(path)


@pytest.fixture(scope='module')
def software_stakeholder(testerchain, agency, stakeholder_config_file_location, test_registry):
    token_agent, staking_agent, policy_agent = agency

    # Setup
    path = stakeholder_config_file_location
    if os.path.exists(path):
        os.remove(path)

    #                          0xaAa482c790b4301bE18D75A0D1B11B2ACBEF798B
    stakeholder_private_key = '255f64a948eeb1595b8a2d1e76740f4683eca1c8f1433d13293db9b6e27676cc'
    address = testerchain.provider.ethereum_tester.add_account(private_key=stakeholder_private_key,
                                                               password=INSECURE_DEVELOPMENT_PASSWORD)

    testerchain.provider.ethereum_tester.unlock_account(account=address, password=INSECURE_DEVELOPMENT_PASSWORD)

    tx = {'to': address,
          'from': testerchain.etherbase_account,
          'value': Web3.toWei('1', 'ether')}

    txhash = testerchain.client.w3.eth.sendTransaction(tx)
    _receipt = testerchain.wait_for_receipt(txhash)

    # Mock TransactingPower consumption (Etherbase)
    transacting_power = TransactingPower(account=testerchain.etherbase_account,
                                         signer=Web3Signer(testerchain.client),
                                         password=INSECURE_DEVELOPMENT_PASSWORD)
    transacting_power.activate()

    token_agent.transfer(amount=NU(200_000, 'NU').to_nunits(),
                         sender_address=testerchain.etherbase_account,
                         target_address=address)

    # Create stakeholder from on-chain values given accounts over a web3 provider
    stakeholder = StakeHolder(registry=test_registry, initial_address=address)

    # Teardown
    yield stakeholder
    if os.path.exists(path):
        os.remove(path)


@pytest.fixture(scope="module")
def stakeholder_configuration(testerchain, agency_local_registry):
    config = StakeHolderConfiguration(provider_uri=testerchain.provider_uri,
                                      registry_filepath=agency_local_registry.filepath)
    return config


@pytest.fixture(scope='module')
def manual_staker(testerchain, agency):
    token_agent, staking_agent, policy_agent = agency

    # its okay to add this key if it already exists.
    address = '0xaaa23A5c74aBA6ca5E7c09337d5317A7C4563075'
    if address not in testerchain.client.accounts:
        staker_private_key = '13378db1c2af06933000504838afc2d52efa383206454deefb1836f8f4cd86f8'
        address = testerchain.provider.ethereum_tester.add_account(staker_private_key,
                                                                   password=INSECURE_DEVELOPMENT_PASSWORD)

    tx = {'to': address,
          'from': testerchain.etherbase_account,
          'value': Web3.toWei('1', 'ether')}

    txhash = testerchain.client.w3.eth.sendTransaction(tx)
    _receipt = testerchain.wait_for_receipt(txhash)

    token_agent.transfer(amount=NU(200_000, 'NU').to_nunits(),
                         sender_address=testerchain.etherbase_account,
                         target_address=address)

    yield address


@pytest.fixture(scope='module')
def manual_worker(testerchain):
    worker_private_key = os.urandom(32).hex()
    address = testerchain.provider.ethereum_tester.add_account(worker_private_key,
                                                               password=INSECURE_DEVELOPMENT_PASSWORD)

    tx = {'to': address,
          'from': testerchain.etherbase_account,
          'value': Web3.toWei('1', 'ether')}

    txhash = testerchain.client.w3.eth.sendTransaction(tx)
    _receipt = testerchain.wait_for_receipt(txhash)
    yield address


#
# Test logging
#

# TODO : Use a pytest Flag to enable/disable this functionality
test_logger = Logger("test-logger")


@pytest.fixture(autouse=True, scope='function')
def log_in_and_out_of_test(request):
    test_name = request.node.name
    module_name = request.module.__name__


    test_logger.info(f"Starting {module_name}.py::{test_name}")
    yield
    test_logger.info(f"Finalized {module_name}.py::{test_name}")


@pytest.fixture(scope="module")
def deploy_contract(testerchain, test_registry) -> Callable[..., Tuple[Contract, TxReceipt]]:
    def wrapped(contract_name, *args, **kwargs):
        return testerchain.deploy_contract(testerchain.etherbase_account,
                                           test_registry,
                                           contract_name,
                                           *args,
                                           **kwargs)

    return wrapped


@pytest.fixture(scope='module')
def get_random_checksum_address():
    def _get_random_checksum_address():
        canonical_address = os.urandom(20)
        checksum_address = to_checksum_address(canonical_address)
        return checksum_address

    return _get_random_checksum_address


@pytest.fixture(scope='module')
def mock_transacting_power_activation(testerchain):
    def _mock_transacting_power_activation(password, account):
        testerchain.transacting_power = TransactingPower(password=password,
                                                         signer=Web3Signer(testerchain.client),
                                                         account=account)
        testerchain.transacting_power.activate()

    return _mock_transacting_power_activation


@pytest.fixture(scope="module")
def fleet_of_highperf_mocked_ursulas(ursula_federated_test_config, request):
    # good_serials = _determine_good_serials(10000, 50000)
    try:
        quantity = request.param
    except AttributeError:
        quantity = 5000  # Bigass fleet by default; that's kinda the point.
    with GlobalLoggerSettings.pause_all_logging_while():
        with mock_secret_source():
            with mock_cert_storage, mock_cert_loading, mock_rest_app_creation, mock_cert_generation, mock_remember_node, mock_message_verification:
                _ursulas = make_federated_ursulas(ursula_config=ursula_federated_test_config,
                                                  quantity=quantity, know_each_other=False)
                all_ursulas = {u.checksum_address: u for u in _ursulas}

                for ursula in _ursulas:
                    ursula.known_nodes._FleetSensor__nodes = all_ursulas
                    ursula.known_nodes.checksum = b"This is a fleet state checksum..".hex()
    yield ursula.known_nodes

    for ursula in _ursulas:
        del MOCK_KNOWN_URSULAS_CACHE[ursula.rest_interface.port]


@pytest.fixture(scope="module")
def highperf_mocked_alice(fleet_of_highperf_mocked_ursulas):
    config = AliceConfiguration(dev_mode=True,
                                domain=TEMPORARY_DOMAIN,
                                network_middleware=MockRestMiddlewareForLargeFleetTests(),
                                federated_only=True,
                                abort_on_learning_error=True,
                                save_metadata=False,
                                reload_metadata=False)

    with mock_cert_storage, mock_verify_node, mock_record_fleet_state, mock_message_verification, mock_keep_learning:
        alice = config.produce(known_nodes=list(fleet_of_highperf_mocked_ursulas.get_nodes())[:1])
    yield alice
    # TODO: Where does this really, truly belong?
    alice._learning_task.stop()


@pytest.fixture(scope="module")
def highperf_mocked_bob(fleet_of_highperf_mocked_ursulas):
    config = BobConfiguration(dev_mode=True,
                              domain=TEMPORARY_DOMAIN,
                              network_middleware=MockRestMiddlewareForLargeFleetTests(),
                              federated_only=True,
                              abort_on_learning_error=True,
                              save_metadata=False,
                              reload_metadata=False)

    with mock_cert_storage, mock_verify_node, mock_record_fleet_state, mock_keep_learning:
        bob = config.produce(known_nodes=list(fleet_of_highperf_mocked_ursulas.get_nodes())[:1])
    yield bob
    bob._learning_task.stop()
    return bob


#
# CLI
#


@pytest.fixture(scope='function')
def test_emitter(mocker):
    # Note that this fixture does not capture console output.
    # Whether the output is captured or not is controlled by
    # the usage of the (built-in) `capsys` fixture or global PyTest run settings.
    return StdoutEmitter()


@pytest.fixture(scope='module')
def click_runner():
    runner = CliRunner()
    yield runner


@pytest.fixture(scope='session')
def nominal_federated_configuration_fields():
    config = UrsulaConfiguration(dev_mode=True, federated_only=True)
    config_fields = config.static_payload()
    yield tuple(config_fields.keys())
    del config


@pytest.fixture(scope='module')
def mock_allocation_infile(testerchain, token_economics, get_random_checksum_address):
    accounts = [get_random_checksum_address() for _ in range(10)]
    # accounts = testerchain.unassigned_accounts
    allocation_data = list()
    amount = 2 * token_economics.minimum_allowed_locked
    min_periods = token_economics.minimum_locked_periods
    for account in accounts:
        substake = [{'checksum_address': account, 'amount': amount, 'lock_periods': min_periods + i} for i in range(24)]
        allocation_data.extend(substake)

    with open(MOCK_ALLOCATION_INFILE, 'w') as file:
        file.write(json.dumps(allocation_data))

    yield MOCK_ALLOCATION_INFILE
    if os.path.isfile(MOCK_ALLOCATION_INFILE):
        os.remove(MOCK_ALLOCATION_INFILE)


@pytest.fixture(scope='function')
def new_local_registry():
    filename = f'{BASE_TEMP_PREFIX}mock-empty-registry-{datetime.now().strftime(DATETIME_FORMAT)}.json'
    registry_filepath = os.path.join(BASE_TEMP_DIR, filename)
    registry = LocalContractRegistry(filepath=registry_filepath)
    registry.write(InMemoryContractRegistry().read())
    yield registry
    if os.path.exists(registry_filepath):
        os.remove(registry_filepath)


@pytest.fixture(scope='module')
def custom_filepath():
    _custom_filepath = MOCK_CUSTOM_INSTALLATION_PATH
    with contextlib.suppress(FileNotFoundError):
        shutil.rmtree(_custom_filepath, ignore_errors=True)
    yield _custom_filepath
    with contextlib.suppress(FileNotFoundError):
        shutil.rmtree(_custom_filepath, ignore_errors=True)


@pytest.fixture(scope='module')
def custom_filepath_2():
    _custom_filepath = MOCK_CUSTOM_INSTALLATION_PATH_2
    with contextlib.suppress(FileNotFoundError):
        shutil.rmtree(_custom_filepath, ignore_errors=True)
    try:
        yield _custom_filepath
    finally:
        with contextlib.suppress(FileNotFoundError):
            shutil.rmtree(_custom_filepath, ignore_errors=True)


@pytest.fixture(scope='module')
def worker_configuration_file_location(custom_filepath):
    _configuration_file_location = os.path.join(MOCK_CUSTOM_INSTALLATION_PATH,
                                                UrsulaConfiguration.generate_filename())
    return _configuration_file_location


@pytest.fixture(scope='module')
def stakeholder_configuration_file_location(custom_filepath):
    _configuration_file_location = os.path.join(MOCK_CUSTOM_INSTALLATION_PATH,
                                                StakeHolderConfiguration.generate_filename())
    return _configuration_file_location
