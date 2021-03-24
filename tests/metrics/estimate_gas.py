#!/usr/bin/env python3


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
from os.path import abspath, dirname

import io
import os
import re
import tabulate
import time
from twisted.logger import ILogObserver, globalLogPublisher, jsonFileLogObserver
from nucypher.crypto.umbral_adapter import UmbralPrivateKey, Signer
from unittest.mock import Mock
from zope.interface import provider

from nucypher.blockchain.economics import StandardTokenEconomics
from nucypher.blockchain.eth.agents import (
    AdjudicatorAgent,
    NucypherTokenAgent,
    PolicyManagerAgent,
    StakingEscrowAgent
)
from nucypher.blockchain.eth.constants import NUCYPHER_CONTRACT_NAMES
from nucypher.crypto.signing import SignatureStamp
from nucypher.exceptions import DevelopmentInstallationRequired
from nucypher.policy.policies import Policy
from nucypher.utilities.logging import Logger
from tests.utils.blockchain import TesterBlockchain

try:
    from tests.utils.ursula import _mock_ursula_reencrypts as mock_ursula_reencrypts
except ImportError:
    raise DevelopmentInstallationRequired(importable_name='tests.utils.ursula')


ALGORITHM_SHA256 = 1
TOKEN_ECONOMICS = StandardTokenEconomics()
MIN_ALLOWED_LOCKED = TOKEN_ECONOMICS.minimum_allowed_locked
MIN_LOCKED_PERIODS = TOKEN_ECONOMICS.minimum_locked_periods
MAX_ALLOWED_LOCKED = TOKEN_ECONOMICS.maximum_allowed_locked
MAX_MINTING_PERIODS = TOKEN_ECONOMICS.maximum_rewarded_periods


class AnalyzeGas:
    """
    Callable twisted log observer with built-in record-keeping for gas estimation runs.
    """

    # Logging
    LOG_NAME = 'estimate-gas'
    LOG_FILENAME = '{}.log.json'.format(LOG_NAME)
    OUTPUT_DIR = os.path.join(abspath(dirname(__file__)), 'results')
    JSON_OUTPUT_FILENAME = '{}.json'.format(LOG_NAME)

    _PATTERN = re.compile(r'''
                          ^          # Anchor at the start of a string
                          (.+)       # Any character sequence longer than 1; Captured
                          \s=\s      # Space-Equal-Space
                          (\d+)      # A sequence of digits; Captured
                          \s\|\s     # Space-Slash-Space
                          (\d+)      # A sequence of digits; Captured
                          $          # Anchor at the end of the string
                          ''', re.VERBOSE)

    def __init__(self) -> None:

        self.log = Logger(self.__class__.__name__)
        self.gas_estimations = dict()

        if not os.path.isdir(self.OUTPUT_DIR):
            os.mkdir(self.OUTPUT_DIR)

    @provider(ILogObserver)
    def __call__(self, event, *args, **kwargs) -> None:

        if event.get('log_namespace') == self.LOG_NAME:
            message = event.get("log_format")

            matches = self._PATTERN.match(message)
            if not matches:
                self.log.debug("No match for {} with pattern {}".format(message, self._PATTERN))
                return

            label, estimates, gas_used = matches.groups()
            self.paint_line(label, estimates, gas_used)
            self.gas_estimations[label] = int(gas_used)

    @staticmethod
    def paint_line(label: str, estimates: str, gas_used: str) -> None:
        print('{label} {estimates:7,} | {gas:7,}'.format(
            label=label.ljust(72, '.'), estimates=int(estimates), gas=int(gas_used)))

    def to_json_file(self) -> None:
        print('Saving JSON Output...')

        epoch_time = str(int(time.time()))
        timestamped_filename = '{}-{}'.format(epoch_time, self.JSON_OUTPUT_FILENAME)
        filepath = os.path.join(self.OUTPUT_DIR, timestamped_filename)
        with open(filepath, 'w') as file:
            file.write(json.dumps(self.gas_estimations, indent=4))

    def start_collection(self) -> None:
        print("Starting Data Collection...")

        json_filepath = os.path.join(self.OUTPUT_DIR, AnalyzeGas.LOG_FILENAME)
        json_io = io.open(json_filepath, "w")
        json_observer = jsonFileLogObserver(json_io)
        globalLogPublisher.addObserver(json_observer)
        globalLogPublisher.addObserver(self)


def mock_ursula(testerchain, account):
    ursula_privkey = UmbralPrivateKey.gen_key()
    ursula_stamp = SignatureStamp(verifying_key=ursula_privkey.pubkey,
                                  signer=Signer(ursula_privkey))

    signed_stamp = testerchain.client.sign_message(account=account,
                                                   message=bytes(ursula_stamp))

    ursula = Mock(stamp=ursula_stamp, decentralized_identity_evidence=signed_stamp)
    return ursula


def generate_args_for_slashing(ursula, corrupt_cfrag: bool = True):
    evidence = mock_ursula_reencrypts(ursula, corrupt_cfrag=corrupt_cfrag)
    args = list(evidence.evaluation_arguments())
    return args


def estimate_gas(analyzer: AnalyzeGas = None) -> None:
    """
    Execute a linear sequence of NyCypher transactions mimicking
    post-deployment usage on a local PyEVM blockchain;
    Record the resulting estimated transaction gas expenditure.

    Note: The function calls below are *order dependant*
    """

    #
    # Setup
    #

    if analyzer is None:
        analyzer = AnalyzeGas()

    log = Logger(AnalyzeGas.LOG_NAME)
    os.environ['GAS_ESTIMATOR_BACKEND_FUNC'] = 'eth.estimators.gas.binary_gas_search_exact'

    # Blockchain
    economics = StandardTokenEconomics(
        base_penalty=MIN_ALLOWED_LOCKED - 1,
        penalty_history_coefficient=0,
        percentage_penalty_coefficient=2,
        reward_coefficient=2
    )
    testerchain, registry = TesterBlockchain.bootstrap_network(economics=economics)
    web3 = testerchain.w3

    print("\n********* SIZE OF MAIN CONTRACTS *********")
    MAX_SIZE = 24576
    rows = list()
    for contract_name in NUCYPHER_CONTRACT_NAMES:
        compiled_contract = testerchain._raw_contract_cache[contract_name]

        version = list(compiled_contract).pop()
        # FIXME this value includes constructor code size but should not
        bin_runtime = compiled_contract[version]['evm']['bytecode']['object']
        bin_length_in_bytes = len(bin_runtime) // 2
        percentage = int(100 * bin_length_in_bytes / MAX_SIZE)
        bar = ('*'*(percentage//2)).ljust(50)
        rows.append((contract_name, bin_length_in_bytes, f'{bar} {percentage}%'))

    headers = ('Contract', 'Size (B)', f'% of max allowed contract size ({MAX_SIZE} B)')
    print(tabulate.tabulate(rows, headers=headers, tablefmt="simple"), end="\n\n")

    # Accounts
    origin, staker1, staker2, staker3, staker4, alice1, alice2, *everyone_else = testerchain.client.accounts

    ursula_with_stamp = mock_ursula(testerchain, staker1)

    # Contracts
    token_agent = NucypherTokenAgent(registry=registry)
    staking_agent = StakingEscrowAgent(registry=registry)
    policy_agent = PolicyManagerAgent(registry=registry)
    adjudicator_agent = AdjudicatorAgent(registry=registry)

    # Contract Callers
    token_functions = token_agent.contract.functions
    staker_functions = staking_agent.contract.functions
    policy_functions = policy_agent.contract.functions
    adjudicator_functions = adjudicator_agent.contract.functions

    analyzer.start_collection()
    print("********* Estimating Gas *********")

    def transact_and_log(label, function, transaction):
        estimates = function.estimateGas(transaction)
        transaction.update(gas=estimates)
        tx = function.transact(transaction)
        receipt = testerchain.wait_for_receipt(tx)
        log.info(f"{label} = {estimates} | {receipt['gasUsed']}")

    def transact(function, transaction):
        transaction.update(gas=1000000)
        tx = function.transact(transaction)
        testerchain.wait_for_receipt(tx)

    # First deposit ever is the most expensive, make it to remove unusual gas spending
    transact(token_functions.approve(staking_agent.contract_address, MIN_ALLOWED_LOCKED * 10), {'from': origin})
    transact(staker_functions.deposit(everyone_else[0], MIN_ALLOWED_LOCKED, MIN_LOCKED_PERIODS), {'from': origin})
    testerchain.time_travel(periods=1)

    #
    # Give Ursula and Alice some coins
    #
    transact_and_log("Transfer tokens", token_functions.transfer(staker1, MIN_ALLOWED_LOCKED * 10), {'from': origin})
    transact(token_functions.transfer(staker2, MIN_ALLOWED_LOCKED * 10), {'from': origin})
    transact(token_functions.transfer(staker3, MIN_ALLOWED_LOCKED * 10), {'from': origin})

    #
    # Ursula and Alice give Escrow rights to transfer
    #
    transact_and_log("Approving transfer",
                     token_functions.approve(staking_agent.contract_address, MIN_ALLOWED_LOCKED * 7),
                     {'from': staker1})
    transact(token_functions.approve(staking_agent.contract_address, MIN_ALLOWED_LOCKED * 6), {'from': staker2})
    transact(token_functions.approve(staking_agent.contract_address, MIN_ALLOWED_LOCKED * 6), {'from': staker3})

    #
    # Ursula and Alice transfer some tokens to the escrow and lock them
    #
    transact_and_log("Initial deposit tokens, first",
                     staker_functions.deposit(staker1, MIN_ALLOWED_LOCKED * 3, MIN_LOCKED_PERIODS),
                     {'from': staker1})
    transact_and_log("Initial deposit tokens, other",
                     staker_functions.deposit(staker2, MIN_ALLOWED_LOCKED * 3, MIN_LOCKED_PERIODS),
                     {'from': staker2})
    transact(staker_functions.deposit(staker3, MIN_ALLOWED_LOCKED * 3, MIN_LOCKED_PERIODS), {'from': staker3})

    transact(staker_functions.bondWorker(staker1), {'from': staker1})
    transact(staker_functions.bondWorker(staker2), {'from': staker2})
    transact(staker_functions.bondWorker(staker3), {'from': staker3})
    transact(staker_functions.setReStake(False), {'from': staker1})
    transact(staker_functions.setReStake(False), {'from': staker2})
    transact(staker_functions.setWindDown(True), {'from': staker1})
    transact(staker_functions.setWindDown(True), {'from': staker2})
    transact(staker_functions.commitToNextPeriod(), {'from': staker1})
    transact(staker_functions.commitToNextPeriod(), {'from': staker2})

    #
    # Wait 1 period and make a commitment
    #
    testerchain.time_travel(periods=1)
    transact_and_log("Make a commitment, first", staker_functions.commitToNextPeriod(), {'from': staker1})
    transact_and_log("Make a commitment, other", staker_functions.commitToNextPeriod(), {'from': staker2})

    #
    # Wait 1 period and mint tokens
    #
    testerchain.time_travel(periods=1)
    transact_and_log("Minting (1 stake), first", staker_functions.mint(), {'from': staker1})
    transact_and_log("Minting (1 stake), other", staker_functions.mint(), {'from': staker2})
    transact_and_log("Make a commitment again, first", staker_functions.commitToNextPeriod(), {'from': staker1})
    transact_and_log("Make a commitment again, other", staker_functions.commitToNextPeriod(), {'from': staker2})
    transact(staker_functions.commitToNextPeriod(), {'from': staker3})

    #
    # Commit again
    #
    testerchain.time_travel(periods=1)
    transact_and_log("Make a commitment + mint, first", staker_functions.commitToNextPeriod(), {'from': staker1})
    transact_and_log("Make a commitment + mint, other", staker_functions.commitToNextPeriod(), {'from': staker2})

    #
    # Create policy
    #
    policy_id_1 = os.urandom(int(Policy.POLICY_ID_LENGTH))
    policy_id_2 = os.urandom(int(Policy.POLICY_ID_LENGTH))
    number_of_periods = 10
    rate = 100
    one_period = economics.hours_per_period * 60 * 60
    value = number_of_periods * rate
    current_timestamp = testerchain.w3.eth.getBlock('latest').timestamp
    end_timestamp = current_timestamp + (number_of_periods - 1) * one_period
    transact_and_log("Creating policy (1 node, 10 periods, pre-committed), first",
                     policy_functions.createPolicy(policy_id_1, alice1, end_timestamp, [staker1]),
                     {'from': alice1, 'value': value})
    transact_and_log("Creating policy (1 node, 10 periods, pre-committed), other",
                     policy_functions.createPolicy(policy_id_2, alice1, end_timestamp, [staker1]),
                     {'from': alice1, 'value': value})

    #
    # Get locked tokens
    #
    transact_and_log("Getting locked tokens", staker_functions.getLockedTokens(staker1, 0), {})

    #
    # Wait 1 period and withdraw tokens
    #
    testerchain.time_travel(periods=1)
    transact_and_log("Withdraw", staker_functions.withdraw(1), {'from': staker1})

    #
    # Make a commitment with re-stake
    #
    transact(staker_functions.setReStake(True), {'from': staker1})
    transact(staker_functions.setReStake(True), {'from': staker2})

    # Used to remove spending for first call in a day for mint and commitToNextPeriod
    transact(staker_functions.commitToNextPeriod(), {'from': staker3})

    transact_and_log("Make a commitment + mint + re-stake",
                     staker_functions.commitToNextPeriod(),
                     {'from': staker2})
    transact_and_log("Make a commitment + mint + re-stake + first fee + first fee rate",
                     staker_functions.commitToNextPeriod(),
                     {'from': staker1})

    transact(staker_functions.setReStake(False), {'from': staker1})
    transact(staker_functions.setReStake(False), {'from': staker2})

    #
    # Wait 2 periods and make a commitment after downtime
    #
    testerchain.time_travel(periods=2)
    transact(staker_functions.commitToNextPeriod(), {'from': staker3})
    transact_and_log("Make a commitment after downtime", staker_functions.commitToNextPeriod(), {'from': staker2})
    transact_and_log("Make a commitment after downtime + updating fee",
                     staker_functions.commitToNextPeriod(),
                     {'from': staker1})

    #
    # Ursula and Alice deposit some tokens to the escrow again
    #
    transact_and_log("Deposit tokens after making a commitment",
                     staker_functions.deposit(staker1, MIN_ALLOWED_LOCKED * 2, MIN_LOCKED_PERIODS),
                     {'from': staker1})
    transact(staker_functions.deposit(staker2, MIN_ALLOWED_LOCKED * 2, MIN_LOCKED_PERIODS), {'from': staker2})

    #
    # Revoke policy
    #
    transact_and_log("Revoking policy", policy_functions.revokePolicy(policy_id_1), {'from': alice1})

    #
    # Wait 1 period
    #
    testerchain.time_travel(periods=1)

    #
    # Create policy with multiple pre-committed nodes
    #
    policy_id_1 = os.urandom(int(Policy.POLICY_ID_LENGTH))
    policy_id_2 = os.urandom(int(Policy.POLICY_ID_LENGTH))
    policy_id_3 = os.urandom(int(Policy.POLICY_ID_LENGTH))
    number_of_periods = 100
    value = 3 * number_of_periods * rate
    current_timestamp = testerchain.w3.eth.getBlock('latest').timestamp
    end_timestamp = current_timestamp + (number_of_periods - 1) * one_period
    transact_and_log("Creating policy (3 nodes, 100 periods, pre-committed), first",
                     policy_functions.createPolicy(policy_id_1, alice1, end_timestamp, [staker1, staker2, staker3]),
                     {'from': alice1, 'value': value})
    transact_and_log("Creating policy (3 nodes, 100 periods, pre-committed), other",
                     policy_functions.createPolicy(policy_id_2, alice1, end_timestamp, [staker1, staker2, staker3]),
                     {'from': alice1, 'value': value})
    value = 2 * number_of_periods * rate
    transact_and_log("Creating policy (2 nodes, 100 periods, pre-committed), other",
                     policy_functions.createPolicy(policy_id_3, alice1, end_timestamp, [staker1, staker2]),
                     {'from': alice1, 'value': value})

    #
    # Wait 1 period and mint tokens
    #
    testerchain.time_travel(periods=1)
    transact(staker_functions.mint(), {'from': staker3})
    transact_and_log("Last minting + updating fee + updating fee rate", staker_functions.mint(), {'from': staker1})
    transact_and_log("Last minting + first fee + first fee rate", staker_functions.mint(), {'from': staker2})

    #
    # Create policy again without pre-committed nodes
    #
    policy_id_1 = os.urandom(int(Policy.POLICY_ID_LENGTH))
    policy_id_2 = os.urandom(int(Policy.POLICY_ID_LENGTH))
    policy_id_3 = os.urandom(int(Policy.POLICY_ID_LENGTH))
    number_of_periods = 100
    value = number_of_periods * rate
    current_timestamp = testerchain.w3.eth.getBlock('latest').timestamp
    end_timestamp = current_timestamp + (number_of_periods - 1) * one_period
    transact_and_log("Creating policy (1 node, 100 periods)",
                     policy_functions.createPolicy(policy_id_1, alice2, end_timestamp, [staker2]),
                     {'from': alice1, 'value': value})
    testerchain.time_travel(periods=1)
    current_timestamp = testerchain.w3.eth.getBlock('latest').timestamp
    end_timestamp = current_timestamp + (number_of_periods - 1) * one_period
    transact_and_log("Creating policy (1 node, 100 periods), next period",
                     policy_functions.createPolicy(policy_id_2, alice2, end_timestamp, [staker2]),
                     {'from': alice1, 'value': value})
    transact_and_log("Creating policy (1 node, 100 periods), another node",
                     policy_functions.createPolicy(policy_id_3, alice2, end_timestamp, [staker1]),
                     {'from': alice1, 'value': value})

    #
    # Mint and revoke policy
    #
    testerchain.time_travel(periods=10)
    transact(staker_functions.commitToNextPeriod(), {'from': staker1})
    transact(staker_functions.commitToNextPeriod(), {'from': staker3})

    testerchain.time_travel(periods=2)
    transact(staker_functions.mint(), {'from': staker3})
    transact_and_log("Last minting after downtime + updating fee",
                     staker_functions.mint(),
                     {'from': staker1})

    testerchain.time_travel(periods=10)
    transact_and_log("Revoking policy after downtime, 1st policy",
                     policy_functions.revokePolicy(policy_id_1),
                     {'from': alice2})
    transact_and_log("Revoking policy after downtime, 2nd policy",
                     policy_functions.revokePolicy(policy_id_2),
                     {'from': alice2})
    transact_and_log("Revoking policy after downtime, 3rd policy",
                     policy_functions.revokePolicy(policy_id_3),
                     {'from': alice2})

    for index in range(5):
        transact(staker_functions.commitToNextPeriod(), {'from': staker1})
        testerchain.time_travel(periods=1)
    transact(staker_functions.mint(), {'from': staker1})

    #
    # Check regular deposit
    #
    transact_and_log("Deposit tokens to new sub-stake",
                     staker_functions.deposit(staker1, MIN_ALLOWED_LOCKED, MIN_LOCKED_PERIODS),
                     {'from': staker1})
    transact_and_log("Deposit tokens using existing sub-stake",
                     staker_functions.depositAndIncrease(0, MIN_ALLOWED_LOCKED),
                     {'from': staker1})

    #
    # ApproveAndCall
    #
    testerchain.time_travel(periods=1)
    transact(staker_functions.mint(), {'from': staker1})

    transact_and_log("ApproveAndCall",
                     token_functions.approveAndCall(staking_agent.contract_address,
                                                    MIN_ALLOWED_LOCKED * 2,
                                                    web3.toBytes(MIN_LOCKED_PERIODS)),
                     {'from': staker1})

    #
    # Locking tokens
    #
    testerchain.time_travel(periods=1)
    transact(staker_functions.commitToNextPeriod(), {'from': staker1})
    transact_and_log("Locking tokens and creating new sub-stake",
                     staker_functions.lockAndCreate(MIN_ALLOWED_LOCKED, MIN_LOCKED_PERIODS),
                     {'from': staker1})
    transact_and_log("Locking tokens using existing sub-stake",
                     staker_functions.lockAndIncrease(0, MIN_ALLOWED_LOCKED),
                     {'from': staker1})

    #
    # Divide stake
    #
    transact_and_log("Divide stake", staker_functions.divideStake(1, MIN_ALLOWED_LOCKED, 2), {'from': staker1})
    transact(staker_functions.divideStake(3, MIN_ALLOWED_LOCKED, 2), {'from': staker1})

    #
    # Divide almost finished stake
    #
    testerchain.time_travel(periods=1)
    transact(staker_functions.commitToNextPeriod(), {'from': staker1})
    testerchain.time_travel(periods=1)
    transact(staker_functions.commitToNextPeriod(), {'from': staker1})

    #
    # Slashing tests
    #
    testerchain.time_travel(periods=1)

    #
    # Slashing
    #
    slashing_args = generate_args_for_slashing(ursula_with_stamp)
    transact_and_log("Slash just value", adjudicator_functions.evaluateCFrag(*slashing_args), {'from': alice1})

    deposit = staker_functions.stakerInfo(staker1).call()[0]
    unlocked = deposit - staker_functions.getLockedTokens(staker1, 0).call()
    transact(staker_functions.withdraw(unlocked), {'from': staker1})

    sub_stakes_length = str(staker_functions.getSubStakesLength(staker1).call())
    slashing_args = generate_args_for_slashing(ursula_with_stamp)
    transact_and_log("Slashing one sub stake and saving old one (" + sub_stakes_length + " sub stakes), 1st",
                     adjudicator_functions.evaluateCFrag(*slashing_args),
                     {'from': alice1})

    sub_stakes_length = str(staker_functions.getSubStakesLength(staker1).call())
    slashing_args = generate_args_for_slashing(ursula_with_stamp)
    transact_and_log("Slashing one sub stake and saving old one (" + sub_stakes_length + " sub stakes), 2nd",
                     adjudicator_functions.evaluateCFrag(*slashing_args),
                     {'from': alice1})

    sub_stakes_length = str(staker_functions.getSubStakesLength(staker1).call())
    slashing_args = generate_args_for_slashing(ursula_with_stamp)
    transact_and_log("Slashing one sub stake and saving old one (" + sub_stakes_length + " sub stakes), 3rd",
                     adjudicator_functions.evaluateCFrag(*slashing_args),
                     {'from': alice1})

    sub_stakes_length = str(staker_functions.getSubStakesLength(staker1).call())
    slashing_args = generate_args_for_slashing(ursula_with_stamp)
    transact_and_log("Slashing two sub stakes and saving old one (" + sub_stakes_length + " sub stakes)",
                     adjudicator_functions.evaluateCFrag(*slashing_args),
                     {'from': alice1})

    for index in range(18):
        transact(staker_functions.commitToNextPeriod(), {'from': staker1})
        testerchain.time_travel(periods=1)

    transact(staker_functions.lockAndCreate(MIN_ALLOWED_LOCKED, MIN_LOCKED_PERIODS), {'from': staker1})
    deposit = staker_functions.stakerInfo(staker1).call()[0]
    unlocked = deposit - staker_functions.getLockedTokens(staker1, 1).call()
    transact(staker_functions.withdraw(unlocked), {'from': staker1})

    sub_stakes_length = str(staker_functions.getSubStakesLength(staker1).call())
    slashing_args = generate_args_for_slashing(ursula_with_stamp)
    transact_and_log("Slashing two sub stakes, shortest and new one (" + sub_stakes_length + " sub stakes)",
                     adjudicator_functions.evaluateCFrag(*slashing_args),
                     {'from': alice1})

    sub_stakes_length = str(staker_functions.getSubStakesLength(staker1).call())
    slashing_args = generate_args_for_slashing(ursula_with_stamp)
    transact_and_log("Slashing three sub stakes, two shortest and new one (" + sub_stakes_length + " sub stakes)",
                     adjudicator_functions.evaluateCFrag(*slashing_args),
                     {'from': alice1})

    slashing_args = generate_args_for_slashing(ursula_with_stamp, corrupt_cfrag=False)
    transact_and_log("Evaluating correct CFrag", adjudicator_functions.evaluateCFrag(*slashing_args), {'from': alice1})

    transact_and_log("Prolong stake", staker_functions.prolongStake(0, 20), {'from': staker1})
    transact_and_log("Merge sub-stakes", staker_functions.mergeStake(2, 3), {'from': staker1})

    # Large number of sub-stakes
    number_of_sub_stakes = 24
    transact(token_functions.approve(staking_agent.contract_address, 0), {'from': origin})
    transact(token_functions.approve(staking_agent.contract_address, MIN_ALLOWED_LOCKED * number_of_sub_stakes),
             {'from': origin})
    for i in range(number_of_sub_stakes):
        transact(staker_functions.deposit(staker4, MIN_ALLOWED_LOCKED, MIN_LOCKED_PERIODS),
                 {'from': origin})
    transact(staker_functions.bondWorker(staker4), {'from': staker4})
    transact(staker_functions.setWindDown(True), {'from': staker4})

    # Used to remove spending for first call in a day for mint and commitToNextPeriod
    transact(staker_functions.commitToNextPeriod(), {'from': staker1})

    transact_and_log(f"Make a commitment ({number_of_sub_stakes} sub-stakes)",
                     staker_functions.commitToNextPeriod(),
                     {'from': staker4})

    testerchain.time_travel(periods=1)
    transact(staker_functions.commitToNextPeriod(), {'from': staker4})
    testerchain.time_travel(periods=1)

    # Used to remove spending for first call in a day for mint and commitToNextPeriod
    transact(staker_functions.commitToNextPeriod(), {'from': staker1})

    transact_and_log(f"Make a commitment + mint + re-stake ({number_of_sub_stakes} sub-stakes)",
                     staker_functions.commitToNextPeriod(),
                     {'from': staker4})

    print("********* All Done! *********")


if __name__ == "__main__":
    print("Starting Up...")
    analyzer = AnalyzeGas()
    estimate_gas(analyzer=analyzer)
    analyzer.to_json_file()
