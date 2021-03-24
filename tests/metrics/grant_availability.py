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
from pathlib import Path

"""
WARNING: This script makes automatic transactions.
Do not use this script unless you know what you
are doing and intend to spend ETH measuring live
policy availability.
"""


import datetime
import maya
import os
import shutil
import time
from eth_typing.evm import ChecksumAddress
from typing import Set, Optional, List, Tuple
from nucypher.crypto.umbral_adapter import UmbralPrivateKey
from web3.main import Web3
from web3.types import Wei

from nucypher.network.middleware import RestMiddleware
from nucypher.characters.lawful import Bob, Ursula, Alice
from nucypher.config.characters import AliceConfiguration
from nucypher.policy.policies import Policy
from nucypher.utilities.logging import GlobalLoggerSettings

# Signer Configuration
# In order to use this script, you must configure a wallet for alice
ADDRESS_ENVVAR: str = 'NUCYPHER_GRANT_METRICS_ADDRESS'
PASSWORD_ENVVAR: str = 'NUCYPHER_GRANT_METRICS_PASSWORD'
SIGNER_ENVVAR: str = 'NUCYPHER_GRANT_METRICS_KEYFILE_PATH'
PROVIDER_ENVVAR: str = 'NUCYPHER_GRANT_METRICS_PROVIDER'


try:
    ALICE_ADDRESS: ChecksumAddress = os.environ[ADDRESS_ENVVAR]
    SIGNER_PASSWORD: str = os.environ[PASSWORD_ENVVAR]
    SIGNER_URI: str = os.environ[SIGNER_ENVVAR]
    ETHEREUM_PROVIDER_URI: str = os.environ[PROVIDER_ENVVAR]
except KeyError:
    message = f'{ADDRESS_ENVVAR}, ' \
              f'{PROVIDER_ENVVAR}, ' \
              f'{SIGNER_ENVVAR} and ' \
              f'{PASSWORD_ENVVAR} ' \
              f'are required to run grant availability metrics.'
    raise RuntimeError(message)

# Alice Configuration
DOMAIN: str = 'mainnet'  # ibex
DEFAULT_SEEDNODE_URIS: List[str] = [
    *RestMiddleware.TEACHER_NODES[DOMAIN],
]
INSECURE_PASSWORD: str = "METRICS_INSECURE_DEVELOPMENT_PASSWORD"
TEMP_ALICE_DIR: str = Path('/', 'tmp', 'grant-metrics')

# Policy Parameters
M: int = 1
N: int = 1
RATE: Wei = Web3.toWei(50, 'gwei')
DURATION: datetime.timedelta = datetime.timedelta(days=1)

# Tuning
DEFAULT_ITERATIONS = 1  # `None` will run forever
SAMPLE_RATE: int = 15  # seconds
GAS_STRATEGY: str = 'fast'
MAX_GAS_PRICE: int = 200  # gwei
LABEL_PREFIX = 'random-metrics-label-'
LABEL_SUFFIXER = lambda: os.urandom(16).hex()
HANDPICKED_URSULA_URIS: List[str] = [
    # DEFAULT_SEEDNODE_URIS[0],  # uncomment to use the seednode for granting
]


def make_random_bob():
    """Generates a random ephemeral Bob instance."""
    bob_verifying_secret = UmbralPrivateKey.gen_key()
    bob_verifying_key = bob_verifying_secret.pubkey
    decrypting_secret = UmbralPrivateKey.gen_key()
    decrypting_key = decrypting_secret.pubkey
    bob = Bob.from_public_keys(verifying_key=bob_verifying_key,
                               encrypting_key=decrypting_key,
                               federated_only=False)
    print(f'Created BOB - {bytes(bob.stamp).hex()}')
    return bob


BOB = make_random_bob()


def metric_grant(alice, handpicked_ursulas: Optional[Set[Ursula]] = None) -> Policy:
    """Perform a granting operation for metrics collection."""
    label = f'{LABEL_PREFIX}{LABEL_SUFFIXER()}'.encode()
    policy_end_datetime = maya.now() + DURATION
    policy = alice.grant(m=M, n=N,
                         handpicked_ursulas=handpicked_ursulas,
                         expiration=policy_end_datetime,
                         bob=BOB,
                         label=label,
                         rate=RATE)
    return policy


def collect(alice: Alice,
            handpicked_ursulas: Optional[Set[Ursula]] = None,
            iterations: Optional[int] = DEFAULT_ITERATIONS,
            ) -> None:
    """Collects grant success and failure rates."""
    policies, i, success, fail = dict(), 0, 0, 0
    while True:
        print(f"Attempt {i+1} of {iterations if iterations is not None else 'infinite'}")
        start = maya.now()
        try:
            policy = metric_grant(alice=alice, handpicked_ursulas=handpicked_ursulas)
        except Exception as e:
            fail += 1
            print(f'GRANT FAIL\n{e}')
        else:
            success += 1
            policies[policy.public_key.hex()] = policy  # track
            print(f"PEK:{policy.public_key.hex()} | HRAC {policy.hrac.hex()}")

        # timeit
        end = maya.now()
        delta = end - start
        print(f"Completed in {(delta).total_seconds()} seconds.")

        # score
        if i+1 != iterations:
            if fail > 0:
                print(f'{fail}/{i+1} ({(fail/(i+1))*100}%) failure rate')
            if success > 0:
                print(f'{success}/{i+1} ({(success/(i+1))*100}%) success rate')
            print(f'Waiting {SAMPLE_RATE} seconds until next sample. ')
            time.sleep(SAMPLE_RATE)

        if i+1 == iterations:
            return  # exit
        else:
            i += 1  # continue


def make_alice(known_nodes: Optional[Set[Ursula]] = None):
    """Initializes a new 'persistent alice configuration' for grant metrics collection."""
    alice_config = AliceConfiguration(
        provider_uri=ETHEREUM_PROVIDER_URI,
        checksum_address=ALICE_ADDRESS,
        signer_uri=f'keystore://{SIGNER_URI}',
        config_root=os.path.join(TEMP_ALICE_DIR),
        domain=DOMAIN,
        known_nodes=known_nodes,
        start_learning_now=False,
        federated_only=False,
        learn_on_same_thread=True,
        gas_strategy=GAS_STRATEGY,
        max_gas_price=MAX_GAS_PRICE,
    )

    alice_config.initialize(password=INSECURE_PASSWORD)
    alice_config.keyring.unlock(password=INSECURE_PASSWORD)
    alice = alice_config.produce()
    alice.signer.unlock(account=ALICE_ADDRESS, password=SIGNER_PASSWORD)
    alice.start_learning_loop(now=True)
    return alice


def setup():
    """Prepares the filesystem and logger for grant metrics collection"""
    shutil.rmtree(TEMP_ALICE_DIR, ignore_errors=True)
    GlobalLoggerSettings.start_console_logging()
    GlobalLoggerSettings.set_log_level('info')


def aggregate_nodes() -> Tuple[Set[Ursula], Set[Ursula]]:
    """generates ursulas from URIs used in grant metrics collection"""

    seednodes = set()
    if DEFAULT_SEEDNODE_URIS:
        for uri in DEFAULT_SEEDNODE_URIS:
            ursula = Ursula.from_seed_and_stake_info(seed_uri=uri, federated_only=False)
            seednodes.add(ursula)

    handpicked_ursulas = set()
    if HANDPICKED_URSULA_URIS:
        for uri in HANDPICKED_URSULA_URIS:
            ursula = Ursula.from_seed_and_stake_info(seed_uri=uri, federated_only=False)
            handpicked_ursulas.add(ursula)

    return seednodes, handpicked_ursulas


if __name__ == '__main__':
    setup()
    seednodes, handpicked_ursulas = aggregate_nodes()
    alice = make_alice(known_nodes=seednodes)
    collect(alice=alice, handpicked_ursulas=handpicked_ursulas)
