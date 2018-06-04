import datetime
import os
import tempfile

import maya
import pytest
from constant_sorrow import constants
from sqlalchemy.engine import create_engine

from nucypher.blockchain.eth.chains import Blockchain
from nucypher.characters import Alice, Bob

from nucypher.config.configs import NucypherConfiguration

from nucypher.data_sources import DataSource
from nucypher.keystore import keystore
from nucypher.keystore.db import Base
from nucypher.keystore.keypairs import SigningKeypair
from tests.utilities import MockNetworkMiddleware, make_ursulas, EVENT_LOOP
from constant_sorrow import constants


@pytest.fixture(scope="module")
def nucypher_test_config(blockchain_config):

    config = NucypherConfiguration(keyring="this is a faked keyring object",
                            blockchain_config=blockchain_config)
    yield config
    NucypherConfiguration.reset()
    Blockchain.sever()
    del config


@pytest.fixture(scope="module")
def idle_policy(alice, bob):
    """
    Creates a Policy, in a manner typical of how Alice might do it, with a unique uri (soon to be "label" - see #183)
    """
    alice.__resource_id += b"/unique-again"  # A unique name each time, like a path.
    n = constants.NUMBER_OF_URSULAS_IN_NETWORK

    policy = alice.create_policy(
        bob,
        alice.__resource_id,
        m=3,
        n=n,
    )
    return policy


@pytest.fixture(scope="module")
def enacted_policy(idle_policy, ursulas):
    # Alice has a policy in mind and knows of enough qualifies Ursulas; she crafts an offer for them.
    deposit = constants.NON_PAYMENT(b"0000000")
    contract_end_datetime = maya.now() + datetime.timedelta(days=5)

    networky_stuff = MockNetworkMiddleware(ursulas)
    found_ursulas = idle_policy.find_ursulas(networky_stuff, deposit, expiration=contract_end_datetime)
    idle_policy.match_kfrags_to_found_ursulas(found_ursulas)
    idle_policy.enact(networky_stuff)  # REST call happens here, as does population of TreasureMap.

    return idle_policy


@pytest.fixture(scope="module")
def alice(ursulas, mock_policy_agent, nucypher_test_config):
    etherbase, alice, bob, *everyone_else = nucypher_test_config.blockchain.chain.interface.w3.eth.accounts

    _alice = Alice(network_middleware=MockNetworkMiddleware(ursulas),
                   policy_agent=mock_policy_agent, ether_address=alice,
                   config=nucypher_test_config)

    _alice.dht_server.listen(8471)
    _alice.__resource_id = b"some_resource_id"
    EVENT_LOOP.run_until_complete(_alice.dht_server.bootstrap([("127.0.0.1", u.dht_port) for u in ursulas]))
    _alice.network_bootstrap([("127.0.0.1", u.rest_port) for u in ursulas])
    return _alice


@pytest.fixture(scope="module")
def bob(ursulas):
    _bob = Bob(network_middleware=MockNetworkMiddleware(ursulas))
    return _bob


@pytest.fixture(scope="module")
def ursulas(nucypher_test_config):

    etherbase, alice, bob, *everyone_else = nucypher_test_config.blockchain.chain.interface.w3.eth.accounts
    ursula_addresses = everyone_else[:NUMBER_OF_URSULAS_IN_NETWORK]

    _ursulas = make_ursulas(ether_addresses=ursula_addresses,
                            ursula_starting_port=URSULA_PORT,
                            config=nucypher_test_config)
    yield _ursulas
    # Remove the DBs that have been sprayed hither and yon.
    for index, ursula in enumerate(_ursulas):
        port = URSULA_PORT + index
        os.remove("test-{}".format(port))


@pytest.fixture(scope="module")
def treasure_map_is_set_on_dht(enacted_policy, ursulas):
    networky_stuff = MockNetworkMiddleware(ursulas)
    enacted_policy.publish_treasure_map(networky_stuff, use_dht=True)


@pytest.fixture(scope="module")
def test_keystore():
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    test_keystore = keystore.KeyStore(engine)
    yield test_keystore


@pytest.fixture(scope="module")
def capsule_side_channel(enacted_policy):
    signing_keypair = SigningKeypair()
    data_source = DataSource(policy_pubkey_enc=enacted_policy.public_key,
                             signing_keypair=signing_keypair)
    message_kit, _signature = data_source.encapsulate_single_message(b"Welcome to the flippering.")
    return message_kit, data_source


@pytest.fixture(scope="function")
def tempfile_path():
    """
    User is responsible for closing the file given at the path.
    """
    _, path = tempfile.mkstemp()
    yield path
    os.remove(path)
