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
import tempfile
from pathlib import Path
from nucypher.crypto.umbral_adapter import UmbralPrivateKey

from nucypher.cli.main import nucypher_cli
from nucypher.policy.identity import Card


@pytest.fixture(scope='module', autouse=True)
def patch_card_directory(session_mocker):
    custom_filepath = '/tmp/nucypher-test-cards-'
    tmpdir = tempfile.TemporaryDirectory(prefix=custom_filepath)
    tmpdir.cleanup()
    session_mocker.patch.object(Card, 'CARD_DIR', return_value=Path(tmpdir.name),
                                new_callable=session_mocker.PropertyMock)
    yield
    tmpdir.cleanup()


@pytest.fixture(scope='module')
def alice_verifying_key():
    return UmbralPrivateKey.gen_key().get_pubkey().hex()


@pytest.fixture(scope='module')
def bob_nickname():
    return 'edward'.capitalize()


@pytest.fixture(scope='module')
def alice_nickname():
    return 'alice'.capitalize()


@pytest.fixture(scope='module')
def bob_verifying_key():
    return UmbralPrivateKey.gen_key().get_pubkey().hex()


@pytest.fixture(scope='module')
def bob_encrypting_key():
    return UmbralPrivateKey.gen_key().get_pubkey().hex()


def test_card_directory_autocreation(click_runner, mocker):
    mocked_mkdir = mocker.patch('os.mkdir')
    mocked_listdir = mocker.patch('os.listdir', side_effect=(FileNotFoundError, []))
    command = ('contacts', 'list')  # form list command
    result = click_runner.invoke(nucypher_cli, command, catch_exceptions=False)
    assert result.exit_code == 0, result.output
    mocked_mkdir.assert_called_once()
    mocked_listdir.call_count = 2


def test_list_cards_with_none_created(click_runner, certificates_tempdir):
    command = ('contacts', 'list')
    result = click_runner.invoke(nucypher_cli, command, catch_exceptions=False)
    assert result.exit_code == 0, result.output
    assert f'No cards found at {Card.CARD_DIR}.' in result.output


def test_create_alice_card_interactive(click_runner, alice_verifying_key, alice_nickname, mocker):
    command = ('contacts', 'create')
    user_input = (
        'a',                  # Alice
        alice_verifying_key,  # Public key
        alice_nickname        # Nickname
    )
    user_input = '\n'.join(user_input)
    assert len(os.listdir(Card.CARD_DIR)) == 0

    # Let's play pretend: this alice does not have the card directory (yet)
    mocker.patch('pathlib.Path.exists', return_value=False)
    mocked_mkdir = mocker.patch('os.mkdir')

    result = click_runner.invoke(nucypher_cli, command, input=user_input, catch_exceptions=False)

    # The path was created.
    mocked_mkdir.assert_called_once()

    assert result.exit_code == 0, result.output
    assert 'Enter Verifying Key' in result.output
    assert 'Saved new card' in result.output
    assert len(os.listdir(Card.CARD_DIR)) == 1


def test_create_alice_card_inline(click_runner, alice_verifying_key, alice_nickname):
    command = ('contacts', 'create',
               '--type', 'a',
               '--verifying-key',  UmbralPrivateKey.gen_key().get_pubkey().hex(),
               '--nickname', 'philippa')

    assert len(os.listdir(Card.CARD_DIR)) == 1
    result = click_runner.invoke(nucypher_cli, command, catch_exceptions=False)
    assert result.exit_code == 0, result.output
    assert 'Saved new card' in result.output
    assert len(os.listdir(Card.CARD_DIR)) == 2


def test_create_bob_card_interactive(click_runner, bob_nickname, bob_encrypting_key, bob_verifying_key):
    command = ('contacts', 'create')
    user_input = (
        'b',                 # Bob
        bob_encrypting_key,  # Public key 1
        bob_verifying_key,   # Public key 2
        bob_nickname         # Nickname
    )
    user_input = '\n'.join(user_input)

    assert len(os.listdir(Card.CARD_DIR)) == 2
    result = click_runner.invoke(nucypher_cli, command, input=user_input, catch_exceptions=False)
    assert result.exit_code == 0, result.output
    assert 'Enter Verifying Key' in result.output
    assert 'Enter Encrypting Key' in result.output
    assert 'Saved new card' in result.output
    assert len(os.listdir(Card.CARD_DIR)) == 3


def test_create_bob_card_inline(click_runner, alice_verifying_key, alice_nickname):
    command = ('contacts', 'create',
               '--type', 'b',
               '--verifying-key',  UmbralPrivateKey.gen_key().get_pubkey().hex(),
               '--encrypting-key', UmbralPrivateKey.gen_key().get_pubkey().hex(),
               '--nickname', 'hans')

    assert len(os.listdir(Card.CARD_DIR)) == 3
    result = click_runner.invoke(nucypher_cli, command, catch_exceptions=False)
    assert result.exit_code == 0, result.output
    assert 'Saved new card' in result.output
    assert len(os.listdir(Card.CARD_DIR)) == 4


def test_show_unknown_card(click_runner, alice_nickname, alice_verifying_key):
    command = ('contacts', 'show', 'idontknowwhothatis')
    result = click_runner.invoke(nucypher_cli, command, catch_exceptions=False)
    assert result.exit_code == 0, result.output
    assert 'Unknown card nickname or ID' in result.output


def test_show_alice_card(click_runner, alice_nickname, alice_verifying_key):
    command = ('contacts', 'show', alice_nickname)
    result = click_runner.invoke(nucypher_cli, command, catch_exceptions=False)
    assert result.exit_code == 0, result.output
    assert alice_nickname in result.output
    assert alice_verifying_key in result.output


def test_show_bob_card(click_runner, bob_nickname, bob_encrypting_key, bob_verifying_key):
    command = ('contacts', 'show', bob_nickname)
    result = click_runner.invoke(nucypher_cli, command, catch_exceptions=False)
    assert result.exit_code == 0, result.output
    assert bob_nickname in result.output
    assert bob_encrypting_key in result.output
    assert bob_verifying_key in result.output


def test_list_card(click_runner, bob_nickname, bob_encrypting_key,
                   bob_verifying_key, alice_nickname, alice_verifying_key):
    command = ('contacts', 'list')
    assert len(os.listdir(Card.CARD_DIR)) == 4
    result = click_runner.invoke(nucypher_cli, command, catch_exceptions=False)
    assert result.exit_code == 0, result.output
    assert bob_nickname in result.output
    assert bob_encrypting_key[:Card.TRUNCATE] in result.output
    assert bob_verifying_key[:Card.TRUNCATE] in result.output
    assert alice_nickname in result.output
    assert alice_verifying_key[:Card.TRUNCATE] in result.output


def test_delete_card(click_runner, bob_nickname):
    command = ('contacts', 'delete', '--id', bob_nickname, '--force')
    assert len(os.listdir(Card.CARD_DIR)) == 4
    result = click_runner.invoke(nucypher_cli, command, catch_exceptions=False)
    assert result.exit_code == 0, result.output
    assert 'Deleted card' in result.output
    assert len(os.listdir(Card.CARD_DIR)) == 3
