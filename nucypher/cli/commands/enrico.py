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


import click
from nucypher.crypto.umbral_adapter import UmbralPublicKey

from nucypher.characters.control.interfaces import EnricoInterface
from nucypher.characters.lawful import Enrico
from nucypher.cli.utils import setup_emitter
from nucypher.cli.config import group_general_config
from nucypher.cli.options import option_dry_run, option_policy_encrypting_key
from nucypher.cli.types import NETWORK_PORT


@click.group()
def enrico():
    """"Enrico the Encryptor" management commands."""


@enrico.command()
@option_policy_encrypting_key(required=True)
@option_dry_run
@click.option('--http-port', help="The host port to run Enrico HTTP services on", type=NETWORK_PORT)
@group_general_config
def run(general_config, policy_encrypting_key, dry_run, http_port):
    """Start Enrico's controller."""

    # Setup
    emitter = setup_emitter(general_config, policy_encrypting_key)
    ENRICO = _create_enrico(emitter, policy_encrypting_key)

    # RPC
    if general_config.json_ipc:
        rpc_controller = ENRICO.make_rpc_controller()
        _transport = rpc_controller.make_control_transport()
        rpc_controller.start()
        return

    ENRICO.log.info('Starting HTTP Character Web Controller')
    controller = ENRICO.make_web_controller()
    return controller.start(http_port=http_port, dry_run=dry_run)


@enrico.command()
@EnricoInterface.connect_cli('encrypt_message')
@click.option('--ipfs', help="Upload the encrypted message to IPFS at the specified gateway URI")
@group_general_config
def encrypt(general_config, policy_encrypting_key, message, file, ipfs):
    """Encrypt a message under a given policy public key."""

    emitter = setup_emitter(general_config=general_config, banner=policy_encrypting_key)

    if ipfs:
        try:
            import ipfshttpclient
        except ImportError:
            raise ImportError("IPFS HTTP client not installed.  Run 'pip install ipfshttpclient' then try again.")

        # Connect to IPFS before proceeding
        ipfs_client = ipfshttpclient.connect(ipfs)
        emitter.message(f"Connected to IPFS Gateway {ipfs}")

    if not policy_encrypting_key:
        policy_encrypting_key = click.prompt("Enter policy encrypting key", type=click.STRING)

    ENRICO = _create_enrico(emitter, policy_encrypting_key)
    if message and file:
        emitter.error(f'Pass either --message or --file, not both.')
        raise click.Abort

    if not message and not file:
        message = click.prompt('Enter plaintext to encrypt', type=click.STRING)

    # Encryption Request
    encryption_request = {'policy_encrypting_key': policy_encrypting_key, 'message': message, 'file': file}
    response = ENRICO.controller.encrypt_message(request=encryption_request)

    # Handle ciphertext upload to sidechannel
    if ipfs:
        cid = ipfs_client.add_str(response['message_kit'])
        emitter.message(f"Uploaded message kit to IPFS (CID {cid})", color='green')

    return response


def _create_enrico(emitter, policy_encrypting_key) -> Enrico:
    policy_encrypting_key = UmbralPublicKey.from_bytes(bytes.fromhex(policy_encrypting_key))
    ENRICO = Enrico(policy_encrypting_key=policy_encrypting_key)
    ENRICO.controller.emitter = emitter
    return ENRICO
