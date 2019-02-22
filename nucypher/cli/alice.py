import datetime
from base64 import b64encode

import click
import maya

from nucypher.cli import actions, painting
from nucypher.cli.config import nucypher_click_config
from nucypher.cli.painting import paint_configuration
from nucypher.cli.types import NETWORK_PORT, EXISTING_READABLE_FILE
from nucypher.config.characters import AliceConfiguration
from nucypher.config.constants import GLOBAL_DOMAIN

ALICE_BANNER = r"""

    / \  | (_) ___ ___
   / _ \ | | |/ __/ _ \
  / ___ \| | | (_|  __/
 /_/   \_|_|_|\___\___|

 the Authority.

"""


@click.command()
@click.argument('action')
@click.option('--teacher-uri', help="An Ursula URI to start learning from (seednode)", type=click.STRING)
@click.option('--quiet', '-Q', help="Disable logging", is_flag=True)
@click.option('--min-stake', help="The minimum stake the teacher must have to be a teacher", type=click.INT, default=0)
@click.option('--discovery-port', help="The host port to run node discovery services on", type=NETWORK_PORT, default=9151)  # TODO
@click.option('--http-port', help="The host port to run Moe HTTP services on", type=NETWORK_PORT, default=8151)  # TODO
@click.option('--federated-only', '-F', help="Connect only to federated nodes", is_flag=True)
@click.option('--network', help="Network Domain Name", type=click.STRING)
@click.option('--config-root', help="Custom configuration directory", type=click.Path())
@click.option('--config-file', help="Path to configuration file", type=EXISTING_READABLE_FILE)
@click.option('--provider-uri', help="Blockchain provider's URI", type=click.STRING)
@click.option('--registry-filepath', help="Custom contract registry filepath", type=EXISTING_READABLE_FILE)
@click.option('--bob-encrypting-key', help="Bob's encrypting key as a hexideicmal string", type=click.STRING)
@click.option('--bob-verifying-key', help="Bob's verifying key as a hexideicmal string", type=click.STRING)
@click.option('--label', help="The label for a policy", type=click.STRING)
@click.option('--m', help="M", type=click.INT)
@click.option('--n', help="N", type=click.INT)
@click.option('--dev', '-d', help="Enable development mode", is_flag=True)
@click.option('--force', help="Don't ask for confirmation", is_flag=True)
@click.option('--dry-run', '-x', help="Execute normally without actually starting the node", is_flag=True)
@nucypher_click_config
def alice(click_config,
          action,
          quiet,
          teacher_uri,
          min_stake,
          http_port,
          discovery_port,
          federated_only,
          network,
          config_root,
          config_file,
          provider_uri,
          registry_filepath,
          dev,
          force,
          dry_run,
          bob_encrypting_key,
          bob_verifying_key,
          label,
          m,
          n):

    """
    Start and manage an "Alice" character.
    """

    if not quiet:
        click.secho(ALICE_BANNER)

    if action == 'init':
        """Create a brand-new persistent Alice"""

        if dev and not quiet:
            click.secho("WARNING: Using temporary storage area", fg='yellow')

        if not config_root:                         # Flag
            config_root = click_config.config_file  # Envvar

        new_alice_config = AliceConfiguration.generate(password=click_config.get_password(confirm=True),
                                                       config_root=config_root,
                                                       rest_host="localhost",
                                                       domains={network} if network else None,
                                                       federated_only=federated_only,
                                                       no_registry=True,  # Yes we have no registry,
                                                       registry_filepath=registry_filepath,
                                                       provider_uri=provider_uri)

        if not quiet:
            painting.paint_new_installation_help(new_configuration=new_alice_config,
                                                 config_root=config_root,
                                                 config_file=config_file)
            return

        else:
            click.secho("OK")

    elif action == "destroy":
        """Delete all configuration files from the disk"""
        if dev:
            message = "'nucypher ursula destroy' cannot be used in --dev mode"
            raise click.BadOptionUsage(option_name='--dev', message=message)

        actions.destroy_system_configuration(config_class=AliceConfiguration,
                                             config_file=config_file,
                                             network=network,
                                             config_root=config_root,
                                             force=force)
        if not quiet:
            click.secho("Destroyed {}".format(config_root))
        return

    #
    # Get Alice Configuration
    #

    if dev:
        alice_config = AliceConfiguration(dev_mode=True,
                                          domains={network},
                                          provider_uri=provider_uri,
                                          federated_only=True)

    else:
        alice_config = AliceConfiguration.from_configuration_file(
            filepath=config_file,
            domains={network or GLOBAL_DOMAIN},
            rest_port=discovery_port,
            provider_uri=provider_uri)

    if not dev:
        actions.unlock_keyring(password=click_config.get_password(), configuration=alice_config)

    # Teacher Ursula
    teacher_uris = [teacher_uri] if teacher_uri else list()
    teacher_nodes = actions.load_seednodes(teacher_uris=teacher_uris,
                                           min_stake=min_stake,
                                           federated_only=federated_only)
    # Produce
    ALICE = alice_config(known_nodes=teacher_nodes)

    if action == "run":
        click.secho(f"Alice Verifying Key {bytes(ALICE.stamp).hex()}", fg="green", bold=True)
        return ALICE.control.start_wsgi_controller(http_port=http_port, dry_run=dry_run)

    elif action == "view":
        """Paint an existing configuration to the console"""
        json_config = AliceConfiguration._read_configuration_file(filepath=config_file or alice_config.config_file_location)
        paint_configuration(json_config=json_config)
        return json_config

    elif action == "create-policy":
        if not all((bob_verifying_key, bob_encrypting_key, label)):
            raise click.BadArgumentUsage(message="--bob-verifying-key, --bob-encrypting-key, and --label are "
                                                 "required options to create a new policy.")

        request_data = {
            'bob_encrypting_key': bob_encrypting_key,
            'bob_signing_key': bob_verifying_key,
            'label': label,
            'm': m,
            'n': n,
        }

        response = ALICE.control.create_policy(**request_data)
        click.secho(response)
        return response

    elif action == "derive-policy":
        response = ALICE.control.derive_policy(label=label)
        click.secho(response)
        return response

    elif action == "grant":
        request_data = {
            'bob_encrypting_key': bob_encrypting_key,
            'bob_signing_key': bob_verifying_key,
            'label': b64encode(bytes(label, encoding='utf-8')).decode(),
            'm': m,
            'n': n,
            'expiration_time': (maya.now() + datetime.timedelta(days=3)).iso8601(),  # TODO
        }

        response = ALICE.control.grant(**request_data)
        click.secho(response)
        return response

    elif action == "revoke":
        raise NotImplementedError  # TODO

    else:
        raise click.BadArgumentUsage(f"No such argument {action}")
