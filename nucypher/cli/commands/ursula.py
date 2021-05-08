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
import shutil
import tempfile
from operator import attrgetter
from pathlib import Path

import click
import pyzipper

from nucypher.blockchain.eth.signers.software import ClefSigner
from nucypher.characters.control.emitters import StdoutEmitter
from nucypher.cli.actions.auth import get_client_password, get_nucypher_password
from nucypher.cli.actions.configure import (
    destroy_configuration,
    handle_missing_configuration_file,
    get_or_update_configuration,
    collect_worker_ip_address
)
from nucypher.cli.actions.configure import forget as forget_nodes, perform_startup_ip_check
from nucypher.cli.actions.select import select_client_account, select_config_file, select_network
from nucypher.cli.commands.deploy import option_gas_strategy
from nucypher.cli.config import group_general_config
from nucypher.cli.literature import (
    DEVELOPMENT_MODE_WARNING,
    FORCE_MODE_WARNING,
    SUCCESSFUL_MANUALLY_SAVE_METADATA
)
from nucypher.cli.options import (
    group_options,
    option_config_file,
    option_config_root,
    option_db_filepath,
    option_dev,
    option_dry_run,
    option_federated_only,
    option_force,
    option_light,
    option_min_stake,
    option_network,
    option_poa,
    option_provider_uri,
    option_registry_filepath,
    option_signer_uri,
    option_teacher_uri,
    option_lonely,
    option_max_gas_price
)
from nucypher.cli.painting.help import paint_new_installation_help
from nucypher.cli.types import EIP55_CHECKSUM_ADDRESS, NETWORK_PORT, WORKER_IP
from nucypher.cli.utils import make_cli_character, setup_emitter
from nucypher.config.characters import UrsulaConfiguration
from nucypher.config.constants import (
    DEFAULT_CONFIG_ROOT,
    NUCYPHER_ENVVAR_WORKER_ETH_PASSWORD,
    TEMPORARY_DOMAIN
)
from nucypher.config.keyring import NucypherKeyring


class UrsulaConfigOptions:

    __option_name__ = 'config_options'

    def __init__(self,
                 provider_uri: str,
                 worker_address: str,
                 federated_only: bool,
                 rest_host: str,
                 rest_port: int,
                 db_filepath: str,
                 network: str,
                 registry_filepath: str,
                 dev: bool,
                 poa: bool,
                 light: bool,
                 gas_strategy: str,
                 max_gas_price: int,  # gwei
                 signer_uri: str,
                 availability_check: bool,
                 lonely: bool
                 ):

        if federated_only:
            if registry_filepath:
                raise click.BadOptionUsage(option_name="--registry-filepath",
                                           message=f"--registry-filepath cannot be used in federated mode.")

        self.provider_uri = provider_uri
        self.signer_uri = signer_uri
        self.worker_address = worker_address
        self.federated_only = federated_only
        self.rest_host = rest_host
        self.rest_port = rest_port  # FIXME: not used in generate()
        self.db_filepath = db_filepath
        self.domain = network
        self.registry_filepath = registry_filepath
        self.dev = dev
        self.poa = poa
        self.light = light
        self.gas_strategy = gas_strategy
        self.max_gas_price = max_gas_price
        self.availability_check = availability_check
        self.lonely = lonely

    def create_config(self, emitter, config_file):
        if self.dev:
            return UrsulaConfiguration(
                emitter=emitter,
                dev_mode=True,
                domain=TEMPORARY_DOMAIN,
                poa=self.poa,
                light=self.light,
                registry_filepath=self.registry_filepath,
                provider_uri=self.provider_uri,
                signer_uri=self.signer_uri,
                gas_strategy=self.gas_strategy,
                max_gas_price=self.max_gas_price,
                checksum_address=self.worker_address,
                federated_only=self.federated_only,
                rest_host=self.rest_host,
                rest_port=self.rest_port,
                db_filepath=self.db_filepath,
                availability_check=self.availability_check
            )
        else:
            if not config_file:
                config_file = select_config_file(emitter=emitter,
                                                 checksum_address=self.worker_address,
                                                 config_class=UrsulaConfiguration)
            try:
                return UrsulaConfiguration.from_configuration_file(
                    emitter=emitter,
                    filepath=config_file,
                    domain=self.domain,
                    registry_filepath=self.registry_filepath,
                    provider_uri=self.provider_uri,
                    signer_uri=self.signer_uri,
                    gas_strategy=self.gas_strategy,
                    max_gas_price=self.max_gas_price,
                    rest_host=self.rest_host,
                    rest_port=self.rest_port,
                    db_filepath=self.db_filepath,
                    poa=self.poa,
                    light=self.light,
                    federated_only=self.federated_only,
                    availability_check=self.availability_check
                )
            except FileNotFoundError:
                return handle_missing_configuration_file(character_config_class=UrsulaConfiguration, config_file=config_file)
            except NucypherKeyring.AuthenticationFailed as e:
                emitter.echo(str(e), color='red', bold=True)
                # TODO: Exit codes (not only for this, but for other exceptions)
                return click.get_current_context().exit(1)

    def generate_config(self, emitter, config_root, force):

        if self.dev:
            raise RuntimeError('Persistent configurations cannot be created in development mode.')

        worker_address = self.worker_address
        if (not worker_address) and not self.federated_only:
            if not worker_address:
                prompt = "Select worker account"
                worker_address = select_client_account(emitter=emitter,
                                                       prompt=prompt,
                                                       provider_uri=self.provider_uri,
                                                       signer_uri=self.signer_uri)

        # Resolve rest host
        if not self.rest_host:
            self.rest_host = collect_worker_ip_address(emitter, network=self.domain, force=force)

        return UrsulaConfiguration.generate(password=get_nucypher_password(emitter=emitter, confirm=True),
                                            config_root=config_root,
                                            rest_host=self.rest_host,
                                            rest_port=self.rest_port,
                                            db_filepath=self.db_filepath,
                                            domain=self.domain,
                                            federated_only=self.federated_only,
                                            worker_address=worker_address,
                                            registry_filepath=self.registry_filepath,
                                            provider_uri=self.provider_uri,
                                            signer_uri=self.signer_uri,
                                            gas_strategy=self.gas_strategy,
                                            max_gas_price=self.max_gas_price,
                                            poa=self.poa,
                                            light=self.light,
                                            availability_check=self.availability_check)

    def get_updates(self) -> dict:
        payload = dict(rest_host=self.rest_host,
                       rest_port=self.rest_port,
                       db_filepath=self.db_filepath,
                       domain=self.domain,
                       federated_only=self.federated_only,
                       checksum_address=self.worker_address,
                       registry_filepath=self.registry_filepath,
                       provider_uri=self.provider_uri,
                       signer_uri=self.signer_uri,
                       gas_strategy=self.gas_strategy,
                       max_gas_price=self.max_gas_price,
                       poa=self.poa,
                       light=self.light,
                       availability_check=self.availability_check)
        # Depends on defaults being set on Configuration classes, filtrates None values
        updates = {k: v for k, v in payload.items() if v is not None}
        return updates


group_config_options = group_options(
    UrsulaConfigOptions,
    provider_uri=option_provider_uri(),
    signer_uri=option_signer_uri,
    gas_strategy=option_gas_strategy,
    max_gas_price=option_max_gas_price,
    worker_address=click.option('--worker-address', help="Run the worker-ursula with a specified address", type=EIP55_CHECKSUM_ADDRESS),
    federated_only=option_federated_only,
    rest_host=click.option('--rest-host', help="The host IP address to run Ursula network services on", type=WORKER_IP),
    rest_port=click.option('--rest-port', help="The host port to run Ursula network services on", type=NETWORK_PORT),
    db_filepath=option_db_filepath,
    network=option_network(),  # Don't set defaults here or they will be applied to config updates. Use the Config API.
    registry_filepath=option_registry_filepath,
    poa=option_poa,
    light=option_light,
    dev=option_dev,
    availability_check=click.option('--availability-check/--disable-availability-check', help="Enable or disable self-health checks while running", is_flag=True, default=None),
    lonely=option_lonely,
)


class UrsulaCharacterOptions:

    __option_name__ = 'character_options'

    def __init__(self, config_options: UrsulaConfigOptions, teacher_uri, min_stake):
        self.config_options = config_options
        self.teacher_uri = teacher_uri
        self.min_stake = min_stake

    def create_character(self, emitter, config_file, json_ipc, load_seednodes=True):
        ursula_config = self.config_options.create_config(emitter, config_file)
        is_clef = ClefSigner.is_valid_clef_uri(self.config_options.signer_uri)
        password_required = all((not ursula_config.federated_only,
                                 not self.config_options.dev,
                                 not json_ipc,
                                 not is_clef))
        __password = None
        if password_required:
            __password = get_client_password(checksum_address=ursula_config.worker_address,
                                             envvar=NUCYPHER_ENVVAR_WORKER_ETH_PASSWORD)

        try:
            URSULA = make_cli_character(character_config=ursula_config,
                                        emitter=emitter,
                                        min_stake=self.min_stake,
                                        teacher_uri=self.teacher_uri,
                                        unlock_keyring=not self.config_options.dev,
                                        client_password=__password,
                                        unlock_signer=False,  # Ursula's unlock is managed separately using client_password.
                                        lonely=self.config_options.lonely,
                                        start_learning_now=load_seednodes,
                                        json_ipc=json_ipc)
            return ursula_config, URSULA

        except NucypherKeyring.AuthenticationFailed as e:
            emitter.echo(str(e), color='red', bold=True)
            # TODO: Exit codes (not only for this, but for other exceptions)
            return click.get_current_context().exit(1)


group_character_options = group_options(
    UrsulaCharacterOptions,
    config_options=group_config_options,
    teacher_uri=option_teacher_uri,
    min_stake=option_min_stake
)


@click.group()
def ursula():
    """"Ursula the Untrusted" PRE Re-encryption node management commands."""


@ursula.command()
@group_config_options
@option_force
@option_config_root
@group_general_config
def init(general_config, config_options, force, config_root):
    """Create a new Ursula node configuration."""
    emitter = setup_emitter(general_config, config_options.worker_address)
    _pre_launch_warnings(emitter, dev=None, force=force)
    if not config_root:
        config_root = general_config.config_root
    if not config_options.federated_only and not config_options.provider_uri:
        raise click.BadOptionUsage('--provider', message="--provider is required to initialize a new ursula.")
    if not config_options.federated_only and not config_options.domain:
        config_options.domain = select_network(emitter)
    ursula_config = config_options.generate_config(emitter, config_root, force)
    filepath = ursula_config.to_configuration_file()
    paint_new_installation_help(emitter, new_configuration=ursula_config, filepath=filepath)


@ursula.command()
@group_config_options
@option_config_file
@option_force
@group_general_config
def destroy(general_config, config_options, config_file, force):
    """Delete Ursula node configuration."""
    emitter = setup_emitter(general_config, config_options.worker_address)
    _pre_launch_warnings(emitter, dev=config_options.dev, force=force)
    ursula_config = config_options.create_config(emitter, config_file)
    destroy_configuration(emitter, character_config=ursula_config, force=force)


@ursula.command()
@group_config_options
@option_config_file
@group_general_config
def forget(general_config, config_options, config_file):
    """Forget all known nodes."""
    emitter = setup_emitter(general_config, config_options.worker_address)
    _pre_launch_warnings(emitter, dev=config_options.dev, force=None)
    ursula_config = config_options.create_config(emitter, config_file)
    forget_nodes(emitter, configuration=ursula_config)


@ursula.command()
@group_character_options
@option_config_file
@option_dry_run
@option_force
@group_general_config
@click.option('--interactive', '-I', help="Run interactively", is_flag=True, default=False)
@click.option('--prometheus', help="Run the ursula prometheus exporter", is_flag=True, default=False)
@click.option('--metrics-port', help="Run a Prometheus metrics exporter on specified HTTP port", type=NETWORK_PORT)
@click.option("--metrics-listen-address", help="Run a prometheus metrics exporter on specified IP address", default='')
@click.option("--metrics-prefix", help="Create metrics params with specified prefix", default="ursula")
@click.option("--metrics-interval", help="The frequency of metrics collection", type=click.INT, default=90)
@click.option("--ip-checkup/--no-ip-checkup", help="Verify external IP matches configuration", default=True)
def run(general_config, character_options, config_file, interactive, dry_run, prometheus, metrics_port,
        metrics_listen_address, metrics_prefix, metrics_interval, force, ip_checkup):
    """Run an "Ursula" node."""

    worker_address = character_options.config_options.worker_address
    emitter = setup_emitter(general_config)
    dev_mode = character_options.config_options.dev
    lonely = character_options.config_options.lonely

    if prometheus and not metrics_port:
        # Require metrics port when using prometheus
        raise click.BadOptionUsage(option_name='metrics-port',
                                   message='--metrics-port is required when using --prometheus')

    _pre_launch_warnings(emitter, dev=dev_mode, force=None)

    prometheus_config: 'PrometheusMetricsConfig' = None
    if prometheus and not dev_mode:
        # Locally scoped to prevent import without prometheus explicitly installed
        from nucypher.utilities.prometheus.metrics import PrometheusMetricsConfig
        prometheus_config = PrometheusMetricsConfig(port=metrics_port,
                                                    metrics_prefix=metrics_prefix,
                                                    listen_address=metrics_listen_address,
                                                    collection_interval=metrics_interval)

    ursula_config, URSULA = character_options.create_character(emitter=emitter,
                                                               config_file=config_file,
                                                               json_ipc=general_config.json_ipc)

    if ip_checkup and not (dev_mode or lonely):
        # Always skip startup IP checks for dev and lonely modes.
        perform_startup_ip_check(emitter=emitter, ursula=URSULA, force=force)

    try:
        URSULA.run(emitter=emitter,
                   start_reactor=not dry_run,
                   interactive=interactive,
                   prometheus_config=prometheus_config,
                   preflight=not dev_mode)
    finally:
        if dry_run:
            URSULA.stop()


@ursula.command(name='save-metadata')
@group_character_options
@option_config_file
@group_general_config
def save_metadata(general_config, character_options, config_file):
    """Manually write node metadata to disk without running."""
    emitter = setup_emitter(general_config, character_options.config_options.worker_address)
    _pre_launch_warnings(emitter, dev=character_options.config_options.dev, force=None)
    _, URSULA = character_options.create_character(emitter, config_file, general_config.json_ipc, load_seednodes=False)
    metadata_path = URSULA.write_node_metadata(node=URSULA)
    emitter.message(SUCCESSFUL_MANUALLY_SAVE_METADATA.format(metadata_path=metadata_path), color='green')


@ursula.command()
@click.argument('action', required=False)
@group_config_options
@option_config_file
@group_general_config
@option_force
def config(general_config, config_options, config_file, force, action):
    """
    View and optionally update the Ursula node's configuration.

    \b
    Sub-Commands
    ~~~~~~~~~~~~~
    ip-address - automatically detect and configure the external IP address.

    """
    emitter = setup_emitter(general_config, config_options.worker_address)
    if not config_file:
        config_file = select_config_file(emitter=emitter,
                                         checksum_address=config_options.worker_address,
                                         config_class=UrsulaConfiguration)
    if action == 'ip-address':
        rest_host = collect_worker_ip_address(emitter=emitter, network=config_options.domain, force=force)
        config_options.rest_host = rest_host
    elif action:
        emitter.echo(f'"{action}" is not a valid command.', color='red')
        raise click.Abort()
    updates = config_options.get_updates()
    get_or_update_configuration(emitter=emitter,
                                config_class=UrsulaConfiguration,
                                filepath=config_file,
                                updates=updates)


def _pre_launch_warnings(emitter, dev, force):
    if dev:
        emitter.echo(DEVELOPMENT_MODE_WARNING, color='yellow', verbosity=1)
    if force:
        emitter.echo(FORCE_MODE_WARNING, color='yellow', verbosity=1)


BACKUP_ENCRYPTION_SETTINGS = {'encryption': pyzipper.WZ_AES, 'nbits': 256}
WORKER_ARCHIVE_ROOT = "worker"
KEYSTORE_ARCHIVE_ROOT = "keystore"


class BackupCliOptions:
    __option_name__ = 'backup_options'

    def __init__(self,
                 worker_path: str,
                 keystore_path: str,
                 backup_path: str,
                 password: str,
                 overwrite: bool,
                 ) -> None:
        self.worker_path = Path(worker_path)
        self.keystore_path = Path(keystore_path)
        self.backup_path = Path(backup_path)
        self.password = password.encode()
        self.overwrite = overwrite


backup_cli_options = group_options(
    BackupCliOptions,
    password=click.option('--password',
                          help="Enter backup password",
                          prompt="Enter backup password",
                          hide_input=True,
                          confirmation_prompt=True),
    worker_path=click.option('--worker-path',
                             help="Path to Ursula worker directory",
                             prompt="Path to Ursula worker directory",
                             type=click.Path(),
                             required=True,
                             default=DEFAULT_CONFIG_ROOT),
    keystore_path=click.option('--keystore-path',
                               help="Path to Ursula keystore directory",
                               prompt="Path to Ursula keystore directory",
                               type=click.Path(),
                               required=True,
                               default=Path.home() / ".ethereum/keystore"),  # TODO: use env var?
    backup_path=click.option('--backup-path',
                             help="Path to backup file",
                             prompt="Path to backup file",
                             type=click.Path(dir_okay=False),
                             default=Path("./ursula-backup.zip"),
                             required=True),
    overwrite=click.option('--overwrite',
                           help="Overwrite existing backup",
                           default=False)
)


@ursula.command()
@group_config_options
@group_general_config
@backup_cli_options
def backup(general_config, config_options, backup_options):
    """
    Backup the Ursula node's configuration.
    """
    emitter = setup_emitter(general_config, config_options.worker_address)
    worker_path, keystore_path, backup_path, password, overwrite = (
        attrgetter('worker_path', 'keystore_path', 'backup_path', 'password', 'overwrite')(backup_options))

    for path in [worker_path, keystore_path]:
        if not path.exists():
            raise FileNotFoundError(f'Path does not exist: {path.absolute()}')

    if backup_path.exists() and not overwrite:
        prompt = f"Path already exists: {backup_path}\nOverwrite?"
        click.confirm(prompt, abort=True)

    with pyzipper.AESZipFile(backup_path, 'w', encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password)
        zf.setencryption(**BACKUP_ENCRYPTION_SETTINGS)
        _write_zf(emitter, zf, worker_path, WORKER_ARCHIVE_ROOT)
        _write_zf(emitter, zf, keystore_path, KEYSTORE_ARCHIVE_ROOT)


def _write_zf(emitter: StdoutEmitter, zf: pyzipper.ZipFile, source: Path, archive_root: str):
    archive_root = Path(archive_root)

    def _write(file_path_, archive_path_):
        emitter.echo(f"Wrote {str(file_path_.absolute())} to {str(archive_path_.absolute())}", verbosity=2)
        zf.write(file_path_, arcname=archive_path_)

    if source.is_file():
        _write(source, archive_root / source.name)
    else:
        for root_path, dirs, files in os.walk(source):
            for file in files:
                file_path = Path(root_path, file)
                archive_path = archive_root / file_path.relative_to(source.parent.absolute())
                _write(file_path, archive_path)

    emitter.echo(f"Wrote f{source}")


@ursula.command()
@group_config_options
@group_general_config
@backup_cli_options
def restore(general_config, config_options, backup_options):
    """
    Restore the Ursula node's configuration.
    """
    emitter = setup_emitter(general_config, config_options.worker_address)
    worker_path, keystore_path, backup_path, password, overwrite = (
        attrgetter('worker_path', 'keystore_path', 'backup_path', 'password', 'overwrite')(backup_options))

    if not backup_path.exists():
        raise FileNotFoundError(f'Backup file does not exist: {backup_path.absolute()}')

    with pyzipper.AESZipFile(backup_path) as zf:
        zf.setpassword(password)
        zf.setencryption(**BACKUP_ENCRYPTION_SETTINGS)
        _read_zf(emitter, zf, KEYSTORE_ARCHIVE_ROOT, keystore_path, overwrite)
        _read_zf(emitter, zf, WORKER_ARCHIVE_ROOT, worker_path, overwrite)


def _read_zf(emitter: StdoutEmitter, zf: pyzipper.ZipFile, archive_root: str, destination_path: Path, overwrite: bool):
    if destination_path.exists() and not overwrite:
        prompt = f"Path already exists: {destination_path}\nOverwrite?"
        click.confirm(prompt, abort=True)

    # Using temporary dir as a workaround for "zf.extract" always treating "archive_item" as a relative path
    temp_dir = tempfile.mkdtemp()
    for archive_item in zf.namelist():
        if archive_item.startswith(archive_root):
            zf.extract(archive_item, temp_dir)
            emitter.echo(f"Extracted {archive_item}", verbosity=2)

    archive_path = Path(temp_dir, archive_root)
    if archive_path.exists():
        shutil.move(archive_path, destination_path)

    emitter.echo(f"Wrote {destination_path.absolute()}")
