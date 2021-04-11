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

import os
import re
from abc import ABC, abstractmethod
from constant_sorrow.constants import (
    UNKNOWN_VERSION,
    UNINITIALIZED_CONFIGURATION,
    NO_KEYRING_ATTACHED,
    NO_BLOCKCHAIN_CONNECTION,
    FEDERATED_ADDRESS,
    DEVELOPMENT_CONFIGURATION,
    LIVE_CONFIGURATION
)


from decimal import Decimal
from eth_utils.address import is_checksum_address
from tempfile import TemporaryDirectory
from typing import Union, Callable, Optional, List
from nucypher.crypto.umbral_adapter import Signature

from nucypher.blockchain.eth.interfaces import BlockchainInterfaceFactory
from nucypher.blockchain.eth.networks import NetworksInventory
from nucypher.blockchain.eth.registry import (
    BaseContractRegistry,
    InMemoryContractRegistry,
    LocalContractRegistry
)
from nucypher.blockchain.eth.signers import Signer
from nucypher.characters.lawful import Ursula
from nucypher.config import constants
from nucypher.config.keyring import NucypherKeyring
from nucypher.config.storages import (
    ForgetfulNodeStorage,
    LocalFileBasedNodeStorage,
    NodeStorage
)
from nucypher.crypto.powers import CryptoPower, CryptoPowerUp
from nucypher.network.middleware import RestMiddleware
from nucypher.utilities.logging import Logger


class BaseConfiguration(ABC):
    """
    Abstract base class for saving a JSON serializable version of the subclass's attributes
    to the disk exported by `static_payload`, generating an optionally unique filename,
    and restoring a subclass instance from the written JSON file by passing the deserialized
    values to the subclass's constructor.

    Implementation:

    `NAME` and `def static_payload` are required for subclasses, for example:

    .. code::

        class MyItem(BaseConfiguration):
            _NAME = 'my-item'

    AND

    .. code::

        def static_payload(self) -> dict:
            payload = dict(**super().static_payload(), key=value)
            return payload

    OR

    .. code::

        def static_payload(self) -> dict:
            subclass_payload = {'key': 'value'}
            payload = {**super().static_payload(), **subclass_payload}
            return payload

    Filepath Generation

    Default behavior *avoids* overwriting an existing configuration file:

    - The name of the JSON file to write/read from is determined by `NAME`.
      When calling `to_configuration_file`.

    - If the default path (i.e. `my-item.json`) already  exists and, optionally,
      `override` is set to `False`, then a `modifer` is appended to the name (i.e. `my-item-<MODIFIER>.json`).

    - If `modifier` is `None` and override is `False`, `FileExistsError` will be raised.

    If the subclass implementation has a global unique identifier, an additional method override
    to `to_configuration_file` will automate the renaming process.

    .. code::

        def to_configuration_file(*args, **kwargs) -> str:
            filepath = super().to_configuration_file(modifier=<MODIFIER>, *args, **kwargs)
            return filepath
    """

    NAME = NotImplemented
    _CONFIG_FILE_EXTENSION = 'json'

    INDENTATION = 2
    DEFAULT_CONFIG_ROOT = constants.DEFAULT_CONFIG_ROOT

    VERSION = NotImplemented

    class ConfigurationError(RuntimeError):
        pass

    class InvalidConfiguration(ConfigurationError):
        pass

    class NoConfigurationRoot(InvalidConfiguration):
        pass

    class OldVersion(InvalidConfiguration):
        pass

    def __init__(self,
                 config_root: str = None,
                 filepath: str = None,
                 *args, **kwargs):

        if self.NAME is NotImplemented:
            error = f'NAME must be implemented on BaseConfiguration subclass {self.__class__.__name__}'
            raise TypeError(error)

        self.config_root = config_root or self.DEFAULT_CONFIG_ROOT
        if not filepath:
            filepath = os.path.join(self.config_root, self.generate_filename())
        self.filepath = filepath

        super().__init__()

    @abstractmethod
    def static_payload(self) -> dict:
        """
        Return a dictionary of JSON serializable configuration key/value pairs
        matching the input specification of this classes __init__.

        Recommended subclass implementations:

        ```
        payload = dict(**super().static_payload(), key=value)
        return payload
        ```

        OR

        ```
        subclass_payload = {'key': 'value'}
        payload = {**super().static_payload(), **subclass_payload}
        return payload
        ```

        """
        payload = dict(config_root=self.config_root)
        return payload

    @classmethod
    def generate_filename(cls, modifier: str = None) -> str:
        """
        Generates the configuration filename with an optional modification string.

        :param modifier: String to modify default filename with.
        :return: The generated filepath string.
        """
        name = cls.NAME.lower()
        if modifier:
            name += f'-{modifier}'
        filename = f'{name}.{cls._CONFIG_FILE_EXTENSION.lower()}'
        return filename

    @classmethod
    def default_filepath(cls, config_root: str = None) -> str:
        """
        Generates the default configuration filepath for the class.

        :return: The generated filepath string
        """
        filename = cls.generate_filename()
        default_path = os.path.join(config_root or cls.DEFAULT_CONFIG_ROOT, filename)
        return default_path

    def generate_filepath(self, filepath: str = None, modifier: str = None, override: bool = False) -> str:
        """
        Generates a filepath for saving to writing to a configuration file.

        Default behavior *avoids* overwriting an existing configuration file:

        - The filepath exists and a filename `modifier` is not provided, then `FileExistsError` will be raised.
        - The modified filepath exists, then `FileExistsError` will be raised.

        To allow re-generation of an existing filepath, set `override` to True.

        :param filepath: A custom filepath to use for configuration.
        :param modifier: A unique string to modify the filename if the file already exists.
        :param override: Allow generation of an existing filepath.
        :return: The generated filepath.

        """
        if not filepath:
            filename = self.generate_filename()
            filepath = os.path.join(self.config_root, filename)
        if os.path.exists(filepath) and not override:
            if not modifier:
                raise FileExistsError(f"{filepath} exists and no filename modifier supplied.")
            filename = self.generate_filename(modifier=modifier)
            filepath = os.path.join(self.config_root, filename)
        self.filepath = filepath
        return filepath

    def _ensure_config_root_exists(self) -> None:
        """
        Before writing to a configuration file, ensures that
        self.config_root exists on the filesystem.

        :return: None.
        """
        if not os.path.exists(self.config_root):
            try:
                os.mkdir(self.config_root, mode=0o755)
            except FileNotFoundError:
                os.makedirs(self.config_root, mode=0o755)

    @classmethod
    def peek(cls, filepath: str, field: str) -> Union[str, None]:
        payload = cls._read_configuration_file(filepath=filepath)
        try:
            result = payload[field]
        except KeyError:
            raise cls.ConfigurationError(f"Cannot peek; No such configuration field '{field}', options are {list(payload.keys())}")
        return result

    def to_configuration_file(self, filepath: str = None, modifier: str = None, override: bool = False) -> str:
        filepath = self.generate_filepath(filepath=filepath, modifier=modifier, override=override)
        self._ensure_config_root_exists()
        filepath = self._write_configuration_file(filepath=filepath, override=override)
        return filepath

    @classmethod
    def from_configuration_file(cls, filepath: str = None, **overrides) -> 'BaseConfiguration':
        filepath = filepath or cls.default_filepath()
        payload = cls._read_configuration_file(filepath=filepath)
        instance = cls(filepath=filepath, **payload, **overrides)
        return instance

    @classmethod
    def _read_configuration_file(cls, filepath: str) -> dict:
        """Reads `filepath` and returns the deserialized JSON payload dict."""
        with open(filepath, 'r') as file:
            raw_contents = file.read()
            payload = cls.deserialize(raw_contents)
        return payload

    def _write_configuration_file(self, filepath: str, override: bool = False) -> str:
        """Writes to `filepath` and returns the written filepath.  Raises `FileExistsError` if the file exists."""
        if os.path.exists(str(filepath)) and not override:
            raise FileExistsError(f"{filepath} exists and no filename modifier supplied.")
        with open(filepath, 'w') as file:
            file.write(self.serialize())
        return filepath

    def serialize(self, serializer=json.dumps) -> str:
        """Returns the JSON serialized output of `static_payload`"""
        payload = self.static_payload()
        payload['version'] = self.VERSION
        serialized_payload = serializer(payload, indent=self.INDENTATION)
        return serialized_payload

    @classmethod
    def deserialize(cls, payload: str, deserializer=json.loads) -> dict:
        """Returns the JSON deserialized content of `payload`"""
        deserialized_payload = deserializer(payload)
        version = deserialized_payload.pop('version', UNKNOWN_VERSION)
        if version != cls.VERSION:
            raise cls.OldVersion(f"Configuration file is the wrong version "
                                 f"Expected version {cls.VERSION}; Got version {version}")
        return deserialized_payload

    def update(self, filepath: str = None, modifier: str = None, **updates) -> None:
        for field, value in updates.items():
            try:
                getattr(self, field)
            except AttributeError:
                raise self.ConfigurationError(f"Cannot update '{field}'. It is an invalid configuration field.")
            else:
                setattr(self, field, value)
        self.to_configuration_file(filepath=filepath, modifier=modifier, override=True)


class CharacterConfiguration(BaseConfiguration):
    """
    'Sideways Engagement' of Character classes; a reflection of input parameters.
    """

    VERSION = 2  # bump when static payload scheme changes

    CHARACTER_CLASS = NotImplemented
    DEFAULT_CONTROLLER_PORT = NotImplemented
    DEFAULT_DOMAIN = NetworksInventory.DEFAULT
    DEFAULT_NETWORK_MIDDLEWARE = RestMiddleware
    TEMP_CONFIGURATION_DIR_PREFIX = 'tmp-nucypher'
    SIGNER_ENVVAR = None

    # When we begin to support other threshold schemes, this will be one of the concepts that makes us want a factory.  #571
    known_node_class = Ursula

    # Gas
    DEFAULT_GAS_STRATEGY = 'fast'

    # Fields specified here are *not* passed into the Character's constructor
    # and can be understood as configuration fields only.
    _CONFIG_FIELDS = ('config_root',
                      'poa',
                      'light',
                      'registry_filepath',
                      'gas_strategy',
                      'max_gas_price',  # gwei
                      'signer_uri',
                      'keyring_root'
                      )

    def __init__(self,

                 # Base
                 emitter=None,
                 config_root: str = None,
                 filepath: str = None,

                 # Mode
                 dev_mode: bool = False,
                 federated_only: bool = False,

                 # Identity
                 checksum_address: str = None,
                 crypto_power: CryptoPower = None,

                 # Keyring
                 keyring: NucypherKeyring = None,
                 keyring_root: str = None,

                 # Learner
                 learn_on_same_thread: bool = False,
                 abort_on_learning_error: bool = False,
                 start_learning_now: bool = True,

                 # Network
                 controller_port: int = None,
                 domain: str = DEFAULT_DOMAIN,
                 interface_signature: Signature = None,
                 network_middleware: RestMiddleware = None,
                 lonely: bool = False,

                 # Node Storage
                 known_nodes: set = None,
                 node_storage: NodeStorage = None,
                 reload_metadata: bool = True,
                 save_metadata: bool = True,

                 # Blockchain
                 poa: bool = None,
                 light: bool = False,
                 provider_uri: str = None,
                 gas_strategy: Union[Callable, str] = DEFAULT_GAS_STRATEGY,
                 max_gas_price: Optional[int] = None,
                 signer_uri: str = None,

                 # Registry
                 registry: BaseContractRegistry = None,
                 registry_filepath: str = None,

                 # Deployed Workers
                 worker_data: dict = None
                 ):

        self.log = Logger(self.__class__.__name__)

        # This constant is used to signal that a path can be generated if one is not provided.
        UNINITIALIZED_CONFIGURATION.bool_value(False)

        # Identity
        # NOTE: NodeConfigurations can only be used with Self-Characters
        self.is_me = True
        self.checksum_address = checksum_address

        # Keyring
        self.crypto_power = crypto_power
        self.keyring = keyring or NO_KEYRING_ATTACHED
        self.keyring_root = keyring_root or UNINITIALIZED_CONFIGURATION

        # Contract Registry
        if registry and registry_filepath:
            if registry.filepath != registry_filepath:
                error = f"Inconsistent registry filepaths for '{registry.filepath}' and '{registry_filepath}'."
                raise ValueError(error)
            else:
                self.log.warn(f"Registry and registry filepath were both passed.")
        self.registry = registry or NO_BLOCKCHAIN_CONNECTION.bool_value(False)
        self.registry_filepath = registry_filepath or UNINITIALIZED_CONFIGURATION

        # Blockchain
        self.poa = poa
        self.is_light = light
        self.provider_uri = provider_uri or NO_BLOCKCHAIN_CONNECTION
        self.signer_uri = signer_uri or None

        # Learner
        self.federated_only = federated_only
        self.domain = domain
        self.learn_on_same_thread = learn_on_same_thread
        self.abort_on_learning_error = abort_on_learning_error
        self.start_learning_now = start_learning_now
        self.save_metadata = save_metadata
        self.reload_metadata = reload_metadata
        self.known_nodes = known_nodes or set()  # handpicked
        self.lonely = lonely

        # Configuration
        self.__dev_mode = dev_mode
        self.config_file_location = filepath or UNINITIALIZED_CONFIGURATION
        self.config_root = UNINITIALIZED_CONFIGURATION

        # Deployed Workers
        self.worker_data = worker_data

        #
        # Federated vs. Blockchain arguments consistency
        #

        #
        # Federated
        #

        if self.federated_only:
            # Check for incompatible values
            blockchain_args = {'filepath': registry_filepath,
                               'poa': poa,
                               'provider_uri': provider_uri,
                               'gas_strategy': gas_strategy,
                               'max_gas_price': max_gas_price}
            if any(blockchain_args.values()):
                bad_args = ", ".join(f"{arg}={val}" for arg, val in blockchain_args.items() if val)
                self.log.warn(f"Arguments {bad_args} are incompatible with federated_only. "
                              f"Overridden with a sane default.")

                # Clear decentralized attributes to ensure consistency with a
                # federated configuration.
                self.poa = False
                self.is_light = False
                self.provider_uri = None
                self.registry_filepath = None
                self.gas_strategy = None
                self.max_gas_price = None

        #
        # Decentralized
        #

        else:
            self.gas_strategy = gas_strategy
            self.max_gas_price = max_gas_price  # gwei
            is_initialized = BlockchainInterfaceFactory.is_interface_initialized(provider_uri=self.provider_uri)
            if not is_initialized and provider_uri:
                BlockchainInterfaceFactory.initialize_interface(provider_uri=self.provider_uri,
                                                                poa=self.poa,
                                                                light=self.is_light,
                                                                emitter=emitter,
                                                                gas_strategy=self.gas_strategy,
                                                                max_gas_price=self.max_gas_price)
            else:
                self.log.warn(f"Using existing blockchain interface connection ({self.provider_uri}).")

            if not self.registry:
                # TODO: These two code blocks are untested.
                if not self.registry_filepath:  # TODO: Registry URI  (goerli://speedynet.json) :-)
                    self.log.info(f"Fetching latest registry from source.")
                    self.registry = InMemoryContractRegistry.from_latest_publication(network=self.domain)
                else:
                    self.registry = LocalContractRegistry(filepath=self.registry_filepath)
                    self.log.info(f"Using local registry ({self.registry}).")

            self.testnet = self.domain != NetworksInventory.MAINNET
            self.signer = Signer.from_signer_uri(self.signer_uri, testnet=self.testnet)

        if dev_mode:
            self.__temp_dir = UNINITIALIZED_CONFIGURATION
            self._setup_node_storage()
            self.initialize(password=DEVELOPMENT_CONFIGURATION)
        else:
            self.__temp_dir = LIVE_CONFIGURATION
            self.config_root = config_root or self.DEFAULT_CONFIG_ROOT
            self._cache_runtime_filepaths()
            self._setup_node_storage(node_storage=node_storage)

        # Network
        self.controller_port = controller_port or self.DEFAULT_CONTROLLER_PORT
        self.network_middleware = network_middleware or self.DEFAULT_NETWORK_MIDDLEWARE(registry=self.registry)
        self.interface_signature = interface_signature

        super().__init__(filepath=self.config_file_location, config_root=self.config_root)

    def __call__(self, **character_kwargs):
        return self.produce(**character_kwargs)

    @classmethod
    def checksum_address_from_filepath(cls, filepath: str) -> str:

        pattern = re.compile(r'''
                             (^\w+)-
                             (0x{1}         # Then, 0x the start of the string, exactly once
                             [0-9a-fA-F]{40}) # Followed by exactly 40 hex chars
                             ''',
                             re.VERBOSE)

        filename = os.path.basename(filepath)
        match = pattern.match(filename)

        if match:
            character_name, checksum_address = match.groups()

        else:
            # Extract from default by "peeking" inside the configuration file.
            default_name = cls.generate_filename()
            if filename == default_name:
                checksum_address = cls.peek(filepath=filepath, field='checksum_address')

                ###########
                # TODO: Cleanup and deprecate worker_address in config files, leaving only checksum_address
                from nucypher.config.characters import UrsulaConfiguration
                if isinstance(cls, UrsulaConfiguration):
                    federated = bool(cls.peek(filepath=filepath, field='federated_only'))
                    if not federated:
                        checksum_address = cls.peek(filepath=cls.filepath, field='worker_address')
                ###########

            else:
                raise ValueError(f"Cannot extract checksum from filepath '{filepath}'")

        if not is_checksum_address(checksum_address):
            raise RuntimeError(f"Invalid checksum address detected in configuration file at '{filepath}'.")
        return checksum_address

    def update(self, **kwargs) -> None:
        """
        A facility for updating existing attributes on existing configuration instances.

        Warning: This method allows mutation and may result in an inconsistent configuration.
        """
        return super().update(modifier=self.checksum_address, filepath=self.config_file_location, **kwargs)

    @classmethod
    def generate(cls, password: str, *args, **kwargs):
        """Shortcut: Hook-up a new initial installation and write configuration file to the disk"""
        node_config = cls(dev_mode=False, *args, **kwargs)
        node_config.initialize(password=password)
        node_config.to_configuration_file()
        return node_config

    def cleanup(self) -> None:
        if self.__dev_mode:
            self.__temp_dir.cleanup()

    @property
    def dev_mode(self) -> bool:
        return self.__dev_mode

    def _setup_node_storage(self, node_storage=None) -> None:
        if self.dev_mode:
            node_storage = ForgetfulNodeStorage(registry=self.registry, federated_only=self.federated_only)
        elif not node_storage:
            node_storage = LocalFileBasedNodeStorage(registry=self.registry,
                                                     config_root=self.config_root,
                                                     federated_only=self.federated_only)
        self.node_storage = node_storage

    def forget_nodes(self) -> None:
        self.node_storage.clear()
        message = "Removed all stored node node metadata and certificates"
        self.log.debug(message)

    def destroy(self) -> None:
        """Parse a node configuration and remove all associated files from the filesystem"""
        self.attach_keyring()
        self.keyring.destroy()
        os.remove(self.config_file_location)

    def generate_parameters(self, **overrides) -> dict:
        """
        Warning: This method allows mutation and may result in an inconsistent configuration.
        """
        merged_parameters = {**self.static_payload(), **self.dynamic_payload, **overrides}
        character_init_params = filter(lambda t: t[0] not in self._CONFIG_FIELDS, merged_parameters.items())
        return dict(character_init_params)

    def produce(self, **overrides) -> CHARACTER_CLASS:
        """Initialize a new character instance and return it."""
        merged_parameters = self.generate_parameters(**overrides)
        character = self.CHARACTER_CLASS(**merged_parameters)
        return character

    @classmethod
    def assemble(cls, filepath: str = None, **overrides) -> dict:
        """
        Warning: This method allows mutation and may result in an inconsistent configuration.
        """
        payload = cls._read_configuration_file(filepath=filepath)
        node_storage = cls.load_node_storage(storage_payload=payload['node_storage'],
                                             federated_only=payload['federated_only'])
        domain = payload['domain']
        max_gas_price = payload.get('max_gas_price')  # gwei
        if max_gas_price:
            max_gas_price = Decimal(max_gas_price)

        # Assemble
        payload.update(dict(node_storage=node_storage, domain=domain, max_gas_price=max_gas_price))
        # Filter out None values from **overrides to detect, well, overrides...
        # Acts as a shim for optional CLI flags.
        overrides = {k: v for k, v in overrides.items() if v is not None}
        payload = {**payload, **overrides}
        return payload

    @classmethod
    def from_configuration_file(cls,
                                filepath: str = None,
                                **overrides  # < ---- Inlet for CLI Flags
                                ) -> 'CharacterConfiguration':
        """Initialize a CharacterConfiguration from a JSON file."""
        filepath = filepath or cls.default_filepath()
        assembled_params = cls.assemble(filepath=filepath, **overrides)
        node_configuration = cls(filepath=filepath, **assembled_params)
        return node_configuration

    def validate(self) -> bool:

        # Top-level
        if not os.path.exists(self.config_root):
            raise self.ConfigurationError(f'No configuration directory found at {self.config_root}.')

        # Sub-paths
        filepaths = self.runtime_filepaths
        for field, path in filepaths.items():
            if path and not os.path.exists(path):
                message = 'Missing configuration file or directory: {}.'
                if 'registry' in path:
                    message += ' Did you mean to pass --federated-only?'
                raise CharacterConfiguration.InvalidConfiguration(message.format(path))
        return True

    def static_payload(self) -> dict:
        """Exported static configuration values for initializing Ursula"""

        payload = dict(

            # Identity
            federated_only=self.federated_only,
            checksum_address=self.checksum_address,
            keyring_root=self.keyring_root,

            # Behavior
            domain=self.domain,
            learn_on_same_thread=self.learn_on_same_thread,
            abort_on_learning_error=self.abort_on_learning_error,
            start_learning_now=self.start_learning_now,
            save_metadata=self.save_metadata,
            node_storage=self.node_storage.payload(),
            lonely=self.lonely,
        )

        # Optional values (mode)
        if not self.federated_only:
            if self.provider_uri:
                if not self.signer_uri:
                    self.signer_uri = self.provider_uri
                payload.update(dict(provider_uri=self.provider_uri,
                                    poa=self.poa,
                                    light=self.is_light,
                                    signer_uri=self.signer_uri))
            if self.registry_filepath:
                payload.update(dict(registry_filepath=self.registry_filepath))

            # Gas Price
            __max_price = str(self.max_gas_price) if self.max_gas_price else None
            payload.update(dict(gas_strategy=self.gas_strategy, max_gas_price=__max_price))

        # Merge with base payload
        base_payload = super().static_payload()
        base_payload.update(payload)

        return payload

    @property  # TODO: Graduate to a method and "derive" dynamic from static payload.
    def dynamic_payload(self) -> dict:
        """Exported dynamic configuration values for initializing Ursula"""
        payload = dict()
        if not self.federated_only:
            payload.update(dict(registry=self.registry, signer=self.signer))

        payload.update(dict(network_middleware=self.network_middleware or self.DEFAULT_NETWORK_MIDDLEWARE(),
                            known_nodes=self.known_nodes,
                            node_storage=self.node_storage,
                            keyring=self.keyring,
                            crypto_power_ups=self.derive_node_power_ups()))

        return payload

    def generate_filepath(self, filepath: str = None, modifier: str = None, override: bool = False) -> str:
        modifier = modifier or self.checksum_address
        filepath = super().generate_filepath(filepath=filepath, modifier=modifier, override=override)
        return filepath

    @property
    def runtime_filepaths(self) -> dict:
        filepaths = dict(config_root=self.config_root,
                         keyring_root=self.keyring_root,
                         registry_filepath=self.registry_filepath)
        return filepaths

    @classmethod
    def generate_runtime_filepaths(cls, config_root: str) -> dict:
        """Dynamically generate paths based on configuration root directory"""
        filepaths = dict(config_root=config_root,
                         config_file_location=os.path.join(config_root, cls.generate_filename()),
                         keyring_root=os.path.join(config_root, 'keyring'))
        return filepaths

    def _cache_runtime_filepaths(self) -> None:
        """Generate runtime filepaths and cache them on the config object"""
        filepaths = self.generate_runtime_filepaths(config_root=self.config_root)
        for field, filepath in filepaths.items():
            if getattr(self, field) is UNINITIALIZED_CONFIGURATION:
                setattr(self, field, filepath)

    def attach_keyring(self, checksum_address: str = None, *args, **kwargs) -> None:
        account = checksum_address or self.checksum_address
        if not account:
            raise self.ConfigurationError("No account specified to unlock keyring")
        if self.keyring is not NO_KEYRING_ATTACHED:
            if self.keyring.checksum_address != account:
                raise self.ConfigurationError("There is already a keyring attached to this configuration.")
            return
        self.keyring = NucypherKeyring(keyring_root=self.keyring_root, account=account, *args, **kwargs)

    def derive_node_power_ups(self) -> List[CryptoPowerUp]:
        power_ups = list()
        if self.is_me and not self.dev_mode:
            for power_class in self.CHARACTER_CLASS._default_crypto_powerups:
                power_up = self.keyring.derive_crypto_power(power_class)
                power_ups.append(power_up)
        return power_ups

    def initialize(self, password: str) -> str:
        """Initialize a new configuration and write installation files to disk."""

        # Development
        if self.dev_mode:
            self.__temp_dir = TemporaryDirectory(prefix=self.TEMP_CONFIGURATION_DIR_PREFIX)
            self.config_root = self.__temp_dir.name

        # Persistent
        else:
            self._ensure_config_root_exists()
            self.write_keyring(password=password)

        self._cache_runtime_filepaths()
        self.node_storage.initialize()

        # Validate
        if not self.__dev_mode:
            self.validate()

        # Success
        message = "Created nucypher installation files at {}".format(self.config_root)
        self.log.debug(message)
        return self.config_root

    def write_keyring(self, password: str, checksum_address: str = None, **generation_kwargs) -> NucypherKeyring:

        # Configure checksum address
        checksum_address = checksum_address or self.checksum_address
        if self.federated_only:
            checksum_address = FEDERATED_ADDRESS
        elif not checksum_address:
            raise self.ConfigurationError(f'No checksum address provided for decentralized configuration.')

        # Generate new keys
        self.keyring = NucypherKeyring.generate(password=password,
                                                keyring_root=self.keyring_root,
                                                checksum_address=checksum_address,
                                                **generation_kwargs)

        # In the case of a federated keyring generation,
        # the generated federated address must be set here.
        if self.federated_only:
            self.checksum_address = self.keyring.checksum_address

        return self.keyring

    @classmethod
    def load_node_storage(cls, storage_payload: dict, federated_only: bool):
        from nucypher.config.storages import NodeStorage
        node_storage_subclasses = {storage._name: storage for storage in NodeStorage.__subclasses__()}
        storage_type = storage_payload[NodeStorage._TYPE_LABEL]
        storage_class = node_storage_subclasses[storage_type]
        node_storage = storage_class.from_payload(payload=storage_payload, federated_only=federated_only)
        return node_storage
