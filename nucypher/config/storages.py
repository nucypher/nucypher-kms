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

import OpenSSL
import binascii
import os
import tempfile
from abc import ABC, abstractmethod

from bytestring_splitter import BytestringSplittingError
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate, NameOID
from eth_utils import is_checksum_address
from typing import Any, Callable, Set, Tuple, Union

from nucypher.acumen.nicknames import Nickname
from nucypher.blockchain.eth.decorators import validate_checksum_address
from nucypher.blockchain.eth.registry import BaseContractRegistry
from nucypher.config.constants import DEFAULT_CONFIG_ROOT
from nucypher.crypto.api import read_certificate_pseudonym, MissingCertificatePseudonym
from nucypher.utilities.logging import Logger


class NodeStorage(ABC):
    _name = NotImplemented
    _TYPE_LABEL = 'storage_type'

    TLS_CERTIFICATE_ENCODING = Encoding.PEM
    TLS_CERTIFICATE_EXTENSION = '.{}'.format(TLS_CERTIFICATE_ENCODING.name.lower())

    class NodeStorageError(Exception):
        pass

    class UnknownNode(NodeStorageError):
        pass

    def __init__(self,
                 federated_only: bool,  # TODO# 466
                 character_class=None,
                 registry: BaseContractRegistry = None,
                 ) -> None:

        from nucypher.characters.lawful import Ursula

        self.log = Logger(self.__class__.__name__)
        self.registry = registry
        self.federated_only = federated_only
        self.character_class = character_class or Ursula

    def __getitem__(self, item):
        return self.get(checksum_address=item, federated_only=self.federated_only)

    def __setitem__(self, key, value):
        return self.store_node_metadata(node=value)

    def __delitem__(self, key):
        self.remove(checksum_address=key)

    def __iter__(self):
        return self.all(federated_only=self.federated_only)

    @property
    @abstractmethod
    def source(self) -> str:
        """Human readable source string"""
        return NotImplemented

    def encode_node_bytes(self, node_bytes):
        return binascii.hexlify(node_bytes)

    def decode_node_bytes(self, encoded_node) -> bytes:
        return binascii.unhexlify(encoded_node)

    def _read_common_name(self, certificate: Certificate):
        x509 = OpenSSL.crypto.X509.from_cryptography(certificate)
        subject_components = x509.get_subject().get_components()
        common_name_as_bytes = subject_components[0][1]
        common_name_from_cert = common_name_as_bytes.decode()
        return common_name_from_cert

    def _write_tls_certificate(self,
                               certificate: Certificate,
                               host: str = None,
                               force: bool = True) -> str:

        # Read
        x509 = OpenSSL.crypto.X509.from_cryptography(certificate)
        subject_components = x509.get_subject().get_components()
        common_name_as_bytes = subject_components[0][1]
        common_name_on_certificate = common_name_as_bytes.decode()
        if not host:
            host = common_name_on_certificate

        try:
            pseudonym = certificate.subject.get_attributes_for_oid(NameOID.PSEUDONYM)[0]
        except IndexError:
            raise MissingCertificatePseudonym(f"Missing checksum address on certificate for host '{host}'. "
                                         f"Does this certificate belong to an Ursula?")
        else:
            checksum_address = pseudonym.value

        if not is_checksum_address(checksum_address):
            raise MissingCertificatePseudonym("Invalid certificate wallet address encountered: {}".format(checksum_address))

        # Validate
        # TODO: It's better for us to have checked this a while ago so that this situation is impossible.  #443
        if host and (host != common_name_on_certificate):
            raise ValueError(f"You passed a hostname ('{host}') that does not match the certificate's common name.")

        certificate_filepath = self.generate_certificate_filepath(checksum_address=checksum_address)
        certificate_already_exists = os.path.isfile(certificate_filepath)
        if force is False and certificate_already_exists:
            raise FileExistsError('A TLS certificate already exists at {}.'.format(certificate_filepath))

        # Write
        os.makedirs(os.path.dirname(certificate_filepath), exist_ok=True)
        with open(certificate_filepath, 'wb') as certificate_file:
            public_pem_bytes = certificate.public_bytes(self.TLS_CERTIFICATE_ENCODING)
            certificate_file.write(public_pem_bytes)

        nickname = Nickname.from_seed(checksum_address)
        self.log.debug(f"Saved TLS certificate for {nickname} {checksum_address}: {certificate_filepath}")

        return certificate_filepath

    @abstractmethod
    def store_node_certificate(self, certificate: Certificate) -> str:
        raise NotImplementedError

    @abstractmethod
    def store_node_metadata(self, node, filepath: str = None) -> str:
        """Save a single node's metadata and tls certificate"""
        raise NotImplementedError

    @abstractmethod
    def generate_certificate_filepath(self, checksum_address: str) -> str:
        raise NotImplementedError

    @abstractmethod
    def payload(self) -> dict:
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def from_payload(self, data: dict, *args, **kwargs) -> 'NodeStorage':
        """Instantiate a storage object from a dictionary"""
        raise NotImplementedError

    @abstractmethod
    def initialize(self):
        """One-time initialization steps to establish a node storage backend"""
        raise NotImplementedError

    @abstractmethod
    def all(self, federated_only: bool, certificates_only: bool = False) -> set:
        """Return s set of all stored nodes"""
        raise NotImplementedError

    @abstractmethod
    def get(self, checksum_address: str, federated_only: bool):
        """Retrieve a single stored node"""
        raise NotImplementedError

    @abstractmethod
    def remove(self, checksum_address: str) -> bool:
        """Remove a single stored node"""
        raise NotImplementedError

    @abstractmethod
    def clear(self) -> bool:
        """Remove all stored nodes"""
        raise NotImplementedError


class ForgetfulNodeStorage(NodeStorage):
    _name = ':memory:'
    __base_prefix = "nucypher-tmp-certs-"

    def __init__(self, parent_dir: str = None, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.__metadata = dict()

        # Certificates
        self.__certificates = dict()
        self.__temporary_certificates = list()
        self._temp_certificates_dir = tempfile.mkdtemp(prefix=self.__base_prefix, dir=parent_dir)

    @property
    def source(self) -> str:
        """Human readable source string"""
        return self._name

    def all(self, federated_only: bool, certificates_only: bool = False) -> set:
        return set(self.__certificates.values() if certificates_only else self.__metadata.values())

    @validate_checksum_address
    def get(self,
            federated_only: bool,
            host: str = None,
            checksum_address: str = None,
            certificate_only: bool = False):

        if not bool(checksum_address) ^ bool(host):
            message = "Either pass checksum_address or host; Not both. Got ({} {})".format(checksum_address, host)
            raise ValueError(message)

        if certificate_only is True:
            try:
                return self.__certificates[checksum_address or host]
            except KeyError:
                raise self.UnknownNode
        else:
            try:
                return self.__metadata[checksum_address or host]
            except KeyError:
                raise self.UnknownNode

    def forget(self) -> bool:
        for temp_certificate in self.__temporary_certificates:
            os.remove(temp_certificate)
        return len(self.__temporary_certificates) == 0

    def store_node_certificate(self, certificate: Certificate):
        checksum_address = read_certificate_pseudonym(certificate=certificate)
        self.__certificates[checksum_address] = certificate
        filepath = self._write_tls_certificate(certificate=certificate)
        return filepath

    def store_node_metadata(self, node, filepath: str = None):
        self.__metadata[node.checksum_address] = node
        return self.__metadata[node.checksum_address]

    @validate_checksum_address
    def generate_certificate_filepath(self, checksum_address: str) -> str:
        filename = '{}.pem'.format(checksum_address)
        filepath = os.path.join(self._temp_certificates_dir, filename)
        return filepath

    @validate_checksum_address
    def remove(self,
               checksum_address: str,
               metadata: bool = True,
               certificate: bool = True
               ) -> Tuple[bool, str]:

        if metadata is True:
            del self.__metadata[checksum_address]
        if certificate is True:
            del self.__certificates[checksum_address]
        return True, checksum_address

    def clear(self, metadata: bool = True, certificates: bool = True) -> None:
        """Forget all stored nodes and certificates"""
        if metadata is True:
            self.__metadata = dict()
        if certificates is True:
            self.__certificates = dict()

    def payload(self) -> dict:
        payload = {self._TYPE_LABEL: self._name}
        return payload

    @classmethod
    def from_payload(cls, payload: dict, *args, **kwargs) -> 'ForgetfulNodeStorage':
        """Alternate constructor to create a storage instance from JSON-like configuration"""
        if payload[cls._TYPE_LABEL] != cls._name:
            raise cls.NodeStorageError
        return cls(*args, **kwargs)

    def initialize(self):
        self.__metadata = dict()
        self.__certificates = dict()


class LocalFileBasedNodeStorage(NodeStorage):
    _name = 'local'
    __METADATA_FILENAME_TEMPLATE = '{}.node'

    class NoNodeMetadataFileFound(FileNotFoundError, NodeStorage.UnknownNode):
        pass

    class InvalidNodeMetadata(NodeStorage.NodeStorageError):
        """Node metadata is corrupt or not possible to parse"""

    def __init__(self,
                 config_root: str = None,
                 storage_root: str = None,
                 metadata_dir: str = None,
                 certificates_dir: str = None,
                 *args, **kwargs
                 ) -> None:

        super().__init__(*args, **kwargs)
        self.log = Logger(self.__class__.__name__)

        self.root_dir = storage_root
        self.metadata_dir = metadata_dir
        self.certificates_dir = certificates_dir
        self._cache_storage_filepaths(config_root=config_root)

    @property
    def source(self) -> str:
        """Human readable source string"""
        return self.root_dir

    def encode_node_bytes(self, node_bytes) -> bytes:
        return node_bytes

    def decode_node_bytes(self, encoded_node) -> bytes:
        return encoded_node

    @staticmethod
    def _generate_storage_filepaths(config_root: str = None,
                                    storage_root: str = None,
                                    metadata_dir: str = None,
                                    certificates_dir: str = None):

        storage_root = storage_root or os.path.join(config_root or DEFAULT_CONFIG_ROOT, 'known_nodes')
        metadata_dir = metadata_dir or os.path.join(storage_root, 'metadata')
        certificates_dir = certificates_dir or os.path.join(storage_root, 'certificates')

        payload = {'storage_root': storage_root,
                   'metadata_dir': metadata_dir,
                   'certificates_dir': certificates_dir}

        return payload

    def _cache_storage_filepaths(self, config_root: str = None):
        filepaths = self._generate_storage_filepaths(config_root=config_root,
                                                     storage_root=self.root_dir,
                                                     metadata_dir=self.metadata_dir,
                                                     certificates_dir=self.certificates_dir)
        self.root_dir = filepaths['storage_root']
        self.metadata_dir = filepaths['metadata_dir']
        self.certificates_dir = filepaths['certificates_dir']

    #
    # Certificates
    #

    @validate_checksum_address
    def __get_certificate_filename(self, checksum_address: str):
        return '{}.{}'.format(checksum_address, Encoding.PEM.name.lower())

    def __get_certificate_filepath(self, certificate_filename: str) -> str:
        return os.path.join(self.certificates_dir, certificate_filename)

    @validate_checksum_address
    def generate_certificate_filepath(self, checksum_address: str) -> str:
        certificate_filename = self.__get_certificate_filename(checksum_address)
        certificate_filepath = self.__get_certificate_filepath(certificate_filename=certificate_filename)
        return certificate_filepath

    @validate_checksum_address
    def __read_node_tls_certificate(self, filepath: str = None, checksum_address: str = None) -> Certificate:
        """Deserialize an X509 certificate from a filepath"""
        if not bool(filepath) ^ bool(checksum_address):
            raise ValueError("Either pass filepath or checksum_address; Not both.")

        if not filepath and checksum_address is not None:
            filepath = self.generate_certificate_filepath(checksum_address)

        try:
            with open(filepath, 'rb') as certificate_file:
                certificate = x509.load_pem_x509_certificate(certificate_file.read(), backend=default_backend())
                # Sanity check:
                # Validate the checksum address inside the cert as a consistency check against
                # nodes that may have been altered on the disk somehow.
                read_certificate_pseudonym(certificate=certificate)
                return certificate
        except FileNotFoundError:
            raise FileNotFoundError("No SSL certificate found at {}".format(filepath))

    #
    # Metadata
    #

    @validate_checksum_address
    def __generate_metadata_filepath(self, checksum_address: str, metadata_dir: str = None) -> str:
        metadata_path = os.path.join(metadata_dir or self.metadata_dir,
                                     self.__METADATA_FILENAME_TEMPLATE.format(checksum_address))
        return metadata_path

    def __read_metadata(self, filepath: str):

        from nucypher.characters.lawful import Ursula

        try:
            with open(filepath, "rb") as seed_file:
                seed_file.seek(0)
                node_bytes = self.decode_node_bytes(seed_file.read())
                node = Ursula.from_bytes(node_bytes, fail_fast=True)
        except FileNotFoundError:
            raise self.NoNodeMetadataFileFound
        except (BytestringSplittingError, Ursula.UnexpectedVersion):
            raise self.InvalidNodeMetadata

        return node

    def __write_metadata(self, filepath: str, node):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "wb") as f:
            f.write(self.encode_node_bytes(bytes(node)))
        self.log.info("Wrote new node metadata to filesystem {}".format(filepath))
        return filepath

    #
    # API
    #
    def all(self, federated_only: bool, certificates_only: bool = False) -> Set[Union[Any, Certificate]]:
        filenames = os.listdir(self.certificates_dir if certificates_only else self.metadata_dir)
        self.log.info("Found {} known node metadata files at {}".format(len(filenames), self.metadata_dir))

        known_certificates = set()
        if certificates_only:
            for filename in filenames:
                certificate = self.__read_node_tls_certificate(os.path.join(self.certificates_dir, filename))
                known_certificates.add(certificate)
            return known_certificates

        else:
            known_nodes = set()
            invalid_metadata = []
            for filename in filenames:
                metadata_path = os.path.join(self.metadata_dir, filename)
                try:
                    node = self.__read_metadata(filepath=metadata_path)
                except self.NodeStorageError:
                    invalid_metadata.append(filename)
                else:
                    known_nodes.add(node)

            if invalid_metadata:
                self.log.warn(f"Couldn't read metadata in {self.metadata_dir} for the following files: {invalid_metadata}")
            return known_nodes

    @validate_checksum_address
    def get(self, checksum_address: str, federated_only: bool, certificate_only: bool = False):
        if certificate_only is True:
            certificate = self.__read_node_tls_certificate(checksum_address=checksum_address)
            return certificate
        metadata_path = self.__generate_metadata_filepath(checksum_address=checksum_address)
        node = self.__read_metadata(filepath=metadata_path)
        return node

    def store_node_certificate(self, certificate: Certificate, force: bool = True):
        certificate_filepath = self._write_tls_certificate(certificate=certificate, force=force)
        return certificate_filepath

    def store_node_metadata(self, node, filepath: str = None) -> str:
        address = node.checksum_address
        filepath = self.__generate_metadata_filepath(checksum_address=address, metadata_dir=filepath)
        self.__write_metadata(filepath=filepath, node=node)
        return filepath

    @validate_checksum_address
    def remove(self, checksum_address: str, metadata: bool = True, certificate: bool = True) -> None:

        if metadata is True:
            metadata_filepath = self.__generate_metadata_filepath(checksum_address=checksum_address)
            os.remove(metadata_filepath)
            self.log.debug("Deleted {} from the filesystem".format(checksum_address))

        if certificate is True:
            certificate_filepath = self.generate_certificate_filepath(checksum_address=checksum_address)
            os.remove(certificate_filepath)
            self.log.debug("Deleted {} from the filesystem".format(checksum_address))

        return

    def clear(self, metadata: bool = True, certificates: bool = True) -> None:
        """Forget all stored nodes and certificates"""

        def __destroy_dir_contents(path) -> None:
            try:
                paths_to_remove = os.listdir(path)
            except FileNotFoundError:
                return
            else:
                for file in paths_to_remove:
                    file_path = os.path.join(path, file)
                    if os.path.isfile(file_path):
                        os.unlink(file_path)

        if metadata is True:
            __destroy_dir_contents(self.metadata_dir)
        if certificates is True:
            __destroy_dir_contents(self.certificates_dir)

        return

    def payload(self) -> dict:
        payload = {
            'storage_type': self._name,
            'storage_root': self.root_dir,
            'metadata_dir': self.metadata_dir,
            'certificates_dir': self.certificates_dir
        }
        return payload

    @classmethod
    def from_payload(cls, payload: dict, *args, **kwargs) -> 'LocalFileBasedNodeStorage':
        storage_type = payload[cls._TYPE_LABEL]
        if not storage_type == cls._name:
            raise cls.NodeStorageError("Wrong storage type. got {}".format(storage_type))
        del payload['storage_type']

        return cls(*args, **payload, **kwargs)

    def initialize(self):
        storage_dirs = (self.root_dir, self.metadata_dir, self.certificates_dir)
        for storage_dir in storage_dirs:
            try:
                os.mkdir(storage_dir, mode=0o755)
            except FileExistsError:
                message = "There are pre-existing files at {}".format(self.root_dir)
                self.log.info(message)
            except FileNotFoundError:
                raise self.NodeStorageError("There is no existing configuration at {}".format(self.root_dir))


class TemporaryFileBasedNodeStorage(LocalFileBasedNodeStorage):
    _name = 'tmp'

    def __init__(self, *args, **kwargs):
        self.__temp_metadata_dir = None
        self.__temp_certificates_dir = None
        self.__temp_root_dir = None
        super().__init__(metadata_dir=self.__temp_metadata_dir,
                         certificates_dir=self.__temp_certificates_dir,
                         storage_root=self.__temp_root_dir,
                         *args, **kwargs)

    # TODO: Pending fix for 1554.
    # def __del__(self):
    #     if self.__temp_metadata_dir is not None:
    #         shutil.rmtree(self.__temp_metadata_dir, ignore_errors=True)
    #         shutil.rmtree(self.__temp_certificates_dir, ignore_errors=True)

    def initialize(self):
        # Root
        self.__temp_root_dir = tempfile.mkdtemp(prefix="nucypher-tmp-nodes-")
        self.root_dir = self.__temp_root_dir

        # Metadata
        self.__temp_metadata_dir = str(Path(self.__temp_root_dir) / "metadata")
        self.metadata_dir = self.__temp_metadata_dir

        # Certificates
        self.__temp_certificates_dir = str(Path(self.__temp_root_dir) / "certs")
        self.certificates_dir = self.__temp_certificates_dir
