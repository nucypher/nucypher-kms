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


import rlp
from eth_account._utils.transactions import assert_valid_fields, Transaction
from eth_utils.address import to_canonical_address
from eth_utils.applicators import apply_key_map, apply_formatters_to_dict
from eth_utils.conversions import decode_hex, to_int
from functools import wraps
from hexbytes import HexBytes
from ledgereth import Transaction as LedgerTransaction, get_account_by_path as ledger_get_account_by_path, sign_transaction as ledger_sign_transaction
from toolz.dicttoolz import dissoc
from trezorlib import ethereum
from trezorlib.client import get_default_client, TrezorClient
from trezorlib.tools import parse_path, Address, H_
from trezorlib.transport import TransportException
from typing import List, Tuple, Union
from urllib.parse import urlparse, parse_qsl
from web3 import Web3

from nucypher.blockchain.eth.decorators import validate_checksum_address
from nucypher.blockchain.eth.signers.base import Signer
from nucypher.characters.control.emitters import StdoutEmitter


def handle_trezor_call(device_func):
    """
    Decorator for calls to trezorlib that require physical device interactions.
    """
    @wraps(device_func)
    def wrapped(trezor, *args, **kwargs):
        import usb1  # may not be installable on some systems (consider CI)
        try:
            result = device_func(trezor, *args, **kwargs)
        except usb1.USBErrorNoDevice:
            error = "The client cannot communicate to the TREZOR USB device. Was it disconnected?"
            raise trezor.NoDeviceDetected(error)
        except usb1.USBErrorBusy:
            raise trezor.DeviceError("The TREZOR USB device is busy.")
        else:
            return result

    return wrapped


class TrezorSigner(Signer):
    """A trezor message and transaction signing client."""

    # BIP44 HD derivation paths
    # https://wiki.trezor.io/Cryptocurrency_standards#bip44
    # https://wiki.trezor.io/Cryptocurrency_standards#slip44

    __BIP_44 = 44
    __ETH_COIN_TYPE = 60     # mainnet
    __TESTNET_COIN_TYPE = 1  # all testnets

    _COIN_TYPE = None  # set in __init__
    _CHAIN_ID = 0
    _DEFAULT_ACCOUNT = 0

    # Cache
    DEFAULT_ACCOUNT_INDEX = 0
    ADDRESS_CACHE_SIZE = 10  # default number of accounts to derive and internally track

    class DeviceError(Exception):
        """Base exception for trezor signing API"""

    class NoDeviceDetected(DeviceError):
        """Raised when an operation requires a device but none are available"""

    def __init__(self, testnet: bool = False):
        self.__client = self._open()
        self._device_id = self.__client.get_device_id()
        self.testnet = testnet     # SLIP44 testnet support for EIP-155 sigatures
        self.__addresses = dict()  # track derived addresses
        self.__cache_addresses()

    @property
    def derivation_root(self) -> str:
        # m/44'/60'/0'/0/x  Mainnet
        # m/44'/1'/0'/0/x   Testnet
        coin_type = self.__TESTNET_COIN_TYPE if self.testnet else self.__ETH_COIN_TYPE
        path = f"{self.__BIP_44}'/{coin_type}'/{self._DEFAULT_ACCOUNT}'/{self._CHAIN_ID}"
        return path

    @handle_trezor_call
    def _open(self) -> TrezorClient:
        try:
            client = get_default_client()
        except TransportException:
            raise self.NoDeviceDetected("Could not find a TREZOR device to connect to. "
                                        "Is it connected and unlocked?")
        return client

    @classmethod
    def uri_scheme(cls) -> str:
        return 'trezor'

    #
    # Internal
    #

    def __get_address_path(self, index: int = None, checksum_address: str = None) -> List[H_]:
        """Resolves a checksum address into an HD path and returns it."""
        if index is not None and checksum_address:
            raise ValueError("Expected index or checksum address; Got both.")
        elif index is not None:
            hd_path = parse_path(f"{self.derivation_root}/{index}")
        else:
            try:
                hd_path = self.__addresses[checksum_address]
            except KeyError:
                raise RuntimeError(f"{checksum_address} was not loaded into the device address cache.")
        return hd_path

    @handle_trezor_call
    def __derive_account(self, index: int = None, hd_path: Address = None) -> str:
        """Resolves a trezorlib HD path into a checksum address and returns it."""
        if not hd_path:
            if index is None:
                raise ValueError("No index or HD path supplied.")  # TODO: better error handling here
            hd_path = self.__get_address_path(index=index)
        address = ethereum.get_address(client=self.__client, n=hd_path, show_display=False)  # TODO: show display?
        return address

    def __cache_addresses(self) -> None:
        """
        Derives trezor ethereum addresses up to ADDRESS_CACHE_SIZE relative to
        the calculated base path and internally caches them for later use.
        """
        emitter = StdoutEmitter()
        for index in range(self.ADDRESS_CACHE_SIZE):
            hd_path = self.__get_address_path(index=index)
            address = self.__derive_account(hd_path=hd_path)
            self.__addresses[address] = hd_path
            message = f"Derived {address} ({self.derivation_root}/{index})"
            emitter.message(message)

    @staticmethod
    def _format_transaction(transaction_dict: dict) -> dict:
        """
        Handle Web3.py -> Trezor native transaction field formatting (non-mutative)
        # https://web3py.readthedocs.io/en/latest/web3.eth.html#web3.eth.Eth.sendRawTransaction
        """
        assert_valid_fields(transaction_dict)
        trezor_transaction_keys = {'gas': 'gas_limit', 'gasPrice': 'gas_price', 'chainId': 'chain_id'}
        trezor_transaction = dict(apply_key_map(trezor_transaction_keys, transaction_dict))
        return trezor_transaction

    @handle_trezor_call
    def __sign_transaction(self, n: List[int], trezor_transaction: dict) -> Tuple[bytes, bytes, bytes]:
        """Internal wrapper for trezorlib transaction signing calls"""
        v, r, s = ethereum.sign_tx(client=self.__client, n=n, **trezor_transaction)
        return v, r, s

    #
    # Trezor Signer API
    #

    @classmethod
    def from_signer_uri(cls, uri: str, testnet: bool = False) -> 'TrezorSigner':
        """Return a trezor signer from URI string i.e. trezor:///my/trezor/path """
        if uri != cls.uri_scheme():  # TODO: #2269 Support "rich URIs" for trezors
            raise cls.InvalidSignerURI(f'{uri} is not a valid trezor URI scheme')
        return cls(testnet=testnet)

    def is_device(self, account: str) -> bool:
        """Trezor is always a device."""
        return True

    @validate_checksum_address
    def unlock_account(self, account: str, password: str, duration: int = None) -> bool:
        """Defer account unlocking to the trezor, do not indicate application level unlocking logic."""
        return True

    @validate_checksum_address
    def lock_account(self, account: str) -> bool:
        """Defer account locking to the trezor, do not indicate application level unlocking logic."""
        return True

    @property
    def accounts(self) -> List[str]:
        """Returns a list of cached trezor checksum addresses from initial derivation."""
        return list(self.__addresses.keys())

    @handle_trezor_call
    def sign_message(self, message: bytes, checksum_address: str) -> HexBytes:
        """
        Signs a message via the TREZOR ethereum sign_message API and returns
        a named tuple containing the signature and the address used to sign it.
        This method requires interaction between the TREZOR and the user.
        """
        # TODO: #2262 Implement Trezor Message Signing
        hd_path = self.__get_address_path(checksum_address=checksum_address)
        signed_message = ethereum.sign_message(self.__client, hd_path, message)
        return HexBytes(signed_message.signature)

    def sign_transaction(self,
                         transaction_dict: dict,
                         rlp_encoded: bool = True
                         ) -> Union[HexBytes, Transaction]:
        """
        Sign a transaction with a trezor hardware wallet.

        This non-mutative method handles transaction validation, field formatting, signing,
        and outgoing serialization.  Accepts a standard transaction dictionary as input,
        and produces an RLP encoded raw signed transaction by default.

        Internally the standard transaction dictionary is reformatted for trezor API consumption
        via calls `trezorlib.client.ethereum.sign_tx`.

        WARNING: This function returns a raw signed transaction which can be
        broadcast by anyone with a connection to the ethereum network.

        ***Treat pre-signed raw transactions produced by this function like money.***

        """

        # Eager enforcement of EIP-155
        # https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md
        #
        # Leave the chain ID in tact for the trezor signing request so that an EIP-155 transaction signature will be applied
        # https://github.com/trezor/trezor-core/pull/311
        if 'chainId' not in transaction_dict:
            raise self.SignerError('Invalid EIP-155 transaction - "chain_id" field is missing in trezor signing request.')

        # Consume the sender inside the transaction request's 'from field.
        try:
            sender_address = transaction_dict['from']
        except KeyError:
            raise self.SignerError("'from' field is missing from trezor signing request.")
        transaction_dict = dissoc(transaction_dict, 'from')

        # Format contract data field for both trezor and eth_account's Transaction
        formatters = {'data': lambda data: Web3.toBytes(HexBytes(data))}
        transaction_dict = dict(apply_formatters_to_dict(formatters, transaction_dict))

        # Format transaction fields for Trezor, Lookup HD path
        trezor_transaction = self._format_transaction(transaction_dict=transaction_dict)

        # Note that the derivation path on the trezor must correlate with the chain id
        # in the transaction. Since Trezor firmware version 2.3.1 mismatched chain_id
        # and derivation path will fail to sign with 'forbidden key path'.
        # https://github.com/trezor/trezor-firmware/issues/1050#issuecomment-640718622
        hd_path = self.__get_address_path(checksum_address=sender_address)  # from cache

        # Trezor signing request
        _v, _r, _s = self.__sign_transaction(n=hd_path, trezor_transaction=trezor_transaction)

        # Create RLP serializable Transaction instance with eth_account
        # chainId is not longer needed since it can later be derived from v
        transaction_dict = dissoc(transaction_dict, 'chainId')

        # 'to' may be blank if this transaction is contract creation
        formatters = {'to': to_canonical_address}
        transaction_dict = dict(apply_formatters_to_dict(formatters, transaction_dict))

        signed_transaction = Transaction(v=to_int(_v),  # type: int
                                         r=to_int(_r),  # bytes -> int
                                         s=to_int(_s),  # bytes -> int
                                         **transaction_dict)

        # Optionally encode as RLP for broadcasting
        if rlp_encoded:
            signed_transaction = HexBytes(rlp.encode(signed_transaction))
        return signed_transaction


class HardwareSigner(Signer):
    """
    Common base class mixin for hardware wallets in general
    """
    def is_device(self, account: str) -> bool:
        """Ledger is always a device."""
        return True

    @validate_checksum_address
    def unlock_account(self, account: str, password: str, duration: int = None) -> bool:
        """Defer account unlocking to the ledger, do not indicate application level unlocking logic."""
        return True

    @validate_checksum_address
    def lock_account(self, account: str) -> bool:
        """Defer account locking to the ledger, do not indicate application level unlocking logic."""
        return True


# Fixup path regex in ledgereth to allow test derivation paths
import ledgereth.utils
ledgereth.utils.BIP32_ETH_PATTERN = r"^44'/(1|60)'/[0-9]+'(/[0-9]+){2}$"
ledgereth.utils.BIP32_LEGACY_LEDGER_PATTERN = r"^44'/(1|60)'/[0-9]+'/[0-9]+$"


class LedgerSigner(HardwareSigner):
    """A ledger message and transaction signing client."""

    __BIP44_TEST = "44'/1'/"
    __BIP44_ETH = "44'/60'/"
    __CHAIN_ID_MAINNET = 1
    __CHAIN_ID_ROPSTEN = 3
    __CHAIN_ID_RINKEBY = 4
    __CHAIN_ID_GOERLI = 5
    __CHAIN_ID_KOVAN = 42

    def __init__(self, testnet: bool = False, count: int = 1, legacy: bool = False, path: str = None):
        self.__addresses = dict()
        self.__testnet = testnet

        emitter = StdoutEmitter()
        paths = (path,) if path else self.__get_paths(testnet, count, legacy)

        for item in paths:
            acct = ledger_get_account_by_path(item)
            self.__addresses[acct.address] = acct
            if testnet and acct.path.startswith(self.__BIP44_ETH):
                raise self.SignerError(f'cannot use production path/account in testnet: {acct.path}/{acct.address}')
            if not testnet and acct.path.startswith(self.__BIP44_TEST):
                raise self.SignerError(f'cannot use testnet path/account in production: {acct.path}/{acct.address}')
            emitter.message(f"Derived {acct.address} ({acct.path})")

    @classmethod
    def uri_scheme(cls) -> str:
        return 'ledger'

    #
    # Internal
    #

    @classmethod
    def __get_paths(cls, testnet: bool, count: int, legacy: bool):
        head = cls.__BIP44_TEST if testnet else cls.__BIP44_ETH
        tail = "0'/{idx:}" if legacy else "{idx:}'/0/0"
        path = head + tail
        return tuple(path.format(idx=i) for i in range(count))

    #
    # Ledger Signer API
    #

    @classmethod
    def from_signer_uri(cls, uri: str, testnet: bool = False) -> 'TrezorSigner':
        """
        Return a ledger signer from URI string (ledger:[path]?count=N&legacy)

        - For the first account using the current ledger live derivation path:
            "ledger"                    "ledger:///"
            "ledger:"                   "ledger?legacy=0"
            "ledger:/"                  "ledger?legacy=no"
            "ledger://"                 "ledger?legacy=false"

        - For the first account using the legacy ledger derivation path:
            "ledger?legacy"             "ledger:///?legacy"
            "ledger:?legacy"            "ledger?legacy=1"
            "ledger:/?legacy"           "ledger?legacy=yes"
            "ledger://?legacy"          "ledger?legacy=true"

        - For additional accounts, specify count as well:
            "ledger:?count=N"           "ledger:?count=N&legacy"

        - You can also specify an explicit path (leading slashes are stripped):
            "ledger:44'/60'/99'/0/0"    "ledger:/44'/1'/99'/0"
        """
        decoded_uri = urlparse(uri)

        scheme = decoded_uri.scheme
        path = decoded_uri.netloc + decoded_uri.path
        path = path.lstrip('/')

        if not scheme:
            scheme = path
            path = None

        if scheme != cls.uri_scheme():
            raise cls.InvalidSignerURI(f'{uri} is not a valid ledger URI')

        legacy = False
        count = 1

        if not path:
            for key, val in parse_qsl(decoded_uri.query, keep_blank_values=True):
                if key == 'legacy':
                    if val.lower() in ('0', 'n', 'no', 'f', 'false'):
                        legacy = False
                    elif val.lower() in ('', '1', 'y', 'yes', 't', 'true'):
                        legacy = True
                    else:
                        raise cls.InvalidSignerURI(f'{uri} is not a valid ledger URI: invalid legacy value {val}')
                elif key == 'count':
                    try:
                        count = int(val)
                    except ValueError as exc:
                        raise cls.InvalidSignerURI(f'{uri} is not a valid ledger URI: invalid count value {exc}')
                else:
                    raise cls.InvalidSignerURI(f'{uri} is not a valid ledger URI: unknown parameter {key}')

        return cls(testnet=testnet, path=path, count=count, legacy=legacy)

    @property
    def accounts(self) -> List[str]:
        """Returns a list of cached ledger checksum addresses from initial derivation."""
        return list(self.__addresses.keys())

    def sign_message(self, message: bytes, checksum_address: str) -> HexBytes:
        """
        Signs a message with a ledger hardware wallet.
        """
        raise self.SignerError('message signing not implemented')

    def __sanity_check_chain_id(self, chain_id: int):
        if not self.__testnet and chain_id != self.__CHAIN_ID_MAINNET:
            raise self.SignerError(f'invalid chain id {chain_id} for mainnet.')

        if self.__testnet and chain_id not in (
            self.__CHAIN_ID_ROPSTEN,
            self.__CHAIN_ID_RINKEBY,
            self.__CHAIN_ID_GOERLI,
            self.__CHAIN_ID_KOVAN,
        ):
            raise self.SignerError(f'invalid chain id {chain_id} for testnet.')

    def sign_transaction(self,
                         transaction_dict: dict,
                         rlp_encoded: bool = True
                         ) -> Union[HexBytes, Transaction]:
        """
        Sign a transaction with a ledger hardware wallet.
        """
        try:
            self.__sanity_check_chain_id(transaction_dict['chainId'])
        except KeyError:
            raise self.SignerError('"chain_id" field is missing in ledger signing request.')

        try:
            sender_address = transaction_dict['from']
        except KeyError:
            raise self.SignerError("'from' field is missing from ledger signing request.")

        try:
            sender_acct = self.__addresses[sender_address]
        except KeyError:
            raise self.SignerError(f"{checksum_address} was not loaded into the device address cache.")

        ledger_tx = LedgerTransaction(
            nonce=transaction_dict['nonce'],
            gasprice=transaction_dict['gasPrice'],
            startgas=transaction_dict['gas'],
            to=to_canonical_address(transaction_dict['to']),
            value=transaction_dict['value'],
            data=decode_hex(transaction_dict['data']),
        )

        stx = ledger_sign_transaction(tx=ledger_tx, sender_path=sender_acct.path)

        if rlp_encoded:
            return HexBytes(stx.raw_transaction())

        return Transaction(v=stx.v, r=stx.r, s=stx.s, **stx)
