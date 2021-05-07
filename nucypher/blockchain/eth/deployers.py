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


from collections import OrderedDict

from constant_sorrow.constants import (
    BARE,
    CONTRACT_NOT_DEPLOYED,
    FULL,
    IDLE,
    INIT
)
from eth_typing.evm import ChecksumAddress
from typing import Dict, List, Tuple
from web3.contract import Contract

from nucypher.blockchain.economics import BaseEconomics, StandardTokenEconomics
from nucypher.blockchain.eth.agents import (
    AdjudicatorAgent,
    ContractAgency,
    EthereumContractAgent,
    MultiSigAgent,
    NucypherTokenAgent,
    PolicyManagerAgent,
    StakingEscrowAgent,
    WorkLockAgent
)
from nucypher.blockchain.eth.constants import DISPATCHER_CONTRACT_NAME, NULL_ADDRESS, STAKING_ESCROW_CONTRACT_NAME
from nucypher.blockchain.eth.interfaces import (
    BlockchainDeployerInterface,
    BlockchainInterfaceFactory,
    VersionedContract,
)
from nucypher.blockchain.eth.registry import BaseContractRegistry
from nucypher.crypto.powers import TransactingPower


class BaseContractDeployer:

    _interface_class = BlockchainDeployerInterface

    agency = NotImplemented
    contract_name = NotImplemented
    deployment_steps = NotImplemented

    _upgradeable = NotImplemented
    _ownable = NotImplemented
    _proxy_deployer = NotImplemented

    can_be_idle = False

    class ContractDeploymentError(Exception):
        pass

    class ContractNotDeployed(ContractDeploymentError):
        pass

    def __init__(self, registry: BaseContractRegistry, economics: BaseEconomics = None):

        # Validate
        self.blockchain = BlockchainInterfaceFactory.get_interface()
        if not isinstance(self.blockchain, BlockchainDeployerInterface):
            raise ValueError("No deployer interface connection available.")

        # Defaults
        self.registry = registry
        self.deployment_receipts = OrderedDict()
        self._contract = CONTRACT_NOT_DEPLOYED
        self.__proxy_contract = NotImplemented
        self.__economics = economics or StandardTokenEconomics()

    @property
    def economics(self) -> BaseEconomics:
        """Read-only access for economics instance."""
        return self.__economics

    @property
    def contract_address(self) -> str:
        if self._contract is CONTRACT_NOT_DEPLOYED:
            raise self.ContractNotDeployed(self.contract_name)
        address = self._contract.address  # type: str
        return address

    @property
    def contract(self):
        return self._contract

    @property
    def dispatcher(self):
        return self.__proxy_contract

    def is_deployed(self, contract_version: str = None) -> bool:
        try:
            self.registry.search(contract_name=self.contract_name, contract_version=contract_version)
        except (BaseContractRegistry.UnknownContract, BaseContractRegistry.NoRegistry):
            return False
        else:
            return True

    def check_deployment_readiness(self,
                                   deployer_address: ChecksumAddress,
                                   contract_version: str = None,
                                   ignore_deployed=False,
                                   fail=True,
                                   additional_rules: List[Tuple[bool, str]] = None,
                                   ) -> Tuple[bool, list]:
        """
        Iterates through a set of rules required for an ethereum
        contract deployer to be eligible for deployment returning a
        tuple or raising an exception if <fail> is True.

        Returns a tuple containing the boolean readiness result and a list of reasons (if any)
        why the deployer is not ready.

        If fail is set to True, raise a configuration error, instead of returning.
        """

        if not ignore_deployed and contract_version is not None:
            contract_version, _data = self.blockchain.find_raw_contract_data(contract_name=self.contract_name,
                                                                             requested_version=contract_version)

        # Compile rules
        rules = [
            (ignore_deployed or not self.is_deployed(contract_version),
             f'Contract {self.contract_name}:{contract_version} already deployed'),
        ]
        if additional_rules:
            rules.extend(additional_rules)

        disqualifications = list()
        for rule_is_satisfied, failure_reason in rules:
            if not rule_is_satisfied:                      # If this rule fails...
                if fail:
                    raise self.ContractDeploymentError(failure_reason)
                disqualifications.append(failure_reason)   # ... here's why

        is_ready = len(disqualifications) == 0
        return is_ready, disqualifications

    def deploy(self,
               transacting_power: TransactingPower,
               deployment_mode=FULL,
               gas_limit: int = None,
               progress: int = None,
               emitter=None,
               **overrides) -> dict:
        """
        Provides for the setup, deployment, and initialization of ethereum smart contracts.
        Emits the configured blockchain network transactions for single contract instance publication.
        """
        raise NotImplementedError

    def make_agent(self) -> EthereumContractAgent:
        agent = self.agency(registry=self.registry, contract=self._contract)
        return agent

    def get_latest_enrollment(self) -> VersionedContract:
        """Get the latest enrolled, bare version of the contract from the registry."""
        contract = self.blockchain.get_contract_by_name(contract_name=self.contract_name,
                                                        registry=self.registry,
                                                        use_proxy_address=False,
                                                        enrollment_version='latest')
        return contract

    def _get_deployed_contract(self):
        if self.contract is None or self.contract is CONTRACT_NOT_DEPLOYED:
            proxy_name = None
            if self._proxy_deployer is not NotImplemented:
                proxy_name = self._proxy_deployer.contract_name
            deployed_contract = self.blockchain.get_contract_by_name(contract_name=self.contract_name,
                                                                     registry=self.registry,
                                                                     proxy_name=proxy_name)
        else:
            deployed_contract = self.contract
        return deployed_contract


class OwnableContractMixin:

    _ownable = True

    class ContractNotOwnable(RuntimeError):
        pass

    @property
    def owner(self) -> ChecksumAddress:
        if self._upgradeable:
            # Get the address of the proxy
            contract = self.get_proxy_deployer()
        else:
            # Get the address of the implementation
            contract = self.blockchain.get_contract_by_name(contract_name=self.contract_name, registry=self.registry)
        owner_address = ChecksumAddress(contract.contract.functions.owner().call())  # blockchain read
        return owner_address

    def transfer_ownership(self,
                           transacting_power: TransactingPower,
                           new_owner: str,
                           transaction_gas_limit: int = None
                           ) -> dict:
        if not self._ownable:
            raise self.ContractNotOwnable(f"{self.contract_name} is not ownable.")

        if self._upgradeable:

            #
            # Upgrade Proxy
            #
            proxy_deployer = self.get_proxy_deployer()
            proxy_contract_function = proxy_deployer.contract.functions.transferOwnership(new_owner)
            receipt = self.blockchain.send_transaction(transacting_power=transacting_power,
                                                       contract_function=proxy_contract_function,
                                                       transaction_gas_limit=transaction_gas_limit)
        else:
            existing_bare_contract = self.blockchain.get_contract_by_name(contract_name=self.contract_name,
                                                                          registry=self.registry)

            #
            # Upgrade Principal
            #

            contract_function = existing_bare_contract.functions.transferOwnership(new_owner)
            receipt = self.blockchain.send_transaction(transacting_power=transacting_power,
                                                       contract_function=contract_function,
                                                       transaction_gas_limit=transaction_gas_limit)
        return receipt


class UpgradeableContractMixin:

    _upgradeable = True
    _proxy_deployer = NotImplemented

    class ContractNotUpgradeable(RuntimeError):
        pass
    
    def deploy(self,
               deployment_mode=FULL,
               gas_limit: int = None,
               progress=None,
               contract_version: str = "latest",
               ignore_deployed: bool = False
               ) -> dict:
        """
        Provides for the setup, deployment, and initialization of ethereum smart contracts.
        Emits the configured blockchain network transactions for single contract instance publication.
        """
        if not self._upgradeable:
            raise self.ContractNotUpgradeable(f"{self.contract_name} is not upgradeable.")
        raise NotImplementedError

    def get_principal_contract(self) -> VersionedContract:
        """
        Get the on-chain targeted version of the principal contract directly without assembling it with its proxy.
        """
        if not self._upgradeable:
            raise self.ContractNotUpgradeable(f"{self.contract_name} is not upgradeable.")
        principal_contract = self.blockchain.get_contract_by_name(contract_name=self.contract_name,
                                                                  registry=self.registry,
                                                                  proxy_name=self._proxy_deployer.contract_name,
                                                                  use_proxy_address=False)
        return principal_contract

    def get_proxy_contract(self) -> VersionedContract:  # TODO: Method seems unused and untested
        if not self._upgradeable:
            raise self.ContractNotUpgradeable(f"{self.contract_name} is not upgradeable.")
        principal_contract = self.get_principal_contract()
        proxy_contract = self.blockchain.get_proxy_contract(registry=self.registry,
                                                            target_address=principal_contract.address,
                                                            proxy_name=self._proxy_deployer.contract_name)
        return proxy_contract

    def get_proxy_deployer(self) -> BaseContractDeployer:
        principal_contract = self.get_principal_contract()
        proxy_deployer = self._proxy_deployer(registry=self.registry,
                                              target_contract=principal_contract,
                                              bare=True)  # acquire access to the proxy itself.
        return proxy_deployer

    def retarget(self,
                 transacting_power: TransactingPower,
                 target_address: str,
                 confirmations: int,
                 gas_limit: int = None,
                 just_build_transaction: bool = False):
        """
        Directly engage a proxy contract for an existing deployment, executing the proxy's
        upgrade interfaces to verify upgradeability and modify the on-chain contract target.
        """

        if not self._upgradeable:
            raise self.ContractNotUpgradeable(f"{self.contract_name} is not upgradeable.")

        # 1 - Get Proxy Deployer
        proxy_deployer = self.get_proxy_deployer()

        # 2 - Retarget (or build retarget transaction)
        if just_build_transaction:
            transaction = proxy_deployer.build_retarget_transaction(sender_address=transacting_power.account,
                                                                    new_target=target_address,
                                                                    gas_limit=gas_limit)
            return transaction
        else:
            receipt = proxy_deployer.retarget(transacting_power=transacting_power,
                                              new_target=target_address,
                                              gas_limit=gas_limit,
                                              confirmations=confirmations)
            return receipt

    def upgrade(self,
                transacting_power: TransactingPower,
                confirmations: int,
                gas_limit: int = None,
                contract_version: str = "latest",
                ignore_deployed: bool = False,
                **overrides):
        """
        Deploy a new version of a contract, then engage the proxy contract's upgrade interfaces.
        """

        # 1 - Raise if not all-systems-go #
        if not self._upgradeable:
            raise self.ContractNotUpgradeable(f"{self.contract_name} is not upgradeable.")
        self.check_deployment_readiness(deployer_address=transacting_power.account,
                                        contract_version=contract_version,
                                        ignore_deployed=ignore_deployed)

        # 2 - Get Proxy Deployer
        proxy_deployer = self.get_proxy_deployer()

        # 3 - Deploy new version
        new_contract, deploy_receipt = self._deploy_essential(transacting_power=transacting_power,
                                                              contract_version=contract_version,
                                                              gas_limit=gas_limit,
                                                              confirmations=confirmations,
                                                              **overrides)

        # 4 - Wrap the escrow contract
        wrapped_contract = self.blockchain._wrap_contract(wrapper_contract=proxy_deployer.contract,
                                                          target_contract=new_contract)

        # 5 - Set the new Dispatcher target
        upgrade_receipt = proxy_deployer.retarget(transacting_power=transacting_power,
                                                  new_target=new_contract.address,
                                                  gas_limit=gas_limit,
                                                  confirmations=confirmations)

        # 6 - Respond
        upgrade_transaction = {'deploy': deploy_receipt, 'retarget': upgrade_receipt}
        self._contract = wrapped_contract  # Switch the contract for the wrapped one
        return upgrade_transaction

    def rollback(self, transacting_power:TransactingPower, gas_limit: int = None):
        """
        Execute an existing deployment's proxy contract, engaging the upgrade rollback interfaces,
        modifying the proxy's on-chain contract target to the most recent previous target.
        """

        if not self._upgradeable:
            raise self.ContractNotUpgradeable(f"{self.contract_name} is not upgradeable.")

        proxy_deployer = self.get_proxy_deployer()
        rollback_receipt = proxy_deployer.rollback(transacting_power=transacting_power, gas_limit=gas_limit)

        return rollback_receipt

    def _finish_bare_deployment(self, deployment_receipt: dict, progress=None) -> dict:
        """Used to divert flow control for bare contract deployments."""
        deployment_step_name = self.deployment_steps[0]
        result = {deployment_step_name: deployment_receipt}
        self.deployment_receipts.update(result)
        if progress:
            progress.update(len(self.deployment_steps))  # Update the progress bar to completion.
        return result


class NucypherTokenDeployer(BaseContractDeployer):

    agency = NucypherTokenAgent
    contract_name = agency.contract_name
    deployment_steps = ('contract_deployment', )
    _upgradeable = False
    _ownable = False

    def deploy(self,
               transacting_power: TransactingPower,
               gas_limit: int = None,
               progress=None,
               confirmations: int = 0,
               deployment_mode=FULL,
               ignore_deployed: bool = False,
               emitter=None,
               **overrides) -> dict:
        """
        Deploy and publish the NuCypher Token contract
        to the blockchain network specified in self.blockchain.network.

        Deployment can only ever be executed exactly once!
        """
        if deployment_mode != FULL:
            raise self.ContractDeploymentError(f"{self.contract_name} cannot be deployed in {deployment_mode} mode")

        self.check_deployment_readiness(deployer_address=transacting_power.account,
                                        ignore_deployed=ignore_deployed)
        
        if emitter:
            emitter.message("\nNext Transaction: Token Contract Creation", color='blue', bold=True)

        # WARNING: Order-sensitive!
        constructor_kwargs = {"_totalSupplyOfTokens": self.economics.erc20_total_supply}
        constructor_kwargs.update(overrides)
        constructor_kwargs = {k: v for k, v in constructor_kwargs.items() if v is not None}
        contract, deployment_receipt = self.blockchain.deploy_contract(transacting_power,
                                                                       self.registry,
                                                                       self.contract_name,
                                                                       gas_limit=gas_limit,
                                                                       confirmations=confirmations,
                                                                       **constructor_kwargs)
        if progress:
            progress.update(1)
        self._contract = contract
        return {self.deployment_steps[0]: deployment_receipt}


class ProxyContractDeployer(BaseContractDeployer):

    contract_name = NotImplemented
    deployment_steps = ('contract_deployment',)
    _upgradeable = False

    def __init__(self, target_contract: Contract, bare: bool = False, *args, **kwargs):
        self.target_contract = target_contract
        super().__init__(*args, **kwargs)
        if bare:
            self._contract = self.blockchain.get_proxy_contract(registry=self.registry,
                                                                target_address=self.target_contract.address,
                                                                proxy_name=self.contract_name)

    def deploy(self,
               transacting_power: TransactingPower,
               gas_limit: int = None,
               progress=None,
               confirmations: int = 0
               ) -> dict:
        constructor_args = (self.target_contract.address,)
        proxy_contract, receipt = self.blockchain.deploy_contract(transacting_power,
                                                                  self.registry,
                                                                  self.contract_name,
                                                                  *constructor_args,
                                                                  gas_limit=gas_limit,
                                                                  confirmations=confirmations)
        if progress:
            progress.update(1)

        self._contract = proxy_contract
        receipts = {self.deployment_steps[0]: receipt}
        self.deployment_receipts.update(receipts)
        return receipts

    def _validate_retarget(self, new_target: str):
        if new_target == self.target_contract.address:
            raise self.ContractDeploymentError(f"{new_target} is already targeted by {self.contract_name}: {self._contract.address}")
        if new_target == self._contract.address:
            raise self.ContractDeploymentError(f"{self.contract_name} {self._contract.address} cannot target itself.")

    def retarget(self,
                 transacting_power: TransactingPower,
                 new_target: str,
                 confirmations: int,
                 gas_limit: int = None,
                 ) -> dict:
        self._validate_retarget(new_target)
        upgrade_function = self._contract.functions.upgrade(new_target)
        upgrade_receipt = self.blockchain.send_transaction(contract_function=upgrade_function,
                                                           transacting_power=transacting_power,
                                                           transaction_gas_limit=gas_limit,
                                                           confirmations=confirmations)
        return upgrade_receipt

    def build_retarget_transaction(self, sender_address: ChecksumAddress, new_target: str, gas_limit: int = None) -> dict:
        self._validate_retarget(new_target)
        upgrade_function = self._contract.functions.upgrade(new_target)
        unsigned_transaction = self.blockchain.build_contract_transaction(sender_address=sender_address,
                                                                          contract_function=upgrade_function,
                                                                          transaction_gas_limit=gas_limit)
        return unsigned_transaction

    def rollback(self,
                 transacting_power: TransactingPower,
                 gas_limit: int = None
                 ) -> dict:
        origin_args = {}  # TODO: Gas management - #842
        if gas_limit:
            origin_args.update({'gas': gas_limit})

        rollback_function = self._contract.functions.rollback()
        rollback_receipt = self.blockchain.send_transaction(contract_function=rollback_function,
                                                            transacting_power=transacting_power,
                                                            payload=origin_args)
        return rollback_receipt


class DispatcherDeployer(OwnableContractMixin, ProxyContractDeployer):
    """
    Ethereum smart contract that acts as a proxy to another ethereum contract,
    used as a means of "dispatching" the correct version of the contract to the client
    """

    contract_name = DISPATCHER_CONTRACT_NAME


class StakingEscrowDeployer(BaseContractDeployer, UpgradeableContractMixin, OwnableContractMixin):
    """
    Deploys the StakingEscrow ethereum contract to the blockchain.  Depends on NucypherTokenAgent
    """

    agency = StakingEscrowAgent
    contract_name = agency.contract_name
    contract_name_stub = "StakingEscrowStub"

    can_be_idle = True
    init_steps = ('stub_deployment', 'dispatcher_deployment')
    preparation_steps = ('contract_deployment', 'dispatcher_retarget')
    activation_steps = ('approve_reward_transfer', 'initialize')
    deployment_steps = preparation_steps + activation_steps
    _proxy_deployer = DispatcherDeployer

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__dispatcher_contract = None

        token_contract_name = NucypherTokenDeployer.contract_name
        self.token_contract = self.blockchain.get_contract_by_name(registry=self.registry,
                                                                   contract_name=token_contract_name)
        self.policy_manager = self._get_contract(deployer_class=PolicyManagerDeployer)
        self.adjudicator = self._get_contract(deployer_class=AdjudicatorDeployer)
        self.worklock = self._get_contract(deployer_class=WorklockDeployer)

    def _get_contract(self, deployer_class) -> VersionedContract:
        contract_name = deployer_class.contract_name
        try:
            proxy_name = deployer_class._proxy_deployer.contract_name
        except AttributeError:
            proxy_name = None
        try:
            return self.blockchain.get_contract_by_name(registry=self.registry,
                                                        contract_name=contract_name,
                                                        proxy_name=proxy_name)
        except self.registry.UnknownContract:
            return None

    def _deploy_stub(self,
                     transacting_power: TransactingPower,
                     gas_limit: int = None,
                     confirmations: int = 0,
                     **overrides):
        constructor_kwargs = {
            "_genesisHoursPerPeriod": self.economics.genesis_hours_per_period,
            "_hoursPerPeriod": self.economics.hours_per_period,
            "_minLockedPeriods": self.economics.minimum_locked_periods,
            "_minAllowableLockedTokens": self.economics.minimum_allowed_locked,
            "_maxAllowableLockedTokens": self.economics.maximum_allowed_locked
        }
        constructor_kwargs.update(overrides)
        constructor_kwargs = {k: v for k, v in constructor_kwargs.items() if v is not None}
        # Force use of the token address from the registry
        constructor_kwargs.update({"_token": self.token_contract.address})
        the_escrow_contract, deploy_receipt = self.blockchain.deploy_contract(
            transacting_power,
            self.registry,
            self.contract_name_stub,
            gas_limit=gas_limit,
            confirmations=confirmations,
            **constructor_kwargs
        )

        return the_escrow_contract, deploy_receipt

    def _deploy_essential(self,
                          transacting_power: TransactingPower,
                          contract_version: str,
                          gas_limit: int = None,
                          confirmations: int = 0,
                          **overrides):
        args = self.economics.staking_deployment_parameters
        constructor_kwargs = {
            "_genesisHoursPerPeriod": args[0],
            "_hoursPerPeriod": args[1],
            "_issuanceDecayCoefficient": args[2],
            "_lockDurationCoefficient1": args[3],
            "_lockDurationCoefficient2": args[4],
            "_maximumRewardedPeriods": args[5],
            "_firstPhaseTotalSupply": args[6],
            "_firstPhaseMaxIssuance": args[7],
            "_minLockedPeriods": args[8],
            "_minAllowableLockedTokens": args[9],
            "_maxAllowableLockedTokens": args[10],
            "_minWorkerPeriods": args[11]
        }
        constructor_kwargs.update(overrides)
        constructor_kwargs = {k: v for k, v in constructor_kwargs.items() if v is not None}
        # Force use of the contract addresses from the registry
        constructor_kwargs.update({"_token": self.token_contract.address,
                                   "_policyManager": self.policy_manager.address,
                                   "_adjudicator": self.adjudicator.address,
                                   "_workLock": self.worklock.address if self.worklock is not None else NULL_ADDRESS})
        the_escrow_contract, deploy_receipt = self.blockchain.deploy_contract(
            transacting_power,
            self.registry,
            self.contract_name,
            gas_limit=gas_limit,
            contract_version=contract_version,
            confirmations=confirmations,
            **constructor_kwargs
        )

        return the_escrow_contract, deploy_receipt

    def deploy(self,
               transacting_power: TransactingPower,
               deployment_mode=INIT,
               gas_limit: int = None,
               progress=None,
               contract_version: str = "latest",
               ignore_deployed: bool = False,
               confirmations: int = 0,
               emitter=None,
               **overrides
               ) -> dict:
        """
        Deploy and publish the StakingEscrow contract
        to the blockchain network specified in self.blockchain.network.

        Emits the following blockchain network transactions:
            - StakingEscrow contract deployment
            - StakingEscrow dispatcher deployment
            - Transfer reward tokens origin to StakingEscrow contract
            - StakingEscrow contract initialization

        Returns transaction receipts in a dict.
        """

        if deployment_mode not in (BARE, IDLE, INIT, FULL):
            raise ValueError(f"Invalid deployment mode ({deployment_mode})")

        # Raise if not all-systems-go
        self.check_deployment_readiness(deployer_address=transacting_power.account,
                                        contract_version=contract_version,
                                        ignore_deployed=ignore_deployed)

        # Build deployment arguments
        origin_args = {}
        if gas_limit:
            origin_args.update({'gas': gas_limit})  # TODO: Gas Management - #842

        if emitter:
            contract_name = self.contract_name_stub if deployment_mode is INIT else self.contract_name
            emitter.message(f"\nNext Transaction: {contract_name} Contract Creation", color='blue', bold=True)

        if deployment_mode is INIT:
            # 1 - Deploy Stub
            the_escrow_contract, deploy_receipt = self._deploy_stub(transacting_power=transacting_power,
                                                                    gas_limit=gas_limit,
                                                                    confirmations=confirmations,
                                                                    **overrides)
        else:
            # 1 - Deploy StakingEscrow
            the_escrow_contract, deploy_receipt = self._deploy_essential(transacting_power=transacting_power,
                                                                         contract_version=contract_version,
                                                                         gas_limit=gas_limit,
                                                                         confirmations=confirmations,
                                                                         **overrides)

            # This is the end of bare deployment.
            if deployment_mode is BARE:
                self._contract = the_escrow_contract
                receipts = self._finish_bare_deployment(deployment_receipt=deploy_receipt, progress=progress)
                return receipts

        if progress:
            progress.update(1)

        if emitter:
            emitter.message(f"\nNext Transaction: {DispatcherDeployer.contract_name} "
                            f"Contract {'Creation' if deployment_mode is INIT else 'Upgrade'} for {self.contract_name}",
                            color='blue', bold=True)

        if deployment_mode is INIT:
            # 2 - Deploy the dispatcher used for updating this contract #
            dispatcher_deployer = DispatcherDeployer(registry=self.registry, target_contract=the_escrow_contract)

            dispatcher_receipts = dispatcher_deployer.deploy(transacting_power=transacting_power, 
                                                             gas_limit=gas_limit,
                                                             confirmations=confirmations)
            dispatcher_deploy_receipt = dispatcher_receipts[dispatcher_deployer.deployment_steps[0]]
        else:
            # 2 - Upgrade dispatcher to the real contract
            the_stub_contract = self.blockchain.get_contract_by_name(registry=self.registry,
                                                                     contract_name=self.contract_name_stub)
            dispatcher_deployer = DispatcherDeployer(registry=self.registry,
                                                     target_contract=the_stub_contract,
                                                     bare=True)

            dispatcher_retarget_receipt = dispatcher_deployer.retarget(transacting_power=transacting_power,
                                                                       new_target=the_escrow_contract.address,
                                                                       gas_limit=gas_limit,
                                                                       confirmations=confirmations)

        if progress:
            progress.update(1)

        # Cache the dispatcher contract
        dispatcher_contract = dispatcher_deployer.contract
        self.__dispatcher_contract = dispatcher_contract

        # Wrap the escrow contract
        wrapped_escrow_contract = self.blockchain._wrap_contract(dispatcher_contract,
                                                                 target_contract=the_escrow_contract)

        # Switch the contract for the wrapped one
        self._contract = wrapped_escrow_contract

        if deployment_mode is INIT:
            preparation_receipts = dict(zip(self.init_steps, (deploy_receipt, dispatcher_deploy_receipt)))
        else:
            preparation_receipts = dict(zip(self.preparation_steps, (deploy_receipt, dispatcher_retarget_receipt)))
        self.deployment_receipts = preparation_receipts

        # 3 & 4 - Activation
        if deployment_mode in (IDLE, INIT):
            # This is the end of deployment without activation: the contract is now idle, waiting for activation
            return preparation_receipts
        else:  # deployment_mode is FULL
            activation_receipts = self.activate(transacting_power=transacting_power,
                                                gas_limit=gas_limit,
                                                progress=progress,
                                                confirmations=confirmations,
                                                emitter=emitter)
            self.deployment_receipts.update(activation_receipts)
            return self.deployment_receipts

    def activate(self,
                 transacting_power: TransactingPower,
                 gas_limit: int = None,
                 progress=None,
                 emitter=None,
                 confirmations: int = 0):

        self._contract = self._get_deployed_contract()
        if not self.ready_to_activate:
            raise self.ContractDeploymentError(f"This StakingEscrow ({self._contract.address}) cannot be activated")

        origin_args = {}
        if gas_limit:
            origin_args.update({'gas': gas_limit})  # TODO: #842 - Gas Management

        # 3 - Approve transferring the reward supply tokens to StakingEscrow #
        if emitter:
            emitter.message(f"\nNext Transaction: Approve Transfer to {self.contract_name}", color='blue', bold=True)
        approve_reward_function = self.token_contract.functions.approve(self._contract.address,
                                                                        self.economics.erc20_reward_supply)

        # TODO: Confirmations / Successful Transaction Indicator / Events ??  - #1193, #1194
        approve_reward_receipt = self.blockchain.send_transaction(contract_function=approve_reward_function,
                                                                  transacting_power=transacting_power,
                                                                  confirmations=confirmations,
                                                                  payload=origin_args)
        if progress:
            progress.update(1)

        # 4 - Initialize the StakingEscrow contract
        if emitter:
            emitter.message(f"\nNext Transaction: {self.contract_name} Initialization", color='blue', bold=True)
        deployer_address = transacting_power.account
        init_function = self._contract.functions.initialize(self.economics.erc20_reward_supply, deployer_address)
        init_receipt = self.blockchain.send_transaction(contract_function=init_function,
                                                        transacting_power=transacting_power,
                                                        confirmations=confirmations,
                                                        payload=origin_args)
        if progress:
            progress.update(1)

        activation_receipts = dict(zip(self.activation_steps, (approve_reward_receipt, init_receipt)))
        return activation_receipts

    @property
    def ready_to_activate(self) -> bool:
        try:
            deployed_contract = self._get_deployed_contract()
        except self.blockchain.UnknownContract:
            return False

        # TODO: Consider looking for absence of Initialized event - see #1193
        # This mimics initialization pre-condition in Issuer (StakingEscrow's base contract)
        current_minting_period = deployed_contract.functions.currentMintingPeriod().call()
        return current_minting_period == 0

    @property
    def is_active(self) -> bool:
        try:
            deployed_contract = self._get_deployed_contract()
        except self.blockchain.UnknownContract:
            return False

        # TODO: Consider looking for Initialized event - see #1193
        # This mimics isInitialized() modifier in Issuer (StakingEscrow's base contract)
        current_minting_period = deployed_contract.functions.currentMintingPeriod().call()
        return current_minting_period != 0


class PolicyManagerDeployer(BaseContractDeployer, UpgradeableContractMixin, OwnableContractMixin):
    """
    Depends on StakingEscrow and NucypherTokenAgent
    """

    agency = PolicyManagerAgent
    contract_name = agency.contract_name
    deployment_steps = ('deployment', 'dispatcher_deployment')
    _proxy_deployer = DispatcherDeployer

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        proxy_name = StakingEscrowDeployer._proxy_deployer.contract_name
        staking_contract_name = StakingEscrowDeployer.contract_name
        try:
            self.staking_contract = self.blockchain.get_contract_by_name(registry=self.registry,
                                                                         contract_name=staking_contract_name,
                                                                         proxy_name=proxy_name)
            # If migration is happening then we should get latest StakingEscrow
            # but this contract is not yet targeted by Dispatcher
            self.staking_implementation = self.blockchain.get_contract_by_name(registry=self.registry,
                                                                               contract_name=staking_contract_name,
                                                                               enrollment_version='latest')
        except self.registry.UnknownContract:
            staking_contract_name = StakingEscrowDeployer.contract_name_stub
            self.staking_contract = self.blockchain.get_contract_by_name(registry=self.registry,
                                                                         contract_name=staking_contract_name,
                                                                         proxy_name=proxy_name)
            self.staking_implementation = self.staking_contract

    def check_deployment_readiness(self, deployer_address: ChecksumAddress, *args, **kwargs) -> Tuple[bool, list]:
        staking_escrow_owner = self.staking_contract.functions.owner().call()
        policy_manager_deployment_rules = [

            # TODO: Check that the owner is the owner of the bare contract instead of the proxy.
            # (deployer_address == staking_escrow_owner,
            #  f'{self.contract_name} must be deployed by the owner of {STAKING_ESCROW_CONTRACT_NAME} ({staking_escrow_owner})')
        ]
        return super().check_deployment_readiness(deployer_address=deployer_address,
                                                  additional_rules=policy_manager_deployment_rules,
                                                  *args, **kwargs)

    def _deploy_essential(self,
                          transacting_power: TransactingPower,
                          contract_version: str,
                          gas_limit: int = None,
                          confirmations: int = 0
                          ) -> tuple:
        constructor_kwargs = {"_escrowDispatcher": self.staking_contract.address,
                              "_escrowImplementation": self.staking_implementation.address}
        policy_manager_contract, deploy_receipt = self.blockchain.deploy_contract(transacting_power,
                                                                                  self.registry,
                                                                                  self.contract_name,
                                                                                  gas_limit=gas_limit,
                                                                                  contract_version=contract_version,
                                                                                  confirmations=confirmations,
                                                                                  **constructor_kwargs)
        return policy_manager_contract, deploy_receipt

    def deploy(self,
               transacting_power: TransactingPower,
               deployment_mode=FULL,
               gas_limit: int = None,
               progress=None,
               contract_version: str = "latest",
               ignore_deployed: bool = False,
               confirmations: int = 0,
               emitter=None,
               ) -> Dict[str, dict]:

        if deployment_mode not in (BARE, IDLE, FULL):
            raise ValueError(f"Invalid deployment mode ({deployment_mode})")

        self.check_deployment_readiness(contract_version=contract_version,
                                        ignore_deployed=ignore_deployed,
                                        deployer_address=transacting_power.account)

        # Creator deploys the policy manager
        if emitter:
            emitter.message(f"\nNext Transaction: {self.contract_name} Contract Creation", color='blue', bold=True)
        policy_manager_contract, deploy_receipt = self._deploy_essential(transacting_power=transacting_power,
                                                                         contract_version=contract_version,
                                                                         gas_limit=gas_limit,
                                                                         confirmations=confirmations)

        # This is the end of bare deployment.
        if deployment_mode is BARE:
            self._contract = policy_manager_contract
            return self._finish_bare_deployment(deployment_receipt=deploy_receipt,
                                                progress=progress)

        if progress:
            progress.update(1)  # how YOU doin?
        if emitter:
            emitter.message(f"\nNext Transaction: {self._proxy_deployer.contract_name} Contract Creation for {self.contract_name}", color='blue', bold=True)

        proxy_deployer = self._proxy_deployer(registry=self.registry, target_contract=policy_manager_contract)

        proxy_deploy_receipt = proxy_deployer.deploy(transacting_power=transacting_power, 
                                                     gas_limit=gas_limit,
                                                     confirmations=confirmations)
        proxy_deploy_receipt = proxy_deploy_receipt[proxy_deployer.deployment_steps[0]]
        if progress:
            progress.update(1)

        # Cache the dispatcher contract
        proxy_contract = proxy_deployer.contract
        self.__proxy_contract = proxy_contract

        # Wrap the PolicyManager contract, and use this wrapper
        wrapped_contract = self.blockchain._wrap_contract(wrapper_contract=proxy_contract,
                                                          target_contract=policy_manager_contract)

        # Gather the transaction receipts
        ordered_receipts = (deploy_receipt, proxy_deploy_receipt)
        deployment_receipts = dict(zip(self.deployment_steps, ordered_receipts))

        self.deployment_receipts = deployment_receipts
        self._contract = wrapped_contract
        return deployment_receipts

    def set_fee_rate_range(self,
                           transacting_power: TransactingPower,
                           minimum: int,
                           default: int,
                           maximum: int,
                           gas_limit: int = None,
                           confirmations: int = 0) -> dict:

        if minimum > default or default > maximum:
            raise ValueError(f"Default fee rate ({default}) must fall within the global fee range by satisfying the condition: "
                             f"minimum ({minimum}) <= default ({default}) <= maximum ({maximum})")

        policy_manager = self.blockchain.get_contract_by_name(registry=self.registry,
                                                              contract_name=self.contract_name,
                                                              proxy_name=self._proxy_deployer.contract_name)

        tx_args = {}
        if gas_limit:
            tx_args.update({'gas': gas_limit})  # TODO: Gas management - 842
        set_range_function = policy_manager.functions.setFeeRateRange(minimum, default, maximum)
        set_range_receipt = self.blockchain.send_transaction(contract_function=set_range_function,
                                                             transacting_power=transacting_power,
                                                             payload=tx_args,
                                                             confirmations=confirmations)

        return set_range_receipt


class StakingInterfaceRouterDeployer(OwnableContractMixin, ProxyContractDeployer):

    contract_name = 'StakingInterfaceRouter'

    # Overwrites rollback method from ProxyContractDeployer since StakingInterfaceRouter doesn't support rollback
    def rollback(self, transacting_power: TransactingPower, gas_limit: int = None) -> dict:
        raise NotImplementedError


class StakingInterfaceDeployer(BaseContractDeployer, UpgradeableContractMixin, OwnableContractMixin):

    contract_name = 'StakingInterface'
    deployment_steps = ('contract_deployment', 'router_deployment')
    number_of_deployment_transactions = 2
    _proxy_deployer = StakingInterfaceRouterDeployer

    # _ownable = False  # TODO: This contract is not truly ownable but we need the logic of the mixin to execute

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        token_contract_name = NucypherTokenDeployer.contract_name
        self.token_contract = self.blockchain.get_contract_by_name(registry=self.registry,
                                                                   contract_name=token_contract_name)

        staking_contract_name = StakingEscrowDeployer.contract_name
        staking_proxy_name = StakingEscrowDeployer._proxy_deployer.contract_name
        try:
            self.staking_contract = self.blockchain.get_contract_by_name(registry=self.registry,
                                                                         contract_name=staking_contract_name,
                                                                         proxy_name=staking_proxy_name)
        except self.registry.UnknownContract:
            staking_contract_name = StakingEscrowDeployer.contract_name_stub
            self.staking_contract = self.blockchain.get_contract_by_name(registry=self.registry,
                                                                         contract_name=staking_contract_name,
                                                                         proxy_name=staking_proxy_name)

        policy_contract_name = PolicyManagerDeployer.contract_name
        policy_proxy_name = PolicyManagerDeployer._proxy_deployer.contract_name
        self.policy_contract = self.blockchain.get_contract_by_name(registry=self.registry,
                                                                    contract_name=policy_contract_name,
                                                                    proxy_name=policy_proxy_name)

        worklock_name = WorklockDeployer.contract_name
        try:
            self.worklock_contract = self.blockchain.get_contract_by_name(registry=self.registry,
                                                                          contract_name=worklock_name)
        except BaseContractRegistry.UnknownContract:
            self.worklock_contract = None

    def _deploy_essential(self,
                          transacting_power: TransactingPower,
                          contract_version: str,
                          gas_limit: int = None,
                          confirmations: int = 0):
        """Note: These parameters are order-sensitive"""
        worklock_address = self.worklock_contract.address if self.worklock_contract else NULL_ADDRESS
        constructor_args = (self.token_contract.address,
                            self.staking_contract.address,
                            self.policy_contract.address,
                            worklock_address)

        contract, deployment_receipt = self.blockchain.deploy_contract(transacting_power,
                                                                       self.registry,
                                                                       self.contract_name,
                                                                       *constructor_args,
                                                                       gas_limit=gas_limit,
                                                                       contract_version=contract_version,
                                                                       confirmations=confirmations)
        return contract, deployment_receipt

    def deploy(self,
               transacting_power: TransactingPower,
               deployment_mode=FULL,
               gas_limit: int = None,
               progress=None,
               contract_version: str = "latest",
               ignore_deployed: bool = False,
               confirmations: int = 0,
               emitter = None
               ) -> dict:
        """
        Deploys a new StakingInterface contract, and a new StakingInterfaceRouter, targeting the former.
        This is meant to be called only once per general deployment.
        """

        if deployment_mode not in (BARE, IDLE, FULL):
            raise ValueError(f"Invalid deployment mode ({deployment_mode})")

        self.check_deployment_readiness(deployer_address=transacting_power.account,
                                        contract_version=contract_version,
                                        ignore_deployed=ignore_deployed)

        # 1 - StakingInterface
        if emitter:
            emitter.message(f"\nNext Transaction: {self.contract_name} Contract Creation", color='blue', bold=True)
        staking_interface_contract, deployment_receipt = self._deploy_essential(transacting_power=transacting_power,
                                                                                contract_version=contract_version,
                                                                                gas_limit=gas_limit,
                                                                                confirmations=confirmations)

        # This is the end of bare deployment.
        if deployment_mode is BARE:
            self._contract = staking_interface_contract
            return self._finish_bare_deployment(deployment_receipt=deployment_receipt, progress=progress)

        if progress:
            progress.update(1)

        # 2 - StakingInterfaceRouter
        if emitter:
            emitter.message(f"\nNext Transaction: {self._proxy_deployer.contract_name} deployment for {self.contract_name}", color='blue', bold=True)
        router_deployer = self._proxy_deployer(registry=self.registry, target_contract=staking_interface_contract)

        router_deployment_receipts = router_deployer.deploy(transacting_power=transacting_power, gas_limit=gas_limit)
        router_deployment_receipt = router_deployment_receipts[router_deployer.deployment_steps[0]]
        if progress:
            progress.update(1)

        # Gather the transaction receipts
        ordered_receipts = (deployment_receipt, router_deployment_receipt)
        deployment_receipts = dict(zip(self.deployment_steps, ordered_receipts))

        self._contract = staking_interface_contract
        return deployment_receipts


class AdjudicatorDeployer(BaseContractDeployer, UpgradeableContractMixin, OwnableContractMixin):

    agency = AdjudicatorAgent
    contract_name = agency.contract_name
    deployment_steps = ('contract_deployment', 'dispatcher_deployment')
    _proxy_deployer = DispatcherDeployer

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        staking_contract_name = StakingEscrowDeployer.contract_name
        proxy_name = StakingEscrowDeployer._proxy_deployer.contract_name
        try:
            self.staking_contract = self.blockchain.get_contract_by_name(registry=self.registry,
                                                                         contract_name=staking_contract_name,
                                                                         proxy_name=proxy_name)
        except self.registry.UnknownContract:
            staking_contract_name = StakingEscrowDeployer.contract_name_stub
            self.staking_contract = self.blockchain.get_contract_by_name(registry=self.registry,
                                                                         contract_name=staking_contract_name,
                                                                         proxy_name=proxy_name)

    def check_deployment_readiness(self, deployer_address: ChecksumAddress, *args, **kwargs) -> Tuple[bool, list]:
        staking_escrow_owner = self.staking_contract.functions.owner().call()
        adjudicator_deployment_rules = [
            (deployer_address == staking_escrow_owner,
             f'{self.contract_name} must be deployed by the owner of {STAKING_ESCROW_CONTRACT_NAME} ({staking_escrow_owner})')
        ]
        return super().check_deployment_readiness(deployer_address=deployer_address,
                                                  additional_rules=adjudicator_deployment_rules,
                                                  *args, **kwargs)

    def _deploy_essential(self,
                          transacting_power: TransactingPower,
                          contract_version: str,
                          gas_limit: int = None,
                          confirmations: int = 0,
                          **overrides):
        args = self.economics.slashing_deployment_parameters
        constructor_kwargs = {
            "_hashAlgorithm": args[0],
            "_basePenalty": args[1],
            "_penaltyHistoryCoefficient": args[2],
            "_percentagePenaltyCoefficient": args[3],
            "_rewardCoefficient": args[4]
        }
        constructor_kwargs.update(overrides)
        constructor_kwargs = {k: v for k, v in constructor_kwargs.items() if v is not None}
        # Force use of the escrow address from the registry
        constructor_kwargs.update({"_escrow": self.staking_contract.address})
        adjudicator_contract, deploy_receipt = self.blockchain.deploy_contract(transacting_power,
                                                                               self.registry,
                                                                               self.contract_name,
                                                                               gas_limit=gas_limit,
                                                                               confirmations=confirmations,
                                                                               contract_version=contract_version,
                                                                               **constructor_kwargs)
        return adjudicator_contract, deploy_receipt

    def deploy(self,
               transacting_power: TransactingPower,
               deployment_mode=FULL,
               gas_limit: int = None,
               progress=None,
               contract_version: str = "latest",
               ignore_deployed: bool = False,
               emitter=None,
               confirmations: int = 0,
               **overrides) -> Dict[str, str]:

        if deployment_mode not in (BARE, IDLE, FULL):
            raise ValueError(f"Invalid deployment mode ({deployment_mode})")

        self.check_deployment_readiness(deployer_address=transacting_power.account,
                                        contract_version=contract_version,
                                        ignore_deployed=ignore_deployed)

        # 1 - Deploy Contract
        if emitter:
            emitter.message(f"\nNext Transaction: {self.contract_name} Contract Creation", color='blue', bold=True)
        adjudicator_contract, deploy_receipt = self._deploy_essential(transacting_power=transacting_power,
                                                                      contract_version=contract_version,
                                                                      gas_limit=gas_limit,
                                                                      confirmations=confirmations,
                                                                      **overrides)

        # This is the end of bare deployment.
        if deployment_mode is BARE:
            self._contract = adjudicator_contract
            return self._finish_bare_deployment(deployment_receipt=deploy_receipt,
                                                progress=progress)

        if progress:
            progress.update(1)

        # 2 - Deploy Proxy
        if emitter:
            emitter.message(f"\nNext Transaction: {self._proxy_deployer.contract_name} Contract Creation for {self.contract_name}", color='blue', bold=True)
        proxy_deployer = self._proxy_deployer(registry=self.registry, target_contract=adjudicator_contract)

        proxy_deploy_receipts = proxy_deployer.deploy(transacting_power=transacting_power,
                                                      gas_limit=gas_limit, 
                                                      confirmations=confirmations)
        proxy_deploy_receipt = proxy_deploy_receipts[proxy_deployer.deployment_steps[0]]
        if progress:
            progress.update(1)

        # Cache the dispatcher contract
        proxy_contract = proxy_deployer.contract
        self.__proxy_contract = proxy_contract

        # Wrap the escrow contract
        wrapped = self.blockchain._wrap_contract(proxy_contract, target_contract=adjudicator_contract)

        # Switch the contract for the wrapped one
        adjudicator_contract = wrapped

        # Gather the transaction receipts
        ordered_receipts = (deploy_receipt, proxy_deploy_receipt)
        deployment_receipts = dict(zip(self.deployment_steps, ordered_receipts))

        self.deployment_receipts = deployment_receipts
        self._contract = adjudicator_contract

        return deployment_receipts


class WorklockDeployer(BaseContractDeployer):

    agency = WorkLockAgent
    contract_name = agency.contract_name
    deployment_steps = ('contract_deployment', 'approve_funding', 'fund_worklock')
    _upgradeable = False

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)
        token_contract_name = NucypherTokenDeployer.contract_name
        self.token_contract = self.blockchain.get_contract_by_name(registry=self.registry,
                                                                   contract_name=token_contract_name)

        staking_contract_name = StakingEscrowDeployer.contract_name
        proxy_name = StakingEscrowDeployer._proxy_deployer.contract_name
        try:
            self.staking_contract = self.blockchain.get_contract_by_name(registry=self.registry,
                                                                         contract_name=staking_contract_name,
                                                                         proxy_name=proxy_name)
        except self.registry.UnknownContract:
            staking_contract_name = StakingEscrowDeployer.contract_name_stub
            self.staking_contract = self.blockchain.get_contract_by_name(registry=self.registry,
                                                                         contract_name=staking_contract_name,
                                                                         proxy_name=proxy_name)

    def _deploy_essential(self, transacting_power: TransactingPower, gas_limit: int = None, confirmations: int = 0):
        # Deploy
        constructor_args = (self.token_contract.address,
                            self.staking_contract.address,
                            *self.economics.worklock_deployment_parameters)

        worklock_contract, receipt = self.blockchain.deploy_contract(transacting_power,
                                                                     self.registry,
                                                                     self.contract_name,
                                                                     *constructor_args,
                                                                     gas_limit=gas_limit,
                                                                     confirmations=confirmations)

        self._contract = worklock_contract
        return worklock_contract, receipt

    def deploy(self,
               transacting_power: TransactingPower,
               gas_limit: int = None, 
               progress=None, 
               confirmations: int = 0,
               deployment_mode=FULL,
               ignore_deployed: bool = False,
               emitter=None,
               ) -> Dict[str, dict]:

        if deployment_mode != FULL:
            raise self.ContractDeploymentError(f"{self.contract_name} cannot be deployed in {deployment_mode} mode")

        self.check_deployment_readiness(deployer_address=transacting_power.account,
                                        ignore_deployed=ignore_deployed)

        # Essential
        if emitter:
            emitter.message(f"\nNext Transaction: {self.contract_name} Contract Creation", color='blue', bold=True)
        worklock_contract, deployment_receipt = self._deploy_essential(transacting_power=transacting_power,
                                                                       gas_limit=gas_limit,
                                                                       confirmations=confirmations)
        if progress:
            progress.update(1)

        # Funding
        approve_receipt, funding_receipt = self.fund(transacting_power=transacting_power,
                                                     progress=progress,
                                                     confirmations=confirmations,
                                                     emitter=emitter)

        # Gather the transaction hashes
        self.deployment_receipts = dict(zip(self.deployment_steps, (deployment_receipt,
                                                                    approve_receipt,
                                                                    funding_receipt)))
        return self.deployment_receipts

    def fund(self,
             transacting_power: TransactingPower,
             progress=None,
             confirmations: int = 0,
             emitter=None
             ) -> Tuple[dict, dict]:
        """
        Convenience method for funding the contract and establishing the
        total worklock lot value to be auctioned.
        """
        supply = int(self.economics.worklock_supply)

        token_agent = ContractAgency.get_agent(NucypherTokenAgent, registry=self.registry)
        if emitter:
            emitter.message(f"\nNext Transaction: Approve Token Transfer to {self.contract_name}", color='blue', bold=True)
        approve_function = token_agent.contract.functions.approve(self.contract_address, supply)
        approve_receipt = self.blockchain.send_transaction(contract_function=approve_function,
                                                           transacting_power=transacting_power,
                                                           confirmations=confirmations)

        if progress:
            progress.update(1)

        if emitter:
            emitter.message(f"\nNext Transaction: Transfer Tokens to {self.contract_name}", color='blue', bold=True)
        funding_function = self.contract.functions.tokenDeposit(supply)
        funding_receipt = self.blockchain.send_transaction(contract_function=funding_function,
                                                           transacting_power=transacting_power,
                                                           confirmations=confirmations)

        if progress:
            progress.update(1)

        return approve_receipt, funding_receipt


class MultiSigDeployer(BaseContractDeployer):

    agency = MultiSigAgent
    contract_name = agency.contract_name
    deployment_steps = ('contract_deployment', )
    _upgradeable = False

    MAX_OWNER_COUNT = 50  # Hard-coded limit in MultiSig contract

    def _deploy_essential(self,
                          transacting_power: TransactingPower,
                          threshold: int,
                          owners: List[str],
                          gas_limit: int = None,
                          confirmations: int = 0):
        if not (0 < threshold <= len(owners) <= self.MAX_OWNER_COUNT):
            raise ValueError(f"Parameters threshold={threshold} and len(owners)={len(owners)} don't satisfy inequality "
                             f"0 < threshold <= len(owners) <= {self.MAX_OWNER_COUNT}")
        if NULL_ADDRESS in owners:
            raise ValueError("The null address is not allowed as an owner")
        if len(owners) != len(set(owners)):
            raise ValueError("Can't use the same owner address more than once")

        constructor_args = (threshold, owners)

        multisig_contract, deploy_receipt = self.blockchain.deploy_contract(transacting_power,
                                                                            self.registry,
                                                                            self.contract_name,
                                                                            *constructor_args,
                                                                            gas_limit=gas_limit,
                                                                            confirmations=confirmations)
        return multisig_contract, deploy_receipt

    def deploy(self,
               transacting_power: TransactingPower,
               deployment_mode=FULL,
               gas_limit: int = None,
               progress=None,
               ignore_deployed: bool = False,
               emitter=None,
               *args, **kwargs
               ) -> dict:

        if deployment_mode != FULL:
            raise self.ContractDeploymentError(f"{self.contract_name} cannot be deployed in {deployment_mode} mode")

        self.check_deployment_readiness(deployer_address=transacting_power.account,
                                        ignore_deployed=ignore_deployed)

        if emitter:
            emitter.message(f"\nNext Transaction: {self.contract_name} Contract Creation", color='blue', bold=True)
        multisig_contract, deploy_receipt = self._deploy_essential(
            transacting_power=transacting_power,
            gas_limit=gas_limit,
            *args, **kwargs)

        # Update the progress bar
        if progress:
            progress.update(1)

        # Gather the transaction receipts
        self.deployment_receipts.update({self.deployment_steps[0]: deploy_receipt})
        self._contract = multisig_contract
        return self.deployment_receipts
