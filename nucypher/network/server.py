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


import weakref

import os
import uuid
from constant_sorrow import constants
from constant_sorrow.constants import FLEET_STATES_MATCH, RELAX, NOT_STAKING
from datetime import datetime, timedelta
from flask import Flask, Response, jsonify, request
from mako import exceptions as mako_exceptions
from mako.template import Template
from maya import MayaDT
from typing import Tuple

from nucypher.blockchain.eth.constants import NULL_ADDRESS
from nucypher.blockchain.eth.utils import period_to_epoch
from nucypher.config.constants import MAX_UPLOAD_CONTENT_LENGTH
from nucypher.crypto.api import InvalidNodeCertificate
from nucypher.crypto.keypairs import HostingKeypair, DecryptingKeypair
from nucypher.crypto.kits import PolicyMessageKit
from nucypher.crypto.powers import KeyPairBasedPower, PowerUpError
from nucypher.crypto.signing import InvalidSignature
from nucypher.datastore.datastore import Datastore, RecordNotFound
from nucypher.datastore.models import TreasureMap as TreasureMapModel
from nucypher.datastore.models import Workorder as WorkOrderModel
from nucypher.network import LEARNING_LOOP_VERSION
from nucypher.network.exceptions import NodeSeemsToBeDown
from nucypher.network.protocols import InterfaceInfo
from nucypher.utilities.logging import Logger

HERE = BASE_DIR = os.path.abspath(os.path.dirname(__file__))
TEMPLATES_DIR = os.path.join(HERE, "templates")

status_template = Template(filename=os.path.join(TEMPLATES_DIR, "basic_status.mako")).get_def('main')


class ProxyRESTServer:
    SERVER_VERSION = LEARNING_LOOP_VERSION
    log = Logger("network-server")

    def __init__(self,
                 rest_host: str,
                 rest_port: int,
                 hosting_power=None,
                 rest_app=None,
                 datastore=None,
                 ) -> None:

        self.rest_interface = InterfaceInfo(host=rest_host, port=rest_port)
        if rest_app:  # if is me
            self.rest_app = rest_app
            self.datastore = datastore
        else:
            self.rest_app = constants.PUBLIC_ONLY

        self.__hosting_power = hosting_power

    def rest_url(self):
        return "{}:{}".format(self.rest_interface.host, self.rest_interface.port)


def make_rest_app(
        db_filepath: str,
        this_node,
        domain,
        log: Logger = Logger("http-application-layer")
        ) -> Tuple[Flask, Datastore]:
    """
    Creates a REST application and an associated ``Datastore`` object.
    Note that the REST app **does not** hold a reference to the datastore;
    it is your responsibility to ensure it lives for as long as the app does.
    """

    # A trampoline function for the real REST app,
    # to ensure that a reference to the node and the datastore object is not held by the app closure.
    # One would think that it's enough to only remove a reference to the node,
    # but `rest_app` somehow holds a reference to itself, Uroboros-like,
    # and will hold the datastore reference if it is created there.

    log.info("Starting datastore {}".format(db_filepath))
    datastore = Datastore(db_filepath)
    rest_app = _make_rest_app(weakref.proxy(datastore), weakref.proxy(this_node), domain, log)

    return rest_app, datastore


def _make_rest_app(datastore: Datastore, this_node, domain: str, log: Logger) -> Flask:

    # TODO: Avoid circular imports :-(
    from nucypher.policy.orders import WorkOrder
    from nucypher.characters.lawful import Alice, Bob, Ursula
    from nucypher.policy.policies import Arrangement
    from nucypher.policy.policies import Policy

    _alice_class = Alice
    _bob_class = Bob
    _node_class = Ursula

    rest_app = Flask("ursula-service")
    rest_app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_CONTENT_LENGTH

    @rest_app.route("/public_information")
    def public_information():
        """REST endpoint for public keys and address."""
        response = Response(response=bytes(this_node), mimetype='application/octet-stream')
        return response

    @rest_app.route('/node_metadata', methods=["GET"])
    def all_known_nodes():
        headers = {'Content-Type': 'application/octet-stream'}
        if this_node._learning_deferred is not RELAX and not this_node._learning_task.running:
            # Learn when learned about
            this_node.start_learning_loop()

        if not this_node.known_nodes:
            return Response(b"", headers=headers, status=204)

        known_nodes_bytestring = this_node.bytestring_of_known_nodes()
        signature = this_node.stamp(known_nodes_bytestring)
        return Response(bytes(signature) + known_nodes_bytestring, headers=headers)

    @rest_app.route('/node_metadata', methods=["POST"])
    def node_metadata_exchange():

        # If these nodes already have the same fleet state, no exchange is necessary.
        learner_fleet_state = request.args.get('fleet')
        if learner_fleet_state == this_node.known_nodes.checksum:
            # log.debug("Learner already knew fleet state {}; doing nothing.".format(learner_fleet_state))  # 1712
            headers = {'Content-Type': 'application/octet-stream'}
            payload = this_node.known_nodes.snapshot() + bytes(FLEET_STATES_MATCH)
            signature = this_node.stamp(payload)
            return Response(bytes(signature) + payload, headers=headers)

        sprouts = _node_class.batch_from_bytes(request.data)

        for node in sprouts:
            this_node.remember_node(node)

        # TODO: What's the right status code here?  202?  Different if we already knew about the node(s)?
        return all_known_nodes()

    @rest_app.route('/consider_arrangement', methods=['POST'])
    def consider_arrangement():
        arrangement = Arrangement.from_bytes(request.data)

        # Verify this node is staking for the entirety of the proposed arrangement.
        if not this_node.federated_only:

            # Get final staking period
            if this_node.stakes.terminal_period is NOT_STAKING:
                this_node.stakes.refresh()
            if this_node.stakes.terminal_period is NOT_STAKING:
                return Response(status=403)  # 403 Forbidden

            # Verify timeframe
            terminal_stake_period = this_node.stakes.terminal_period
            terminal_stake_epoch = period_to_epoch(period=terminal_stake_period,
                                                   seconds_per_period=this_node.economics.seconds_per_period)
            arrangement_expiration = arrangement.expiration.epoch
            if arrangement_expiration > terminal_stake_epoch:
                # I'm sorry David, I'm afraid I can't do that.
                return Response(status=403)  # 403 Forbidden

        signature = this_node.sign(bytes(arrangement))
        headers = {'Content-Type': 'application/octet-stream'}
        return Response(bytes(signature), status=200, headers=headers)

    @rest_app.route('/reencrypt', methods=["POST"])
    def reencrypt():
        # TODO: Cache & Optimize

        # Work Order
        work_order_payload = request.data
        work_order = WorkOrder.from_rest_payload(rest_payload=work_order_payload, ursula=this_node)
        hrac = work_order.hrac
        log.info(f"Work Order from {work_order.bob} for policy {hrac.hex()}, signed {work_order.receipt_signature}")

        # Right off the bat, if this HRAC is already known to be revoked, reject the order.
        if hrac in this_node.revoked_policies:
            return Response(response="Invalid KFrag sender.", status=401)  # 401 - Unauthorized

        # Alice & Relayer
        alice = _alice_class.from_public_keys(verifying_key=work_order.alice_verifying_key)
        alice_verifying_key = alice.stamp.as_umbral_pubkey()
        policy_relayer = _alice_class.from_public_keys(verifying_key=work_order.relayer_verifying_key)

        # Bob
        bob_ip_address = request.remote_addr
        bob_verifying_key = work_order.bob.stamp.as_umbral_pubkey()
        bob = _bob_class.from_public_keys(verifying_key=bob_verifying_key)
        bob_workorder_signature = work_order.receipt_signature
        bob_identity_message = f"[{bob_ip_address}] Bob({bytes(bob.stamp).hex()})"

        # Verify & Decrypt KFrag Payload
        encrypted_kfrag_payload = PolicyMessageKit.from_bytes(work_order.encrypted_kfrag)
        try:
            plaintext_kfrag_payload = this_node.verify_from(stranger=alice,
                                                            message_kit=encrypted_kfrag_payload,
                                                            decrypt=True)
        except InvalidSignature:
            return Response(response="Invalid KFrag sender.", status=401)  # 401 - Unauthorized
        except DecryptingKeypair.DecryptionFailed:
            return Response(response="KFrag decryption failed.", status=403)   # 403 - Forbidden

        # Verify KFrag Authorization (offchain)
        signed_writ, kfrag = work_order.kfrag_payload_splitter(plaintext_kfrag_payload)
        try:
            this_node.verify_kfrag_authorization(alice=policy_relayer,
                                                 kfrag=kfrag,
                                                 signed_writ=signed_writ,
                                                 work_order=work_order)
        except Policy.Unauthorized:
            message = f'{bob_identity_message} Unauthorized work order.'
            log.info(message)
            this_node.suspicious_activities_witnessed['unauthorized'].append(message)
            return Response(message, status=401)  # 401 - Unauthorized

        if not this_node.federated_only:

            # Verify Policy Payment (onchain)
            try:
                this_node.verify_policy_payment(hrac=hrac)
            except Policy.Unpaid:
                message = f"{bob_identity_message} Policy {hrac.hex()} is unpaid."
                record = (policy_relayer, message)
                this_node.suspicious_activities_witnessed['freeriders'].append(record)
                return Response(message, status=402)  # 402 - Payment Required
            except Policy.Unknown:
                message = f"{bob_identity_message} Policy {hrac.hex()} is not a published policy."
                return Response(message, status=404)  # 404 - Not Found

            # Verify Active Policy (onchain)
            try:
                this_node.verify_active_policy(hrac=hrac)
            except Policy.Inactive:
                message = f"{bob_identity_message} Policy {hrac.hex()} is not active."
                return Response(message, status=403)  # 403 - Forbidden
            except this_node.Policy.Expired:
                message = f"{bob_identity_message} Policy {hrac.hex()} is expired."
                return Response(message, status=403)  # 403 - Forbidden

        # Re-encrypt
        response = this_node._reencrypt(kfrag=kfrag,
                                        work_order=work_order,
                                        alice_verifying_key=alice_verifying_key)

        # Now, Ursula saves evidence of this workorder to her database...
        # Note: we give the work order a random ID to store it under.
        with datastore.describe(WorkOrderModel, str(uuid.uuid4()), writeable=True) as new_workorder:
            new_workorder.bob_verifying_key = bob_verifying_key
            new_workorder.bob_signature = bob_workorder_signature

        headers = {'Content-Type': 'application/octet-stream'}
        return Response(headers=headers, response=response)

    @rest_app.route('/revoke', methods=['POST'])
    def revoke():
        from nucypher.policy.orders import Revocation
        revocation = Revocation.from_bytes(request.data)
        # TODO: Implement offchain revocation.
        return Response(status=200)

    @rest_app.route('/treasure_map/<identifier>')
    def provide_treasure_map(identifier):
        headers = {'Content-Type': 'application/octet-stream'}
        try:
            with datastore.describe(TreasureMapModel, identifier) as stored_treasure_map:
                response = Response(stored_treasure_map.treasure_map, headers=headers)
            log.info(f"{this_node} providing TreasureMap {identifier}")
        except RecordNotFound:
            log.info(f"{this_node} doesn't have requested TreasureMap under {identifier}")
            response = Response(f"No Treasure Map with identifier {identifier}", status=404, headers=headers)
        return response

    @rest_app.route('/treasure_map/', methods=['POST'])
    def receive_treasure_map():
        """
        Okay, so we've received a TreasureMap to store. We begin verifying
        the treasure map by first validating the request and the received
        treasure map itself.

        We set the datastore identifier as the HRAC if the node is running
        as a decentralized node. Otherwise, we use the map_id in
        federated mode.
        """

        if not this_node.federated_only:
            from nucypher.policy.maps import SignedTreasureMap as _MapClass
        else:
            from nucypher.policy.maps import TreasureMap as _MapClass

        # Step 1: First, we verify the signature of the received treasure map.
        # This step also deserializes the treasure map if it's signed correctly.
        try:
            received_treasure_map = _MapClass.from_bytes(bytes_representation=request.data, verify=True)
        except _MapClass.InvalidSignature:
            log.info(f"Bad TreasureMap HRAC Signature; not storing for HRAC {received_treasure_map._hrac.hex()}")
            return Response("This TreasureMap's HRAC is not properly signed.", status=401)

        # Additionally, we determine the map identifier from the type of node.
        # If the node is federated, we also set the expiration for a week.
        if not this_node.federated_only:
            map_identifier = received_treasure_map._hrac.hex()
        else:
            map_identifier = received_treasure_map.public_id()
            expiration_date = MayaDT.from_datetime(datetime.utcnow() + timedelta(days=7))

        # Step 2: Check if we already have the treasure map.
        try:
            with datastore.describe(TreasureMapModel, map_identifier) as stored_treasure_map:
                if _MapClass.from_bytes(stored_treasure_map.treasure_map) == received_treasure_map:
                    return Response("Already have this map.", status=303)
        except RecordNotFound:
            # This appears to be a new treasure map that we don't have!
            pass

        # Step 3: If the node is decentralized, we check that the received
        # treasure map is valid pursuant to an active policy.
        # We also set the expiration from the data on the blockchain here.
        if not this_node.federated_only:
            policy = this_node.policy_agent.fetch_policy(policy_id=received_treasure_map._hrac)
            # If the Policy doesn't exist, the policy_data is all zeros.
            if policy.sponsor is NULL_ADDRESS:
                log.info(f"TreasureMap is for non-existent Policy; not storing {map_identifier}")
                return Response("The Policy for this TreasureMap doesn't exist.", status=409)

            # Check that this treasure map is from Alice per the Policy.
            if not received_treasure_map.verify_blockchain_signature(checksum_address=policy.owner):
                log.info(f"Bad TreasureMap ID; not storing {map_identifier}")
                return Response("This TreasureMap doesn't match a paid Policy.", status=402)

            # Check that this treasure map is valid for the Policy datetime and that it's not disabled.
            if policy.disabled or datetime.utcnow() >= datetime.utcfromtimestamp(policy.end_timestamp):
                log.info(f"Received TreasureMap for an expired/disabled policy; not storing {map_identifier}")
                return Response("This TreasureMap is for an expired/disabled policy.", status=403)
            expiration_date = MayaDT.from_datetime(datetime.utcfromtimestamp(policy.end_timestamp))

        # Step 4: Finally, we store our treasure map under its identifier!
        log.info(f"{this_node} storing TreasureMap {map_identifier}")
        with datastore.describe(TreasureMapModel, map_identifier, writeable=True) as new_treasure_map:
            new_treasure_map.treasure_map = bytes(received_treasure_map)
            new_treasure_map.expiration = expiration_date
        return Response("Treasure map stored!", status=201)

    @rest_app.route("/ping", methods=['GET', 'POST'])
    def ping():
        """
        GET: Asks this node: "What is my IP address?"
        POST: Asks this node: "Can you access my public information endpoint?"
        """

        if request.method == 'GET':
            requester_ip_address = request.remote_addr
            return Response(requester_ip_address, status=200)

        elif request.method == 'POST':
            try:
                requesting_ursula = Ursula.from_bytes(request.data)
                requesting_ursula.mature()
            except ValueError:
                return Response({'error': 'Invalid Ursula'}, status=400)
            else:
                initiator_address, initiator_port = tuple(requesting_ursula.rest_interface)

            # Compare requester and posted Ursula information
            request_address = request.remote_addr
            if request_address != initiator_address:
                message = f'Origin address mismatch: Request origin is {request_address} but metadata claims {initiator_address}.'
                return Response({'error': message}, status=400)

            #
            # Make a Sandwich
            #

            try:
                # Fetch and store initiator's teacher certificate.
                certificate = this_node.network_middleware.get_certificate(host=initiator_address, port=initiator_port)
                certificate_filepath = this_node.node_storage.store_node_certificate(certificate=certificate)
                requesting_ursula_bytes = this_node.network_middleware.client.node_information(host=initiator_address,
                                                                                               port=initiator_port,
                                                                                               certificate_filepath=certificate_filepath)
            except NodeSeemsToBeDown:
                return Response({'error': 'Unreachable node'}, status=400)  # ... toasted

            except InvalidNodeCertificate:
                return Response({'error': 'Invalid TLS certificate - missing checksum address'}, status=400)  # ... invalid

            # Compare the results of the outer POST with the inner GET... yum
            if requesting_ursula_bytes == request.data:
                return Response(status=200)
            else:
                return Response({'error': 'Suspicious node'}, status=400)

    @rest_app.route('/status/', methods=['GET'])
    def status():
        return_json = request.args.get('json') == 'true'
        omit_known_nodes = request.args.get('omit_known_nodes') == 'true'
        status_info = this_node.status_info(omit_known_nodes=omit_known_nodes)
        if return_json:
            return jsonify(status_info.to_json())
        headers = {"Content-Type": "text/html", "charset": "utf-8"}
        try:
            content = status_template.render(status_info)
        except Exception as e:
            text_error = mako_exceptions.text_error_template().render()
            html_error = mako_exceptions.html_error_template().render()
            log.debug("Template Rendering Exception:\n" + text_error)
            return Response(response=html_error, headers=headers, status=500)
        return Response(response=content, headers=headers)

    return rest_app


class TLSHostingPower(KeyPairBasedPower):
    _keypair_class = HostingKeypair
    provides = ("get_deployer",)

    class NoHostingPower(PowerUpError):
        pass

    not_found_error = NoHostingPower

    def __init__(self,
                 host: str,
                 public_certificate=None,
                 public_certificate_filepath=None,
                 *args, **kwargs) -> None:

        if public_certificate and public_certificate_filepath:
            # TODO: Design decision here: if they do pass both, and they're identical, do we let that slide?  NRN
            raise ValueError("Pass either a public_certificate or a public_certificate_filepath, not both.")

        if public_certificate:
            kwargs['keypair'] = HostingKeypair(certificate=public_certificate, host=host)
        elif public_certificate_filepath:
            kwargs['keypair'] = HostingKeypair(certificate_filepath=public_certificate_filepath, host=host)
        super().__init__(*args, **kwargs)
