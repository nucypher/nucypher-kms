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

import binascii
import os
import uuid
from bytestring_splitter import BytestringSplitter
from constant_sorrow import constants
from constant_sorrow.constants import FLEET_STATES_MATCH, NO_BLOCKCHAIN_CONNECTION, NO_KNOWN_NODES, RELAX
from datetime import datetime, timedelta
from flask import Flask, Response, jsonify, request
from mako import exceptions as mako_exceptions
from mako.template import Template
from maya import MayaDT
from typing import Tuple
from umbral.kfrags import KFrag
from web3.exceptions import TimeExhausted

import nucypher
from nucypher.acumen.comprehension import BUCKETS
from nucypher.config.constants import MAX_UPLOAD_CONTENT_LENGTH
from nucypher.crypto.api import MissingCertificatePseudonym
from nucypher.crypto.keypairs import HostingKeypair
from nucypher.crypto.kits import UmbralMessageKit
from nucypher.crypto.powers import KeyPairBasedPower, PowerUpError
from nucypher.crypto.signing import InvalidSignature
from nucypher.crypto.utils import canonical_address_from_umbral_key
from nucypher.datastore.datastore import Datastore, RecordNotFound, DatastoreTransactionError
from nucypher.datastore.models import PolicyArrangement, TreasureMap, Workorder
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
        log: Logger=Logger("http-application-layer")
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

    from nucypher.characters.lawful import Alice, Ursula
    _alice_class = Alice
    _node_class = Ursula

    rest_app = Flask("ursula-service")
    rest_app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_CONTENT_LENGTH

    @rest_app.route("/public_information")
    def public_information():
        """REST endpoint for public keys and address."""
        response = Response(response=bytes(this_node), mimetype='application/octet-stream')
        return response

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

            except MissingCertificatePseudonym:
                return Response({'error': 'Invalid TLS certificate - missing checksum address'}, status=400)  # ... invalid

            # Compare the results of the outer POST with the inner GET... yum
            if requesting_ursula_bytes == request.data:
                return Response(status=200)
            else:
                return Response({'error': 'Suspicious node'}, status=400)

    @rest_app.route('/node_metadata', methods=["GET"])
    def all_known_nodes():
        headers = {'Content-Type': 'application/octet-stream'}

        if this_node._learning_deferred is not RELAX and not this_node._learning_task.running:
            # TODO: Is this every something we don't want to do?
            this_node.start_learning_loop()

        if this_node.known_nodes.checksum is NO_KNOWN_NODES:
            return Response(b"", headers=headers, status=204)

        label = request.args.get('label')
        known_nodes_bytestring = this_node.bytestring_of_known_nodes(label=label)
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
        else:
            sprouts = _node_class.batch_from_bytes(request.data)
            for node in sprouts:
                this_node.remember_node(node)
            # TODO: What's the right status code here?  202?  Different if we already knew about the node(s)?
            return all_known_nodes()

    @rest_app.route('/consider_arrangement', methods=['POST'])
    def consider_arrangement():
        from nucypher.policy.policies import Arrangement
        arrangement = Arrangement.from_bytes(request.data)

        # TODO: Look at the expiration and figure out if we're even staking that long.  1701
        with datastore.describe(PolicyArrangement, arrangement.id.hex(), writeable=True) as new_policy_arrangement:
            new_policy_arrangement.arrangement_id = arrangement.id.hex().encode()
            new_policy_arrangement.expiration = arrangement.expiration
            new_policy_arrangement.alice_verifying_key = arrangement.alice_verifying_key

        # TODO: Fine, we'll add the arrangement here, but if we never hear from Alice again to enact it,
        # we need to prune it at some point.  #1700

        headers = {'Content-Type': 'application/octet-stream'}
        # TODO: Make this a legit response #234.
        return Response(b"This will eventually be an actual acceptance of the arrangement.", headers=headers)

    @rest_app.route("/kFrag/<id_as_hex>", methods=['POST'])
    def set_policy(id_as_hex):
        """
        REST endpoint for setting a kFrag.
        """
        policy_message_kit = UmbralMessageKit.from_bytes(request.data)

        alices_verifying_key = policy_message_kit.sender_verifying_key
        alice = _alice_class.from_public_keys(verifying_key=alices_verifying_key)

        try:
            cleartext = this_node.verify_from(alice, policy_message_kit, decrypt=True)
        except InvalidSignature:
            # TODO: Perhaps we log this?  Essentially 355.
            return Response("Invalid Signature", status_code=400)

        if not this_node.federated_only:
            # This splitter probably belongs somewhere canonical.
            transaction_splitter = BytestringSplitter(32)
            tx, kfrag_bytes = transaction_splitter(cleartext, return_remainder=True)

            try:
                # Get all of the arrangements and verify that we'll be paid.
                # TODO: We'd love for this part to be impossible to reduce the risk of collusion.  #1274
                arranged_addresses = this_node.policy_agent.fetch_arrangement_addresses_from_policy_txid(tx, timeout=this_node.synchronous_query_timeout)
            except TimeExhausted:
                # Alice didn't pay.  Return response with that weird status code.
                this_node.suspicious_activities_witnessed['freeriders'].append((alice, f"No transaction matching {tx}."))
                return Response(f"No paid transaction matching {tx} for this node", status=402)

            this_node_has_been_arranged = this_node.checksum_address in arranged_addresses
            if not this_node_has_been_arranged:
                this_node.suspicious_activities_witnessed['freeriders'].append((alice, f"The transaction {tx} does not list me as a Worker - it lists {arranged_addresses}."))
                return Response(f"This node was not listed as servicing the policy in transaction {tx}", status=402)
        else:
            _tx = NO_BLOCKCHAIN_CONNECTION
            kfrag_bytes = cleartext
        kfrag = KFrag.from_bytes(kfrag_bytes)

        if not kfrag.verify(signing_pubkey=alices_verifying_key):
            return Response(f"Signature on {kfrag} is invalid", status=403)

        with datastore.describe(PolicyArrangement, id_as_hex, writeable=True) as policy_arrangement:
            if not policy_arrangement.alice_verifying_key == alice.stamp.as_umbral_pubkey():
                return Response("Policy arrangement's signing key does not match sender's", status=403)
            policy_arrangement.kfrag = kfrag

        # TODO: Sign the arrangement here.  #495
        return ""  # TODO: Return A 200, with whatever policy metadata.

    @rest_app.route('/kFrag/<id_as_hex>', methods=["DELETE"])
    def revoke_arrangement(id_as_hex):
        """
        REST endpoint for revoking/deleting a KFrag from a node.
        """
        from nucypher.policy.collections import Revocation

        revocation = Revocation.from_bytes(request.data)
        log.info("Received revocation: {} -- for arrangement {}".format(bytes(revocation).hex(), id_as_hex))

        # Check that the request is the same for the provided revocation
        if not id_as_hex == revocation.arrangement_id.hex():
            log.debug("Couldn't identify an arrangement with id {}".format(id_as_hex))
            return Response(status_code=400)

        try:
            with datastore.describe(PolicyArrangement, id_as_hex, writeable=True) as policy_arrangement:
                if revocation.verify_signature(policy_arrangement.alice_verifying_key):
                    policy_arrangement.delete()
        except (DatastoreTransactionError, InvalidSignature) as e:
            log.debug("Exception attempting to revoke: {}".format(e))
            return Response(response='KFrag not found or revocation signature is invalid.', status=404)
        else:
            log.info("KFrag successfully removed.")
            return Response(response='KFrag deleted!', status=200)

    @rest_app.route('/kFrag/<id_as_hex>/reencrypt', methods=["POST"])
    def reencrypt_via_rest(id_as_hex):

        # Get Policy Arrangement
        try:
            arrangement_id = binascii.unhexlify(id_as_hex)
        except (binascii.Error, TypeError):
            return Response(response=b'Invalid arrangement ID', status=405)
        try:
            # Get KFrag
            # TODO: Yeah, well, what if this arrangement hasn't been enacted?  1702
            with datastore.describe(PolicyArrangement, id_as_hex) as policy_arrangement:
                kfrag = policy_arrangement.kfrag
                alice_verifying_key = policy_arrangement.alice_verifying_key
        except RecordNotFound:
            return Response(response=arrangement_id, status=404)

        # Get Work Order
        from nucypher.policy.collections import WorkOrder  # Avoid circular import
        alice_address = canonical_address_from_umbral_key(alice_verifying_key)
        work_order_payload = request.data
        work_order = WorkOrder.from_rest_payload(arrangement_id=arrangement_id,
                                                 rest_payload=work_order_payload,
                                                 ursula=this_node,
                                                 alice_address=alice_address)
        log.info(f"Work Order from {work_order.bob}, signed {work_order.receipt_signature}")

        # Re-encrypt
        response = this_node._reencrypt(kfrag=kfrag,
                                        work_order=work_order,
                                        alice_verifying_key=alice_verifying_key)

        # Now, Ursula saves this workorder to her database...
        # Note: we give the work order a random ID to store it under.
        with datastore.describe(Workorder, str(uuid.uuid4()), writeable=True) as new_workorder:
            new_workorder.arrangement_id = work_order.arrangement_id
            new_workorder.bob_verifying_key = work_order.bob.stamp.as_umbral_pubkey()
            new_workorder.bob_signature = work_order.receipt_signature

        headers = {'Content-Type': 'application/octet-stream'}
        return Response(headers=headers, response=response)

    @rest_app.route('/treasure_map/<identifier>')
    def provide_treasure_map(identifier):
        headers = {'Content-Type': 'application/octet-stream'}

        try:
            with datastore.describe(TreasureMap, identifier) as stored_treasure_map:
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

        We set the datastore identifier as the HRAC iff the node is running
        as a decentralized node. Otherwise, we use the map_id in
        federated mode.
        """
        if not this_node.federated_only:
            from nucypher.policy.collections import SignedTreasureMap as _MapClass
        else:
            from nucypher.policy.collections import TreasureMap as _MapClass

        # Step 1: First, we verify the signature of the received treasure map.
        # This step also deserializes the treasure map iff it's signed correctly.
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
            with datastore.describe(TreasureMap, map_identifier) as stored_treasure_map:
                if _MapClass.from_bytes(stored_treasure_map.treasure_map) == received_treasure_map:
                    return Response("Already have this map.", status=303)
        except RecordNotFound:
            # This appears to be a new treasure map that we don't have!
            pass

        # Step 3: If the node is decentralized, we check that the received
        # treasure map is valid pursuant to an active policy.
        # We also set the expiration from the data on the blockchain here.
        if not this_node.federated_only:
            policy_data, alice_checksum_address = this_node.policy_agent.fetch_policy(
                    received_treasure_map._hrac,
                    with_owner=True)
            # If the Policy doesn't exist, the policy_data is all zeros.
            if not policy_data[5]:
                log.info(f"TreasureMap is for non-existent Policy; not storing {map_identifier}")
                return Response("The Policy for this TreasureMap doesn't exist.", status=409)

            # Check that this treasure map is from Alice per the Policy.
            if not received_treasure_map.verify_blockchain_signature(checksum_address=alice_checksum_address):
                log.info(f"Bad TreasureMap ID; not storing {map_identifier}")
                return Response("This TreasureMap doesn't match a paid Policy.", status=402)

            # Check that this treasure map is valid for the Policy datetime and that it's not disabled.
            if policy_data[0] or datetime.utcnow() >= datetime.utcfromtimestamp(policy_data[5]):
                log.info(f"Received TreasureMap for an expired/disabled policy; not storing {map_identifier}")
                return Response("This TreasureMap is for an expired/disabled policy.", status=402)
            expiration_date = MayaDT.from_datetime(datetime.utcfromtimestamp(policy_data[5]))

        # Step 4: Finally, we store our treasure map under its identifier!
        log.info(f"{this_node} storing TreasureMap {map_identifier}")
        with datastore.describe(TreasureMap, map_identifier, writeable=True) as new_treasure_map:
            new_treasure_map.treasure_map = bytes(received_treasure_map)
            new_treasure_map.expiration = expiration_date
        return Response("Treasure map stored!", status=201)

    @rest_app.route('/status/', methods=['GET'])
    def status():
        label = request.args.get('label')
        if label:
            label = label.upper()
        if request.args.get('json'):
            payload = this_node.abridged_node_details(raise_invalid=False)
            response = jsonify(payload)
            return response

        else:
            headers = {"Content-Type": "text/html", "charset": "utf-8"}
            previous_states = list(reversed(this_node.known_nodes.states.values()))[:5]

            # Ensure these nodes are matured for inspection
            peers = this_node.known_nodes.get_nodes(label=label)
            for node in peers:
                node.mature()

            try:
                content = status_template.render(this_node=this_node,
                                                 buckets=[label] if label else BUCKETS,
                                                 known_nodes=this_node.known_nodes,
                                                 previous_states=previous_states,
                                                 domain=domain,
                                                 version=nucypher.__version__,
                                                 checksum_address=this_node.checksum_address)
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
