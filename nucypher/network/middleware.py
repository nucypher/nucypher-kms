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


import requests
import socket
import ssl
import time
from bytestring_splitter import VariableLengthBytestring
from constant_sorrow.constants import CERTIFICATE_NOT_SAVED, EXEMPT_FROM_VERIFICATION
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from requests.exceptions import SSLError
from requests.packages.urllib3.exceptions import RequestError

from nucypher.blockchain.eth.networks import NetworksInventory
from nucypher.crypto.signing import signature_splitter
from nucypher.crypto.splitters import cfrag_splitter
from nucypher.utilities.logging import Logger

EXEMPT_FROM_VERIFICATION.bool_value(False)


class NucypherMiddlewareClient:
    library = requests
    timeout = 1.2

    def __init__(self, registry=None, *args, **kwargs):
        self.registry = registry

    @staticmethod
    def response_cleaner(response):
        return response

    def verify_and_parse_node_or_host_and_port(self, node_or_sprout, host, port):
        """
        Does two things:
        1) Verifies the node (unless it is EXEMPT_FROM_VERIFICATION, like when we initially get its certificate)
        2) Parses the node into a host and port, or returns the provided host and port.
        :return: A 3-tuple: host string, certificate, and the library to be used for the connection.
        """
        if node_or_sprout:
            if node_or_sprout is not EXEMPT_FROM_VERIFICATION:
                node = node_or_sprout.mature()  # Morph into a node.
                node.verify_node(network_middleware_client=self, registry=self.registry)
        return self.parse_node_or_host_and_port(node_or_sprout, host, port)

    def parse_node_or_host_and_port(self, node, host, port):
        if node:
            if any((host, port)):
                raise ValueError("Don't pass host and port if you are passing the node.")
            host = node.rest_url()
            certificate_filepath = node.certificate_filepath
        elif all((host, port)):
            host = f"{host}:{port}"
            certificate_filepath = CERTIFICATE_NOT_SAVED
        else:
            raise ValueError("You need to pass either the node or a host and port.")

        return host, certificate_filepath, self.library

    def invoke_method(self, method, url, *args, **kwargs):
        self.clean_params(kwargs)
        if not kwargs.get("timeout"):
            if self.timeout:
                kwargs["timeout"] = self.timeout
        response = method(url, *args, **kwargs)
        return response

    def clean_params(self, request_kwargs):
        """
        No cleaning needed.
        """

    def node_information(self, host, port, certificate_filepath):
        # TODO: The only time a node is exempt from verification - when we are first getting its info.
        response = self.get(node_or_sprout=EXEMPT_FROM_VERIFICATION,
                            host=host, port=port,
                            path="public_information",
                            timeout=2,
                            certificate_filepath=certificate_filepath)
        return response.content

    def __getattr__(self, method_name):
        # Quick sanity check.
        if method_name not in ("post", "get", "put", "patch", "delete"):
            raise TypeError(f"This client is for HTTP only - you need to use a real HTTP verb, not '{method_name}'.")

        def method_wrapper(path,
                           node_or_sprout=None,
                           host=None,
                           port=None,
                           certificate_filepath=None,
                           *args, **kwargs):
            host, node_certificate_filepath, http_client = self.verify_and_parse_node_or_host_and_port(node_or_sprout, host, port)

            if certificate_filepath:
                filepaths_are_different = node_certificate_filepath != certificate_filepath
                node_has_a_cert = node_certificate_filepath is not CERTIFICATE_NOT_SAVED
                if node_has_a_cert and filepaths_are_different:
                    raise ValueError("Don't try to pass a node with a certificate_filepath while also passing a"
                                     " different certificate_filepath.  What do you even expect?")
            else:
                certificate_filepath = node_certificate_filepath

            method = getattr(http_client, method_name)
            url = f"https://{host}/{path}"

            response = self.invoke_method(method, url, verify=certificate_filepath, *args, **kwargs)
            cleaned_response = self.response_cleaner(response)
            if cleaned_response.status_code >= 300:
                if cleaned_response.status_code == 400:
                    raise RestMiddleware.BadRequest(reason=cleaned_response.json)
                elif cleaned_response.status_code == 404:
                    m = f"While trying to {method_name} {args} ({kwargs}), server 404'd.  Response: {cleaned_response.content}"
                    raise RestMiddleware.NotFound(m)
                else:
                    m = f"Unexpected response while trying to {method_name} {args},{kwargs}: {cleaned_response.status_code} {cleaned_response.content}"
                    raise RestMiddleware.UnexpectedResponse(m, status=cleaned_response.status_code)
            return cleaned_response

        return method_wrapper

    def node_selector(self, node):
        return node.rest_url(), self.library

    def __len__(self):
        return 0  # Workaround so debuggers can represent objects of this class despite the unusual __getattr__.


class RestMiddleware:
    log = Logger()

    _client_class = NucypherMiddlewareClient

    TEACHER_NODES = {
        NetworksInventory.MAINNET: ('https://mainnet.nucypher.network:9151',),
        NetworksInventory.LYNX: ('https://lynx.nucypher.network:9151',),
        NetworksInventory.IBEX: ('https://ibex.nucypher.network:9151',),
    }

    class UnexpectedResponse(Exception):
        def __init__(self, message, status, *args, **kwargs):
            super().__init__(message, *args, **kwargs)
            self.status = status

    class NotFound(UnexpectedResponse):
        def __init__(self, *args, **kwargs):
            super().__init__(status=404, *args, **kwargs)

    class BadRequest(UnexpectedResponse):
        def __init__(self, reason, *args, **kwargs):
            self.reason = reason
            super().__init__(message=reason, status=400, *args, **kwargs)

    def __init__(self, registry=None):
        self.client = self._client_class(registry)

    def get_certificate(self, host, port, timeout=3, retry_attempts: int = 3, retry_rate: int = 2,
                        current_attempt: int = 0):

        socket.setdefaulttimeout(timeout)  # Set Socket Timeout

        try:
            self.log.info(f"Fetching seednode {host}:{port} TLS certificate")
            seednode_certificate = ssl.get_server_certificate(addr=(host, port))

        except socket.timeout:
            if current_attempt == retry_attempts:
                message = f"No Response from seednode {host}:{port} after {retry_attempts} attempts"
                self.log.info(message)
                raise ConnectionRefusedError("No response from {}:{}".format(host, port))
            self.log.info(f"No Response from seednode {host}:{port}. Retrying in {retry_rate} seconds...")
            time.sleep(retry_rate)
            return self.get_certificate(host, port, timeout, retry_attempts, retry_rate, current_attempt + 1)

        except OSError:
            raise  # TODO: #1835

        else:
            certificate = x509.load_pem_x509_certificate(seednode_certificate.encode(),
                                                         backend=default_backend())
            return certificate

    def propose_arrangement(self, node, arrangement):
        response = self.client.post(node_or_sprout=node,
                                    path="consider_arrangement",
                                    data=bytes(arrangement),
                                    timeout=2)
        return response

    def enact_policy(self, ursula, kfrag_id, payload):
        response = self.client.post(node_or_sprout=ursula,
                                    path=f'kFrag/{kfrag_id.hex()}',
                                    data=payload,
                                    timeout=2)
        return response

    def reencrypt(self, work_order):
        ursula_rest_response = self.send_work_order_payload_to_ursula(work_order)
        splitter = cfrag_splitter + signature_splitter
        cfrags_and_signatures = splitter.repeat(ursula_rest_response.content)
        return cfrags_and_signatures

    def revoke_arrangement(self, ursula, revocation):
        # TODO: Implement revocation confirmations
        response = self.client.delete(
            node_or_sprout=ursula,
            path=f"kFrag/{revocation.arrangement_id.hex()}",
            data=bytes(revocation),
        )
        return response

    def get_competitive_rate(self):
        return NotImplemented

    def get_treasure_map_from_node(self, node, map_identifier):
        response = self.client.get(node_or_sprout=node,
                                   path=f"treasure_map/{map_identifier}",
                                   timeout=2)
        return response

    def put_treasure_map_on_node(self, node, map_payload):
        response = self.client.post(node_or_sprout=node,
                                    path=f"treasure_map/",
                                    data=map_payload,
                                    timeout=2)
        return response

    def send_work_order_payload_to_ursula(self, work_order):
        payload = work_order.payload()
        id_as_hex = work_order.arrangement_id.hex()
        response = self.client.post(
            node_or_sprout=work_order.ursula,
            path=f"kFrag/{id_as_hex}/reencrypt",
            data=payload,
            timeout=2
        )
        return response

    def check_rest_availability(self, initiator, responder):
        response = self.client.post(node_or_sprout=responder,
                                    data=bytes(initiator),
                                    path="ping",
                                    timeout=6,  # Two round trips are expected
                                    )
        return response

    def get_nodes_via_rest(self,
                           node,
                           announce_nodes=None,
                           nodes_i_need=None,
                           fleet_checksum=None):
        if nodes_i_need:
            # TODO: This needs to actually do something.  NRN
            # Include node_ids in the request; if the teacher node doesn't know about the
            # nodes matching these ids, then it will ask other nodes.
            pass

        if fleet_checksum:
            params = {'fleet': fleet_checksum}
        else:
            params = {}

        if announce_nodes:
            payload = bytes().join(bytes(VariableLengthBytestring(n)) for n in announce_nodes)
            response = self.client.post(node_or_sprout=node,
                                        path="node_metadata",
                                        params=params,
                                        data=payload,
                                        )
        else:
            response = self.client.get(node_or_sprout=node,
                                       path="node_metadata",
                                       params=params)

        return response
