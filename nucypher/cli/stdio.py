#!/usr/local/bin/python3

import os
import sys
import json
import struct
import traceback
import logging

from click.exceptions import BadParameter
from click.testing import CliRunner
from nucypher.cli.main import nucypher_cli
from nucypher.config.constants import USER_LOG_DIR
from nucypher.characters.control.interfaces import PUBLIC_INTERFACES

log_file = LOG_PATH = os.path.join(USER_LOG_DIR, f'native-messaging.log')
logging.basicConfig(filename=log_file, filemode='w', level=logging.DEBUG)

def get_message():
    message_length = sys.stdin.buffer.read(4)
    if len(message_length) == 0:
        sys.exit(0)
    messageLength = struct.unpack('@I', message_length)[0]
    message = sys.stdin.buffer.read(messageLength).decode('utf-8')
    return json.loads(message)

def encode_message(message):
    """Encode a message for transmission, given its content. """
    encodedContent = json.dumps(message).encode('utf-8')
    encodedLength = struct.pack('@I', len(encodedContent))
    return {'length': encodedLength, 'content': encodedContent}


# Send an encoded message to stdout
def send_message(message):
    sys.stdout.buffer.write(message['length'])
    sys.stdout.buffer.write(message['content'])
    sys.stdout.buffer.flush()


click_runner = CliRunner()  # TODO: Make Proper

try:
    logging.debug('starting up')
    while True:
        request = get_message()  # < -------- REQUEST FROM BROWSER

        logging.debug(f"incoming data: {request}")
        action = request['action']
        character = request.get('character', '')

        options_request = request.pop('options', False)

        if options_request and character:
            logging.debug("options request")
            interface = PUBLIC_INTERFACES.get(character)
            schema = interface().schema_spec
            logging.debug(schema)
            output = {
                "input": request,
                "route": f"{character}.options",
                "result": schema,
            }
            final_message = encode_message(output)
            logging.debug(f"Sending to the browser: {final_message}")
            send_message(final_message)  # < ---- RESPONSE TO BROWSER

        else:
            params = []
            if character:
                params.append(character)
            params.append(action)
            route_key = '.'.join(params)
            #  if there is no password, the process will just hang
            #  so lets deal with that now.


            try:
                NUCYPHER_KEYRING_PASSWORD = request['keyring_password']
            except KeyError:
                output = {
                    "input": request,
                    "result": None,
                    "error": "keyring password is required",
                    "route": route_key,
                }
                send_message(encode_message(output))
            else:
                params.append('--json-ipc')

                for param, value in request['args'].items():
                    param = param.replace("_", "-")
                    if value is True:
                        params.append(f"--{param}")
                    else:
                        params.extend((f"--{param}", value))

                # INTERNAL INTERFACE
                environ = {'NUCYPHER_KEYRING_PASSWORD': NUCYPHER_KEYRING_PASSWORD}
                result = None
                try:
                    logging.debug(f"calling nucypher with params: {' '.join(params)}")
                    nc_result = click_runner.invoke(nucypher_cli, params, catch_exceptions=True, env=environ)
                    logging.debug(f"result is: {nc_result.output}")
                    result = nc_result.output
                except BadParameter as e:
                    logging.debug(f"NuCypher CLI error ==== \n {'.'.join(dir(e).keys())}")

                    exc_type, exc_value, exc_traceback = sys.exc_info()
                    lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
                    err = ''.join('\n' + line for line in lines)  # Log it or whatever here
                    logging.debug(f"NuCypher CLI error ==== \n {err}")
                except Exception as e:
                    logging.debug(f"NuCypher CLI error ==== \n {'.'.join(dir(e).keys())}")
                ####

                del request['keyring_password']
                output = {
                    "input": request,
                    "route": route_key,
                    "result": result,
                }
                final_message = encode_message(output)
                logging.debug(f"Sending to the browser: {final_message}")
                send_message(final_message)  # < ---- RESPONSE TO BROWSER

except Exception:
    exc_type, exc_value, exc_traceback = sys.exc_info()
    lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
    err = ''.join('\n' + line for line in lines)  # Log it or whatever here
    logging.debug(f"ERROR ============= \n {err}")