import random
from socket import SHUT_RD
import os
import sys
sys.path.insert(0, os.getcwd())
from PortForwarding import PortForwarding as pw
from tornado.web import Application, RequestHandler
from typing import Dict
from cryptography.fernet import Fernet
from concurrent.futures import ThreadPoolExecutor
from tornado.concurrent import run_on_executor
from tornado.web import Application, RequestHandler, escape, gen
from tornado.ioloop import IOLoop
import socket
import configparser
import logging
import logging.config
TCP_PROTO = 'tcp'
UDP_PROTO = 'udp'
log = logging.getLogger(__name__)
config = None
udp_bufsize = 1024 * 64
tcp_bufsize = 1024 * 64

SYMETRIC_KEY: str = ''
fernet: Fernet = None

mapping_connection: Dict = {}


def read_symtrickey_from_file() -> str:
    with open('./files/symetric.key', 'r') as f:
        return f.readline()


def init_config():
    # print('Loading config at startup!')
    global config
    config = configparser.ConfigParser()
    config.read('config/configs.ini')


def init_log():
    global config
    # Just a workaround, but whatever, this is just a cheap script
    if os.path.join(config['LOGGER']['log_file_path']):
        if not os.path.exists(os.path.join(config['LOGGER']['log_file_path'])):
            os.makedirs(os.path.join(config['LOGGER']['log_file_path']))
    logging_config = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'standard': {
                'format': '%(asctime)s [%(levelname)s] %(name)s: %(lineno)d: %(message)s'
            },
        },
        'handlers': {
            'default_handler': {
                'class': 'logging.handlers.TimedRotatingFileHandler',
                'level': config['LOGGER']['file_log_level'],
                'formatter': 'standard',
                'filename': os.path.join(config['LOGGER']['log_file_path'], 'application.log'),
                'encoding': 'utf8',
                'backupCount': 10,
                'when': 'd',
                'interval': 1,
            },
            'stdout_handler': {
                'class': 'logging.StreamHandler',
                'level': config['LOGGER']['std_out_log_level'],
                'formatter': 'standard'
            }
        },
        'loggers': {
            '': {
                'handlers': ['default_handler', 'stdout_handler'],
                'level': config['LOGGER']['default_log_level'],
                'propagate': False
            }
        }
    }
    logging.config.dictConfig(logging_config)


def decode(input: str) -> str:
    return fernet.decrypt(input.encode())


def encode(input: str) -> str:
    return fernet.encrypt(input.encode())


class ProxyForwardHandler(RequestHandler):

    executor = ThreadPoolExecutor(max_workers=50)

    # def set_default_headers(self):
    #     log.debug("Setting up CORS")
    #     self.set_header("Access-Control-Allow-Origin", "*")
    #     self.set_header("Access-Control-Allow-Headers", "*")
    #     self.set_header('Access-Control-Allow-Methods', "*")

    # def options(self):
    #     # no body
    #     self.set_status(204)
    #     self.finish()

    @run_on_executor
    def get(self):
        request_parse = self.request.path
        request_parse = request_parse[1:]
        decode_request = decode(request_parse).decode()
        #log.info("DAY LA REQUEST: " + decode_request)
        # If the request is not in the map, it does look like that it's a new port forwarding request
        if decode_request in mapping_connection:
            data: socket.socket = mapping_connection[decode_request]
            message = data.recv(pw.tcp_bufsize)
            # log.info(message)
            if message:
                #log.info("Co send voi " + str(message))
                self.set_status(200)
                self.write(message)
            else:
                try:
                    data.shutdown(SHUT_RD)
                except:
                    pass
                del mapping_connection[decode_request]
                self.set_status(404)
            return
        if len(decode_request.split(":")) == 3:
            decode_request = decode_request.split(":")
            # log.info(decode_request)
            proto, dest_ip, dest_port = decode_request[0], decode_request[1], decode_request[2]
            # Create a reserve socket then connect it to remote endpoint
            reserved_socket: socket.socket = pw.create_socket(proto, False)
            reserved_socket.connect((dest_ip, int(dest_port)))
            random_key = random.randint(0, 9999999)
            mapping_connection[str(random_key)] = reserved_socket
            # log.info(reserved_socket)
            # From now on, we will use this key as a long-polling GET method to get reponse from server
            self.set_status(201)
            self.write(str(random_key))
        else:
            self.set_status(404)
            # self.finish()

    @run_on_executor
    def post(self):
        request_parse = self.request.path
        request_parse = request_parse[1:]
        decode_request = decode(request_parse).decode()
        # log.info(decode_request)
        # If the request is not in the list, it does look like that it's a new port forwarding request
        if decode_request in mapping_connection:
            data: socket.socket = mapping_connection[decode_request]
            data.sendall(self.request.body)
            self.set_status(200)
        else:
            self.set_status(404)


def make_app():
    urls = [(r'/.*', ProxyForwardHandler)]
    return Application(urls, debug=True)


if __name__ == "__main__":
    init_config()
    init_log()
    SYMETRIC_KEY = read_symtrickey_from_file()
    fernet = Fernet(SYMETRIC_KEY)
    app = make_app()
    port: int = int(config['HTTPTUNNEL']['listen-port'])
    app.listen(port)
    log.info("HTTP Server is listening on port %d" % port)
    IOLoop.instance().start()
