import traceback
import ssl
from tornado import web
import websocket
import argparse
import requests
import logging.config
import logging
import configparser
import tornado
from cryptography.fernet import Fernet
from socket import SHUT_RD, timeout
from concurrent.futures import thread
import threading
import socket
import sys
import os

if __name__ == '__main__':
    sys.path.insert(0, os.getcwd())
    print(os.getcwd())
    from PortForwarding import PortForwarding as pw

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", help="Listening interface", required=True)
    parser.add_argument("--port",
                        help="Listening port", required=True)
    parser.add_argument("-x", help="Proxy URL")
    parser.add_argument("-r", help="protocol:host:port", required=True)
    parser.add_argument("--url", help="Your Proxy Pass URL xD", required=True)
    parser = parser.parse_args()
URL = parser.url

log = logging.getLogger(__name__)
config = None
fernet: Fernet = None
SYMETRIC_KEY: str = ''


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


def shutdown_socket(to_shutdown: socket.socket):
    try:
        #log.info("Shutting down socket")
        to_shutdown.shutdown(SHUT_RD)
        #log.info("Shutdown socket successfully")
    except:
        pass


def listen_and_forward_to_websocket(client: socket, ws: websocket.WebSocket):
    message = ' '
    while message:
        # log.info(client)
        message = client.recv(pw.tcp_bufsize)
        if message:
            # log.info(type(message))
            try:
                ws.send_binary(message)
            except:
                pass
        else:
            shutdown_socket(client)
            try:
                ws.close()
            except:
                pass
            break


def listen_ws_and_forward_to_socket(client: socket, ws: websocket.WebSocket):
    message = ' '
    while message:
        message = ws.recv()
        if message:
            # log.info(message)
            client.sendall(message)
        else:
            #log.info("Dong cmn socket roi")
            shutdown_socket(client)


if __name__ == '__main__':
    init_config()
    init_log()
    listen_socket: socket.socket = pw.create_socket('tcp', True)
    listen_socket.bind((parser.host, int(parser.port)))
    listen_socket.listen(5)
    SYMETRIC_KEY = read_symtrickey_from_file()
    log.info("Your symetric key: " + SYMETRIC_KEY)
    fernet = Fernet(SYMETRIC_KEY)
    while(True):
        try:
            client = listen_socket.accept()[0]
            ws = websocket.WebSocket()
            # If proxy is required? Then parse it
            http_proxy_host = ''
            http_proxy_port = 1
            if parser.x:
                proxy = parser.x
                proxy = proxy.split(":")
                if len(proxy) == 2:
                    http_proxy_host = proxy[0]
                    http_proxy_port = proxy[1]
                else:
                    log.info(
                        "Proxy should be informat http_host:http_port (1.1.1.1:80)")
                    sys.exit(1)
            if parser.x:
                log.info("Connecting via proxy " + str(proxy))
                ws.connect(URL + "/",
                           timeout=60, http_proxy_host=http_proxy_host, http_proxy_port=http_proxy_port)
            else:
                ws.connect(URL + "/",
                           timeout=60)
            ws.send(encode(parser.r))
            message = ws.recv()
            if message == 'OK':
                log.info("Successfully tunnel")
                threading._start_new_thread(
                    listen_and_forward_to_websocket, (client, ws))
                threading._start_new_thread(
                    listen_ws_and_forward_to_socket, (client, ws))
        except Exception as e:
            log.error(e)
            traceback.print_exc()
