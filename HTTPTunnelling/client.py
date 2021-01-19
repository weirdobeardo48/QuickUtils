import argparse
from config.init_config import ConfigUtils
from logger.get_logger import LoggerUtils
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
from PortForwarding import SimplePortForwarding as pw

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", help="Listening interface", required=True)
    parser.add_argument("--port",
                        help="Listening port", required=True)
    parser.add_argument("-x", help="Proxy URL")
    parser.add_argument("-r", help="protocol:host:port", required=True)
    parser.add_argument("--url", help="Your Proxy Pass URL xD", required=True)
    parser = parser.parse_args()
if parser.x:
    proxyDict = {
        "http": parser.x
    }

URL = parser.url

log = logging.getLogger(__name__)
config = None
fernet: Fernet = None
SYMETRIC_KEY: str = ''


def read_symtrickey_from_file() -> str:
    with open('./files/symetric.key', 'r') as f:
        return f.readline()


logger_utils = LoggerUtils()
config_utils = ConfigUtils()

if __name__ == "__main__":
    config = config_utils.get_configparser("./config/configs.ini")
    log = logger_utils.init_log(config=config)


def decode(input: str) -> str:
    return fernet.decrypt(input.encode()).decode()


def encode(input: str) -> str:
    return fernet.encrypt(input.encode()).decode()


def shutdown_socket(to_shutdown: socket.socket):
    try:
        #log.info("Shutting down socket")
        to_shutdown.shutdown(SHUT_RD)
        #log.info("Shutdown socket successfully")
    except:
        pass


def get_and_forward_to_client(client: socket, id: str):
    while True:
        try:
            r = requests.get(URL + "/" +
                             (encode(id)), timeout=1200, proxies=proxyDict)
            if r.status_code == 200:
                ## log.info("Kaka " + str(r.content))
                client.sendall(r.content)
            else:
                shutdown_socket(client)
                return
        except:
            pass


def listen_and_forward_to_http_server(client: socket, id: str):
    # log.info(id)
    while True:
        message = ' '
        message = client.recv(pw.tcp_bufsize)
        if message:
            try:
                r = requests.post(URL + "/" +
                                  (encode(id)), message, timeout=20, proxies=proxyDict)
                if r.status_code != 200:
                    shutdown_socket(client)
                    break
            except:
                pass
        else:
            shutdown_socket(client)
            break


if __name__ == '__main__':
    listen_socket: socket.socket = pw.create_socket('tcp', True)
    listen_socket.bind((parser.host, int(parser.port)))
    listen_socket.listen(5)
    # Add to the listening socket set
    SYMETRIC_KEY = read_symtrickey_from_file()
    #log.info("Your symetric key: " + SYMETRIC_KEY)
    fernet = Fernet(SYMETRIC_KEY)
    while(True):
        try:
            client = listen_socket.accept()[0]
            #log.info("OK GO ")
            r = requests.get(URL + "/" +
                             encode(parser.r), timeout=10, proxies=proxyDict, verify=False)
            # log.info(r.text)
            if r.status_code == 201:
                threading._start_new_thread(
                    get_and_forward_to_client, (client, r.text))
                threading._start_new_thread(
                    listen_and_forward_to_http_server, (client, r.text))
        except Exception as e:
            log.exception(e)
