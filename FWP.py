import re
import socket
import sys
import threading
import time
import traceback
import logging
import logging.config
import os
import configparser

log = logging.getLogger(__name__
                        )
config = None
bufsize = 1024 * 128


def init_config():
    # print('Loading config at startup!')
    global config
    config = configparser.ConfigParser()
    config.read('config/configs.ini')


# Init config right away
init_config()

binding = set()


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


udp_nat_port = {}


def forward_udp(params):
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sk.settimeout(300)
    sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sk.bind((params[1], int(params[2])))
    while True:
        client = sk.recvfrom(bufsize)
        if client:
            if client[1] not in udp_nat_port:
                server_socket = socket.socket(
                    socket.AF_INET, socket.SOCK_DGRAM)
                server_socket.connect((params[4], int(params[5])))
                server_socket.sendall(client[0])
                server_msg = server_socket.recvfrom(bufsize)
                udp_nat_port[client[1]] = server_socket
                udp_nat_port[server_msg[1]] = client[1]
                sk.sendto(server_msg[0], client[1])
                thread = threading.Thread(target=forward_udp_to_udp, args=[
                                          sk, server_socket])
                thread.start()
            else:
                server_socket = udp_nat_port.get(client[1])
                server_socket.sendall(client[0])


def forward_udp_to_udp(listen_socket: socket.socket, client_socket: socket.socket):
    while True:
        try:
            server_msg = client_socket.recvfrom(bufsize)
            if server_msg:
                listen_socket.sendto(
                    server_msg[0], udp_nat_port[server_msg[1]])
        except:
            # If it throws exception, looks like the socket has been closed, let's close our socket
            try:
                client_socket.shutdown(socket.SHUT_RD)
            except:
                print()
            try:
                del udp_nat_port[udp_nat_port[server_msg[1]]]
                log.debug("Removing entry from map to prevent anything wrong")
            except:
                print()
            try:
                del udp_nat_port[server_msg[1]]
            except:
                print()


def forward_tcp(params):
    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.bind((params[1], int(params[2])))
    sk.listen(5)
    binding.add(sk)
    try:
        while True:
            client = sk.accept()[0]
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # At the moment, udp over tcp is not currently supported
            server.connect((params[4], int(params[5])))
            log.info("Routing connect: %s ---> %s ---> %s ---> %s" %
                     (client.getpeername(), client.getsockname(), server.getsockname(), server.getpeername()))
            threading._start_new_thread(forward_tcp_to_tcp, (client, server))
            threading._start_new_thread(forward_tcp_to_tcp, (server, client))
    except Exception as e:
        sk.shutdown(socket.SHUT_RD)
        traceback.print_exc()
    finally:
        thread = threading.Thread(target=forward_tcp, args=[params])


def forward_tcp_to_tcp(source, destination):
    try:
        log.debug("Ongoing connection route: %s ---> %s ---> %s" %
                  (source.getpeername(), source.getsockname(), destination.getpeername()))
    except:
        # Do nothing
        log.debug("Socket closed maybe??")
    string = ' '
    while string:
        string = source.recv(1024)
        if string:
            destination.sendall(string)
        else:
            try:
                source.shutdown(socket.SHUT_RD)
            except:
                # traceback.print_exc()
                print()
            try:
                destination.shutdown(socket.SHUT_WR)
            except:
                # traceback.print_exc()
                print()


def parse_params(param):
    to_split = re.split("\\s+", param)
    # log.info(to_split)
    if len(to_split) < 6:
        return None
    else:
        return [to_split[0], to_split[1], to_split[2], to_split[3], to_split[4], to_split[5]]


def main():
    log.info("ANM makes me do this, dont blame me, blame yourself")
    # Let's read params from file, for security reason, I will read the file from current directory, then parse it, catch me if you can bitch!
    # The file name should be "hack code" to fw_params.so, rofl, they would not open this cause it looks like a fucking library file
    params = set()  # Create a set, so we can avoid duplicate entry
    running = set()
    command = "reload"
    while True:  # For whatever happen, even the sky is falling down, keep the program alive xD
        if command == "reload":
            try:
                log.info("Forwarding!!!!!!!!!!!!!!")
                with open(os.path.join(os.getcwd(), 'files', 'fw_params.so'), 'r') as f:
                    lines = f.readlines()
                    log.debug(lines)
                    for line in lines:
                        params.add(line)
                # Kaka, we have a list need to do
                for param in params:
                    # log.info(param)
                    if param not in running:
                        running.add(param)
                    else:
                        log.info("%s is NAT-ed, Ignore!!" % param)
                        continue
                    param = parse_params(param=param)
                    # log.info(param)
                    if param is not None:
                        log.info("Forwarding with params: Source - %s:%s, Dest - %s:%s" %
                                 (param[1], param[2], param[4], param[5]))
                        # Fork TCP Forward
                        if param[0] == 'tcp':
                            thread = threading.Thread(
                                target=forward_tcp, args=[param])
                            thread.start()
                        # Fork UDP Forward
                        if param[0] == 'udp':
                            thread = threading.Thread(
                                target=forward_udp, args=[param])
                            thread.start()
            except:
                traceback.print_exc()
            finally:
                command = ""
        elif command == "exit":
            for sk in binding:
                try:
                    sk.shutdown(socket.SHUT_RD)
                except:
                    traceback.print_exc()
            sys.exit(1)
        else:
            log.info("Command not found!")
            # log.info(command)
        command = input()


if __name__ == '__main__':
    # Init the fucking log
    init_log()
    # And start the program
    main()
