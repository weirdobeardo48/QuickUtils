#!/usr/bin/python3
"""
This script is written By TruongNX to bypass several inspection tools at work. Use it at your own risk! Kaka
"""
import time
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

TCP_PROTO = 'tcp'
UDP_PROTO = 'udp'
log = logging.getLogger(__name__)
config = None
udp_bufsize = 1024 * 8
tcp_bufsize = 1024 * 8


def init_config():
    # print('Loading config at startup!')
    global config
    config = configparser.ConfigParser()
    config.read('config/configs.ini')


# Init config right away
init_config()

# Since config has been initinated, let's check if user want to change the buffer size


def apply_bufsize():
    if 'udp-bufsize' in config['FORWARD']:
        try:
            udp_bufsize = int(config['FORWARD']['udp-bufsize'])
            log.info("Custom udp-bufersize: %d" % udp_bufsize)
        except:
            log.info("udp-bufsize should be an integer")
    if 'tcp-bufsize' in config['FORWARD']:
        try:
            tcp_bufsize = int(config['FORWARD']['tcp-bufsize'])
            log.info("Custom tcp-bufersize: %d" % tcp_bufsize)
        except:
            log.info("tcp-bufsize should be an integer")


apply_bufsize()
# End checking udp, tcp buf size


# Creating a listening_sockets so we can manage the running socket
listening_sockets = set()
# Mapping UDP NAT PORT
udp_nat_port = {}
udp_over_tcp = {}


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


def create_socket(socket_type: str, is_listen_port: bool) -> socket.socket:
    new_socket: socket.socket = None
    if socket_type == UDP_PROTO:
        new_socket = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM)
    elif socket_type == TCP_PROTO:
        new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if not is_listen_port:
        # Set default timeout
        port_timeout = 300
        if 'port-timeout' in config['FORWARD']:
            try:
                port_timeout = int(config['FORWARD']['port-timeout'])
            except:
                log.info(
                    "port-timeout in your configuration is not a valid integer")
        if port_timeout > 0 and not is_listen_port:
            log.info("Creating %s socket with timeout: %d" %
                     (socket_type, port_timeout))
            new_socket.settimeout(port_timeout)
    if is_listen_port:
        # This option makes the port is usable by many connection
        new_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    return new_socket


def listen_udp(params):
    sk = create_socket(UDP_PROTO, True)
    # Bind the UDP port
    sk.bind((params[1], int(params[2])))
    # Add to the listening socket set
    listening_sockets.add(sk)
    while True:
        client = sk.recvfrom(udp_bufsize)
        if client:
            # Check if client has initiated a connection before, if not, create a new thread, reserve port for this connection and add it to the dictionary, so later on, we can reuse the reserve socket
            # Client has not sent data to the sk before, or the old session has been killed
            if params[3] == 'tcp':
                # What if user are aquiring UDP over TCP? Then well, we need to create a reserve tcp socket
                if client[1] not in udp_over_tcp:
                    reserve_socket = create_socket(TCP_PROTO, False)
                    log.debug(reserve_socket)
                    reserve_socket.connect((params[4], int(params[5])))
                    reserve_socket.sendall(client[0])
                    udp_over_tcp[client[1]] = reserve_socket
                    threading._start_new_thread(
                        listen_udp_forward_tcp_to_udp, (reserve_socket, sk, client[1]))
                else:
                    try:
                        reserve_socket = udp_over_tcp[client[1]]
                        # log.debug(reserve_socket)
                        reserve_socket.sendall(client[0])
                    except:
                        traceback.print_exc()
            elif params[3] == 'udp':
                reserve_socket = create_socket(UDP_PROTO, False)
                if client[1] not in udp_nat_port:
                    # Well, there is a connection to the socket that, let's handle it
                    # We create a reserve socket for this client, so every request from this client ()

                    # Established a connection from reserve UDP socket to destination socket, even UDP is a stateless protocol, we can still use system connect(2) method to make an UDP connection is "ESTABLISHED" --> the reserve UDP socket will accept only packet from destination --> That's the point, so we can avoid unwanted data
                    reserve_socket.connect((params[4], int(params[5])))
                    reserve_socket.sendall(client[0])
                    # Get response from destination socket --> Because we have made an connection with destination socket, it might safe to receive data without checking original port and IP <3.

                    server_msg = reserve_socket.recvfrom(udp_bufsize)

                    # Add to map, so next time, if the same client send a request, we can get the correct reserve socket to send request to the destination
                    udp_nat_port[client[1]] = reserve_socket
                    udp_nat_port[server_msg[1]] = client[1]

                    # After we got the message, we cannot use the reserve socket to send data back to the client --> It will be rejected since sk is the socket that client connected to, not the reserve one, so we will use the sk to send data back to the client
                    sk.sendto(server_msg[0], client[1])

                    # Create a new thread to handle message that is sent from destination to reserve socket
                    thread = threading.Thread(target=forward_udp_to_udp, args=[
                        sk, reserve_socket])
                    thread.start()
                # Client has sent data to the sk before (and we still have its reserve socket)
                else:
                    # Simply as shit, just get the reserve socket, and send data to the destination, but I'm wondering if this would block another connection as well ? Should I fork a thread to make sure others connection will be not blocked by this?
                    reserve_socket = udp_nat_port.get(client[1])
                    reserve_socket.sendall(client[0])


def forward_udp_to_udp(listen_socket: socket.socket, client_socket: socket.socket):
    while True:
        try:
            server_msg = client_socket.recvfrom(udp_bufsize)
            if server_msg:
                listen_socket.sendto(
                    server_msg[0], udp_nat_port[server_msg[1]])
            else:
                try:
                    client_socket.shutdown(socket.SHUT_RD)
                except:
                    pass  # Do nothing then
                try:
                    del udp_nat_port[udp_nat_port[server_msg[1]]]
                    log.debug(
                        "Removing entry from map to prevent anything wrong")
                except:
                    pass  # Do nothing then
                try:
                    del udp_nat_port[server_msg[1]]
                except:
                    pass  # Do nothing then
                break
        except:
            # If it throws exception, looks like the socket has been closed, let's close our socket
            try:
                client_socket.shutdown(socket.SHUT_RD)
            except:
                pass  # Do nothing then
            try:
                del udp_nat_port[udp_nat_port[server_msg[1]]]
                log.debug("Removing entry from map to prevent anything wrong")
            except:
                pass  # Do nothing then
            try:
                del udp_nat_port[server_msg[1]]
            except:
                pass  # Do nothing then
            break


def listen_udp_forward_tcp_to_udp(tcp_client_socket: socket.socket, udp_listening_socket: socket.socket, udp_client: tuple):
    log.debug("Listening UDP: Forwarding TCP to UDP")
    server_msg = ' '
    while server_msg:
        try:
            server_msg = tcp_client_socket.recv(tcp_bufsize)
            if server_msg:
                udp_listening_socket.sendto(server_msg, udp_client)
            else:
                try:
                    tcp_client_socket.shutdown(socket.SHUT_RD)
                except:
                    pass
                try:
                    del udp_over_tcp[udp_client]
                except:
                    pass
        except:
            traceback.print_exc()
            try:
                tcp_client_socket.close()
            except:
                pass
            try:
                del udp_over_tcp[udp_client]
            except:
                pass
            break


def listen_tcp_forward_udp_to_tcp(udp_reserve_socket: socket.socket, tcp_client_socket: socket.socket):
    log.debug("Listening TCP: Forwarding UDP To TCP")
    while True:
        try:
            server_msg = udp_reserve_socket.recvfrom(udp_bufsize)
            if server_msg:
                tcp_client_socket.sendall(server_msg[0])
            else:
                try:
                    udp_reserve_socket.close()
                except:
                    pass
                try:
                    tcp_client_socket.close()
                except:
                    pass
                break
        except:
            try:
                udp_reserve_socket.close()
            except:
                pass
            try:
                tcp_client_socket.close()
            except:
                pass
            break


def listen_tcp_forward_tcp_to_udp(tcp_client_socket: socket.socket, udp_reserve_socket: socket.socket):
    log.debug("Listening TCP : Forward TCP To UDP")
    message = ' '
    while message:
        message = tcp_client_socket.recv(tcp_bufsize)
        try:
            if message:
                udp_reserve_socket.sendall(message)
            else:
                try:
                    tcp_client_socket.close()
                except:
                    pass
                try:
                    udp_reserve_socket.close()
                except:
                    pass
                break
        except:
            traceback.print_exc()
            try:
                tcp_client_socket.close()
            except:
                pass
            try:
                udp_reserve_socket.close()
            except:
                pass
            break


def listen_tcp(params):
    sk = create_socket(TCP_PROTO, True)
    sk.bind((params[1], int(params[2])))
    sk.listen(5)
    # Add to the listening socket set
    listening_sockets.add(sk)
    while True:
        try:
            # Accept connection from the client with 3-some handshake xD
            client: socket.socket = sk.accept()[0]
            # Create a reserve socket, depend on target protocol, set it to the correct matter
            reserve_socket: socket.socket = None
            if params[3] == 'tcp':
                reserve_socket = create_socket(TCP_PROTO, False)
            if params[3] == 'udp':
                reserve_socket = create_socket(UDP_PROTO, False)
            reserve_socket.connect((params[4], int(params[5])))
            # Ininiated a connection to the target
            log.debug("Routing connect: %s ---> %s ---> %s ---> %s" %
                      (client.getpeername(), client.getsockname(), reserve_socket.getsockname(), reserve_socket.getpeername()))
            if params[3] == 'tcp':
                # Create 2 thread that handle bi-directional connection from client - reserve_socket
                threading._start_new_thread(
                    forward_tcp_to_tcp, (client, reserve_socket))
                threading._start_new_thread(
                    forward_tcp_to_tcp, (reserve_socket, client))
            elif params[3] == 'udp':
                threading._start_new_thread(
                    listen_tcp_forward_udp_to_tcp, (reserve_socket, client))
                threading._start_new_thread(
                    listen_tcp_forward_tcp_to_udp, (client, reserve_socket))
        except Exception as e:
            try:
                client.shutdown(socket.SHUT_RD)
            except:
                pass
            pass


def forward_tcp_to_tcp(source, destination):
    try:
        log.debug("Ongoing connection route: %s ---> %s ---> %s" %
                  (source.getpeername(), source.getsockname(), destination.getpeername()))
    except:
        # Do nothing
        log.debug("Socket closed maybe??")
    message = ' '
    while message:
        message = source.recv(tcp_bufsize)
        if message:
            destination.sendall(message)
        else:
            try:
                source.shutdown(socket.SHUT_RD)
            except:
                # traceback.print_exc()
                pass  # Do nothing then
            try:
                destination.shutdown(socket.SHUT_WR)
            except:
                # traceback.print_exc()
                pass  # Do nothing then
            break


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
            # Reload the config, you might need to restart to apply new config to old forward session.
            init_config()
            try:
                log.info("Forwarding!!!!!!!!!!!!!!")
                # Now read list to forward file from config.
                with open(config['FORWARD']['forward-list']) as f:
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
                        log.info("Forwarding with params: Source - %s:%s:%s, Dest - %s:%s:%s" %
                                 (param[0], param[1], param[2], param[3], param[4], param[5]))
                        # Fork TCP Forward
                        if param[0] == 'tcp':
                            thread = threading.Thread(
                                target=listen_tcp, args=[param])
                            thread.start()
                        # Fork UDP Forward
                        if param[0] == 'udp':
                            thread = threading.Thread(
                                target=listen_udp, args=[param])
                            thread.start()
            except:
                traceback.print_exc()
            finally:
                command = ""
        elif command == "exit":
            for sk in listening_sockets:
                try:
                    sk.shutdown(socket.SHUT_RD)
                except:
                    # traceback.print_exc()
                    pass
            sys.exit(1)
        elif command == "stop":
            # This command to shut down all the listening socket
            for listening_socket in listening_sockets:
                try:
                    listening_socket.shutdown(socket.SHUT_RD)
                except:
                    pass  # Do nothing then
        else:
            log.info("Command not found!")
            # log.info(command)
        command = input()


if __name__ == '__main__':
    # Init the fucking log
    init_log()
    # And start the program
    main()

"""
For python version that lower than 3.6, you might experienced some issue with this:
    server : socket.socket = None 
    change this to
    server = None
    and it should work
"""
