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

log = logging.getLogger(__name__
                        )
config = None

udp_bufsize = 1024 * 128
tcp_bufsize = 1024 * 128


def init_config():
    # print('Loading config at startup!')
    global config
    config = configparser.ConfigParser()
    config.read('config/configs.ini')


# Init config right away
init_config()

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


def listen_udp(params):
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    # Set default UDP timeout, this is important, or else, since UDP is a stateless protocol, you might be getting exhausted port due to this. Normally, I recommend to set it to 300s
    udp_timeout = 300
    # Read UDP timeout from config
    if 'udp-timeout' in config['FORWARD']:
        try:
            udp_timeout = int(config['FORWARD']['udp-timeout'])
        except:
            log.info("UDP Timeout in configuration file is not a valid integer")

    sk.settimeout(udp_timeout)
    # This option makes the port is usable by many connection
    sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
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
                    server_socket = socket.socket(
                        socket.AF_INET, socket.SOCK_STREAM)
                    server_socket.connect((params[4], int(params[5])))
                    server_socket.sendall(client[0])
                    udp_over_tcp[client[1]] = server_socket
                    threading._start_new_thread(
                        listen_udp_forward_tcp_to_udp, (server_socket, sk, client[1]))
                else:
                    try:
                        server_socket = udp_over_tcp[client[1]]
                        # log.debug(server_socket)
                        server_socket.sendall(client[0])
                    except:
                        traceback.print_exc()
            elif params[3] == 'udp':
                server_socket = socket.socket(
                    socket.AF_INET, socket.SOCK_DGRAM)
                if client[1] not in udp_nat_port:
                    # Well, there is a connection to the socket that, let's handle it
                    # We create a reserve socket for this client, so every request from this client ()

                    # Established a connection from reserve UDP socket to destination socket, even UDP is a stateless protocol, we can still use system connect(2) method to make an UDP connection is "ESTABLISHED" --> the reserve UDP socket will accept only packet from destination --> That's the point, so we can avoid unwanted data
                    server_socket.connect((params[4], int(params[5])))
                    server_socket.sendall(client[0])
                    # Get response from destination socket --> Because we have made an connection with destination socket, it might safe to receive data without checking original port and IP <3.

                    server_msg = server_socket.recvfrom(udp_bufsize)

                    # Add to map, so next time, if the same client send a request, we can get the correct reserve socket to send request to the destination
                    udp_nat_port[client[1]] = server_socket
                    udp_nat_port[server_msg[1]] = client[1]

                    # After we got the message, we cannot use the reserve socket to send data back to the client --> It will be rejected since sk is the socket that client connected to, not the reserve one, so we will use the sk to send data back to the client
                    sk.sendto(server_msg[0], client[1])

                    # Create a new thread to handle message that is sent from destination to reserve socket
                    thread = threading.Thread(target=forward_udp_to_udp, args=[
                        sk, server_socket])
                    thread.start()
                # Client has sent data to the sk before (and we still have its reserve socket)
                else:
                    # Simply as shit, just get the reserve socket, and send data to the destination, but I'm wondering if this would block another connection as well ? Should I fork a thread to make sure others connection will be not blocked by this?
                    server_socket = udp_nat_port.get(client[1])
                    server_socket.sendall(client[0])


def forward_udp_to_udp(listen_socket: socket.socket, client_socket: socket.socket):
    while True:
        try:
            server_msg = client_socket.recvfrom(udp_bufsize)
            if server_msg:
                listen_socket.sendto(
                    server_msg[0], udp_nat_port[server_msg[1]])
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
                tcp_client_socket.shutdown(socket.SHUT_RD)
            except:
                pass
            try:
                del udp_over_tcp[udp_client]
            except:
                pass


def listen_tcp_forward_udp_to_tcp(udp_reserve_socket: socket.socket, tcp_client_socket: socket.socket):
    log.debug("Listening TCP: Forwarding UDP To TCP")
    while True:
        try:
            server_msg = udp_reserve_socket.recvfrom(udp_bufsize)
            if server_msg:
                tcp_client_socket.sendall(server_msg[0])
        except:
            try:
                udp_reserve_socket.shutdown(socket.SHUT_RD)
            except:
                pass
            try:
                tcp_client_socket.shutdown(socket.SHUT_RD)
            except:
                pass


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
                    tcp_client_socket.shutdown(socket.SHUT_RD)
                except:
                    pass
                try:
                    udp_reserve_socket.shutdown(socket.SHUT_RD)
                except:
                    pass
        except:
            traceback.print_exc()
            try:
                tcp_client_socket.shutdown(socket.SHUT_RD)
            except:
                pass
            try:
                udp_reserve_socket.shutdown(socket.SHUT_RD)
            except:
                pass


def listen_tcp(params):
    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.bind((params[1], int(params[2])))
    sk.listen(5)
    # Add to the listening socket set
    listening_sockets.add(sk)
    try:
        while True:
            # Accept connection from the client with 3-some handshake xD
            client = sk.accept()[0]
            # Create a reserve socket, depend on target protocol, set it to the correct matter
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if params[3] == 'udp':
                server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                server.connect((params[4], int(params[5])))
            elif params[3] == 'tcp':
                server.connect((params[4], int(params[5])))
            # Ininiated a connection to the target
            log.debug("Routing connect: %s ---> %s ---> %s ---> %s" %
                      (client.getpeername(), client.getsockname(), server.getsockname(), server.getpeername()))
            if params[3] == 'tcp':
                # Create 2 thread that handle bi-directional connection from client - server
                threading._start_new_thread(
                    forward_tcp_to_tcp, (client, server))
                threading._start_new_thread(
                    forward_tcp_to_tcp, (server, client))
            elif params[3] == 'udp':
                threading._start_new_thread(
                    listen_tcp_forward_udp_to_tcp, (server, client))
                threading._start_new_thread(
                    listen_tcp_forward_tcp_to_udp, (client, server))
    except Exception as e:
        sk.shutdown(socket.SHUT_RD)
        traceback.print_exc()
    finally:
        thread = threading.Thread(target=listen_tcp, args=[params])


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
                listening_socket = socket.socket(listening_socket)
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
