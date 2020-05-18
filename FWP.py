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


def init_config():
    # print('Loading config at startup!')
    global config
    config = configparser.ConfigParser()
    config.read('config/configs.ini')


# Init config right away
init_config()


def init_log():
    global config
    # Just a workaround, but whatever, this just a cheap script
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


def do_forward(params):
    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.bind((params[0], int(params[1])))
    sk.listen(5)
    try:
        while True:
            client = sk.accept()[0]
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.connect((params[2], int(params[3])))
            log.info("Routing connect: %s ---> %s ---> %s" % (client.getpeername(), client.getsockname(), server.getpeername()))
            threading._start_new_thread(forward, (client, server))
            threading._start_new_thread(forward, (server, client))
    except Exception as e:
        sk.shutdown(socket.SHUT_RD)
        traceback.print_exc()
    finally:
        thread = threading.Thread(target=do_forward, args=[params])


def forward(source, destination):
    string = ' '
    while string:
        string = source.recv(1024)
        if string:
            log.debug("Ongoing connection route: %s ---> %s ---> %s" % (source.getpeername(), source.getsockname(), destination.getpeername()))
            destination.sendall(string)
        else:
            try:
                source.shutdown(socket.SHUT_RD)
            except:
                traceback.print_exc()
            try:
                destination.shutdown(socket.SHUT_WR)
            except:
                traceback.print_exc()


def parse_params(param):
    to_split = re.split("\\s+", param)
    # log.info(to_split)
    if len(to_split) < 4:
        return None
    else:
        return [to_split[0], to_split[1], to_split[2], to_split[3]]


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
                    log.info(param)
                    if param not in running:
                        running.add(param)
                    else:
                        log.info("%s is NAT-ed, Ignore!!" % param)
                        continue
                    param = parse_params(param=param)
                    log.info(param)
                    if param is not None:
                        log.info("Forwarding with params: Source - %s:%s, Dest - %s:%s" %
                                 (param[0], param[1], param[2], param[3]))
                        thread = threading.Thread(
                            target=do_forward, args=[param])
                        thread.start()
            except:
                traceback.print_exc()
            finally:
                command = ""
        else:
            log.info("Command not found!")
            # log.info(command)
        command = input()


if __name__ == '__main__':
    # Init the fucking log
    init_log()
    # And start the program
    main()
