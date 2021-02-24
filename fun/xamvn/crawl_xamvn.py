#!/usr/bin/python3
import argparse
import configparser
import json
import logging
import logging.config
import os
import traceback

from fun.xamvn.xamvn_utils import XamVN

# Take argument
parser = argparse.ArgumentParser()

parser.add_argument('--url', required=True, help="URL to xamvn thread")
parser.add_argument(
    '--fromPage', help="The page you want crawler to start from")
parser.add_argument('--toPage', required=True,
                    help="The page you want crawler to finish at")
# At the moment, I haven't done the login part yet, pull request please?
parser.add_argument('--username',
                    help="Your user name, not necessary, but required you have to login first, to have the cookies")
parser.add_argument('--password',
                    help="Your password, not necessary, but required you have to login first, to have the cookies")
parser.add_argument("--proxy", help="Your proxy information")

parser.add_argument('-o',
                    '--output', help="Output folder where the files would be downloaded to")

parser.add_argument("--interval", help="Interval between crawling")

parser = parser.parse_args()


URL = parser.url
user_name = parser.username
password = parser.password
from_page = parser.fromPage
proxy_server = parser.proxy
output_folder = parser.output
INTERVAL = 1
if parser.interval is not None:
    interval = int(parser.interval)
to_page = int(parser.toPage)

# We are gonna read config from config files by using this function
CONFIG = None


def init_config():
    """
    Init config, read from file ./config/configs.ini
    """
    # print('Loading config at startup!')
    global CONFIG
    CONFIG = configparser.ConfigParser()
    CONFIG.read('config/configs.ini')


# End init config, call it in what ever you want to read, or re-read!


# This help us easier in defining log!

log = logging.getLogger(__name__)


def init_log():
    """
    Init logger
    """
    global CONFIG
    # Just a workaround, but whatever, this just a cheap script
    if os.path.join(CONFIG['LOGGER']['log_file_path']):
        if not os.path.exists(os.path.join(CONFIG['LOGGER']['log_file_path'])):
            os.makedirs(os.path.join(CONFIG['LOGGER']['log_file_path']))
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
                'level': CONFIG['LOGGER']['file_log_level'],
                'formatter': 'standard',
                'filename': os.path.join(CONFIG['LOGGER']['log_file_path'], 'application.log'),
                'encoding': 'utf8',
                'backupCount': 10,
                'when': 'd',
                'interval': 1,
            },
            'stdout_handler': {
                'class': 'logging.StreamHandler',
                'level': CONFIG['LOGGER']['std_out_log_level'],
                'formatter': 'standard'
            }
        },
        'loggers': {
            '': {
                'handlers': ['default_handler', 'stdout_handler'],
                'level': CONFIG['LOGGER']['default_log_level'],
                'propagate': False
            }
        }
    }

    logging.config.dictConfig(logging_config)


# End defining log


def read_json_file_to_dict(file_path) -> dict:
    """
    Read from json file and parse it to python dictionary
    """
    with open(file=file_path, mode="r") as f:
        text = "".join(f.readlines())
        return json.loads(text)


def get_headers() -> dict:
    """"
    Read from ./fun/xamvn/files/headers.json file and parse it to dictionary
    """
    return read_json_file_to_dict('./fun/xamvn/files/headers.json')


def get_cookies() -> dict:
    """
    Read from ./fun/xamvn/files/cookies.json file and parse it to dictionary
    """
    return read_json_file_to_dict('./fun/xamvn/files/cookies.json')


if __name__ == '__main__':
    # Read config
    init_config()
    # Init log
    init_log()

    log.info("Let's get started")
    log.debug("Arguments:")
    log.debug(parser)

    headers = get_headers()
    cookies = get_cookies()

    if headers is not None:
        try:
            xamvn = XamVN(headers=headers, cookies=cookies)

            # Basic params
            xamvn.apply_params(from_page=from_page,
                               to_page=to_page, URL=URL)

            # Set proxy
            if proxy_server is not None:
                xamvn.apply_params(proxy=proxy_server)

            # Download folder
            if output_folder is not None:
                xamvn.apply_params(output_folder=output_folder)
            else:
                xamvn.apply_params(
                    output_folder=CONFIG['XAMVN']['default-download-dir'])

            # Interval between crawl
            if INTERVAL is not None:
                xamvn.apply_params(interval=INTERVAL)
            else:
                xamvn.apply_params(interval=int(
                    CONFIG['CHROME-DRIVER']['interval-between-crawl']))
            # Do the job
            xamvn.crawl()
        except Exception as exception:
            traceback.print_exc()
            log.exception(exception)

    else:
        log.error("Specify your headers in a file call headers.json")
