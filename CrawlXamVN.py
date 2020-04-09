from selenium import webdriver
import requests
import os
import logging
import logging.config
import configparser
import argparse

f = requests.Session()

# Take argument
parser = argparse.ArgumentParser()

parser.add_argument('--url', required=True, help="URL to xamvn thread")
parser.add_argument('--fromPage', help="The page you want crawler to start from")
parser.add_argument('--toPage', required=True, help="The page you want crawler to finish at")
# At the moment, I haven't do the login part
parser.add_argument('--username',
                    help="Your user name, not necessary, but required you have to login first, to have the cookies")
parser.add_argument('--password',
                    help="Your password, not necessary, but required you have to login first, to have the cookies")
parser = parser.parse_args()

URL = parser.url
user_name = parser.username
password = parser.password
from_page = parser.fromPage
to_page = int(parser.toPage)

# We are gonna read config from config files by using this function
config = None


def init_config():
    # print('Loading config at startup!')
    global config
    config = configparser.ConfigParser()
    config.read('config/configs.ini')


# End init config, call it in what ever you want to read, or re-read!


# This help us easier in defining log!

log = logging.getLogger(__name__)


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


# End defining log

# Temporary, too lazy to do this, please make a pull request for parsing cookies, request headers from Chrome to requests
requests_headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.163 Safari/537.36',
    'authority': 'xamvn.cc',
    'pragma': 'no-cache',
    'cache-control': 'no-cache',
    'upgrade-insecure-requests': '1',
    'sec-fetch-dest': 'document',
    'sec-fetch-site': 'none',
    'sec-fetch-mode': 'navigate',
    'authority': 'xamvn.cc',
    'pragma': 'no-cache',
    'cache-control': 'no-cache',
    'sec-fetch-dest': 'image',
    'sec-fetch-site': 'same-origin',
    'sec-fetch-mode': 'no-cors',
    'cookie': '__cfduid=def25efddd8206543a6f399b3d3a15f9d1586339627; xfa_user=149239%2CBr28pk8oVswzurYQN6Aq5Wb-cVwrKgUXj9nGBxTi; xfa_csrf=T7MZSoQUm_WlxUaN; xfa_session=xBabxE1Vd6IGz70mqq3QB63oMOM7hE4O'
}


def get_element_url_and_download(elements):
    count = 0
    global f
    for element in elements:
        link = element.get_attribute('src')
        log.info("Getting URL: %s" % link)
        # Getting images that are uploaded by user, or embed by users, not avatar, logo, blah
        if 'attachments' in link or 'proxy.php' in link or 'video' in link:
            import time

            log.info("Sleeping for %s second" % str(config['CHROME-DRIVER']['interval-between-crawl']))
            time.sleep(int(config['CHROME-DRIVER']['interval-between-crawl']))
            count += 1
            f = requests.get(link, headers=requests_headers)
            log.info("Status code: " + str(f.status_code))
            if f.status_code == 200:
                log.info("Downloading")
                if not os.path.exists(
                        os.path.join(config['XAMVN']['default-download-dir'], str(currentPage))):
                    os.makedirs(
                        os.path.join(config['XAMVN']['default-download-dir'], str(currentPage)))
                file_type = str(f.headers['Content-Type']).split('/')[-1]
                with open(os.path.join(config['XAMVN']['default-download-dir'], str(currentPage),
                                       str(count) + "." + file_type), 'wb') as file:
                    file.write(f.content)
                log.info("Done getting URL: %s" % link)


if __name__ == '__main__':
    # Read config
    init_config()
    # Init log
    init_log()

    log.info("Let's get started")
    log.debug("Arguments:")
    log.debug(parser)
    log.info("Initializing Chrome Web Driver")

    # We need several options to make sure all the cookies, cache will not be missed!
    chromeOptions = webdriver.ChromeOptions()
    log.debug('Chrome --user-data-dir is %s' % config['XAMVN']['user-data-dir'])
    chromeOptions.add_argument('%s=%s' % ('--user-data-dir', config['XAMVN']['user-data-dir']))
    if config['CHROME-DRIVER']['headless-mode'] == '1':
        log.debug('Chrome is running in headless mode')
        chromeOptions.add_argument("--headless")
    chromeOptions.add_experimental_option("prefs", {
        "download.default_directory": config['XAMVN']['default-download-dir'],
        'profile.default_content_setting_values.automatic_downloads': 2,
    })
    desired = chromeOptions.to_capabilities()
    desired['loggingPrefs'] = {'performance': 'ALL'}
    driver = webdriver.Chrome(desired_capabilities=desired,
                              executable_path=config['CHROME-DRIVER']['executable-path'])
    log.info('End initializing Chrome Web Driver')

    # Get URL, to get some cookies, blah blah, and parse them to the fucking request
    driver.get(URL)
    currentPage = 1
    if from_page is not None:
        currentPage = int(from_page)
    log.info('Getting cookies')
    cookies = driver.get_cookies()
    log.info('Creating request session and put the cookies from Chrome to requests')
    for cook in cookies:
        for cookie in cook:
            log.debug('Adding cookie: %s -- value: %s' % (cookie, cook[cookie]))
            f.cookies.set(cookie, cook[cookie])
        # break
    while currentPage < to_page + 1:
        log.info('Getting page: %s' % str(currentPage))
        driver.get(URL + '/page-' + str(currentPage))

        # Get all the images
        images = driver.find_elements_by_tag_name('img')
        if len(images) != 0:
            get_element_url_and_download(images)
        else:
            log.info('Cannot find any images')
        # Get all the videos
        videos = driver.find_elements_by_tag_name('source')
        if len(videos) != 0:
            get_element_url_and_download(videos)
        currentPage += 1
