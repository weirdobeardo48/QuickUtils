import os
import configparser
import logging
import logging.config


class LoggerUtils():
    def __init__(self) -> None:
        super().__init__()

    def init_log(self, config: configparser.ConfigParser()):
        # Just a workaround, but whatever, this is just a cheap script
        if os.path.join(config['LOGGER']['log_file_path']):
            if not os.path.exists(os.path.join(config['LOGGER']['log_file_path'])):
                os.makedirs(os.path.join(config['LOGGER']['log_file_path']))
        logging_config = {
            'version': 1,
            'disable_existing_loggers': False,
            'formatters': {
                'standard': {
                    'format': '%(asctime)s [%(levelname)s] %(name)s [%(processName)s %(threadName)s]: %(lineno)d: %(message)s'
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
