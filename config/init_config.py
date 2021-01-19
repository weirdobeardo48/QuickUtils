import configparser


class ConfigUtils:
    def __init__(self) -> None:
        super().__init__()

    def get_configparser(self, config_file_path: str) -> configparser.ConfigParser():
        # log.info('Loading config at startup!')
        config = configparser.ConfigParser()
        config.read(config_file_path)
        return config
