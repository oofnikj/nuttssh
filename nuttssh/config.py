import os
import sys
import logging

from configparser import ConfigParser, BasicInterpolation


config = ConfigParser(interpolation=BasicInterpolation())


try:
    config_file = os.environ.get('NUTTSSH_CONFIG_FILE', 'nuttssh.ini')
    config.read_file(open(config_file, 'r'))

    LISTEN_HOST          = config.get('server', 'listen_host')
    LISTEN_PORT          = config.getint('server', 'listen_port')
    SERVER_FQDN          = config.get('server', 'server_fqdn')
    ENABLE_AUTH          = config.getboolean('server', 'enable_auth')
    ALLOW_NEW_CLIENTS    = config.getboolean('server', 'allow_new_clients')
    ALLOW_PTY            = config.getboolean('server', 'allow_pty')
    ENABLE_SHELL         = config.getboolean('server', 'enable_shell')

    AUTHORIZED_KEYS_FILE = config.get('keys', 'authorized_keys_file')
    HOST_KEY_FILE = []
    for item in config.items('keys'):
        if item[0] not in ('host_key_dir', 'authorized_keys_file'):
            HOST_KEY_FILE.append(item[1])
except FileNotFoundError:
    logging.error(f'Config file "{config_file}" not found')
    sys.exit(1)
except Exception as e:
    logging.error(f'Error parsing config file:\n{e}')
    sys.exit(1)
