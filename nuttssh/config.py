import os


LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = int(os.environ.get('SSH_LISTEN_PORT', 2222))
HOST_KEY_FILE = ([os.environ.get('SSH_HOST_KEY_FILE_ECDSA', 'keys/ecdsa-sha2-nistp256')]
               + [os.environ.get('SSH_HOST_KEY_FILE_ED25519', 'keys/ssh-ed25519')]
               + [os.environ.get('SSH_HOST_KEY_FILE_RSA', 'keys/ssh-rsa')])
AUTHORIZED_KEYS_FILE = os.environ.get('SSH_AUTHORIZED_KEYS_FILE', 'keys/authorized_keys')
SERVER_FQDN = os.environ.get('SSH_SERVER_FQDN', 'localhost')