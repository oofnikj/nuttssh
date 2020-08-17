import os


LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = int(os.environ.get('SSH_LISTEN_PORT', 2222))
HOST_KEY_DIR = (os.environ.get('SSH_HOST_KEY_DIR', 'keys'))
HOST_KEY_FILE = ([os.environ.get('SSH_HOST_KEY_FILE_ECDSA',
                    f'{HOST_KEY_DIR}/ecdsa-sha2-nistp256')]
               + [os.environ.get('SSH_HOST_KEY_FILE_ED25519',
                    f'{HOST_KEY_DIR}/ssh-ed25519')]
               + [os.environ.get('SSH_HOST_KEY_FILE_RSA',
                    f'{HOST_KEY_DIR}/ssh-rsa')])
AUTHORIZED_KEYS_FILE = os.environ.get('SSH_AUTHORIZED_KEYS_FILE',
                    f'{HOST_KEY_DIR}/authorized_keys')
SERVER_FQDN = os.environ.get('SSH_SERVER_FQDN', 'localhost')
ALLOW_PTY = False