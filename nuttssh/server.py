# Nuttssh - Copyright Matthijs Kooijman <matthijs@stdin.nl>
#
# This file is made available under the MIT license. See the accompanying
# LICENSE file for the full text.
#
# This file handle the main SSH server, authentication and creation of
# circuits.

import os
import logging
import collections
import asyncssh

from . import util, commands, config
from .permissions import Permissions, access_levels, default_access


class NuttsshDaemon:
    """Daemon that listens on a port and serves multiple connections."""

    def __init__(self):
        # Maps listening names to NutsshServers listening on that name
        self.listener_names = collections.defaultdict(list)

    async def start(self):
        """
        Asynchronously start the SSH server, and process connections.

        This server will listen on the configured host and port.
        """
        def server_factory():
            return NuttsshServer(self)

        algs = ('ecdsa-sha2-nistp256', 'ssh-ed25519', 'ssh-rsa')
        server_host_keys = []
        for i, keyfile in enumerate(config.HOST_KEY_FILE):
            try:
                with open(keyfile, 'r'):
                    server_host_keys.append(keyfile)
            except FileNotFoundError:
                logging.info(f"Generating host key: {algs[i]}")
                key = asyncssh.generate_private_key(algs[i])
                server_host_keys.append(key)
                open(keyfile, 'w').write(key.export_private_key().decode())
                open(f'{keyfile}.pub', 'w').write(
                    key.export_public_key().decode())
                os.chmod(keyfile, 0o600)

        await asyncssh.listen(
            config.LISTEN_HOST, config.LISTEN_PORT,
            server_host_keys=server_host_keys,
            server_factory=server_factory,
            allow_pty=config.ALLOW_PTY)


class NuttsshServer(asyncssh.SSHServer):
    """
    SSHServer class that serves a single connection.

    This is created by asyncssh on each incoming connections and its methods
    are called to decide how to handle incoming requests.
    """

    def __init__(self, daemon):
        self.daemon = daemon
        # Maps ports to SlaveListener objects
        self.listeners = {}
        self.username = None
        # Primary name
        self.hostname = None
        # Additional names
        self.aliases = []
        # All names
        self.names = []
        self.permissions = set()
        self.authorized_keys = None

    def connection_made(self, conn):
        """Called when the connection is opened."""
        self.conn = conn
        logging.info('Connection received from %s',
                     conn.get_extra_info('peername')[0])

    def connection_lost(self, exc):
        """Called when the connection is lost."""
        if exc:
            logging.error('Connection error: %s', str(exc))
        else:
            logging.info('Connection closed.')

        # Clean up (just in case, all listeners should have been closed and
        # removed themselves already)
        for listener in self.listeners:
            listener.close()

    def public_key_auth_supported(self):
        """Called to see if public key auth is (still) supported."""
        return True

    def validate_public_key(self, username, key):
        """Called when the client presents a key for authentication."""
        # Look up the peer address, to support the "from" key option.

        peer_addr = self.conn.get_extra_info('peername')[0]
        keystr = key.export_public_key().decode().strip()
        if config.ENABLE_AUTH:
            try:
                options = self.authorized_keys.validate(key, username,
                                                        peer_addr)
                if 'denied' in options.get('access'):
                    logging.debug("Rejecting key %s %s", keystr, username)
                    return False

            except AttributeError:  # options == None
                if not config.ALLOW_NEW_CLIENTS:
                    return False

                options = default_access
                logging.info(
                    'Adding new key for user %s with default permissions'
                    % username)
                options_str = ','.join(
                    [f'{k}="{v}"' for k in default_access.keys()
                        for v in default_access[k]])
                key_data = '%s %s %s@%s\n' % (options_str, keystr,
                                              username, peer_addr)
                if self.authorized_keys is None:
                    self.authorized_keys = (
                        asyncssh.import_authorized_keys(key_data))
                else:
                    self.authorized_keys.load(key_data)
                with open(config.AUTHORIZED_KEYS_FILE, 'a') as f:
                    f.write(key_data)
        else:
            options = default_access

        logging.debug("Accepting key %s %s %s",
                      str(options), keystr, username)

        self.process_key_options(options)

        return True

    def process_key_options(self, options):
        """Process the options of the accepted key."""
        access = options.get('access', [])
        if not access:
            # TODO: Should this disconnect, or skip this key?
            logging.warning("Used key has no access level")

        self.permissions = set()
        for level in access:
            try:
                self.permissions |= access_levels[level]
            except KeyError:
                logging.error("Key has unknown access level: \"%s\"", level)

        # If not specified in the key options, assume that the username is the
        # hostname.
        hostnames = options.get('hostname', [self.username])
        if len(hostnames) > 1:
            logging.warning("Multiple hostnames specified, using the first")
        self.hostname = hostnames[0]
        self.aliases = options.get('alias', [])
        self.aliases.append(f'{self.hostname}-{util.rand_suffix()}')
        self.names = [self.hostname] + self.aliases
        logging.debug(f'Aliases: {self.aliases}')

    def begin_auth(self, username):
        """The client has started authentication with the given username."""
        self.username = username
        try:
            self.authorized_keys = asyncssh.read_authorized_keys(
                config.AUTHORIZED_KEYS_FILE)
        except FileNotFoundError:
            logging.info("Generating authorized keys file")
            with open(config.AUTHORIZED_KEYS_FILE, 'w'):
                pass
            return True
        except ValueError:
            logging.info("Authorized keys file is empty")
            return True
        except Exception as e:
            # No point in continuing without authorized keys
            logging.error("Failed to read key file: %s", e)
            raise asyncssh.DisconnectError(
                asyncssh.DISC_NO_MORE_AUTH_METHODS_AVAILABLE,
                "Invalid server configuration", "en")

        # Auth required
        return True

    def server_requested(self, listen_host, listen_port):
        """The client requested us to open a listening port."""
        if config.ENABLE_AUTH and Permissions.LISTEN not in self.permissions:
            logging.error("No LISTEN permission, denying request")
            return False

        # We do not support dynamic ports
        if listen_port == 0:
            logging.error("Dynamic listen port not supported, denying request")
            return False

        # TODO: Should we require listen_host to be "localhost"? That matches
        # the semantics of our "virtual listener" structure best?

        logging.info("Creating virtual listener for %s, port %s",
                     self.names, listen_port)

        return self.create_listener(listen_host, listen_port)

    def connection_requested(self, dest_host, dest_port, orig_host, orig_port):
        """
        The client requested us to make a connection to a given host and port.

        The original host and port indicate the source of the connection on
        client side (but are irrelevant here).
        """
        if config.ENABLE_AUTH and Permissions.INITIATE not in self.permissions:
            logging.error("No INITIATE permission, denying request")
            raise asyncssh.ChannelOpenError(
                asyncssh.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                "Insufficient permissions to connect", "en")
        return self.connect_to_server(dest_host, dest_port)

    def session_requested(self):
        """
        Called when a session/channel is requested by the client.

        A session can be a shell, command or subsystem request (e.g. sftp).
        """

        async def process_factory(process):
            await commands.handle_command(self, process, process.command)

        # We should return a session object, that needs to handle all parts of
        # session setup (env vars, pty request, command request, etc.). We let
        # asyncssh handle that, and once a full command or shell requests is
        # received, handle the resulting command.
        return asyncssh.SSHServerProcess(
            process_factory=process_factory,
            sftp_factory=None,
            allow_scp=False,
        )

    def create_listener(self, host, port):
        """Create and register a new listener."""
        # If this is the first, prepend ourselves to the list of listening
        # names
        if not self.listeners:
            for alias in self.aliases:
                self.daemon.listener_names[alias].insert(0, self)

        if port in self.listeners:
            logging.error("Duplicate listen port %s requested, refusing the"
                          "second one", port)
            return False

        # This remembers listen_host so we can tell the client what listener is
        # being used, but it is otherwise ignored.
        listener = VirtualListener(self, host, port)

        self.listeners[port] = listener

        return listener

    def remove_listener(self, listener, port):
        """
        Remove a listener.

        Should only be called from VirtualListener.close()
        """
        del self.listeners[port]

        # If the last listener was closed, unregister our aliases
        if not self.listeners:
            for alias in self.aliases:
                self.daemon.listener_names[alias].remove(self)

        logging.info("Removed virtual listener for %s, port %s",
                     self.names, port)

    async def connect_to_server(self, host, port):
        # Split off any index from the name, defaulting to the most recent
        # client (index 0)
        name, index = util.split_hostname_index(host, 0)

        # Find the server
        servers = self.daemon.listener_names[name]
        if not servers:
            logging.error("Server %s not found", name)
            raise asyncssh.ChannelOpenError(
                asyncssh.OPEN_CONNECT_FAILED,
                "Server %s not found" % (name,), "en")

        try:
            server = servers[index]
        except IndexError:
            logging.error("Invalid index %s for server %s", index, name)
            raise asyncssh.ChannelOpenError(
                asyncssh.OPEN_CONNECT_FAILED,
                "Invalid index %s for server %s" % (index, name), "en")

        # Find the port
        logging.debug("%s", server.listeners)
        listener = server.listeners.get(port, None)
        if not listener:
            logging.error("Port %s on server %s not found",
                          port, server.hostname)
            raise asyncssh.ChannelOpenError(
                asyncssh.OPEN_CONNECT_FAILED,
                "Port %s on server %s not found" % (port, server.hostname),
                "en")

        # This creates a connection back to the server that requested the port
        # forward (using the listener). It uses two instances of the
        # SSHForwarder class to forward data between this server connection and
        # the requested incoming connection.
        # TODO: SSHForwarder is not documented as a public API. Should we use
        # it?
        peer_factory = asyncssh.forward.SSHForwarder
        _, conn = await listener.create_connection(peer_factory)
        return asyncssh.forward.SSHForwarder(conn)


class VirtualListener(asyncssh.SSHListener):
    """
    Represents the server side of a listening port opened by a client.

    This class mostly serves as a way to trick open listening ports, and allows
    asyncssh to close existing listeners (on client request, or when the
    connection is closed). Additionally, this class handles creating new
    tunneled connections to the client when an (virtual) connection to the
    listening port is made.
    """

    def __init__(self, server, listen_host, listen_port):
        self.server = server
        self.listen_host = listen_host
        self.listen_port = listen_port

    async def create_connection(self, peer_factory):
        """
        Create a new tunneled connection to the underlying client.

        This looks to the client like an incoming connection on the listening
        port.

        This works similar to asyncio.create_connection: The peer_factory will
        be passed the created connection and should return the peer, and when
        data comes in on the connection it is passed to the data_received
        method on the peer.
        """
        # This passes the original listen host and port, so the client knows
        # which port forward this connection belongs to
        return await self.server.conn.create_connection(
            peer_factory, self.listen_host, self.listen_port,
        )

    def close(self):
        """
        Close this listener.

        Called when the client cancels it, or the connection is closed.
        """
        self.server.remove_listener(self, self.listen_port)

    async def wait_close(self):
        """Wait for all listeners to be closed."""
        # Since closing is synchronous, no need to wait here.
        pass
