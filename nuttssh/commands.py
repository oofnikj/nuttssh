# Nuttssh - Copyright Matthijs Kooijman <matthijs@stdin.nl>
#
# This file is made available under the MIT license. See the accompanying
# LICENSE file for the full text.
#
# This file handles commands that can be executed through SSH, to inspect and
# administrate the server.

from . import util, config
from .permissions import Permissions


async def handle_command(server, process, command):
    """
    Parse and handle a single command from a client.

    This is the main entry point for the commands module.

    :param server: The NuttsshServer object for the current connection.
    :param process: The SSHServerProcess object created by AsyncSSH for this
                    command channel.
    :param command: The command to execute. This is either the string passed by
                    the SSH client, or None when no command was passed (and a
                    shell was requested).
    """
    supported_commands = ['listeners']
    process.stdout.write(f'Hello {server.username}!\n')
    if server.listeners:
        await forwarding(server, process)
        return

    if command is None:
        process.stderr.write('This server does not support'
                             ' interactive sessions.\r\n')

    elif command not in supported_commands:
        process.stderr.write('Unsupported command.\r\n')
        process.exit(1)

    else:
        eval(f'{command}(server, process)')


def listeners(server, process):
    """List all active listeners."""
    # TODO: Put this in a decorator?
    if (config.ENABLE_AUTH and Permissions.LIST_LISTENERS not in
            server.permissions):
        process.stderr.write("Permission denied\n")
        process.exit(1)
        return

    process.stdout.write("Listening clients:\n")

    names = server.daemon.listener_names
    if names:
        for name in sorted(names.keys()):
            for i, s in enumerate(names[name]):
                # TODO: Option to list aliases separately?
                if name != s.hostname:
                    continue

                peername = s.conn.get_extra_info('peername')
                ip = peername[0]
                ports = (lp.listen_port for lp in s.listeners.values())
                if i == 0:
                    connect_name = name
                else:
                    connect_name = util.join_hostname_index(name, i)

                line = "  {}: ip={} aliases={} ports={}\n".format(
                    connect_name,
                    ip,
                    ','.join(s.aliases),
                    ','.join(str(p) for p in sorted(ports)),
                )
                process.stdout.write(line)
    else:
        process.stdout.write("  None\n")
    process.exit(0)


async def forwarding(server, process):
    server_alias = server.aliases[0]
    service_ports = list(server.listeners.keys())
    virtual_ports = [server.listeners[p].listen_port for p in service_ports]
    client_conn_str = f'ssh -n {config.SERVER_FQDN} -p {config.LISTEN_PORT} '
    for idx, p in enumerate(service_ports):
        client_conn_str += (
            f'-L {service_ports[idx]}:{server_alias}:{virtual_ports[idx]} ')

    process.stdout.write(
        f'Virtual listener for ports {service_ports} created.\n'
        f'Connect a client by running\n  {client_conn_str}\n')
    await process.wait_closed()
    process.exit(0)
