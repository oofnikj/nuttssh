# Nuttssh - Copyright Matthijs Kooijman <matthijs@stdin.nl>
#
# This file is made available under the MIT license. See the accompanying
# LICENSE file for the full text.
#
# This file handles commands that can be executed through SSH, to inspect and
# administrate the server.

import cmd
import logging
from asyncssh import BreakReceived, misc
from . import util, config
from .permissions import Permissions

supported_commands = []


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
    process.stdout.write(f'Hello {server.username}\r\n')
    if server.listeners:
        forwarding(server, process)
        return

    if command is None:
        if config.ENABLE_SHELL:
            await shell(server, process)

        else:
            process.stderr.write('This server does not support'
                                 ' interactive sessions.\r\n')
            logging.warning('Interactive shell disabled')
            process.exit(1)

    elif command not in supported_commands:
        process.stderr.write('Unsupported command\n')
        process.exit(1)

    else:
        eval(f'{command}(server, process)')
        process.exit(0)


def register_command(func):
    """Register command in the list of supported commands"""
    supported_commands.append(func.__name__)
    return func


@register_command
def listeners(server, process):
    """List all active listeners."""
    if (config.ENABLE_AUTH and Permissions.LIST_LISTENERS not in
            server.permissions):
        process.stderr.write("Permission denied\r\n")
        return

    process.stdout.write("Listening clients:\n")

    names = server.daemon.listener_names
    if names:
        for name in sorted(names.keys()):
            for i, s in enumerate(names[name]):
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


def forwarding(server, process):
    """Display forwarding instructions"""
    server_alias = server.aliases[0]
    service_ports = list(server.listeners.keys())
    virtual_ports = [server.listeners[p].listen_port for p in service_ports]
    client_conn_str = f'ssh {config.SERVER_FQDN} -p {config.LISTEN_PORT} -N '
    for idx, p in enumerate(service_ports):
        client_conn_str += (
            f'-L {service_ports[idx]}:{server_alias}:{virtual_ports[idx]} ')

    process.stdout.write(
        f'Virtual listener for ports {service_ports} created.\n'
        f'Connect a client by running\n  {client_conn_str}\n')


class NuttShell(cmd.Cmd):
    # prompt = "\x1b[1m>\x1b[0m "
    prompt = "🥜 "
    intro = "type 'help' to get a list of commands\n"

    def __init__(self, server, process):
        super().__init__()
        self.server = server
        self.process = process
        self.use_rawinput = False
        self.stdin = process.stdin
        self.stdout = process.stdout

    async def cmdloop(self):
        if (config.ENABLE_AUTH and Permissions.ADMIN
                not in self.server.permissions):
            self.process.stdout.write("Permission denied\n")
            self.process.exit(1)

        self.process.stdout.write(self.intro)

        while True:
            try:
                self.process.stdout.write(self.prompt)
                line = (await self.process.stdin.readline())
                if not line:
                    break

                if self.server.conn._transport._closing:
                    raise BrokenPipeError(
                        'Transport is no longer open')

                if self.process._recv_buf_len > 4096:
                    raise BrokenPipeError(
                        'Buffer size for interactive shell exceeded: ',
                        str(self.process._recv_buf_len))

                self.onecmd(line)

            except BrokenPipeError as e:
                self.process.exit(1)
                self.process.logger.error(''.join(e.args))
                break

            except (BreakReceived, misc.TerminalSizeChanged):
                self.process.stdout.write('\n')
                pass

    def emptyline(self):
        return

    def do_quit(self, arg):
        '''exit the shell'''
        self.stdout.write('Exiting\n')
        self.process.exit(0)

    def do_listeners(self, arg=None):
        '''show active listeners'''
        listeners(self.server, self.process)

    def do_whoami(self, arg):
        '''print the current user's information'''
        self.stdout.write(
            f'User name: {self.server.username}\n'
            f'Aliases: {",".join(self.server.aliases)}\n'
            f'Permissions: {[p.name for p in self.server.permissions]}\n'
        )


async def shell(server, process):
    ns = NuttShell(server, process)
    await ns.cmdloop()
    process.exit(0)
