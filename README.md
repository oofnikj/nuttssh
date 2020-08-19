Nuttssh - SSH-based virtual tunnel switchboard server
=====================================================

![https://gitlab.com/oofnik/nuttssh/container_registry/](https://gitlab.com/oofnik/nuttssh/badges/master/pipeline.svg)

Nuttssh is a small Python-based SSH server that internally connects forwarded
ports between different SSH clients. It was designed to work as a way to
connect to services running on machines behind NAT:

1. An initiator opens an SSH connection to nuttssh with remote port forwarding.
2. A second client connects to nuttssh with local port forwarding.
3. Nuttssh acts like a virtual switchboard, connecting the clients over an 
  encrypted tunnel.

This works very similar to using a normal SSH server with port forwarding, 
except that when using Nuttssh:
- No actual TCP ports are opened on the server.
- Clients do not need to actually authenticate as a system user. Nuttssh
  handles its own key authentication.
- When multiple clients request a listening port, they can use the same port
  number, since their hostname will be used to select the right one. This
  removes the need to ensure that each listening client chooses a unique port
  number.
- When connecting to a listening port, a hostname and the regular port number
  (e.g. 22 for SSH) can be used, rather than having to keep track of which
  port number maps to which client.

To circumvent the downsides of normal SSH port forwarding (in particular the
last two), Nuttssh was created. It replaces the central server, while still
allowing normal SSH clients to be used.

Nuttssh still young, but should be usable already. There is still plenty of
room for improvement, especially with regard to configurability.

## Terminology

- Nuttssh server: The central server that accepts connections from various
  hosts and connects them together.
- Initiator: A host that connects to the Nuttssh server and requests
  listening ports by SSH remote port forwarding ( `ssh -R` ). 
- Client: A host that connects to the Nuttssh server and requests a connection
  to an initiator by SSH local port forwarding ( `ssh -L` ).
- Circuit: the virtual connection between two hosts through the Nuttssh
  server. Called a circuit to disambiguate from the normal connection between
  the client and the Nuttssh server.

Note that a host is typically either a client or an initiator, but given
sufficient permissions, a client could also act as both.

**NOTE**: This is a fork of the [original Nuttssh](https://github.com/matthijskooijman/nuttssh)
by Matthijs Kooijman. This version changes the default behavior to 
*trust any SSH key on connect*, adding it (with default permissions) to the 
authorized keys file. In addition, listeners can only connect to initiators 
by using the initiator alias, which is auto-generated by appending a random 
suffix to the username supplied by the initiator upon connecting to nuttssh.

## Installing / running

The easiest way to run nuttssh is with Docker:

    docker build -t nuttssh .
    docker run --name nuttssh -p2222:2222 \
      -v keys:/nuttssh/keys nuttssh

Host keys will be generated on first run and preserved in a Docker volume.

## Configuration

Configuration is handled in the configuration file `nuttssh.ini`. The path
to this file can be set by the environment variable `NUTTSSH_CONFIG_FILE`.

### Access control

To control access to the nuttssh server, an `authorized_keys` file must be
present. If it isn't, nuttssh will create a blank one. This file uses the same
format as OpenSSH's `authorized_keys` file. Each line must contain a single
public key (copied from e.g. the `id_rsa.pub` file). In front of the public
key, options can be added.

For example, a file could look like this (keys are truncated for the example):

    access="listen" ssh-rsa AAAAB3NzaC1yc2EAAAADAJnmVYPYe94v user@host
    access="listen",access="initiate",from="192.168.1.0/24" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAA+ user@host

This consists of a comma-separated list of options, a keytype, the actual key
and a comment.

Currently, the following options are supported:
- `access` to specify the permissions for the client. Supported values are
  as follows:
  - `initiate` to allow opening listening ports
  - `listen` to allow connecting to listening ports
  - `list` to view all connected clients
  - `admin` to access the interactive shell, if enabled.
  The value `denied` can be used to ban a key. A denied key will return
  "permission denied" upon connect.
  This option can be specified more than once, 
  to give more than one type of permission. New users are granted `initiate`
  and `listen` permissions by default.
- `from` to limit connections to specific hosts. The value is a
   comma-separated list of patterns. Each pattern can be a glob pattern (using
   `*` and `?` , e.g. `"*.mydomain.tld"` ) matched against the address and
   hostname, or a CIDR-style address and mask (e.g. `"192.168.1.0/24"` ). A
   connection is allowed if it matches at least one of the patterns in the
   list. This option can be specified multiple times, in which case a
   connection must match (one element of) each `from` option separately.

   See the OpenSSH `authorized_keys` manpage for more info on this option.
- `hostname` and `alias` allow configuring the name(s) that can be used to
   connect to this client. See below for details.

Note that when a client has multiple keys, the first one offered by the client
that is present in the `authorized_keys` file is used, even when another is
also present and has more permissions or other options.

### Server hostnames and aliases

Each connected client has a hostname, and an optional list of alias names. The
hostname is used in various places to refer to a client, while only the aliases 
can be used to select a listening client to connect to.

By default, the username specified by the client is used as its hostname (this
looks a bit like a hack, but it seems like the cleanest approach). Using the
`hostname` option in `authorized_keys` , this hostname can be overridden for a
given connection. Using the `alias` option, additional alias names can be
specified (the option must be specified multiple times for multiple aliases).

When multiple listening clients each claim the same name (hostname or alias), 
the last client to connect will be reached using that name. To reach the other
clients, you can add an index to the hostname. E.g. when two listening clients
both use `test` as their hostname, you can connect to the most recent one using
`test` (or `test~0` ) and the older one using `test~1` .
<!-- TODO: remove this indexing feature, it's made redundant by using random suffixes -->

### Connecting listening clients

Connections to the Nuttssh server use the normal SSH protocol, so can use a
regular SSH client. To open up a listening port, the normal port forwarding
options can be used. For example:

    ssh user1@nuttssh.example.org -p 2222 -n -R 6379:localhost:6379

This connects to a Nuttssh server running on `nuttssh.example.org` , port 2222.
Our hostname ( `user1` ) is passed as the username. Use `-n` so we don't redirect
`stdin` to Nutssh, making it possible to send to the background (e.g. by 
appending `&` to the command). Upon connecting, a (virtual) port 6379 is opened
on the Nuttssh server, ready to forward to a client.
Nuttssh will print out a command for a client to connect, something like

    ssh user2@nuttssh.example.org -p 2222 -N -L 6379:user1-a4h5ig8:6379

The listener (user2) will then be able to connect to `localhost:6379` on
user1's machine as if it were running on user2's `localhost:6379` .

Typically you want a listening client to be continuously connected (and
reconnect on errors). This is easy using `autossh` , just replace `ssh` with
`autossh` , and that will take care of autoconnecting.

By default, `autossh` uses additional port forwards to test connectivity, which
do not work with Nuttssh so these should be disabled in favor of letting SSH
itself do keepalive. Additionally, when running unattended, `autossh` should be
told to always keep retrying, even on startup errors.

#### Changing port numbers

The above examples all assume that the listening clients requests a listening
port 6379 and forwards any incoming circuits to `localhost:6379` , which is probably
the common case. However, it is also possible to forward to a different local
host or port by specifying them with the `-R` option.

For example:

    ssh user1@nuttssh.example.org -p 2222 -n -R 9736:localhost:6379

This requests a virtual port 9736 on the Nuttssh server and connects any incoming
circuits to port 6379 on localhost. Note that this is completely invisible to
the initiating clients, since these only need to specify the hostname
( `user1-<suffix>` ) and virtual listening port (9736).

### Connecting initiating clients

Initiating clients also use the plain SSH protocol and can use a normal SSH
client. For example, to set up an SSH connection to the listening client from
the previous example, using a circuit through the NuttSSH server:

    ssh -J nuttssh.example.org:2222 user1

This instructs ssh to first connect to `nuttssh.example.org` , port 2222 and
then inside that connection, ask the Nuttssh server to set up a circuit
(tunneled connection) to `user1` , port 22 (not specified explicitly). This
hostname and port combination is then matched by the Nuttssh server to the
previously connected listening client and the circuit is routed to that client.
Finally, the listening client then completes the circuit by locally connecting
to its own SSH port, as requested by the `localhost:22` part in its `-R`
option.

This makes use of the SSH `-J` option, using the Nuttssh as a *jump host*. This
is convenient for routing SSH connections through a circuit, but does not work
for other kinds of connections. Fortunately, ssh allows other ways to set up
these circuit connections as well.

Note that this makes two SSH connections, one to the Nuttssh server and one to
the listening client. This also means that authentication must happen twice.

#### Forwarding stdin/stdout through a circuit

SSH can also forward data on its stdin and stdout streams into a circuit.
For example, `user1` opens a listening connection as above:

    ssh user1@nuttssh.example.org -p 2222 -n -R 6379:localhost:6379

Then `user2` connects to `user1`'s listener:

    ssh user2@nuttssh.example.org -p 2222 -W user1-a4h5ig8:6379

This opens a circuit to `user1` who is already connected and remote-forwarding
port 6379, and connects it to the stdin and stdout of the local ssh client of `user2`.

#### Routing a SOCKS proxy requests through a circuit

SSH supports exposing a SOCKS proxy. This proxy is implemented completely in
the local SSH client, and allows (local) programs, such as a webbrowser, to
route all of their traffic through the proxy. In this case, this means all
connections will be made through circuits (and thus connections can be made to
all listening hosts, but not other hosts).

To set this up, run:

    ssh -D 3128 nuttssh.example.org -p 2222 -N

This instructs ssh to open up a SOCKS proxy port on local port 3128, which can
then be used by other programs.

Note that this setup requires the client to support SOCKS v5 and do name
resolution through the proxy (e.g. Firefox has a "Proxy DNS when using SOCKS
v5" option for this). Without this (and with SOCKS v4), names are locally
resolved (which will fail) and only the resulting IP address is included in the
proxy request.

### Using ssh config files

All of the above mentioned ssh options (except `-N` it seems) can also be
configured through SSH configuration file options, so you can define some
presets and apply them by just passing a hostname to ssh. See the `ssh_config`
manpage for more info.

# Contributing

This is an open project, and contributions are welcomed. For bug reports, 
feature suggestions and questions, please use the github issue tracker. To
contribute patches, use github pull requests.

When contributing patches, make sure to provide good quality contributions. In
particular, code style should be consistent, commits should be cleanly
separated with a single logical change per commit and commit messages should be
clear. In other words, make sure the code and commit history is easy to read
and review. Additionally, please explicitly state that you make your
patch available under the MIT license.

To check the coding style of the code, the flake8 tool is used. As a
convenience, a `Makefile` is provided that allows running `make check` to run
all checks (currently only flake8). This should not return any errors after any
commit, so make sure to run it regularly. To fix import sorting errors, run
`make sort` .

# License (also setup.py)

Nuttssh was written by Matthijs Kooijman. Its sources, as well as the
accompanying documentation and other files in this repository are available
under the MIT license. See the [ `LICENSE` ](LICENSE) file for the full license text.

# About Nuttssh

Nuttssh was originally created for the [Meetjestad!](http://www.meetjestad.net)
project, to provide lightweight remote control for LoRa gateways spread
throughout the city on varying internet connections (usually not publically
reachable due to NAT). After some initial experiments with a reverse SSH
connection and SSH channel multiplexing (which worked, but resulted in fragile
code), the current approach of using port forwards was implemented. For this, 
some inspiration was taking from
[ssh-proxy](https://github.com/luke-jr/ssh-proxy), which also uses remote port
forwarding (but uses key fingerprints to identify clients, and probably
predates the SSH "jump host" feature).

Since how Nuttssh works seems a bit similar to the way telephone switchboards
used to work years ago, Nuttssh is named after Emma & Stella Nutt, which were
the first two female telephone switchboard operators. The name "circuit" is
also taken from telephone jargon.
