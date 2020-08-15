# Nuttssh - Copyright Matthijs Kooijman <matthijs@stdin.nl>
#
# This file is made available under the MIT license. See the accompanying
# LICENSE file for the full text.
#
# This file handle the main SSH server, authentication and creation of
# circuits.

import re
import random


def split_hostname_index(name, default=None):
    """
    Split the index out of a hostname.

    E.g. splits "test^1" into ("test", 1). If no index is present, returns
    (name, default).
    """
    match = re.match(r'^(.*)~(\d+)$', name)
    if match:
        return match.group(1), int(match.group(2))
    else:
        return name, default


def join_hostname_index(hostname, index):
    """Joins a hostname with an index, reversing split_hostname_index()."""
    return "{}~{}".format(hostname, index)

def rand_suffix(length=7):
    """Generate a random suffix of `length` chars"""
    charset = '0123456789abcdefghijklmnopqrstuvwxyz'
    return ''.join(random.choice(charset) for i in range(length))