import enum


class Permissions(enum.Enum):
    # Open (virtual) ports for listening
    LISTEN = 1
    # Connecting to (virtual) ports
    INITIATE = 2
    # Connecting to (virtual) ports
    LIST_LISTENERS = 3


"""
Predefined access levels, mapping to a more fine-grained list of permissions.
"""
access_levels = {
    'listen': {Permissions.LISTEN},
    'initiate': {Permissions.INITIATE},
    'list': {Permissions.LIST_LISTENERS},
}

"""
Default access granted to new users
"""
default_access = {
    'access': ['listen', 'initiate']
}
