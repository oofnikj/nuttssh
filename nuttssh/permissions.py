import enum


class Permissions(enum.Enum):
    # Open (virtual) ports for listening
    LISTEN = 1
    # Connecting to (virtual) ports
    INITIATE = 2
    # Connecting to (virtual) ports
    LIST_LISTENERS = 3
    # Admin shell
    ADMIN = 4


"""
Predefined access levels, mapping to a more fine-grained list of permissions.
"""
access_levels = {
    'listen': {Permissions.LISTEN},
    'initiate': {Permissions.INITIATE},
    'list': {Permissions.LIST_LISTENERS},
    'admin': {Permissions.ADMIN},
}

"""
Default access granted to new users
"""
default_access = {
    'access': ['listen', 'initiate']
}
