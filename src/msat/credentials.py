"""In-memory credential store.

Security model (non-negotiable):
  * Credentials live ONLY in instance attributes of this class, for the
    duration of the process.
  * No file I/O, no logging of secrets, no macOS Keychain, no config
    file. Nothing in this module touches the disk.
  * ``clear()`` wipes the attributes. The app calls it on Disconnect
    and on exit; when the process exits the memory is gone.

The app owns a single CredentialStore instance for the global
connection (one server / domain / username / password shared by all
four tabs), because AD, DHCP and DNS all run on the
same domain controllers.
"""


class CredentialStore:
    """Holds one connection's credentials in memory only."""

    def __init__(self):
        self.server = None
        self.domain = None
        self.username = None
        self.password = None
        self.port = None

    def set(self, server, domain, username, password, port=None):
        """Store credentials (in memory only)."""
        self.server = server
        self.domain = domain
        self.username = username
        self.password = password
        self.port = port

    def clear(self):
        """Wipe all stored values."""
        self.server = None
        self.domain = None
        self.username = None
        self.password = None
        self.port = None

    @property
    def is_set(self):
        """True when a complete set of credentials is held."""
        return bool(self.server and self.username and self.password)

    def __repr__(self):
        # Deliberately never includes the password (or username).
        return "CredentialStore(server={!r})".format(self.server)
