"""Generic environment defaults for MSAT.

These are PLACEHOLDER defaults only — they ship with the app so it
runs out of the box, and they are not tied to any real environment.
Every one of them is shown in the connection bar as an editable field
(or a dropdown with a free-text entry), so the user can point the app
at any server. Use Settings (in the connection bar) to save your own
defaults; they are stored in ``~/.msat/settings.json`` and
override these placeholders. Nothing here is a hardcoded,
unchangeable constant.

There is a single servers list. Which servers have the DNS or DHCP
roles is detected at connection time (role detection) — the app does
not assume it from the list.
"""

APP_NAME = "MSAT"
APP_TITLE = "MSAT — macOS Server Administration Tools"
APP_VERSION = "1.8.8"

# Placeholder domain. Set your own in Settings.
DEFAULT_DOMAIN = "example.local"

# Placeholder servers (domain controllers). Set your own in Settings.
SERVERS = ["dc1", "dc2", "dc3"]

DEFAULT_SERVER = "dc1"

# LDAPS (636) for Active Directory; WinRM HTTP (5985) + NTLM for
# DHCP / DNS (pywinrm encrypts the messages).
DEFAULT_LDAPS_PORT = 636
DEFAULT_WINRM_PORT = 5985
