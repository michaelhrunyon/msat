"""MSAT — macOS Server Administration Tools.

A Tkinter front end for managing Active Directory, DHCP and DNS on
Windows Server domain controllers, from macOS.

Transports (all cross-platform, pure Python):
  * Active Directory — LDAP over LDAPS (port 636) via ``ldap3``.
  * DHCP / DNS — PowerShell over WinRM (port 5985, NTLM)
    via ``pywinrm``.

Credentials are collected at connection time, held in memory only, and
never written to disk (see :mod:`msat.credentials`).
"""

from .constants import APP_VERSION

# Single source of truth: the version lives in constants.py (and is
# mirrored in msat.spec for the .app bundle); __init__ re-exports it
# rather than carrying its own number.
__version__ = APP_VERSION
