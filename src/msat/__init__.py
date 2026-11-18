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

__version__ = "0.1.0"
