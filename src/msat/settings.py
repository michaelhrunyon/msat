"""User-defined defaults for MSAT (Settings).

Settings live in ``~/.msat/settings.json`` — a ``.msat`` directory in
the user's home directory, outside the repo and outside the app
bundle, so they can never be committed and they work the same whether
the app is run from source or installed as MSAT.app in
/Applications (a .app bundle must not be written to — it is
read-only once installed, and Gatekeeper can translocate it).
Settings hold ONLY the connection defaults: the AD domain, the
servers list, and the default server. They NEVER hold credentials
(no username, no password); the settings file must never contain a
credential, and :func:`save_settings` refuses to write one.

There is a single servers list — the servers to connect to and to
check for the DNS/DHCP roles. Role detection at connection time
sorts out what each server does; there is no separate list per role.

``load_settings()`` returns the saved values, falling back per-field
to the generic placeholders in :mod:`msat.constants` when the file
does not exist or a field is missing/invalid. A stale ``dc_servers``
(or ``dhcp_servers``) key from an older settings file is translated
to ``servers`` when ``servers`` itself is absent, and dropped
otherwise. ``save_settings()`` writes only the three known fields.
"""

import json
import os
from pathlib import Path

from .constants import (DEFAULT_DOMAIN, DEFAULT_SERVER, SERVERS)

# The only fields settings may contain. Anything else — in
# particular any credential, or a stale per-role server list — is
# dropped on save and ignored on load. The whitelist in
# :func:`save_settings` is the guard that keeps credentials out of
# the file; there is no separate forbidden-keys list (one was tried
# and never consulted, so it was removed rather than left as a
# misleading second guard).
SETTINGS_KEYS = ("domain", "servers", "default_server")

# Keys from older settings files that named a per-role server list.
# On load, ``dc_servers`` is translated to ``servers`` when ``servers``
# itself is absent; anything else here is dropped.
_LEGACY_SERVER_KEYS = ("dc_servers", "dhcp_servers")


def get_settings_path():
    """``~/.msat/settings.json`` in the user's home directory.

    Fixed location — it does not honour ``$XDG_CONFIG_HOME``, so
    running from source and running as an installed .app use the
    same file. The .app bundle itself is never written to.
    """
    return Path(os.path.expanduser("~")) / ".msat" / "settings.json"


def _legacy_settings_path():
    """The v1.7.0 location (``~/.config/msat/settings.json``).

    Checked only when the new location has no file, so v1.7.0
    settings are not lost on upgrade. Never written to.
    """
    return (Path(os.path.expanduser("~")) / ".config" / "msat"
            / "settings.json")


def _read_json(path):
    """The parsed JSON value at ``path``, or None on any failure
    (missing file, unreadable file, invalid JSON)."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError, UnicodeDecodeError):
        return None


def _clean_str(value, fallback):
    """A non-empty string, or the fallback."""
    if isinstance(value, str) and value.strip():
        return value.strip()
    return fallback


def _clean_list(value, fallback):
    """A non-empty list of non-empty strings, or the fallback."""
    if isinstance(value, list):
        cleaned = [item.strip() for item in value
                   if isinstance(item, str) and item.strip()]
        if cleaned:
            return cleaned
    return list(fallback)


def default_settings():
    """The generic placeholders, as a settings dict."""
    return {
        "domain": DEFAULT_DOMAIN,
        "servers": list(SERVERS),
        "default_server": DEFAULT_SERVER,
    }


def load_settings(path=None):
    """Saved settings, falling back per-field to the generic defaults.

    Missing file, unreadable file, invalid JSON, or a missing/invalid
    field all fall back to the generic placeholder for that field —
    never all-or-nothing, and never an exception. When the new
    location has no file, the v1.7.0 location
    (``~/.config/msat/settings.json``) is checked, so settings saved
    by v1.7.0 are not lost; the next save writes to the new location.
    A stale ``dc_servers`` key is translated to ``servers`` when
    ``servers`` itself is absent; any other unknown key (including a
    stale ``dhcp_servers``) is ignored.
    """
    settings = default_settings()
    if path is not None:
        raw = _read_json(Path(path))
    else:
        target = get_settings_path()
        raw = _read_json(target)
        if raw is None and not target.exists():
            # Migration: v1.7.0 kept settings at the old location.
            raw = _read_json(_legacy_settings_path())
    if not isinstance(raw, dict):
        return settings
    servers = raw.get("servers")
    if servers is None:
        # Older file: a per-role server list stands in for the single
        # servers list (first legacy key wins).
        for key in _LEGACY_SERVER_KEYS:
            if raw.get(key) is not None:
                servers = raw.get(key)
                break
    settings["domain"] = _clean_str(raw.get("domain"), DEFAULT_DOMAIN)
    settings["servers"] = _clean_list(servers, SERVERS)
    settings["default_server"] = _clean_str(raw.get("default_server"),
                                             DEFAULT_SERVER)
    return settings


def save_settings(settings, path=None):
    """Write only the three known settings fields as JSON.

    Any other key in ``settings`` — including any credential field
    and any stale per-role server list — is dropped, so a credential
    (or an obsolete list) can never be persisted. Returns the dict
    that was actually written.
    """
    cleaned = {
        "domain": _clean_str(settings.get("domain"), DEFAULT_DOMAIN),
        "servers": _clean_list(settings.get("servers"), SERVERS),
        "default_server": _clean_str(settings.get("default_server"),
                                      DEFAULT_SERVER),
    }
    target = Path(path) if path is not None else get_settings_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8") as fh:
        json.dump(cleaned, fh, indent=2)
        fh.write("\n")
    return cleaned
