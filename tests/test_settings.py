"""Tests for user-defined defaults (Settings).

Settings live in ``~/.msat/settings.json`` and hold ONLY the
domain, the servers list, and the default server — never credentials.
The module tests use a tmp path so they never touch the real settings
file.
"""

import json
import tkinter as tk

import pytest

from msat.constants import (DEFAULT_DOMAIN, DEFAULT_SERVER, SERVERS)
from msat.dialogs import SettingsDialog
from msat.settings import (default_settings, get_settings_path,
                           load_settings, save_settings)


@pytest.fixture
def root():
    try:
        r = tk.Tk()
    except tk.TclError as exc:
        pytest.skip("No display available: {}".format(exc))
    yield r
    try:
        r.destroy()
    except tk.TclError:
        pass


CUSTOM = {
    "domain": "corp.example",
    "servers": ["ad01", "ad02"],
    "default_server": "ad02",
}


# -- module: round-trip and fallback ---------------------------------------

def test_settings_round_trip(tmp_path):
    path = tmp_path / "settings.json"
    save_settings(CUSTOM, path=path)
    loaded = load_settings(path=path)
    assert loaded == CUSTOM


def test_settings_fallback_when_no_file(tmp_path):
    loaded = load_settings(path=tmp_path / "does-not-exist.json")
    assert loaded == {
        "domain": DEFAULT_DOMAIN,
        "servers": list(SERVERS),
        "default_server": DEFAULT_SERVER,
    }


def test_settings_fallback_per_field_when_missing(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"domain": "corp.example"}),
                    encoding="utf-8")
    loaded = load_settings(path=path)
    assert loaded["domain"] == "corp.example"
    assert loaded["servers"] == list(SERVERS)
    assert loaded["default_server"] == DEFAULT_SERVER


def test_settings_fallback_per_field_when_invalid(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({
        "domain": "",
        "servers": "not-a-list",
        "default_server": None,
    }), encoding="utf-8")
    loaded = load_settings(path=path)
    assert loaded["domain"] == DEFAULT_DOMAIN
    assert loaded["servers"] == list(SERVERS)
    assert loaded["default_server"] == DEFAULT_SERVER


def test_settings_fallback_when_file_is_not_json(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text("this is not json {", encoding="utf-8")
    assert load_settings(path=path) == default_settings()


def test_settings_file_never_contains_a_credential(tmp_path):
    path = tmp_path / "settings.json"
    dirty = dict(CUSTOM)
    dirty["username"] = "admin"
    dirty["password"] = "s3cret"
    dirty["token"] = "abc123"
    dirty["api_key"] = "xyz"
    written = save_settings(dirty, path=path)
    assert "username" not in written
    assert "password" not in written
    assert "token" not in written
    assert "api_key" not in written
    raw = path.read_text(encoding="utf-8")
    for forbidden in ("admin", "s3cret", "abc123", "xyz",
                      "username", "password", "token", "api_key"):
        assert forbidden not in raw
    assert load_settings(path=path) == CUSTOM


def test_settings_drops_stale_server_keys_on_save(tmp_path):
    """A stale per-role server list is dropped, never persisted."""
    path = tmp_path / "settings.json"
    dirty = dict(CUSTOM)
    dirty["dc_servers"] = ["ad01", "ad02"]
    dirty["dhcp_servers"] = ["ad01"]
    written = save_settings(dirty, path=path)
    assert set(written) == {"domain", "servers", "default_server"}
    assert "dc_servers" not in written
    assert "dhcp_servers" not in written
    raw = path.read_text(encoding="utf-8")
    assert "dc_servers" not in raw
    assert "dhcp_servers" not in raw
    assert load_settings(path=path) == CUSTOM


def test_settings_load_translates_stale_dc_servers(tmp_path):
    """An older file with dc_servers (no servers key) is honoured."""
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({
        "domain": "corp.example",
        "dc_servers": ["ad01", "ad02"],
        "default_server": "ad02",
    }), encoding="utf-8")
    loaded = load_settings(path=path)
    assert loaded == CUSTOM


def test_settings_load_prefers_servers_over_stale_keys(tmp_path):
    """When servers is present, stale per-role lists are ignored."""
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({
        "domain": "corp.example",
        "servers": ["ad01", "ad02"],
        "dc_servers": ["other01"],
        "dhcp_servers": ["other02"],
        "default_server": "ad02",
    }), encoding="utf-8")
    loaded = load_settings(path=path)
    assert loaded == CUSTOM


def test_settings_path_is_under_home_dot_msat():
    import os
    from pathlib import Path
    path = get_settings_path()
    assert path == Path(os.path.expanduser("~")) / ".msat" / "settings.json"
    assert path.name == "settings.json"
    assert path.parent.name == ".msat"


def test_settings_load_migrates_from_old_location(tmp_path, monkeypatch):
    """A v1.7.0 settings file at ~/.config/msat/settings.json is
    honoured when ~/.msat/settings.json does not exist yet, and the
    next save writes to the new location."""
    import os

    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    old = home / ".config" / "msat" / "settings.json"
    old.parent.mkdir(parents=True)
    old.write_text(json.dumps(CUSTOM), encoding="utf-8")
    new = home / ".msat" / "settings.json"
    assert not new.exists()

    assert load_settings() == CUSTOM

    # Saving writes to the new location; the old file is untouched.
    save_settings(CUSTOM)
    assert new.exists()
    assert json.loads(new.read_text(encoding="utf-8")) == CUSTOM
    assert json.loads(old.read_text(encoding="utf-8")) == CUSTOM


# -- dialog: prefill and collect -------------------------------------------

def _listbox_values(dlg):
    return list(dlg._servers_list.get(0, tk.END))


def _select_row(dlg, index):
    """Select a listbox row the way a click would (fires the binding
    that enables the − button)."""
    dlg._servers_list.selection_set(index)
    dlg._servers_list.event_generate("<<ListboxSelect>>")


def test_settings_dialog_prefill_and_collect(root):
    dlg = SettingsDialog(root, CUSTOM)
    assert dlg.domain.get() == "corp.example"
    assert _listbox_values(dlg) == ["ad01", "ad02"]
    assert list(dlg.default_combo["values"]) == ["ad01", "ad02"]
    assert dlg.default_combo.get() == "ad02"
    assert dlg.collect() == CUSTOM
    dlg.destroy()


def test_settings_dialog_add_server_via_plus_button(root):
    dlg = SettingsDialog(root, CUSTOM)
    dlg._new_entry.insert(0, "ad03")
    dlg._add_btn.invoke()
    assert _listbox_values(dlg) == ["ad01", "ad02", "ad03"]
    assert list(dlg.default_combo["values"]) == ["ad01", "ad02", "ad03"]
    # The explicit default (ad02) is kept when a server is added.
    assert dlg.default_combo.get() == "ad02"
    assert dlg.collect()["servers"] == ["ad01", "ad02", "ad03"]
    dlg.destroy()


def test_settings_dialog_add_server_via_enter_key(root):
    dlg = SettingsDialog(root, CUSTOM)
    # The entry has its own Return binding (event_generate does not
    # deliver synthetic key events in this xvfb environment, so the
    # wiring is checked directly: the binding exists, invoking its
    # handler adds the server, and it returns "break" so the
    # dialog-level Return (Save) does not fire).
    assert any("Return" in pattern for pattern in dlg._new_entry.bind())
    dlg._new_entry.insert(0, "ad03")
    assert dlg._on_new_entry_return(None) == "break"
    assert _listbox_values(dlg) == ["ad01", "ad02", "ad03"]
    # Enter added the server instead of saving (the dialog is open).
    assert dlg.result is None
    dlg.destroy()


def test_settings_dialog_duplicate_add_is_ignored(root):
    dlg = SettingsDialog(root, CUSTOM)
    dlg._new_entry.insert(0, "ad01")
    dlg._add_btn.invoke()
    assert _listbox_values(dlg) == ["ad01", "ad02"]
    assert list(dlg.default_combo["values"]) == ["ad01", "ad02"]
    assert dlg.collect() == CUSTOM
    dlg.destroy()


def test_settings_dialog_remove_server_via_minus_button(root):
    dlg = SettingsDialog(root, CUSTOM)
    _select_row(dlg, 0)
    dlg._minus_btn.invoke()
    assert _listbox_values(dlg) == ["ad02"]
    assert list(dlg.default_combo["values"]) == ["ad02"]
    # ad02 was the explicit default and survives; still the default.
    assert dlg.default_combo.get() == "ad02"
    dlg.destroy()


def test_settings_dialog_minus_button_state(root):
    dlg = SettingsDialog(root, CUSTOM)
    assert dlg._minus_btn.instate(["disabled"])
    _select_row(dlg, 0)
    assert not dlg._minus_btn.instate(["disabled"])
    dlg.destroy()


def test_settings_dialog_dropdown_options_track_servers_list(root):
    dlg = SettingsDialog(root, CUSTOM)
    assert list(dlg.default_combo["values"]) == ["ad01", "ad02"]
    dlg._new_entry.insert(0, "ad03")
    dlg._add_btn.invoke()
    assert list(dlg.default_combo["values"]) == ["ad01", "ad02", "ad03"]
    _select_row(dlg, 2)
    dlg._minus_btn.invoke()
    assert list(dlg.default_combo["values"]) == ["ad01", "ad02"]
    dlg.destroy()


def test_settings_dialog_auto_default_single_server(root):
    dlg = SettingsDialog(root, {"domain": "corp.example",
                                "servers": ["only01"],
                                "default_server": ""})
    assert dlg.default_combo.get() == "only01"
    assert dlg.collect()["default_server"] == "only01"
    dlg.destroy()


def test_settings_dialog_auto_default_first_server_when_no_pick(root):
    dlg = SettingsDialog(root, {"domain": "corp.example",
                                "servers": ["ad01", "ad02"],
                                "default_server": ""})
    assert dlg.default_combo.get() == "ad01"
    assert dlg.collect()["default_server"] == "ad01"
    dlg.destroy()


def test_settings_dialog_explicit_dropdown_pick_is_kept(root):
    dlg = SettingsDialog(root, {"domain": "corp.example",
                                "servers": ["ad01", "ad02"],
                                "default_server": ""})
    assert dlg.default_combo.get() == "ad01"  # auto: first entry
    dlg.default_combo.set("ad02")
    dlg.default_combo.event_generate("<<ComboboxSelected>>")
    assert dlg.collect()["default_server"] == "ad02"
    # Adding a server keeps the explicit pick.
    dlg._new_entry.insert(0, "ad03")
    dlg._add_btn.invoke()
    assert dlg.default_combo.get() == "ad02"
    dlg.destroy()


def test_settings_dialog_explicit_default_pick_survives_add(root):
    dlg = SettingsDialog(root, CUSTOM)  # saved default ad02
    dlg._new_entry.insert(0, "ad03")
    dlg._add_btn.invoke()
    assert dlg.default_combo.get() == "ad02"
    assert dlg.collect()["default_server"] == "ad02"
    dlg.destroy()


def test_settings_dialog_removing_default_falls_back_to_first(root):
    dlg = SettingsDialog(root, CUSTOM)  # saved default ad02
    _select_row(dlg, 1)
    dlg._minus_btn.invoke()
    assert _listbox_values(dlg) == ["ad01"]
    assert dlg.default_combo.get() == "ad01"
    assert dlg.collect()["default_server"] == "ad01"
    dlg.destroy()


def test_settings_dialog_rejects_empty_domain(root, monkeypatch):
    # messagebox is modal and would block the test forever under xvfb.
    monkeypatch.setattr("msat.dialogs.messagebox.showwarning",
                        lambda *a, **k: None)
    dlg = SettingsDialog(root, CUSTOM)
    dlg.domain.delete(0, tk.END)
    assert dlg.validate() is False
    dlg.destroy()


def test_settings_dialog_rejects_empty_servers_list(root, monkeypatch):
    # messagebox is modal and would block the test forever under xvfb.
    monkeypatch.setattr("msat.dialogs.messagebox.showwarning",
                        lambda *a, **k: None)
    dlg = SettingsDialog(root, CUSTOM)
    while dlg._servers:
        _select_row(dlg, 0)
        dlg._minus_btn.invoke()
    assert dlg._servers == []
    assert dlg.validate() is False
    dlg.destroy()


# -- app wiring: settings drive the connection bar --------------------------

def test_app_uses_saved_settings_for_bar_defaults(root, monkeypatch):
    from msat.app import MSATApp

    monkeypatch.setattr("msat.app.load_settings",
                        lambda path=None: dict(CUSTOM))
    app = MSATApp(root)
    assert app.server_var.get() == "ad02"
    assert app.domain_var.get() == "corp.example"
    assert list(app.server_combo["values"]) == ["ad01", "ad02"]
    # No detection has run yet (disconnected), so the DHCP note is empty.
    assert app.dhcp_note["text"] == ""
    root.update_idletasks()


def test_app_apply_settings_refreshes_bar(root, monkeypatch):
    from msat.app import MSATApp

    monkeypatch.setattr("msat.app.load_settings",
                        lambda path=None: default_settings())
    app = MSATApp(root)
    app.settings = dict(CUSTOM)
    app._apply_settings_to_bar()
    assert app.server_var.get() == "ad02"
    assert app.domain_var.get() == "corp.example"
    assert list(app.server_combo["values"]) == ["ad01", "ad02"]
    root.update_idletasks()
