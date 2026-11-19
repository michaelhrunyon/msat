"""GUI smoke tests — build the real Tkinter UI under a virtual display.

Run under xvfb (Linux) with:  xvfb-run -a pytest tests/test_gui_smoke.py
On macOS these run against the real display.
"""

import tkinter as tk

import pytest

from msat.app import MSATApp
from msat.constants import APP_TITLE
from msat.dialogs import SettingsDialog, UserPropertiesDialog
from msat.settings import default_settings
from tests.conftest import FakeWinRMClient


class FakeADClient:
    """Stand-in for ADClient: bind always succeeds, directory is empty."""

    def __init__(self, server=None, domain=None, username=None, password=None,
                 port=636, connection=None):
        self.server = server
        self.domain = domain
        self._connected = False

    def connect(self):
        self._connected = True
        return True

    def validate_connection(self):
        return True

    def disconnect(self):
        self._connected = False

    def get_default_naming_context(self):
        return "DC=example,DC=local"

    def get_root_dse(self):
        return {"defaultNamingContext": "DC=example,DC=local"}

    def list_sites(self):
        return []

    def list_subnets(self):
        return []

    def list_trusted_domains(self):
        return []

    def list_children(self, dn):
        return []


class FakeWinRM(FakeWinRMClient):
    """FakeWinRMClient that accepts WinRMClient's constructor arguments."""

    def __init__(self, host, username=None, password=None, port=5985, **kwargs):
        super().__init__()
        self.host = host


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


@pytest.fixture
def patched_clients(monkeypatch):
    monkeypatch.setattr("msat.app.ADClient", FakeADClient)
    monkeypatch.setattr("msat.app.WinRMClient", FakeWinRM)
    # Role detection: dc1/dc2 have DNS + DHCP, dc3 has DNS only.
    # (Matches the generic environment; a test can monkeypatch
    # msat.app.detect_server_roles again to vary it.)
    def _roles(client):
        if getattr(client, "host", None) == "dc3":
            return {"DNS": True, "DHCP": False}
        return {"DNS": True, "DHCP": True}
    monkeypatch.setattr("msat.app.detect_server_roles", _roles)


@pytest.fixture(autouse=True)
def generic_settings(monkeypatch):
    """Pin the connection-bar defaults to the generic placeholders.

    MSATApp loads the user's saved Settings on startup; without this,
    a real ``~/.msat/settings.json`` in the test runner's home
    would change the bar defaults and make these tests non-deterministic.
    """
    monkeypatch.setattr("msat.app.load_settings",
                        lambda path=None: default_settings())


def _all_toolbar_buttons(app):
    return (app.ad_toolbar_buttons + app.dhcp_toolbar_buttons +
            app.dns_toolbar_buttons + [app.info_refresh_btn])


def _connect_app(app, server="dc1"):
    app.server_var.set(server)
    app.domain_var.set("example.local")
    app.username_var.set("michael")
    app.password_var.set("secret")
    app._global_connect()
    app.root.update_idletasks()


def test_main_window_builds_with_all_tabs(root):
    app = MSATApp(root)
    assert root.title() == APP_TITLE
    notebook = root.nametowidget("!notebook")
    labels = [notebook.tab(i, "text") for i in range(notebook.index("end"))]
    assert labels == ["AD Users & Computers", "DHCP", "DNS",
                      "Directory Info"]
    # One global connection bar: Connect enabled, Disconnect disabled,
    # status "Not connected". All tab toolbars start disabled.
    assert str(app.connect_btn["state"]) == "normal"
    assert str(app.disconnect_btn["state"]) == "disabled"
    assert app.conn_status["text"] == "Not connected"
    assert app.server_var.get() == "dc1"
    assert app.domain_var.get() == "example.local"
    for btn in _all_toolbar_buttons(app):
        assert str(btn["state"]) == "disabled"
    # A single credential store, shared by all tabs, initially empty.
    assert isinstance(app.creds, object)
    assert not app.creds.is_set
    assert app.ad_client is None
    assert app.dhcp is None
    assert app.dns is None
    # DHCP server picker is hidden until a dc3 connection needs it.
    assert app.dhcp_server_frame.winfo_manager() == ""
    root.update_idletasks()


def test_global_connect_enables_all_tabs_then_disconnect_disables(root,
                                                                  patched_clients):
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    assert app.ad_client is not None
    assert app.creds.is_set
    assert str(app.connect_btn["state"]) == "disabled"
    assert str(app.disconnect_btn["state"]) == "normal"
    assert app.conn_status["text"] == "Connected to dc1"
    assert "Connected to dc1" in app.statusbar["text"]
    # DHCP/DNS/Info toolbars are fully enabled on connect.
    for btn in (app.dhcp_toolbar_buttons + app.dns_toolbar_buttons +
                [app.info_refresh_btn]):
        assert str(btn["state"]) == "normal"
    # AD: the buttons that need no selection are enabled; the row
    # actions are disabled until a row is selected (v1.8.7).
    _assert_ad_buttons_no_selection(app)
    # The AD tree root was populated from the (fake) directory.
    assert app.ad_tree.exists("DC=example,DC=local")

    app._global_disconnect()
    root.update_idletasks()
    assert app.ad_client is None
    assert app.dhcp is None
    assert app.dns is None
    assert not app.creds.is_set
    assert str(app.connect_btn["state"]) == "normal"
    assert str(app.disconnect_btn["state"]) == "disabled"
    assert app.conn_status["text"] == "Not connected"
    assert app.statusbar["text"] == "Disconnected."
    for btn in _all_toolbar_buttons(app):
        assert str(btn["state"]) == "disabled"
    assert not app.ad_tree.get_children()


def test_global_connect_rejects_bad_credentials(root, patched_clients,
                                                monkeypatch):
    """A failed LDAP bind must not mark the app connected."""
    shown = []
    monkeypatch.setattr("msat.app.messagebox.showerror",
                        lambda *a, **k: shown.append(a))

    class FailingADClient(FakeADClient):
        def connect(self):
            raise Exception("Could not connect to dc1 over LDAPS (port 636): "
                            "invalidCredentials")

    monkeypatch.setattr("msat.app.ADClient", FailingADClient)
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    assert app.ad_client is None
    assert not app.creds.is_set
    assert shown, "expected an error dialog for the failed bind"
    assert str(app.connect_btn["state"]) == "normal"
    assert str(app.disconnect_btn["state"]) == "disabled"
    for btn in _all_toolbar_buttons(app):
        assert str(btn["state"]) == "disabled"


def test_global_connect_invalid_credentials_message(root, patched_clients,
                                                  monkeypatch):
    """A bind rejected for bad credentials gets the plain-language dialog
    and a visible 'Connection failed: invalid credentials' status."""
    from msat.ldap_client import ADInvalidCredentialsError
    shown = []
    monkeypatch.setattr("msat.app.messagebox.showerror",
                        lambda *a, **k: shown.append(a))

    class BadCredsADClient(FakeADClient):
        def connect(self):
            raise ADInvalidCredentialsError(
                "Invalid credentials — the username or password is "
                "incorrect for dc1.")

    monkeypatch.setattr("msat.app.ADClient", BadCredsADClient)
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    assert app.ad_client is None
    assert not app.creds.is_set
    assert app.dns is None and app.dhcp is None
    assert not app.ad_tree.get_children()
    assert str(app.connect_btn["state"]) == "normal"
    assert str(app.disconnect_btn["state"]) == "disabled"
    for btn in _all_toolbar_buttons(app):
        assert str(btn["state"]) == "disabled"
    assert shown, "expected the invalid-credentials dialog"
    title, message = shown[0][0], shown[0][1]
    assert title == "Invalid credentials"
    assert "username or password is incorrect" in message
    assert app.conn_status["text"] == "Connection failed: invalid credentials"
    assert "invalid credentials" in app.statusbar["text"].lower()


def test_global_connect_validation_search_failure_stays_disconnected(
        root, patched_clients, monkeypatch):
    """A bind that succeeds but a validation search that fails for
    credentials must also abort the connect before anything loads."""
    from msat.ldap_client import ADInvalidCredentialsError
    shown = []
    monkeypatch.setattr("msat.app.messagebox.showerror",
                        lambda *a, **k: shown.append(a))

    class StaleCredsADClient(FakeADClient):
        def validate_connection(self):
            raise ADInvalidCredentialsError(
                "Invalid credentials — the username or password is "
                "incorrect for dc1.")

    monkeypatch.setattr("msat.app.ADClient", StaleCredsADClient)
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    assert app.ad_client is None
    assert not app.creds.is_set
    assert not app.ad_tree.get_children()
    assert shown and shown[0][0] == "Invalid credentials"
    assert app.conn_status["text"] == "Connection failed: invalid credentials"


def test_password_return_invokes_connect(root, patched_clients):
    """Enter in the password field acts like clicking Connect."""
    app = MSATApp(root)
    # The password entry has its own Return binding (event_generate
    # does not deliver synthetic key events in this xvfb environment,
    # so the wiring is checked directly: the binding exists, invoking
    # its handler connects, and it returns "break").
    assert any("Return" in pattern for pattern in app.password_entry.bind())
    app.server_var.set("dc1")
    app.domain_var.set("example.local")
    app.username_var.set("michael")
    app.password_var.set("secret")
    assert app._on_password_return(None) == "break"
    root.update_idletasks()
    assert app.ad_client is not None
    assert app.creds.is_set
    assert str(app.connect_btn["state"]) == "disabled"
    assert str(app.disconnect_btn["state"]) == "normal"
    assert app.conn_status["text"] == "Connected to dc1"


def test_password_return_is_noop_when_connected(root, patched_clients):
    """Enter in the password field must not disconnect or reconnect
    when the app is already connected."""
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    assert app.ad_client is not None
    client = app.ad_client
    assert app._on_password_return(None) == "break"
    root.update_idletasks()
    # Same client, still connected, still showing connected.
    assert app.ad_client is client
    assert str(app.connect_btn["state"]) == "disabled"
    assert str(app.disconnect_btn["state"]) == "normal"
    assert app.conn_status["text"] == "Connected to dc1"


def test_connect_button_blue_while_connecting(root, patched_clients,
                                              monkeypatch):
    """Connect turns blue while the LDAP bind runs, then returns to
    gray with Disconnect blue once connected.

    The blue state must be applied and a redraw forced *before*
    the blocking bind — a recording client captures both at the
    moment connect() runs.
    """
    app = MSATApp(root)
    seen = []
    redraws = []
    orig_update = root.update_idletasks

    def counting_update():
        redraws.append(1)
        return orig_update()

    monkeypatch.setattr(root, "update_idletasks", counting_update)

    class RecordingADClient(FakeADClient):
        def connect(self):
            seen.append(str(app.connect_btn.cget("default")))
            seen.append(len(redraws))
            return super().connect()

    monkeypatch.setattr("msat.app.ADClient", RecordingADClient)
    _connect_app(app, "dc1")
    root.update_idletasks()
    assert seen[0] == "active", "Connect must be blue while connecting"
    assert seen[1] >= 1, "a redraw must be forced before the blocking bind"
    assert str(app.connect_btn.cget("default")) == "normal"
    assert str(app.disconnect_btn.cget("default")) == "active"


def test_password_return_turns_connect_blue_while_connecting(
        root, patched_clients, monkeypatch):
    """Enter in the password field takes the same blue-while-connecting
    path as clicking Connect."""
    app = MSATApp(root)
    seen = []

    class RecordingADClient(FakeADClient):
        def connect(self):
            seen.append(str(app.connect_btn.cget("default")))
            return super().connect()

    monkeypatch.setattr("msat.app.ADClient", RecordingADClient)
    app.server_var.set("dc1")
    app.domain_var.set("example.local")
    app.username_var.set("michael")
    app.password_var.set("secret")
    assert app._on_password_return(None) == "break"
    root.update_idletasks()
    assert seen == ["active"]
    assert str(app.connect_btn.cget("default")) == "normal"
    assert str(app.disconnect_btn.cget("default")) == "active"


def test_connect_button_gray_on_failed_connect(root, patched_clients,
                                               monkeypatch):
    """A failed connect returns Connect to gray and leaves
    Disconnect gray (not connected)."""
    from msat.ldap_client import ADInvalidCredentialsError
    shown = []
    monkeypatch.setattr("msat.app.messagebox.showerror",
                        lambda *a, **k: shown.append(a))

    class BadCredsADClient(FakeADClient):
        def connect(self):
            raise ADInvalidCredentialsError(
                "Invalid credentials — the username or password is "
                "incorrect for dc1.")

    monkeypatch.setattr("msat.app.ADClient", BadCredsADClient)
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    assert shown, "expected the invalid-credentials dialog"
    assert app.ad_client is None
    assert str(app.connect_btn.cget("default")) == "normal"
    assert str(app.disconnect_btn.cget("default")) == "normal"
    assert str(app.connect_btn["state"]) == "normal"
    assert str(app.disconnect_btn["state"]) == "disabled"


def test_disconnect_returns_buttons_to_gray(root, patched_clients):
    """Disconnecting returns both buttons to their default gray."""
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    assert str(app.disconnect_btn.cget("default")) == "active"
    app._global_disconnect()
    root.update_idletasks()
    assert str(app.connect_btn.cget("default")) == "normal"
    assert str(app.disconnect_btn.cget("default")) == "normal"
    assert str(app.connect_btn["state"]) == "normal"
    assert str(app.disconnect_btn["state"]) == "disabled"


def test_root_return_guard_installed(root, patched_clients):
    """A Return guard is installed on the toplevel so a stray
    Return in a search box or treeview cannot invoke the default
    (blue) button, and it returns "break"."""
    app = MSATApp(root)
    assert app.root.bind("<Return>"), "expected a Return guard on the root"
    assert app._on_root_return(None) == "break"


def test_dhcp_uses_global_server_when_it_has_dhcp(root, patched_clients):
    app = MSATApp(root)
    _connect_app(app, "dc2")
    root.update_idletasks()
    # dc2 runs DHCP: no picker, DHCP targets the global server.
    assert app.dhcp_server_frame.winfo_manager() == ""
    assert app._dhcp_server == "dc2"
    assert app.dhcp_server_var.get() == "dc2"


def test_dhcp_falls_back_to_picker_when_global_server_is_dc3(root,
                                                             patched_clients):
    app = MSATApp(root)
    _connect_app(app, "dc3")
    root.update_idletasks()
    # dc3 has no DHCP: the picker appears, defaulting to dc1,
    # and the DHCP manager targets dc1 with the global credentials.
    assert app.dhcp_server_frame.winfo_manager() == "pack"
    assert app.dhcp_server_var.get() == "dc1"
    assert app._dhcp_server == "dc1"
    assert app.creds.is_set

    # Switching the picker to the other DHCP server retargets DHCP.
    app.dhcp_server_var.set("dc2")
    app._dhcp_on_server_change()
    root.update_idletasks()
    assert app._dhcp_server == "dc2"


def test_user_properties_dialog_diff(root):
    """General-tab edits + cleared attributes produce a change-only diff."""
    attrs = {
        "displayName": {"values": ["John Doe"], "binary": False},
        "sAMAccountName": {"values": ["jdoe"], "binary": False},
        "mail": {"values": ["jdoe@example.local"], "binary": False},
        "title": {"values": ["Analyst"], "binary": False},
        "proxyAddresses": {"values": ["SMTP:jdoe@example.local",
                                      "smtp:jdoe@mail.example.local"],
                           "binary": False},
        "objectGUID": {"values": ["000102030405060708090a0b0c0d0e0f"],
                       "binary": True},
    }
    dlg = UserPropertiesDialog(root, "John Doe", attrs)
    root.update_idletasks()
    assert dlg._general_entries["displayName"].get() == "John Doe"
    assert dlg._general_entries["sAMAccountName"].get() == "jdoe"
    assert str(dlg._general_entries["sAMAccountName"]["state"]) == "disabled"
    # Binary rows are listed but flagged read-only.
    assert "(binary, read-only)" in dlg._attr_tree.item(
        "objectGUID", "values")[1]
    # Edit the title, clear mail (via the editor values + sync).
    dlg._general_entries["title"].delete(0, tk.END)
    dlg._general_entries["title"].insert(0, "Lead Analyst")
    dlg._values["mail"] = None
    dlg._sync_general_entry("mail")
    dlg._on_save()
    assert dlg.result == {"title": ["Lead Analyst"], "mail": None}


def test_user_properties_dialog_cancel(root):
    attrs = {"displayName": {"values": ["John Doe"], "binary": False}}
    dlg = UserPropertiesDialog(root, "John Doe", attrs)
    dlg._on_cancel()
    assert dlg.result is None


def test_search_entries_enable_with_connection(root, patched_clients):
    app = MSATApp(root)
    assert len(app._search_entries) == 3  # AD, DHCP, DNS
    for entry in app._search_entries:
        assert str(entry["state"]) == "disabled"
    _connect_app(app, "dc1")
    root.update_idletasks()
    for entry in app._search_entries:
        assert str(entry["state"]) == "normal"
    app._global_disconnect()
    root.update_idletasks()
    for entry in app._search_entries:
        assert str(entry["state"]) == "disabled"


def test_ad_search_filters_rows(root, patched_clients):
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    app._ad_rows = [
        {"dn": "CN=jdoe,DC=example,DC=local", "name": "John Doe",
         "type": "user", "description": "Analyst", "status": "Enabled"},
        {"dn": "CN=asmith,DC=example,DC=local", "name": "Alice Smith",
         "type": "user", "description": "Manager", "status": "Enabled"},
    ]
    app._ad_apply_filter()
    assert len(app.ad_list.get_children()) == 2
    app._ad_search_var.set("john")
    app._ad_apply_filter()
    assert len(app.ad_list.get_children()) == 1
    app._ad_search_var.set("MANAGER")
    app._ad_apply_filter()
    assert len(app.ad_list.get_children()) == 1  # case-insensitive
    app._ad_search_var.set("zzzz")
    app._ad_apply_filter()
    assert len(app.ad_list.get_children()) == 0
    app._ad_search_var.set("")
    app._ad_apply_filter()
    assert len(app.ad_list.get_children()) == 2  # clearing restores all


def test_ad_list_shows_locked_column(root, patched_clients):
    """Locked-out users are identifiable at a glance in their own
    'Locked' column ('Yes'); other rows are blank there."""
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    assert "Locked" in app.ad_list["columns"]
    app._ad_rows = [
        {"dn": "CN=locked,DC=example,DC=local", "name": "Locked User",
         "type": "user", "description": "", "status": "Enabled, Locked",
         "locked": True},
        {"dn": "CN=jdoe,DC=example,DC=local", "name": "John Doe",
         "type": "user", "description": "Analyst", "status": "Enabled",
         "locked": False},
        {"dn": "CN=WS01,DC=example,DC=local", "name": "WS01",
         "type": "computer", "description": "", "status": "Enabled",
         "locked": False},
    ]
    app._ad_apply_filter()
    values = {app.ad_list.item(i, "values")[0]: app.ad_list.item(i, "values")
              for i in app.ad_list.get_children()}
    assert values["Locked User"][4] == "Yes"
    assert values["John Doe"][4] == ""
    assert values["WS01"][4] == ""
    # The Status column still carries the lockout detail too.
    assert values["Locked User"][3] == "Enabled, Locked"


def test_ad_search_clear_button_restores_full_list(root, patched_clients):
    """The AD search row's clear (×) button empties the search text
    and restores the full, unfiltered list."""
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    app._ad_rows = [
        {"dn": "CN=jdoe,DC=example,DC=local", "name": "John Doe",
         "type": "user", "description": "Analyst", "status": "Enabled"},
        {"dn": "CN=asmith,DC=example,DC=local", "name": "Alice Smith",
         "type": "user", "description": "Manager", "status": "Enabled"},
    ]
    app._ad_apply_filter()
    assert len(app.ad_list.get_children()) == 2
    app._ad_search_var.set("john")
    app._ad_apply_filter()
    assert len(app.ad_list.get_children()) == 1
    # One clear button per search row (AD, DHCP, DNS), in tab order;
    # the first is the AD one.
    assert len(app._search_clear_btns) == 3
    assert app._search_clear_btns[0]["text"] == "×"
    app._search_clear_btns[0].invoke()
    assert app._ad_search_var.get() == ""
    assert len(app.ad_list.get_children()) == 2


def test_search_clear_buttons_exist_on_all_tabs(root, patched_clients):
    """Every tab search row (AD, DHCP, DNS) has a clear (×) button
    that empties its own search text; the buttons follow the search
    entries' enabled/disabled state."""
    app = MSATApp(root)
    assert len(app._search_clear_btns) == 3
    for btn in app._search_clear_btns:
        assert btn["text"] == "×"
        assert str(btn["state"]) == "disabled"  # disconnected
    _connect_app(app, "dc1")
    root.update_idletasks()
    for btn in app._search_clear_btns:
        assert str(btn["state"]) == "normal"
    # Each button clears only its own tab's search text.
    app._ad_search_var.set("john")
    app._dhcp_search_var.set("scope")
    app._dns_search_var.set("zone")
    app._search_clear_btns[1].invoke()  # DHCP
    assert app._dhcp_search_var.get() == ""
    assert app._ad_search_var.get() == "john"
    assert app._dns_search_var.get() == "zone"
    app._search_clear_btns[2].invoke()  # DNS
    assert app._dns_search_var.get() == ""
    app._search_clear_btns[0].invoke()  # AD
    assert app._ad_search_var.get() == ""
    app._global_disconnect()
    root.update_idletasks()
    for btn in app._search_clear_btns:
        assert str(btn["state"]) == "disabled"


def test_attr_search_clear_button_restores_full_list(root):
    """The Attribute Editor search box's clear (×) button empties
    the search text and restores the full attribute list."""
    from msat.dialogs import UserPropertiesDialog

    attrs = {
        "displayName": {"values": ["John Doe"], "binary": False},
        "mail": {"values": ["jdoe@example.local"], "binary": False},
        "title": {"values": ["Analyst"], "binary": False},
    }
    dlg = UserPropertiesDialog(root, "John Doe", attrs)
    root.update_idletasks()
    assert len(dlg._attr_tree.get_children()) == 3
    dlg._attr_search_var.set("mail")
    dlg._fill_attr_tree()
    assert len(dlg._attr_tree.get_children()) == 1
    assert dlg._attr_clear_btn["text"] == "×"
    dlg._attr_clear_btn.invoke()
    assert dlg._attr_search_var.get() == ""
    assert len(dlg._attr_tree.get_children()) == 3
    dlg._on_cancel()


def test_user_properties_dialog_shows_lockout(root):
    """The User Properties General tab shows the lockout state as a
    read-only 'Locked out' row — Yes when lockoutTime is non-zero,
    No otherwise — and it is never written back on Save."""
    attrs_locked = {
        "displayName": {"values": ["Locked User"], "binary": False},
        "sAMAccountName": {"values": ["locked"], "binary": False},
        "lockoutTime": {"values": ["133000000000000000"], "binary": False},
    }
    dlg = UserPropertiesDialog(root, "Locked User", attrs_locked)
    root.update_idletasks()
    assert dlg._lockout_entry.get() == "Yes"
    assert str(dlg._lockout_entry["state"]) == "disabled"
    # Not an editable General field, so Save cannot write it back.
    assert "lockoutTime" not in dlg._general_entries
    dlg._on_save()
    assert "lockoutTime" not in (dlg.result or {})
    attrs_unlocked = {
        "displayName": {"values": ["John Doe"], "binary": False},
        "sAMAccountName": {"values": ["jdoe"], "binary": False},
        "lockoutTime": {"values": ["0"], "binary": False},
    }
    dlg2 = UserPropertiesDialog(root, "John Doe", attrs_unlocked)
    root.update_idletasks()
    assert dlg2._lockout_entry.get() == "No"
    dlg2._on_cancel()
    # Missing lockoutTime also means not locked.
    attrs_missing = {
        "displayName": {"values": ["Jane Doe"], "binary": False},
        "sAMAccountName": {"values": ["jane"], "binary": False},
    }
    dlg3 = UserPropertiesDialog(root, "Jane Doe", attrs_missing)
    root.update_idletasks()
    assert dlg3._lockout_entry.get() == "No"
    dlg3._on_cancel()


def test_quiet_refresh_reports_failure_without_dialog(root, patched_clients,
                                                     monkeypatch):
    """A failing tab load during connect is a status message, not a modal."""
    shown = []
    monkeypatch.setattr("msat.app.messagebox.showerror",
                        lambda *a, **k: shown.append(a))
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    assert not shown

    class Boom:
        def list_zones(self):
            raise Exception("DNS zone list failed: access denied.")

    app.dns = Boom()
    result = app._dns_refresh(quiet=True)
    assert result is not True
    assert "access denied" in str(result)
    assert not shown, "quiet refresh must not pop a dialog"
    assert "DNS zone list failed" in app.statusbar["text"]
    # The loud (toolbar Refresh) path still shows the modal.
    app._dns_refresh()
    assert shown, "explicit Refresh should show the error dialog"


def test_nested_tree_open_populates_depth_two_placeholder(root,
                                                          patched_clients):
    """Expanding a nested OU replaces its 'Loading…' placeholder (v1.4).

    Regression test: the v1.3 open handler resolved the opened node via
    focus/selection, which failed for nested nodes (focus stays on the
    parent), so EXAMPLE > Users kept a stuck placeholder. The handler now
    scans the whole tree for open nodes with a placeholder, regardless
    of depth or which node has focus.
    """
    import tkinter as tk

    from msat.app import _LOADING_SUFFIX

    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()

    class NestedAD(FakeADClient):
        def list_children(self, dn):
            if dn == "OU=Users,OU=EXAMPLE,DC=example,DC=local":
                return [{"dn": "OU=Sub,OU=Users,OU=EXAMPLE,DC=example,DC=local",
                         "type": "ou"}]
            return []

    app.ad_client = NestedAD()
    root_dn = "DC=example,DC=local"
    example_dn = "OU=EXAMPLE,DC=example,DC=local"
    users_dn = "OU=Users,OU=EXAMPLE,DC=example,DC=local"
    # Rebuild the tree: root > EXAMPLE > Users (open, placeholder child).
    app._clear_tree(app.ad_tree)
    app.ad_tree.insert("", tk.END, iid=root_dn, text="example", open=True)
    app.ad_tree.insert(root_dn, tk.END, iid=example_dn, text="EXAMPLE",
                       open=True)
    app.ad_tree.insert(example_dn, tk.END, iid=users_dn, text="Users",
                       open=True)
    app.ad_tree.insert(users_dn, tk.END,
                       iid=users_dn + _LOADING_SUFFIX, text="Loading…")
    # Focus stays on the root (the v1.3 failure mode): the handler must
    # not depend on it.
    app.ad_tree.focus(root_dn)
    app.ad_tree.selection_set(root_dn)
    root.update_idletasks()

    app._ad_on_tree_open(None)
    root.update_idletasks()

    children = app.ad_tree.get_children(users_dn)
    assert users_dn + _LOADING_SUFFIX not in children
    assert "OU=Sub,OU=Users,OU=EXAMPLE,DC=example,DC=local" in children


def test_tree_open_deferred_populates_depth_one_and_two(root, patched_clients):
    """The open handler defers to idle so it sees the settled open state.

    Regression test (v1.5): in v1.4 the handler scanned synchronously
    from <<TreeviewOpen>>, which can fire before the clicked node's
    open state settles — Builtin (depth 1) kept a stuck placeholder
    even though the root's children loaded. The handler now defers
    the scan with after_idle, so by the time it runs the open state
    has settled for the node that was just expanded, at any depth.
    """
    import tkinter as tk

    from msat.app import _LOADING_SUFFIX

    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()

    class NestedAD(FakeADClient):
        def list_children(self, dn):
            if dn == "CN=Builtin,DC=example,DC=local":
                return []  # Builtin holds only groups: tree stays empty
            if dn == "OU=Users,OU=EXAMPLE,DC=example,DC=local":
                return [{"dn": "OU=Sub,OU=Users,OU=EXAMPLE,DC=example,DC=local",
                         "name": "Sub", "type": "ou",
                         "description": "", "status": ""}]
            return []

    app.ad_client = NestedAD()
    root_dn = "DC=example,DC=local"
    builtin_dn = "CN=Builtin,DC=example,DC=local"
    example_dn = "OU=EXAMPLE,DC=example,DC=local"
    users_dn = "OU=Users,OU=EXAMPLE,DC=example,DC=local"
    app._clear_tree(app.ad_tree)
    app.ad_tree.insert("", tk.END, iid=root_dn, text="example", open=True)
    app.ad_tree.insert(root_dn, tk.END, iid=builtin_dn, text="Builtin",
                       open=False)
    app.ad_tree.insert(builtin_dn, tk.END,
                       iid=builtin_dn + _LOADING_SUFFIX, text="Loading…")
    app.ad_tree.insert(root_dn, tk.END, iid=example_dn, text="EXAMPLE",
                       open=True)
    app.ad_tree.insert(example_dn, tk.END, iid=users_dn, text="Users",
                       open=False)
    app.ad_tree.insert(users_dn, tk.END,
                       iid=users_dn + _LOADING_SUFFIX, text="Loading…")
    root.update_idletasks()

    # Simulate <<TreeviewOpen>> firing BEFORE the open state settles:
    # the handler runs, then the state settles, then idle callbacks run.
    app._ad_on_tree_open(None)
    app.ad_tree.item(builtin_dn, open=True)
    app.ad_tree.item(users_dn, open=True)
    root.update_idletasks()

    builtin_children = app.ad_tree.get_children(builtin_dn)
    assert builtin_dn + _LOADING_SUFFIX not in builtin_children
    assert builtin_children == ()  # groups only: expanded but empty
    users_children = app.ad_tree.get_children(users_dn)
    assert users_dn + _LOADING_SUFFIX not in users_children
    assert "OU=Sub,OU=Users,OU=EXAMPLE,DC=example,DC=local" in users_children


def test_tree_open_failure_in_one_node_does_not_abort_scan(
        root, patched_clients, monkeypatch):
    """One node's populate failure must not stop other nodes loading."""
    import tkinter as tk

    from msat.app import _LOADING_SUFFIX

    shown = []
    monkeypatch.setattr("msat.app.messagebox.showerror",
                        lambda *a, **k: shown.append(a))
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()

    class FlakyAD(FakeADClient):
        def list_children(self, dn):
            if dn == "CN=Builtin,DC=example,DC=local":
                raise Exception("LDAP search failed: operationsError")
            if dn == "OU=Users,OU=EXAMPLE,DC=example,DC=local":
                return [{"dn": "OU=Sub,OU=Users,OU=EXAMPLE,DC=example,DC=local",
                         "name": "Sub", "type": "ou",
                         "description": "", "status": ""}]
            return []

    app.ad_client = FlakyAD()
    root_dn = "DC=example,DC=local"
    builtin_dn = "CN=Builtin,DC=example,DC=local"
    users_dn = "OU=Users,OU=EXAMPLE,DC=example,DC=local"
    app._clear_tree(app.ad_tree)
    app.ad_tree.insert("", tk.END, iid=root_dn, text="example", open=True)
    app.ad_tree.insert(root_dn, tk.END, iid=builtin_dn, text="Builtin",
                       open=True)
    app.ad_tree.insert(builtin_dn, tk.END,
                       iid=builtin_dn + _LOADING_SUFFIX, text="Loading…")
    app.ad_tree.insert(root_dn, tk.END, iid=users_dn, text="Users",
                       open=True)
    app.ad_tree.insert(users_dn, tk.END,
                       iid=users_dn + _LOADING_SUFFIX, text="Loading…")
    root.update_idletasks()

    app._ad_on_tree_open(None)
    root.update_idletasks()

    # Users still populated despite Builtin failing.
    users_children = app.ad_tree.get_children(users_dn)
    assert "OU=Sub,OU=Users,OU=EXAMPLE,DC=example,DC=local" in users_children
    # Builtin kept its placeholder for a retry (the failure path
    # re-inserts it) and exactly one error dialog was shown.
    builtin_children = app.ad_tree.get_children(builtin_dn)
    assert builtin_dn + _LOADING_SUFFIX in builtin_children
    assert len(shown) == 1


def test_properties_attr_search_filters_and_preserves_edits(root):
    """Attribute Editor search narrows by name; edits survive filtering."""
    from msat.dialogs import UserPropertiesDialog

    attrs = {
        "displayName": {"values": ["John Doe"], "binary": False},
        "mail": {"values": ["jdoe@example.local"], "binary": False},
        "proxyAddresses": {"values": ["SMTP:jdoe@example.local",
                                      "smtp:jdoe@mail.example.local"],
                           "binary": False},
        "title": {"values": ["Analyst"], "binary": False},
    }
    dlg = UserPropertiesDialog(root, "John Doe", attrs)
    root.update_idletasks()
    assert len(dlg._attr_tree.get_children()) == 4
    # Filter by attribute name.
    dlg._attr_search_var.set("proxy")
    dlg._fill_attr_tree()
    rows = dlg._attr_tree.get_children()
    assert len(rows) == 1
    assert dlg._attr_tree.item(rows[0], "values")[0] == "proxyAddresses"
    # Edit a value while filtered, then clear: the edit is kept.
    dlg._values["title"] = ["Lead Analyst"]
    dlg._attr_search_var.set("")
    dlg._fill_attr_tree()
    assert len(dlg._attr_tree.get_children()) == 4
    assert dlg._values["title"] == ["Lead Analyst"]
    # Value text also matches (SMTP appears in proxyAddresses values).
    dlg._attr_search_var.set("smtp:")
    dlg._fill_attr_tree()
    rows = dlg._attr_tree.get_children()
    assert len(rows) == 1
    assert dlg._attr_tree.item(rows[0], "values")[0] == "proxyAddresses"
    dlg._on_cancel()


def test_group_properties_dialog_shows_members(root):
    """Group Properties opens with General, Members and Attribute Editor."""
    from msat.dialogs import GroupPropertiesDialog

    attrs = {
        "displayName": {"values": ["IT Admins"], "binary": False},
        "sAMAccountName": {"values": ["ITAdmins"], "binary": False},
        "description": {"values": ["IT administrators"], "binary": False},
        "groupType": {"values": ["-2147483646"], "binary": False},
        "distinguishedName": {"values": ["CN=IT Admins,OU=Groups,DC=example,DC=local"],
                              "binary": False},
        "member": {"values": ["CN=jdoe,OU=Users,DC=example,DC=local"],
                   "binary": False},
        "objectGUID": {"values": ["000102030405060708090a0b0c0d0e0f"],
                       "binary": True},
    }
    members = [{"dn": "CN=jdoe,OU=Users,DC=example,DC=local",
                "name": "John Doe", "sam": "jdoe",
                "display_name": "John Doe", "type": "user"}]

    class FakeClient:
        def add_group_member(self, group_dn, member_dn):
            raise AssertionError("no membership change expected")
        def remove_group_member(self, group_dn, member_dn):
            raise AssertionError("no membership change expected")
        def search_users(self, base_dn, query):
            return []
        def search_groups(self, base_dn, query):
            return []

    dlg = GroupPropertiesDialog(root, "IT Admins", attrs, FakeClient(),
                                "DC=example,DC=local",
                                "CN=IT Admins,OU=Groups,DC=example,DC=local",
                                members)
    root.update_idletasks()
    # Members tab lists the resolved member.
    rows = dlg._member_tree.get_children()
    assert len(rows) == 1
    values = dlg._member_tree.item(rows[0], "values")
    assert values[0] == "John Doe"
    assert values[1] == "jdoe"
    assert values[2] == "User"
    # General tab shows the group type label.
    assert "Global security" in dlg._group_type_label()
    # Attribute Editor lists member as read-only.
    assert "(read-only)" in dlg._attr_tree.item("member", "values")[1]
    # Editing displayName produces a change-only diff (member excluded).
    dlg._general_entries["displayName"].delete(0, tk.END)
    dlg._general_entries["displayName"].insert(0, "IT Admins 2")
    dlg._on_save()
    assert dlg.result == {"displayName": ["IT Admins 2"]}
    assert dlg.membership_changes == []


def test_group_properties_add_remove_member_applies_immediately(
        root, monkeypatch):
    """Members tab Add/Remove call the client immediately and update the list."""
    from msat import dialogs
    from msat.dialogs import GroupPropertiesDialog

    group_dn = "CN=IT Admins,OU=Groups,DC=example,DC=local"
    attrs = {
        "displayName": {"values": ["IT Admins"], "binary": False},
        "sAMAccountName": {"values": ["ITAdmins"], "binary": False},
        "member": {"values": ["CN=jdoe,OU=Users,DC=example,DC=local"],
                   "binary": False},
    }
    members = [{"dn": "CN=jdoe,OU=Users,DC=example,DC=local",
                "name": "John Doe", "sam": "jdoe",
                "display_name": "John Doe", "type": "user"}]

    class FakeClient:
        def __init__(self):
            self.added = []
            self.removed = []
        def add_group_member(self, group_dn, member_dn):
            self.added.append((group_dn, member_dn))
        def remove_group_member(self, group_dn, member_dn):
            self.removed.append((group_dn, member_dn))
        def search_users(self, base_dn, query):
            return []
        def search_groups(self, base_dn, query):
            return []

    client = FakeClient()
    dlg = GroupPropertiesDialog(root, "IT Admins", attrs, client,
                                "DC=example,DC=local", group_dn, members)
    root.update_idletasks()
    assert len(dlg._member_tree.get_children()) == 1

    # Add Alice via the picker (stubbed to return her immediately).
    new_member = {"dn": "CN=asmith,OU=Users,DC=example,DC=local",
                  "name": "Alice Smith", "sam": "asmith",
                  "display_name": "Alice Smith", "type": "user"}

    class FakePicker:
        def __init__(self, *a, **k):
            self.result = new_member
        def wait_window(self):
            pass

    monkeypatch.setattr(dialogs, "MemberPickerDialog", FakePicker)
    dlg._on_add_member()
    assert client.added == [(group_dn, "CN=asmith,OU=Users,DC=example,DC=local")]
    assert len(dlg._member_tree.get_children()) == 2
    assert dlg.membership_changes == [("added", "Alice Smith")]
    # The Attribute Editor's member row stays in sync.
    assert "CN=asmith" in dlg._attr_tree.item("member", "values")[1]

    # Remove John: select his row and confirm the prompt.
    monkeypatch.setattr("msat.dialogs.messagebox.askyesno",
                        lambda *a, **k: True)
    dlg._member_tree.selection_set("CN=jdoe,OU=Users,DC=example,DC=local")
    dlg._on_remove_member()
    assert client.removed == [(group_dn, "CN=jdoe,OU=Users,DC=example,DC=local")]
    assert len(dlg._member_tree.get_children()) == 1
    assert dlg.membership_changes[-1] == ("removed", "John Doe")
    dlg._on_cancel()


def test_double_click_routes_group_vs_user(root, patched_clients, monkeypatch):
    """Double-clicking a group opens Group Properties; a user opens User Properties."""
    from msat import dialogs

    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    opened = []

    class FakeUserDlg:
        def __init__(self, *a, **k):
            opened.append("user")
            self.result = None
        def wait_window(self):
            pass

    class FakeGroupDlg:
        def __init__(self, *a, **k):
            opened.append("group")
            self.result = None
            self.membership_changes = []
        def wait_window(self):
            pass

    monkeypatch.setattr(dialogs, "UserPropertiesDialog", FakeUserDlg)
    monkeypatch.setattr(dialogs, "GroupPropertiesDialog", FakeGroupDlg)
    app.ad_client.get_object_attributes = lambda dn: {}
    app.ad_client.resolve_members = lambda dns: []
    app._ad_rows = [
        {"dn": "CN=jdoe,OU=Users,DC=example,DC=local", "name": "John Doe",
         "type": "user", "description": "", "status": "Enabled"},
        {"dn": "CN=Admins,OU=IT,DC=example,DC=local", "name": "Admins",
         "type": "group", "description": "", "status": ""},
    ]
    app._ad_apply_filter()
    # Double-click the user row.
    app.ad_list.selection_set("CN=jdoe,OU=Users,DC=example,DC=local")
    app._ad_on_list_double_click(None)
    assert opened == ["user"]
    # Double-click the group row.
    app.ad_list.selection_set("CN=Admins,OU=IT,DC=example,DC=local")
    app._ad_on_list_double_click(None)
    assert opened == ["user", "group"]


def test_edit_reservation_dialog_prefills_fields(root):
    """Edit Reservation dialog is pre-filled with the current values."""
    from msat.dialogs import EditReservationDialog

    dlg = EditReservationDialog(root, "192.168.1.0", {
        "IPAddress": "192.168.1.50", "Name": "Printer",
        "ClientId": "AA-BB-CC-DD-EE-FF", "Description": "Front printer"})
    root.update_idletasks()
    assert dlg.ip.get() == "192.168.1.50"
    assert dlg.mac.get() == "AA-BB-CC-DD-EE-FF"
    assert dlg.name.get() == "Printer"
    assert dlg.description.get() == "Front printer"
    dlg._on_cancel()


def test_edit_record_dialog_prefills_fields(root):
    """Edit Record dialog is pre-filled; name/type are read-only."""
    from msat.dialogs import EditRecordDialog

    dlg = EditRecordDialog(root, "example.local", {
        "HostName": "dc1", "RecordType": "A", "TTL": 3600.0,
        "Data": "192.168.1.10", "RemoveData": "192.168.1.10"})
    root.update_idletasks()
    assert dlg._name == "dc1" and dlg._rtype == "A"
    assert dlg.data.get() == "192.168.1.10"
    assert dlg.ttl.get() == "3600"
    dlg._on_cancel()

    # MX splits the display value into host + preference.
    dlg = EditRecordDialog(root, "example.local", {
        "HostName": "@", "RecordType": "MX", "TTL": 3600.0,
        "Data": "10 mail.example.local", "RemoveData": "mail.example.local"})
    root.update_idletasks()
    assert dlg.data.get() == "mail.example.local"
    assert dlg.preference.get() == "10"
    dlg._on_cancel()


# -- role detection and tab gating (v1.8.0) ----------------------------------

def _button_states(buttons):
    return {btn["text"]: str(btn["state"]) for btn in buttons}


def _assert_ad_buttons_no_selection(app):
    """AD toolbar state with no row selected (v1.8.7 selection gating):
    the buttons that need no selection are enabled; the row actions
    (Enable / Disable / Unlock / Reset Password / Add to Group /
    Move / Properties / Delete) are disabled until a row is selected."""
    states = _button_states(app.ad_toolbar_buttons)
    for label in ("New User", "New Computer", "New Group", "Refresh"):
        assert states[label] == "normal", label
    for label in ("Enable", "Disable", "Unlock", "Reset Password",
                  "Add to Group", "Move...", "Properties", "Delete"):
        assert states[label] == "disabled", label


def _assert_ad_buttons_with_selection(app):
    """AD toolbar state with a row selected: every button enabled."""
    states = _button_states(app.ad_toolbar_buttons)
    for label, state in states.items():
        assert state == "normal", label


def test_dns_tab_disabled_when_dns_role_absent(root, patched_clients,
                                              monkeypatch):
    """A server without the DNS role gets a gated DNS tab (note + tools
    disabled, Refresh stays enabled); AD and Directory Info stay on."""
    monkeypatch.setattr(
        "msat.app.detect_server_roles",
        lambda client: {"DNS": False, "DHCP": True})
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    assert app._dns_enabled is False
    assert app._dhcp_enabled is True
    states = _button_states(app.dns_toolbar_buttons)
    assert states["Refresh"] == "normal"
    assert states["Add Record"] == "disabled"
    assert states["Edit Record"] == "disabled"
    assert states["Remove Record"] == "disabled"
    assert str(app._dns_search_entry["state"]) == "disabled"
    assert "dc1" in app.dns_note["text"]
    assert "DNS Server role" in app.dns_note["text"]
    assert "DNS tab disabled" in app.dns_note["text"]
    assert "DNS Server role is not installed on dc1" in app.statusbar["text"]
    # AD and Directory Info are unaffected by a missing DNS role:
    # the AD buttons follow the connected state (the row actions are
    # disabled only because nothing is selected, v1.8.7).
    _assert_ad_buttons_no_selection(app)
    assert str(app.info_refresh_btn["state"]) == "normal"


def test_dhcp_tab_disabled_when_no_server_has_dhcp(root, patched_clients,
                                                   monkeypatch):
    """No DHCP role anywhere: the DHCP tab is gated with a note naming
    the missing role; DNS and AD stay on."""
    monkeypatch.setattr(
        "msat.app.detect_server_roles",
        lambda client: {"DNS": True, "DHCP": False})
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    assert app._dhcp_enabled is False
    assert app._dns_enabled is True
    assert app._dhcp_candidates == []
    states = _button_states(app.dhcp_toolbar_buttons)
    assert states["Refresh"] == "normal"
    assert states["Add Reservation"] == "disabled"
    assert states["Edit Reservation"] == "disabled"
    assert states["Remove Reservation"] == "disabled"
    assert states["Superscopes"] == "disabled"
    assert "DHCP Server role" in app.dhcp_note["text"]
    assert "DHCP tab disabled" in app.dhcp_note["text"]
    assert "DHCP Server role is not installed" in app.statusbar["text"]
    # The picker is hidden when there is no DHCP server to pick.
    assert app.dhcp_server_frame.winfo_manager() == ""
    # DNS still loads.
    assert all(str(b["state"]) == "normal" for b in app.dns_toolbar_buttons)


def test_detection_unavailable_leaves_all_tabs_enabled(root, patched_clients,
                                                       monkeypatch):
    """When role detection itself fails, the connection is not broken
    and no tab is disabled — the app falls back to all tabs enabled
    and says so in the status bar."""
    from msat.winrm_client import WinRMError

    def _boom(client):
        raise WinRMError("WinRM request to {} failed: connection refused"
                         .format(client.host))

    monkeypatch.setattr("msat.app.detect_server_roles", _boom)
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    assert app.ad_client is not None
    assert app._roles_available is False
    assert app._dns_enabled is True
    assert app._dhcp_enabled is True
    assert app._dhcp_server == "dc1"
    # DHCP/DNS/Info toolbars are fully enabled; AD follows the
    # connected state (row actions disabled only because nothing is
    # selected, v1.8.7).
    for btn in (app.dhcp_toolbar_buttons + app.dns_toolbar_buttons +
                [app.info_refresh_btn]):
        assert str(btn["state"]) == "normal"
    _assert_ad_buttons_no_selection(app)
    assert "Role detection unavailable" in app.statusbar["text"]


def test_dhcp_refresh_rechecks_missing_role(root, patched_clients,
                                            monkeypatch):
    """Refresh on a gated DHCP tab re-runs discovery; if a DHCP server
    is found now, the tab is enabled and loads."""
    monkeypatch.setattr(
        "msat.app.detect_server_roles",
        lambda client: {"DNS": True, "DHCP": False})
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    assert app._dhcp_enabled is False

    # The DHCP role is installed on dc1 afterwards.
    monkeypatch.setattr(
        "msat.app.detect_server_roles",
        lambda client: {"DNS": True, "DHCP": True})
    result = app._dhcp_refresh()
    root.update_idletasks()
    assert result is True
    assert app._dhcp_enabled is True
    assert app._dhcp_server == "dc1"
    assert all(str(b["state"]) == "normal" for b in app.dhcp_toolbar_buttons)
    assert "Loaded 0 DHCP scope(s)." in app.statusbar["text"]


def test_dns_refresh_rechecks_missing_role(root, patched_clients,
                                           monkeypatch):
    """Refresh on a gated DNS tab re-checks the role; if it is present
    now, the tab is enabled and loads."""
    monkeypatch.setattr(
        "msat.app.detect_server_roles",
        lambda client: {"DNS": False, "DHCP": True})
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    assert app._dns_enabled is False

    # The DNS role is installed on dc1 afterwards.
    monkeypatch.setattr(
        "msat.app.detect_server_roles",
        lambda client: {"DNS": True, "DHCP": True})
    result = app._dns_refresh()
    root.update_idletasks()
    assert result is True
    assert app._dns_enabled is True
    assert app.dns_note["text"] == ""
    assert all(str(b["state"]) == "normal" for b in app.dns_toolbar_buttons)
    assert "Loaded 0 DNS zone(s)." in app.statusbar["text"]


def test_ad_tab_always_enabled_when_both_roles_missing(root, patched_clients,
                                                       monkeypatch):
    """AD and Directory Info never depend on role detection."""
    monkeypatch.setattr(
        "msat.app.detect_server_roles",
        lambda client: {"DNS": False, "DHCP": False})
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    assert app._dns_enabled is False
    assert app._dhcp_enabled is False
    # AD is not gated by the missing roles: its buttons follow the
    # connected state (row actions disabled only because nothing is
    # selected, v1.8.7).
    _assert_ad_buttons_no_selection(app)
    assert str(app.info_refresh_btn["state"]) == "normal"
    assert app.ad_tree.exists("DC=example,DC=local")


# -- v1.8.5: review fixes ------------------------------------------------------

def test_disconnect_clears_password_field(root, patched_clients):
    """Disconnect wipes the password from the entry field and its
    StringVar (v1.8.5), not just the credential store."""
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    assert app.password_var.get() == "secret"
    assert app.password_entry.get() == "secret"
    app._global_disconnect()
    root.update_idletasks()
    assert app.password_var.get() == ""
    assert app.password_entry.get() == ""
    assert app.creds.password is None


def test_dhcp_server_switch_updates_label(root, patched_clients):
    """Switching the DHCP server picker updates the 'Managing DHCP
    on ...' label (v1.8.5)."""
    app = MSATApp(root)
    _connect_app(app, "dc3")  # dc3 has no DHCP: the picker shows dc1/dc2
    root.update_idletasks()
    assert "Managing DHCP on dc1." in app.dhcp_note["text"]
    app.dhcp_server_var.set("dc2")
    app._dhcp_on_server_change()
    root.update_idletasks()
    assert app._dhcp_server == "dc2"
    assert "Managing DHCP on dc2." in app.dhcp_note["text"]


def test_role_gating_disables_search_clear_buttons(root, patched_clients,
                                                   monkeypatch):
    """When a role is missing, the tab's search entry AND its clear
    (×) button are disabled (v1.8.5)."""
    monkeypatch.setattr(
        "msat.app.detect_server_roles",
        lambda client: {"DNS": False, "DHCP": False})
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    assert str(app._dns_search_entry["state"]) == "disabled"
    assert str(app._dns_search_clear_btn["state"]) == "disabled"
    assert str(app._dhcp_search_entry["state"]) == "disabled"
    assert str(app._dhcp_search_clear_btn["state"]) == "disabled"
    # The AD search row is unaffected (AD is always enabled).
    assert str(app._search_entries[0]["state"]) == "normal"
    assert str(app._search_clear_btns[0]["state"]) == "normal"


def test_dhcp_discovery_short_circuits_when_connected_server_has_dhcp(
        root, patched_clients, monkeypatch):
    """When the connected server has the DHCP role, the other
    configured servers are not probed (v1.8.5)."""
    calls = []

    def counting_roles(client):
        calls.append(getattr(client, "host", None))
        if getattr(client, "host", None) == "dc3":
            return {"DNS": True, "DHCP": False}
        return {"DNS": True, "DHCP": True}

    monkeypatch.setattr("msat.app.detect_server_roles", counting_roles)
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    assert calls == ["dc1"]


def test_dhcp_discovery_probes_other_servers_when_connected_server_lacks_dhcp(
        root, patched_clients, monkeypatch):
    """When the connected server has no DHCP role, the other
    configured servers are probed in order (v1.8.5)."""
    calls = []

    def counting_roles(client):
        calls.append(getattr(client, "host", None))
        if getattr(client, "host", None) == "dc3":
            return {"DNS": True, "DHCP": False}
        return {"DNS": True, "DHCP": True}

    monkeypatch.setattr("msat.app.detect_server_roles", counting_roles)
    app = MSATApp(root)
    _connect_app(app, "dc3")
    root.update_idletasks()
    assert calls == ["dc3", "dc1", "dc2"]


def test_tree_select_runs_one_list_children_query(root, patched_clients):
    """Clicking a tree node runs list_children once for that DN
    (v1.8.5): the old code ran it twice (list view + tree children)."""
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    root_dn = "DC=example,DC=local"
    assert app.ad_tree.exists(root_dn + "__loading__")
    calls = []
    orig = app.ad_client.list_children

    def counting(dn):
        calls.append(dn)
        return orig(dn)

    app.ad_client.list_children = counting
    app.ad_tree.selection_set(root_dn)
    app._ad_on_tree_select(None)
    assert calls == [root_dn]


def test_dhcp_refresh_scope_reloads_with_filter_active(root, patched_clients):
    """After an add/edit/remove, the scope reloads even when a search
    filter is active (v1.8.5): the filter rebuilds the scopes tree
    and wipes the selection, which used to make the post-change
    refresh a no-op and leave the lists stale."""
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    scopes = [{"ScopeId": "192.168.1.0", "Name": "Office",
               "SubnetMask": "255.255.255.0", "State": "Active",
               "StartRange": "192.168.1.10", "EndRange": "192.168.1.200",
               "LeaseDuration": "1.00:00:00"}]
    leases = [{"IPAddress": "192.168.1.10", "HostName": "PC-01",
               "ClientId": "00-11-22-33-44-55", "AddressState": "Active",
               "LeaseExpiryTime": "2026-11-14T10:00:00",
               "ClientType": "DHCP"}]
    reservations = [{"IPAddress": "192.168.1.50", "Name": "Printer",
                     "ClientId": "AA-BB-CC-DD-EE-FF",
                     "Description": "Front printer", "Type": "DHCP"}]
    calls = {"leases": 0, "reservations": 0}

    def list_leases(scope_id):
        calls["leases"] += 1
        return list(leases)

    def list_reservations(scope_id):
        calls["reservations"] += 1
        return list(reservations)

    app.dhcp.list_scopes = lambda: list(scopes)
    app.dhcp.list_leases = list_leases
    app.dhcp.list_reservations = list_reservations
    app._dhcp_refresh()
    root.update_idletasks()
    assert len(app.dhcp_scopes.get_children()) == 1
    app.dhcp_scopes.selection_set(app.dhcp_scopes.get_children()[0])
    app._dhcp_on_scope_select(None)
    assert app._dhcp_current_scope == "192.168.1.0"
    assert len(app.dhcp_leases.get_children()) == 1
    assert len(app.dhcp_reservations.get_children()) == 1
    # A search filter rebuilds the scopes tree and wipes the selection.
    app._dhcp_search_var.set("office")
    app._dhcp_apply_filter()
    assert app.dhcp_scopes.selection() == ()
    # The post-change refresh (what add/edit/remove now call) still
    # reloads the scope's leases and reservations — the canonical
    # rows prove it, even though the active filter hides rows that
    # do not match "office" (correct: the filter still applies).
    calls["leases"] = 0
    calls["reservations"] = 0
    app._dhcp_refresh_scope(app._dhcp_current_scope)
    assert calls["leases"] == 1
    assert calls["reservations"] == 1
    assert len(app._dhcp_leases_rows) == 1
    assert len(app._dhcp_reservations_rows) == 1
    # Clearing the filter shows the reloaded rows in the trees.
    app._dhcp_search_var.set("")
    app._dhcp_apply_filter()
    assert len(app.dhcp_leases.get_children()) == 1
    assert len(app.dhcp_reservations.get_children()) == 1


def test_dns_refresh_zone_reloads_with_filter_active(root, patched_clients):
    """After an add/edit/remove, the zone reloads even when a search
    filter is active (v1.8.5): the filter rebuilds the zones tree and
    wipes the selection, which used to make the post-change refresh
    a no-op and leave the records stale."""
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    zones = [{"ZoneName": "example.local", "ZoneType": "Primary",
              "IsDsIntegrated": True, "IsReverseLookupZone": False,
              "DynamicUpdate": "Secure"}]
    records = [{"HostName": "dc1", "RecordType": "A", "TimeStamp": None,
                "TTL": 3600.0, "Data": "192.168.1.10",
                "RemoveData": "192.168.1.10"}]
    calls = {"records": 0}

    def list_records(zone):
        calls["records"] += 1
        return list(records)

    app.dns.list_zones = lambda: list(zones)
    app.dns.list_records = list_records
    app._dns_refresh()
    root.update_idletasks()
    assert len(app.dns_zones.get_children()) == 1
    app.dns_zones.selection_set(app.dns_zones.get_children()[0])
    app._dns_on_zone_select(None)
    assert app._dns_current_zone == "example.local"
    assert len(app.dns_records.get_children()) == 1
    app._dns_search_var.set("example")
    app._dns_apply_filter()
    assert app.dns_zones.selection() == ()
    # The post-change refresh (what add/edit/remove now call) still
    # reloads the zone's records — the canonical rows prove it, even
    # though the active filter hides rows that do not match
    # "example" (correct: the filter still applies).
    calls["records"] = 0
    app._dns_refresh_zone(app._dns_current_zone)
    assert calls["records"] == 1
    assert len(app._dns_records_rows) == 1
    # Clearing the filter shows the reloaded rows in the tree.
    app._dns_search_var.set("")
    app._dns_apply_filter()
    assert len(app.dns_records.get_children()) == 1


def test_new_user_passes_must_change_without_second_password_write(
        root, patched_clients, monkeypatch):
    """_ad_new_user passes must_change into create_user (v1.8.5) and
    does not call reset_password a second time."""
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    created = {}
    reset_calls = []

    class _SpyAD(FakeADClient):
        def create_user(self, ou_dn, sam, given="", sn="", display_name="",
                        password=None, upn=None, user_account_control=512,
                        must_change=False):
            created["must_change"] = must_change
            created["sam"] = sam
            return "CN={},{}".format(display_name or sam, ou_dn)

        def reset_password(self, dn, new_password, must_change=False):
            reset_calls.append((dn, new_password, must_change))

    app.ad_client = _SpyAD()
    app._ad_current_dn = "DC=example,DC=local"

    class _FakeDialog:
        def __init__(self, parent, ou_dn):
            self.result = {"ou": "OU=Users,DC=example,DC=local",
                           "sam": "jdoe", "given": "John", "sn": "Doe",
                           "display": "John Doe", "password": "Temp1234!",
                           "must_change": True}

        def wait_window(self):
            return None

    monkeypatch.setattr("msat.app.dialogs.NewUserDialog", _FakeDialog)
    app._ad_refresh = lambda: None
    app._ad_new_user()
    assert created["must_change"] is True
    assert created["sam"] == "jdoe"
    assert reset_calls == []


def test_search_filter_is_debounced(root, patched_clients):
    """Typing in a search box does not filter immediately (v1.8.5):
    the filter runs ~150 ms after the last keystroke."""
    import time
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    app._ad_rows = [
        {"dn": "CN=jdoe,DC=example,DC=local", "name": "John Doe",
         "type": "user", "description": "Analyst", "status": "Enabled"},
        {"dn": "CN=asmith,DC=example,DC=local", "name": "Alice Smith",
         "type": "user", "description": "Manager", "status": "Enabled"},
    ]
    app._ad_apply_filter()
    assert len(app.ad_list.get_children()) == 2
    entry = app._search_entries[0]  # AD search entry
    # Focus the entry first: a real keystroke goes to the focused
    # widget, and a synthetic KeyRelease is only delivered to the
    # entry when it has focus. focus_force() (not focus_set()) is
    # needed under xvfb, where the window manager does not grant
    # focus to the test window on its own.
    entry.focus_force()
    app._ad_search_var.set("john")
    entry.event_generate("<KeyRelease>", keysym="n")
    root.update()
    # Not yet filtered — the debounce has not fired.
    assert len(app.ad_list.get_children()) == 2
    time.sleep(0.25)
    root.update()
    assert len(app.ad_list.get_children()) == 1


def test_disconnect_cancels_pending_search_debounce(root, patched_clients,
                                                    monkeypatch):
    """Disconnect cancels a pending search-debounce timer (v1.8.6):
    typing then disconnecting within 150 ms must not run the filter
    after disconnect, and disconnect itself must not raise."""
    import time
    calls = []
    orig_apply = MSATApp._ad_apply_filter

    def _counting(self):
        calls.append(1)
        return orig_apply(self)

    # Patch the class method before building the app: _make_search_row
    # captures the bound method at construction time, so the debounced
    # callback must already be the counting wrapper.
    monkeypatch.setattr(MSATApp, "_ad_apply_filter", _counting)
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    app._ad_rows = [
        {"dn": "CN=jdoe,DC=example,DC=local", "name": "John Doe",
         "type": "user", "description": "Analyst", "status": "Enabled"},
        {"dn": "CN=asmith,DC=example,DC=local", "name": "Alice Smith",
         "type": "user", "description": "Manager", "status": "Enabled"},
    ]
    app._ad_apply_filter()
    assert len(app.ad_list.get_children()) == 2
    entry = app._search_entries[0]  # AD search entry
    entry.focus_force()
    app._ad_search_var.set("john")
    entry.event_generate("<KeyRelease>", keysym="n")
    root.update()
    # A timer is now pending (the debounce has not fired).
    assert app._search_debounce_pending[0].get("after_id") is not None
    # Disconnect before the 150 ms debounce elapses.
    calls.clear()
    app._global_disconnect()
    root.update_idletasks()
    # The pending timers were cancelled and forgotten.
    assert all(p.get("after_id") is None
               for p in app._search_debounce_pending)
    time.sleep(0.25)
    root.update()
    # The filter did not run after disconnect, and the list stayed empty.
    assert calls == []
    assert len(app.ad_list.get_children()) == 0


def test_disconnect_with_pending_debounce_then_destroy_succeeds(
        root, patched_clients):
    """Disconnect with a pending search debounce must not break a
    later root.destroy() (v1.8.7 regression): the debounce timer is
    scheduled with entry.after, and cancelling it via
    root.after_cancel corrupted Tcl's callback bookkeeping, so
    destroy() raised "can't delete Tcl command" and left the window
    (and its pending startup update check) alive — which then fired
    during a later test and opened a second update dialog."""
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    app._ad_rows = [
        {"dn": "CN=jdoe,DC=example,DC=local", "name": "John Doe",
         "type": "user", "description": "Analyst", "status": "Enabled"},
    ]
    app._ad_apply_filter()
    entry = app._search_entries[0]  # AD search entry
    entry.focus_force()
    app._ad_search_var.set("john")
    entry.event_generate("<KeyRelease>", keysym="n")
    root.update()
    # A timer is now pending (the debounce has not fired).
    assert app._search_debounce_pending[0].get("after_id") is not None
    app._global_disconnect()
    root.update_idletasks()
    # Destroying the root must succeed — no "can't delete Tcl command".
    root.destroy()
    # The interpreter is gone, so any further Tk call raises; that
    # error itself proves the window was destroyed.
    with pytest.raises(tk.TclError):
        root.winfo_exists()


def test_search_clear_button_still_filters_immediately(root, patched_clients):
    """The × clear button filters immediately, not via the debounce
    (v1.8.6): it is unaffected by the disconnect-timer tracking."""
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    app._ad_rows = [
        {"dn": "CN=jdoe,DC=example,DC=local", "name": "John Doe",
         "type": "user", "description": "Analyst", "status": "Enabled"},
        {"dn": "CN=asmith,DC=example,DC=local", "name": "Alice Smith",
         "type": "user", "description": "Manager", "status": "Enabled"},
    ]
    app._ad_search_var.set("john")
    app._ad_apply_filter()
    assert len(app.ad_list.get_children()) == 1
    app._search_clear_btns[0].invoke()
    root.update_idletasks()
    assert app._ad_search_var.get() == ""
    assert len(app.ad_list.get_children()) == 2


def test_edit_record_dialog_empty_ttl_does_not_raise(root):
    """An empty TTL in the record does not crash EditRecordDialog
    (v1.8.5): int(float('')) used to raise ValueError."""
    from msat.dialogs import EditRecordDialog
    dlg = EditRecordDialog(root, "example.local", {
        "HostName": "dc1", "RecordType": "A", "TTL": "",
        "Data": "192.168.1.10", "RemoveData": "192.168.1.10"})
    try:
        assert dlg.ttl.get() == ""
    finally:
        dlg._on_cancel()


def test_edit_record_dialog_non_numeric_ttl_shows_empty(root):
    """A non-numeric TTL shows an empty TTL field, not a crash."""
    from msat.dialogs import EditRecordDialog
    dlg = EditRecordDialog(root, "example.local", {
        "HostName": "dc1", "RecordType": "A", "TTL": "not-a-number",
        "Data": "192.168.1.10", "RemoveData": "192.168.1.10"})
    try:
        assert dlg.ttl.get() == ""
    finally:
        dlg._on_cancel()


def test_edit_record_dialog_float_ttl_shows_integer(root):
    """A float TTL (e.g. 3600.0 from the JSON) shows as an integer."""
    from msat.dialogs import EditRecordDialog
    dlg = EditRecordDialog(root, "example.local", {
        "HostName": "dc1", "RecordType": "A", "TTL": 3600.0,
        "Data": "192.168.1.10", "RemoveData": "192.168.1.10"})
    try:
        assert dlg.ttl.get() == "3600"
    finally:
        dlg._on_cancel()


def test_record_dialogs_reject_negative_ttl(root, monkeypatch):
    """A negative TTL is rejected by both record dialogs (v1.8.5)."""
    from msat.dialogs import AddRecordDialog, EditRecordDialog
    shown = []
    monkeypatch.setattr("msat.dialogs.messagebox.showwarning",
                        lambda *a, **k: shown.append(a))
    add = AddRecordDialog(root, "example.local")
    try:
        add.name.insert(0, "pc01")
        add.data.insert(0, "192.168.1.10")
        add.ttl.insert(0, "-5")
        assert add.validate() is False
        assert shown, "expected a warning about the negative TTL"
    finally:
        add._on_cancel()
    shown.clear()
    edit = EditRecordDialog(root, "example.local", {
        "HostName": "dc1", "RecordType": "A", "TTL": 3600.0,
        "Data": "192.168.1.10", "RemoveData": "192.168.1.10"})
    try:
        edit.ttl.delete(0, tk.END)
        edit.ttl.insert(0, "-5")
        assert edit.validate() is False
        assert shown, "expected a warning about the negative TTL"
    finally:
        edit._on_cancel()
    # Zero is a valid TTL (no caching) and is accepted.
    shown.clear()
    edit2 = EditRecordDialog(root, "example.local", {
        "HostName": "dc1", "RecordType": "A", "TTL": 3600.0,
        "Data": "192.168.1.10", "RemoveData": "192.168.1.10"})
    try:
        edit2.ttl.delete(0, tk.END)
        edit2.ttl.insert(0, "0")
        assert edit2.validate() is True
    finally:
        edit2._on_cancel()


def test_info_refresh_lists_all_naming_contexts(root, patched_clients):
    """Directory Info shows every naming context (v1.8.5): the old
    get_root_dse collapsed the list to its first element."""
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    app.ad_client.get_root_dse = lambda: {
        "defaultNamingContext": "DC=example,DC=local",
        "namingContexts": ["DC=example,DC=local",
                           "CN=Configuration,DC=example,DC=local",
                           "CN=Schema,CN=Configuration,DC=example,DC=local"]}
    app._info_refresh()
    text = app.info_text.get("1.0", tk.END)
    assert ("Naming contexts: DC=example,DC=local, "
            "CN=Configuration,DC=example,DC=local, "
            "CN=Schema,CN=Configuration,DC=example,DC=local") in text


# -- v1.8.7: move AD object to another OU + AD context menu ------------------

def _ad_rows_jdoe():
    """Two user rows for the AD list (bypassing the server)."""
    return [{"dn": "CN=jdoe,OU=Users,DC=example,DC=local", "name": "John Doe",
             "type": "user", "description": "Analyst", "status": "Enabled"},
            {"dn": "CN=asmith,OU=Users,DC=example,DC=local", "name": "Alice Smith",
             "type": "user", "description": "Manager", "status": "Enabled"}]


def test_move_button_enabled_only_with_selection(root, patched_clients):
    """Move (and the other row actions) are disabled with no selection."""
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    _assert_ad_buttons_no_selection(app)
    # A row in the list, selected: every AD button enables.
    app._ad_rows = _ad_rows_jdoe()
    app._ad_apply_filter()
    root.update_idletasks()
    app.ad_list.selection_set("CN=jdoe,OU=Users,DC=example,DC=local")
    root.update()
    _assert_ad_buttons_with_selection(app)
    # Clearing the selection disables the row actions again.
    app.ad_list.selection_remove(app.ad_list.selection())
    root.update()
    _assert_ad_buttons_no_selection(app)


def test_move_dialog_shows_current_location_and_destination_picker(
        root, monkeypatch):
    """MoveObjectDialog shows the object's location and an OU picker."""
    from msat.dialogs import MoveObjectDialog

    monkeypatch.setattr("msat.dialogs.messagebox.showwarning",
                        lambda *a, **k: None)

    class _PickerClient:
        """list_children returns containers for the domain and OU=Users."""
        def list_children(self, dn):
            if dn == "DC=example,DC=local":
                return [
                    {"dn": "OU=Users,DC=example,DC=local", "type": "ou"},
                    {"dn": "OU=IT,DC=example,DC=local", "type": "ou"},
                    {"dn": "CN=Builtin,DC=example,DC=local", "type": "container"},
                    {"dn": "CN=jdoe,OU=Users,DC=example,DC=local", "type": "user"},
                ]
            if dn == "OU=Users,DC=example,DC=local":
                return [
                    {"dn": "OU=Sub,OU=Users,DC=example,DC=local", "type": "ou"},
                ]
            return []

    dlg = MoveObjectDialog(
        root, _PickerClient(), "DC=example,DC=local",
        "CN=jdoe,OU=Users,DC=example,DC=local", "John Doe", "user",
        "OU=Users,DC=example,DC=local")
    root.update_idletasks()
    try:
        assert dlg.title() == "Move — John Doe"
        assert dlg._object_label["text"] == "John Doe (user)"
        assert dlg._current_label["text"] == "OU=Users,DC=example,DC=local"
        # The picker lists containers only — the leaf user is not a destination.
        assert dlg.tree.exists("OU=Users,DC=example,DC=local")
        assert dlg.tree.exists("OU=IT,DC=example,DC=local")
        assert dlg.tree.exists("CN=Builtin,DC=example,DC=local")
        assert not dlg.tree.exists("CN=jdoe,OU=Users,DC=example,DC=local")
        # The current parent is marked in the tree.
        assert "(current location)" in dlg.tree.item(
            "OU=Users,DC=example,DC=local", "text")
        # Nothing selected yet: Move is disabled.
        assert str(dlg._ok_button["state"]) == "disabled"
        assert dlg.dest_label["text"] == "Destination: (none selected)"
        # Expanding OU=Users loads its sub-OU (open top-down: the
        # domain root first, then Users). A programmatic item(open=True)
        # does not generate <<TreeviewOpen>> (only a triangle click
        # does), so the handler is called directly, as the main tree
        # tests do.
        dlg.tree.item("DC=example,DC=local", open=True)
        dlg.tree.item("OU=Users,DC=example,DC=local", open=True)
        dlg._on_open(None)
        root.update_idletasks()
        assert dlg.tree.exists("OU=Sub,OU=Users,DC=example,DC=local")
        # Picking another OU enables Move and shows the destination DN.
        dlg.tree.selection_set("OU=IT,DC=example,DC=local")
        root.update()
        assert str(dlg._ok_button["state"]) == "normal"
        assert dlg.dest_label["text"] == \
            "Destination: OU=IT,DC=example,DC=local"
        assert dlg.validate() is True
        assert dlg.collect() == {
            "destination_dn": "OU=IT,DC=example,DC=local"}
        # Picking the current parent disables Move and says so.
        dlg.tree.selection_set("OU=Users,DC=example,DC=local")
        root.update()
        assert str(dlg._ok_button["state"]) == "disabled"
        assert "current location" in dlg.dest_label["text"]
        assert dlg.validate() is False
    finally:
        dlg._on_cancel()


def test_move_dialog_open_deferred_populates_expanded_ou(root, monkeypatch):
    """The Move dialog's open handler defers to idle (v1.8.8 regression).

    Regression test (v1.8.8): the dialog copied the old v1.4 synchronous
    pattern — _on_open scanned the tree from <<TreeviewOpen>> directly,
    which can fire before the clicked node's open state settles, so the
    just-expanded OU read as closed, was skipped, and its "Loading…"
    placeholder stuck forever. The handler now defers the scan with
    after_idle, mirroring the main tree's v1.5 fix, so by the time it
    runs the open state has settled.
    """
    from msat.dialogs import MoveObjectDialog, _MOVE_LOADING_SUFFIX

    monkeypatch.setattr("msat.dialogs.messagebox.showwarning",
                        lambda *a, **k: None)

    class _PickerClient:
        def list_children(self, dn):
            if dn == "DC=example,DC=local":
                return [
                    {"dn": "OU=Users,DC=example,DC=local", "type": "ou"},
                ]
            if dn == "OU=Users,DC=example,DC=local":
                return [
                    {"dn": "OU=Sub,OU=Users,DC=example,DC=local",
                     "type": "ou"},
                ]
            return []

    dlg = MoveObjectDialog(
        root, _PickerClient(), "DC=example,DC=local",
        "CN=jdoe,OU=Users,DC=example,DC=local", "John Doe", "user",
        "OU=Users,DC=example,DC=local")
    root.update_idletasks()
    try:
        users_dn = "OU=Users,DC=example,DC=local"
        sub_dn = "OU=Sub,OU=Users,DC=example,DC=local"
        # The domain is already expanded (that is how Users is visible);
        # Users itself still shows its placeholder and is not yet open.
        dlg.tree.item("DC=example,DC=local", open=True)
        assert dlg.tree.exists(users_dn)
        assert dlg.tree.get_children(users_dn) == \
            (users_dn + _MOVE_LOADING_SUFFIX,)
        assert not dlg.tree.exists(sub_dn)

        # Simulate <<TreeviewOpen>> firing BEFORE the open state settles:
        # the handler runs, then the state settles, then idle callbacks run.
        dlg._on_open(None)
        dlg.tree.item(users_dn, open=True)
        root.update_idletasks()

        users_children = dlg.tree.get_children(users_dn)
        assert users_dn + _MOVE_LOADING_SUFFIX not in users_children
        assert sub_dn in users_children
    finally:
        dlg._on_cancel()


def test_ad_move_refreshes_list_after_success(root, patched_clients, monkeypatch):
    """A successful move refreshes the list (object gone from the old OU)."""
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    moved = {}
    rows = _ad_rows_jdoe()

    class _MoveAD(FakeADClient):
        def list_children(self, dn):
            return list(rows)

        def move_object(self, dn, new_parent_dn):
            moved["dn"] = dn
            moved["dest"] = new_parent_dn
            rows[:] = [r for r in rows if r["dn"] != dn]
            return "{},{}".format("CN=jdoe", new_parent_dn)

    app.ad_client = _MoveAD()
    app._ad_current_dn = "OU=Users,DC=example,DC=local"
    app._ad_rows = list(rows)
    app._ad_apply_filter()
    root.update_idletasks()

    class _FakeMoveDialog:
        def __init__(self, parent, client, domain_dn, object_dn, object_name,
                     object_type, current_parent_dn):
            self.result = {"destination_dn": "OU=IT,DC=example,DC=local"}

        def wait_window(self):
            return None

    monkeypatch.setattr("msat.app.dialogs.MoveObjectDialog", _FakeMoveDialog)
    app.ad_list.selection_set("CN=jdoe,OU=Users,DC=example,DC=local")
    root.update()
    app._ad_move()
    root.update_idletasks()
    assert moved == {"dn": "CN=jdoe,OU=Users,DC=example,DC=local",
                     "dest": "OU=IT,DC=example,DC=local"}
    assert "CN=jdoe,OU=Users,DC=example,DC=local" not in \
        app.ad_list.get_children()
    assert "CN=asmith,OU=Users,DC=example,DC=local" in \
        app.ad_list.get_children()
    assert "Moved John Doe to OU=IT,DC=example,DC=local." in \
        app.statusbar["text"]


def test_ad_move_failure_leaves_list_unchanged(root, patched_clients, monkeypatch):
    """A failed move shows the error and leaves the list unchanged."""
    shown = []
    monkeypatch.setattr("msat.app.messagebox.showerror",
                        lambda *a, **k: shown.append(a))
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()

    class _FailMoveAD(FakeADClient):
        def move_object(self, dn, new_parent_dn):
            raise Exception("Move failed: entry already exists")

    app.ad_client = _FailMoveAD()
    app._ad_current_dn = "OU=Users,DC=example,DC=local"
    app._ad_rows = _ad_rows_jdoe()
    app._ad_apply_filter()
    root.update_idletasks()

    class _FakeMoveDialog:
        def __init__(self, *args):
            self.result = {"destination_dn": "OU=IT,DC=example,DC=local"}

        def wait_window(self):
            return None

    monkeypatch.setattr("msat.app.dialogs.MoveObjectDialog", _FakeMoveDialog)
    app.ad_list.selection_set("CN=jdoe,OU=Users,DC=example,DC=local")
    root.update()
    app._ad_move()
    root.update_idletasks()
    assert shown, "expected an error dialog"
    assert len(app.ad_list.get_children()) == 2
    assert "CN=jdoe,OU=Users,DC=example,DC=local" in \
        app.ad_list.get_children()


def test_ad_move_rejects_containers(root, patched_clients, monkeypatch):
    """Move refuses containers/OUs — leaf objects only."""
    shown = []
    monkeypatch.setattr("msat.app.messagebox.showinfo",
                        lambda *a, **k: shown.append(a))
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    called = []

    class _MoveAD(FakeADClient):
        def move_object(self, dn, new_parent_dn):
            called.append((dn, new_parent_dn))

    app.ad_client = _MoveAD()
    app._ad_current_dn = "DC=example,DC=local"
    app._ad_rows = [{"dn": "OU=IT,DC=example,DC=local", "name": "IT",
                     "type": "ou", "description": "", "status": ""}]
    app._ad_apply_filter()
    root.update_idletasks()
    app.ad_list.selection_set("OU=IT,DC=example,DC=local")
    root.update()
    app._ad_move()
    assert shown, "expected a 'Not applicable' info dialog"
    assert called == [], "move_object must not be called for a container"


# -- AD context menu (v1.8.7) --------------------------------------------------

def test_ad_context_menu_contains_toolbar_actions(root, patched_clients):
    """The context menu offers the toolbar actions, including Move."""
    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    labels = [app._ad_context_menu.entrycget(i, "label")
              for i in range(app._ad_context_menu.index("end") + 1)]
    toolbar_labels = [btn["text"] for btn in app.ad_toolbar_buttons]
    assert labels == toolbar_labels
    assert "Move..." in labels


def test_ad_context_menu_right_click_selects_row(root, patched_clients):
    """Right-clicking a row selects it, then shows the menu."""
    import types

    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    app._ad_rows = _ad_rows_jdoe()
    app._ad_apply_filter()
    root.update()
    posted = []
    app._ad_context_menu.post = lambda x, y: posted.append((x, y))
    dn = "CN=asmith,OU=Users,DC=example,DC=local"
    bbox = app.ad_list.bbox(dn)
    assert bbox, "row must be visible for a right-click"
    event = types.SimpleNamespace(x=bbox[0] + 2, y=bbox[1] + 2,
                                  x_root=100, y_root=200)
    app._ad_on_list_right_click(event)
    root.update_idletasks()
    assert app.ad_list.selection() == (dn,)
    assert posted == [(100, 200)]


def test_ad_context_menu_state_matches_toolbar(root, patched_clients):
    """Menu items mirror the toolbar buttons' state, with and without a selection."""
    import types

    app = MSATApp(root)
    _connect_app(app, "dc1")
    root.update_idletasks()
    app._ad_rows = _ad_rows_jdoe()
    app._ad_apply_filter()
    root.update()
    app._ad_context_menu.post = lambda x, y: None

    def _menu_states():
        return {app._ad_context_menu.entrycget(i, "label"):
                str(app._ad_context_menu.entrycget(i, "state"))
                for i in range(app._ad_context_menu.index("end") + 1)}

    def _toolbar_states():
        return {btn["text"]: str(btn["state"])
                for btn in app.ad_toolbar_buttons}

    # No selection: right-click empty space; the row actions are
    # disabled in both the menu and the toolbar.
    event = types.SimpleNamespace(x=1, y=9999, x_root=100, y_root=200)
    app._ad_on_list_right_click(event)
    root.update_idletasks()
    assert _menu_states() == _toolbar_states()
    assert _menu_states()["Move..."] == "disabled"
    assert _menu_states()["Delete"] == "disabled"
    assert _menu_states()["Properties"] == "disabled"
    assert _menu_states()["New User"] == "normal"
    assert _menu_states()["Refresh"] == "normal"

    # With a selection: right-click the row; everything is enabled.
    dn = "CN=jdoe,OU=Users,DC=example,DC=local"
    bbox = app.ad_list.bbox(dn)
    assert bbox
    event = types.SimpleNamespace(x=bbox[0] + 2, y=bbox[1] + 2,
                                  x_root=100, y_root=200)
    app._ad_on_list_right_click(event)
    root.update_idletasks()
    assert _menu_states() == _toolbar_states()
    assert all(s == "normal" for s in _menu_states().values())
