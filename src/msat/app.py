"""MSAT main window — Tkinter / ttk.

Tabs: AD Users & Computers, DHCP, DNS, Directory Info.

One global connection serves every tab: the connection bar at the top
of the window collects server / domain / username / password once, and
the password is held in a single :class:`~msat.credentials.CredentialStore`
(memory only) and wiped on Disconnect and on exit. Nothing is ever
written to disk. All four tools run on the same domain controllers, so
there is no per-tab connection.

Policy management is deliberately NOT in this tool — that work is done
in the management console on a domain controller (RDP).

LDAP calls run on the UI thread deliberately: the ldap3 connection is
bound on this thread and is not safe to use from a worker thread (a
background-thread search returns operationsError from the DC).
"""

import tkinter as tk
from tkinter import messagebox, ttk

from . import dialogs, updater
from .constants import (APP_TITLE, APP_VERSION, DEFAULT_LDAPS_PORT,
                        DEFAULT_WINRM_PORT)
from .credentials import CredentialStore
from .dhcp import DHCPManager
from .dns import DNSManager
from .ldap_client import ADClient, ADInvalidCredentialsError
from .settings import load_settings, save_settings
from .winrm_client import WinRMClient, detect_server_roles

# Suffix marking a tree node's "Loading..." placeholder child. Plain
# ASCII on purpose: a null byte ("\x00") in a Treeview iid is silently
# truncated by Tcl, so "DN\x00loading" collides with the DN itself.
_LOADING_SUFFIX = "__loading__"


def _dn_label(dn):
    """'OU=IT,DC=example,DC=local' -> 'IT'; 'DC=example,DC=local' -> 'example'."""
    if not dn:
        return ""
    first = dn.split(",", 1)[0]
    if "=" in first:
        return first.split("=", 1)[1].replace("\\,", ",")
    return first


class MSATApp:
    def __init__(self, root):
        self.root = root
        root.title(APP_TITLE)
        # Wide enough for the AD tab toolbar (10 buttons) to fit
        # without clipping; the minimum keeps it from being shrunk
        # below the toolbar width.
        root.geometry("1280x800")
        root.minsize(1200, 650)

        # One credential store (memory only) for the global connection.
        self.creds = CredentialStore()

        # Effective connection defaults: the user's saved Settings
        # (~/.msat/settings.json) when present, else the
        # generic placeholders from constants.py. Never credentials.
        self.settings = load_settings()

        self.ad_client = None  # ADClient (LDAPS) — shared by the AD and Info tabs
        self.dhcp = None       # DHCPManager (WinRM) — server may differ, see below
        self.dns = None        # DNSManager (WinRM, global server)
        self._dhcp_server = None  # server the current DHCP manager targets

        # Role detection state, per connection (cleared on disconnect,
        # re-run on every connect — never cached across connections).
        # AD and Directory Info are always enabled (LDAP). DNS/DHCP
        # are enabled only where the role is detected.
        self._roles = {}            # server -> {"DNS": bool, "DHCP": bool}
        self._roles_available = True  # False when detection itself failed
        self._dns_enabled = True
        self._dhcp_enabled = True
        self._dhcp_candidates = []  # servers detected to have the DHCP role
        self._role_notes = {}       # "dns"/"dhcp" -> why the tab is disabled

        # Client-side search boxes (AD / DHCP / DNS). The Entry widgets
        # are disabled when disconnected; their StringVars are cleared
        # on disconnect so a stale filter cannot hide freshly loaded rows.
        # Each search row also has a small clear (×) button, tracked
        # here so it is enabled/disabled with its entry.
        self._search_entries = []
        self._search_vars = []
        self._search_clear_btns = []
        # Pending debounce timers, one per search row (see
        # _make_search_row): each entry is the row's {"after_id": ...}
        # dict. _global_disconnect cancels them so a filter cannot
        # fire after the trees have been cleared.
        self._search_debounce_pending = []

        self._build_global_bar()

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        self.ad_tab = ttk.Frame(self.notebook, padding=6)
        self.dhcp_tab = ttk.Frame(self.notebook, padding=6)
        self.dns_tab = ttk.Frame(self.notebook, padding=6)
        self.info_tab = ttk.Frame(self.notebook, padding=6)
        self.notebook.add(self.ad_tab, text="AD Users & Computers")
        self.notebook.add(self.dhcp_tab, text="DHCP")
        self.notebook.add(self.dns_tab, text="DNS")
        self.notebook.add(self.info_tab, text="Directory Info")

        self._build_ad_tab()
        self._build_dhcp_tab()
        self._build_dns_tab()
        self._build_info_tab()

        self.statusbar = ttk.Label(root, text="Ready.", relief=tk.SUNKEN, anchor=tk.W)
        self.statusbar.pack(side=tk.BOTTOM, fill=tk.X)
        self._build_menu()
        root.protocol("WM_DELETE_WINDOW", self._on_close)

        # Deferred update check: the main window appears first, then
        # the check runs synchronously (5-second timeout). It is
        # silent unless a newer release is actually found — see
        # _check_for_updates.
        self.root.after(2000, self._startup_update_check)

    # -- menu bar / updates --------------------------------------------------

    def _build_menu(self):
        """Menu bar: a Help menu with the manual update check."""
        self._menubar = tk.Menu(self.root, tearoff=0)
        self._help_menu = tk.Menu(self._menubar, tearoff=0)
        self._help_menu.add_command(label="Check for Updates…",
                                    command=self._manual_update_check)
        self._menubar.add_cascade(label="Help", menu=self._help_menu)
        self.root.config(menu=self._menubar)

    def _startup_update_check(self):
        """Automatic check shortly after launch (silent unless an
        update is found)."""
        self._check_for_updates(manual=False)

    def _manual_update_check(self):
        """Help → Check for Updates… — always says what it found."""
        self._check_for_updates(manual=True)

    def _check_for_updates(self, manual=False):
        """Check GitHub Releases for a newer MSAT version.

        Automatic (startup) checks are completely silent unless a
        newer release is found: up-to-date, unreachable or malformed
        responses produce no dialog and no status-bar noise. A manual
        check reports what it found instead. No background threads are
        used — the check is one short synchronous request on the UI
        thread.
        """
        release = updater.get_latest_release()
        if release is None:
            if manual:
                messagebox.showinfo(
                    "Check for Updates",
                    "Could not reach GitHub to check for updates.\n"
                    "Check your connection and try again.",
                    parent=self.root)
            return
        if not updater.is_newer(release["tag"], APP_VERSION):
            if manual:
                messagebox.showinfo(
                    "Check for Updates",
                    "You have the latest version (v{}).".format(APP_VERSION),
                    parent=self.root)
            return
        dlg = dialogs.UpdateDialog(self.root, release, APP_VERSION)
        self.root.wait_window(dlg)

    # -- global connection ---------------------------------------------------

    def _build_global_bar(self):
        """One connection bar for all tabs, above the notebook."""
        bar = ttk.Frame(self.root, padding=(6, 6, 6, 0))
        bar.pack(fill=tk.X)

        ttk.Label(bar, text="Server:").pack(side=tk.LEFT)
        self.server_var = tk.StringVar(value=self.settings["default_server"])
        self.server_combo = ttk.Combobox(bar, textvariable=self.server_var,
                                         values=self.settings["servers"],
                                         width=14)
        self.server_combo.pack(side=tk.LEFT, padx=(2, 8))

        ttk.Label(bar, text="Domain:").pack(side=tk.LEFT)
        self.domain_var = tk.StringVar(value=self.settings["domain"])
        self.domain_entry = ttk.Entry(bar, textvariable=self.domain_var,
                                      width=16)
        self.domain_entry.pack(side=tk.LEFT, padx=(2, 8))

        ttk.Label(bar, text="Username:").pack(side=tk.LEFT)
        self.username_var = tk.StringVar()
        self.username_entry = ttk.Entry(bar, textvariable=self.username_var,
                                        width=18)
        self.username_entry.pack(side=tk.LEFT, padx=(2, 8))

        ttk.Label(bar, text="Password:").pack(side=tk.LEFT)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(bar, textvariable=self.password_var,
                                        width=18, show="*")
        self.password_entry.pack(side=tk.LEFT, padx=(2, 8))
        # Enter in the password field acts like clicking Connect.
        self.password_entry.bind("<Return>", self._on_password_return)

        self.connect_btn = ttk.Button(bar, text="Connect",
                                      command=self._global_connect)
        self.connect_btn.pack(side=tk.LEFT, padx=(4, 2))
        self.disconnect_btn = ttk.Button(bar, text="Disconnect",
                                         command=self._global_disconnect,
                                         state=tk.DISABLED)
        self.disconnect_btn.pack(side=tk.LEFT, padx=2)
        self.settings_btn = ttk.Button(bar, text="Settings…",
                                       command=self._open_settings)
        self.settings_btn.pack(side=tk.LEFT, padx=2)
        self.conn_status = ttk.Label(bar, text="Not connected")
        self.conn_status.pack(side=tk.LEFT, padx=8)

        # Return guard for the button accent (below): a button in
        # the "default" state is the toplevel's default button, so
        # a Return keypress in a widget that does not handle Return
        # itself (a search box, a treeview) would invoke it — with
        # Disconnect blue while connected, a stray Return in a
        # search field would disconnect the app. Swallow Return at
        # the toplevel. The password entry handles Return itself
        # (its widget binding fires first and returns "break"), so
        # Enter-to-Connect is unaffected, and a focused button
        # still answers Return through its own binding.
        self.root.bind("<Return>", self._on_root_return)

    def _on_root_return(self, _event):
        """Swallow Return at the toplevel (see _build_global_bar).

        Returns "break" so a Return in a widget with no Return
        binding of its own never reaches the default button.
        """
        return "break"

    def _open_settings(self):
        """Edit the connection defaults (domain, servers).

        Saves to ``~/.msat/settings.json`` (never credentials),
        then refreshes the connection bar and the DHCP tab from the
        new values. Disabled while connected — change defaults while
        disconnected, then Connect.
        """
        if self.ad_client is not None:
            messagebox.showinfo(
                "Settings",
                "Disconnect first, then change Settings.",
                parent=self.root)
            return
        dlg = dialogs.SettingsDialog(self.root, self.settings)
        self.root.wait_window(dlg)
        if dlg.result is None:
            return
        self.settings = save_settings(dlg.result)
        self._apply_settings_to_bar()
        self._update_dhcp_labels()
        self.set_status("Settings saved to ~/.msat/settings.json.")

    def _apply_settings_to_bar(self):
        """Refresh the connection bar from the current settings."""
        self.server_combo.config(values=self.settings["servers"])
        self.server_var.set(self.settings["default_server"])
        self.domain_var.set(self.settings["domain"])

    def _on_password_return(self, _event):
        """Enter in the password field acts like clicking Connect.

        No-op when already connected — the entry is disabled then,
        but guard anyway so Enter can never trigger a disconnect or
        a reconnect. Returns "break" so the keypress goes no further.
        """
        if self.ad_client is not None:
            return "break"
        self._global_connect()
        return "break"

    def _global_connect(self):
        server = self.server_var.get().strip()
        domain = self.domain_var.get().strip() or self.settings["domain"]
        username = self.username_var.get().strip()
        password = self.password_var.get()
        if not server or not username or not password:
            messagebox.showwarning("Missing value",
                                   "Server, username and password are required.",
                                   parent=self.root)
            return
        # The connection is underway: turn Connect blue while the
        # blocking LDAP bind/validation runs. The connect is
        # synchronous, so force a redraw first — without it the
        # blue state would never be painted before the bind blocks.
        # The "default" option is the macOS way to draw a ttk
        # button blue (Aqua ignores a plain background colour).
        self.connect_btn.config(default="active")
        self.root.update_idletasks()
        self.creds.set(server, domain, username, password, DEFAULT_LDAPS_PORT)
        # The LDAP bind is the credential check, and a search right
        # after it proves the credentials are actually usable: a
        # stale or restricted credential can bind yet fail every
        # search (the DC answers operationsError), which used to
        # surface later as a cryptic tree-loading error. Validate up
        # front; a failure here aborts the connect before anything
        # is marked connected, and the reason is stated plainly.
        client = ADClient(server=server, domain=domain, username=username,
                          password=password, port=DEFAULT_LDAPS_PORT)
        try:
            client.connect()
            client.validate_connection()
        except ADInvalidCredentialsError:
            self._fail_connect(
                "Invalid credentials",
                "Invalid credentials — the username or password is "
                "incorrect. Check your credentials and try again.",
                "Connection failed: invalid credentials")
            return
        except Exception as exc:  # noqa: BLE001 - shown to the user
            self._fail_connect("Connection failed", str(exc),
                               "Connection failed")
            return
        self.ad_client = client
        # WinRM managers share the global credentials. Their sessions
        # are lazy — nothing goes on the wire until the first command
        # runs, so a WinRM problem on one server does not block the
        # LDAP-validated connection.
        self.dns = DNSManager(WinRMClient(host=server, username=username,
                                          password=password,
                                          port=DEFAULT_WINRM_PORT))
        self.dhcp = None
        self._dhcp_server = None
        # Role detection: examine the installed roles on the
        # connected server and gate the DNS/DHCP tabs on what is
        # actually there. AD and Directory Info are always enabled
        # (a successful LDAP bind means AD DS is present).
        self._roles = {}
        self._roles_available = True
        self._dns_enabled = True
        self._dhcp_enabled = True
        self._dhcp_candidates = []
        self._role_notes = {}
        roles = self._detect_roles(server)
        if roles is None:
            # Detection itself failed (WinRM down, auth, timeout).
            # Do NOT break the connection and do NOT disable tabs:
            # fall back to all tabs enabled, DHCP targeting the
            # connected server, and say so in the status bar.
            self._roles_available = False
            self._dhcp_candidates = [server]
            self.dhcp_server_var.set(server)
        else:
            self._dns_enabled = roles["DNS"]
            if not roles["DNS"]:
                self._role_notes["dns"] = (
                    "DNS Server role is not installed on {} — "
                    "DNS tab disabled.".format(server))
            # DHCP: the connected server first, then the other
            # configured servers in order; the first one with the
            # DHCP role wins.
            self._discover_dhcp()
        self._sync_dhcp_server_row()
        self._set_connected(True)
        # Populate the AD tree root (children load when expanded).
        root_dn = client.get_default_naming_context()
        self._clear_tree(self.ad_tree)
        self._clear_tree(self.ad_list)
        self.ad_tree.insert("", tk.END, iid=root_dn, text=domain, open=False)
        self.ad_tree.insert(root_dn, tk.END, iid=root_dn + _LOADING_SUFFIX,
                            text="Loading…")
        self._ad_current_dn = root_dn
        # Load the enabled tabs' data now that the managers exist. A
        # tab that fails here must NOT pop a modal dialog — the AD
        # connection itself is fine, and the failure is reported in
        # the status bar instead. The user can retry from the tab's
        # own Refresh button, where a modal is fine. A tab whose
        # role is missing is not loaded at all.
        loads = []
        if self._dhcp_enabled:
            loads.append(("DHCP", self._dhcp_refresh(quiet=True)))
        if self._dns_enabled:
            loads.append(("DNS", self._dns_refresh(quiet=True)))
        loads.append(("Directory Info", self._info_refresh(quiet=True)))
        failures = []
        for label, result in loads:
            if result is not True:
                failures.append("{}: {}".format(label, result))
        enabled = ["AD", "Directory Info"]
        if self._dns_enabled:
            enabled.append("DNS")
        if self._dhcp_enabled:
            enabled.append("DHCP")
        status = "Connected to {} ({}).".format(server, ", ".join(enabled))
        if not self._roles_available:
            status += " Role detection unavailable — tabs enabled."
        for note in self._role_notes.values():
            status += " " + note
        if failures:
            status += " Some tabs failed to load — " + "; ".join(failures) + \
                      ". Use the tab's Refresh to retry."
        self.set_status(status)

    def _global_disconnect(self):
        if self.ad_client is not None:
            self.ad_client.disconnect()
            self.ad_client = None
        self.dhcp = None
        self._dhcp_server = None
        self.dns = None
        self.creds.clear()
        # Wipe the password from the UI as well as the store: the
        # entry field and its StringVar would otherwise keep the
        # password in memory (and visible) after disconnecting,
        # against the wipe-on-disconnect model in credentials.py.
        self.password_var.set("")
        # Role detection is per-connection: forget it all, so the
        # next connect re-detects for its own server.
        self._roles = {}
        self._roles_available = True
        self._dns_enabled = True
        self._dhcp_enabled = True
        self._dhcp_candidates = []
        self._role_notes = {}
        self._set_connected(False)
        # Clear every tab's view.
        self._clear_tree(self.ad_tree)
        self._clear_tree(self.ad_list)
        self._ad_current_dn = None
        self._ad_rows = []
        # Cancel any pending search-debounce timers before clearing
        # the search text: a keystroke made just before Disconnect
        # schedules a filter 150 ms out, and without cancelling it
        # the filter would fire after the trees have been cleared.
        # after_cancel on an already-fired timer raises TclError, so
        # guard it — the debounced wrapper clears the stored ID when
        # it fires, so this is only a belt-and-braces guard.
        for pending in self._search_debounce_pending:
            after_id = pending.get("after_id")
            if after_id is not None:
                try:
                    self.root.after_cancel(after_id)
                except tk.TclError:
                    pass
                pending["after_id"] = None
        for var in self._search_vars:
            var.set("")
        for tree in (self.dhcp_scopes, self.dhcp_leases, self.dhcp_reservations):
            self._clear_tree(tree)
        self._dhcp_current_scope = None
        self._dhcp_scopes_rows = []
        self._dhcp_leases_rows = []
        self._dhcp_reservations_rows = []
        self._clear_tree(self.dns_zones)
        self._clear_tree(self.dns_records)
        self._dns_current_zone = None
        self._dns_record_data = {}
        self._dns_zones_rows = []
        self._dns_records_rows = []
        self.info_text.config(state=tk.NORMAL)
        self.info_text.delete("1.0", tk.END)
        self.info_text.config(state=tk.DISABLED)
        self._clear_tree(self.info_sites)
        self._clear_tree(self.info_trusts)
        self._sync_dhcp_server_row()
        self.set_status("Disconnected.")

    def _set_connected(self, connected):
        """Enable/disable the global bar and every tab's toolbar."""
        self.connect_btn.config(state=tk.DISABLED if connected else tk.NORMAL)
        self.disconnect_btn.config(state=tk.NORMAL if connected else tk.DISABLED)
        # Accent (blue) state. While connected the Disconnect
        # button is blue and Connect is back to gray; while
        # disconnected neither is. This also clears the transient
        # "connecting" blue on Connect, on success and on failure
        # (via _fail_connect) alike.
        self.connect_btn.config(default="normal")
        self.disconnect_btn.config(default="active" if connected else "normal")
        self.conn_status.config(
            text="Connected to {}".format(self.server_var.get().strip())
            if connected else "Not connected")
        state = tk.NORMAL if connected else tk.DISABLED
        for widget in (self.server_combo, self.domain_entry,
                       self.username_entry, self.password_entry):
            widget.config(state=tk.DISABLED if connected else tk.NORMAL)
        for btn in (self.ad_toolbar_buttons + self.dhcp_toolbar_buttons +
                    self.dns_toolbar_buttons + [self.info_refresh_btn]):
            btn.config(state=state)
        for entry in self._search_entries:
            entry.config(state=state)
        for btn in self._search_clear_btns:
            btn.config(state=state)
        # Role gating overrides the plain connected/disconnected
        # state: a tab whose role is missing stays gated even though
        # the app is connected.
        self._apply_role_gating()

    # -- role detection and tab gating ------------------------------------

    def _detect_roles(self, server, refresh=False):
        """Detect the DNS/DHCP roles on one server (cached per connection).

        Returns ``{"DNS": bool, "DHCP": bool}``, or None when
        detection fails on that server (WinRM error, timeout, bad
        output). A None here never raises — the caller decides the
        fallback. ``refresh=True`` re-probes the server instead of
        using the cached result (used by Refresh to re-check a role
        that was missing, in case it was installed since).
        """
        if not refresh and server in self._roles:
            return self._roles[server]
        client = WinRMClient(host=server, username=self.creds.username,
                             password=self.creds.password,
                             port=DEFAULT_WINRM_PORT)
        try:
            roles = detect_server_roles(client)
        except Exception:  # noqa: BLE001 - detection failure is a fallback
            return None
        self._roles[server] = roles
        return roles

    def _discover_dhcp(self, refresh=False):
        """Find the servers with the DHCP role, connected server first.

        Sets ``_dhcp_candidates`` (in check order), ``_dhcp_enabled``
        and the DHCP role note. Returns True when at least one server
        has the DHCP role. A server whose detection fails is skipped —
        it cannot be confirmed to have DHCP.

        Fast path: when the connected server itself has the DHCP
        role, it IS the DHCP server, so probing the other configured
        servers adds dead wait on every connect — and stalls the UI
        until WinRM times out if one is offline or firewalled. The
        picker is hidden whenever the connected server has DHCP, so
        the other servers would never be shown anyway.
        """
        server = self.server_var.get().strip()
        roles = self._detect_roles(server, refresh=refresh)
        if roles is not None and roles["DHCP"]:
            self._dhcp_candidates = [server]
            self._dhcp_enabled = True
            self._role_notes.pop("dhcp", None)
            self.dhcp_server_var.set(server)
            return True
        ordered = [s for s in self.settings["servers"] if s != server]
        candidates = []
        for cand in ordered:
            roles = self._detect_roles(cand, refresh=refresh)
            if roles is not None and roles["DHCP"]:
                candidates.append(cand)
        self._dhcp_candidates = candidates
        if candidates:
            self._dhcp_enabled = True
            self._role_notes.pop("dhcp", None)
            chosen = server if server in candidates else candidates[0]
            self.dhcp_server_var.set(chosen)
            return True
        self._dhcp_enabled = False
        self._role_notes["dhcp"] = (
            "DHCP Server role is not installed on any configured "
            "server — DHCP tab disabled.")
        return False

    def _apply_role_gating(self):
        """Enable/disable the DNS and DHCP tabs from role detection.

        AD and Directory Info are always enabled (LDAP). A tab whose
        role is missing has its tools disabled and shows a note
        naming the server and the missing role; its Refresh button
        stays enabled so the role can be re-checked (install the
        role, then Refresh). When not connected, everything is
        disabled and the notes are cleared. When detection was
        unavailable, every tab is enabled.
        """
        connected = self.ad_client is not None
        if connected and not self._dns_enabled:
            self.dns_note.config(text=self._role_notes.get("dns", ""))
            for btn in self.dns_toolbar_buttons:
                if btn["text"] == "Refresh":
                    btn.config(state=tk.NORMAL)
                else:
                    btn.config(state=tk.DISABLED)
            self._dns_search_entry.config(state=tk.DISABLED)
            self._dns_search_clear_btn.config(state=tk.DISABLED)
        elif connected:
            self.dns_note.config(text="")
            for btn in self.dns_toolbar_buttons:
                btn.config(state=tk.NORMAL)
            self._dns_search_entry.config(state=tk.NORMAL)
            self._dns_search_clear_btn.config(state=tk.NORMAL)
        else:
            self.dns_note.config(text="")
        if connected and not self._dhcp_enabled:
            self.dhcp_note.config(
                text=self._role_notes.get("dhcp", ""))
            for btn in self.dhcp_toolbar_buttons:
                if btn["text"] == "Refresh":
                    btn.config(state=tk.NORMAL)
                else:
                    btn.config(state=tk.DISABLED)
            self._dhcp_search_entry.config(state=tk.DISABLED)
            self._dhcp_search_clear_btn.config(state=tk.DISABLED)
        elif connected:
            self._update_dhcp_labels()
            for btn in self.dhcp_toolbar_buttons:
                btn.config(state=tk.NORMAL)
            self._dhcp_search_entry.config(state=tk.NORMAL)
            self._dhcp_search_clear_btn.config(state=tk.NORMAL)
        else:
            self.dhcp_note.config(text="")

    # -- DHCP server selection ---------------------------------------------

    def _sync_dhcp_server_row(self):
        """Show the DHCP server picker only when the connected server
        is not the DHCP server being managed.

        The picker lists the servers detected to have the DHCP role.
        It appears when the connected server has no DHCP role and
        another server does; otherwise DHCP uses the connected
        server and the picker stays hidden.
        """
        connected = self.ad_client is not None
        server = self.server_var.get().strip()
        if (connected and self._dhcp_enabled and self._dhcp_candidates
                and server not in self._dhcp_candidates):
            self.dhcp_server_combo.config(values=self._dhcp_candidates)
            if self.dhcp_server_var.get().strip() not in self._dhcp_candidates:
                self.dhcp_server_var.set(self._dhcp_candidates[0])
            self.dhcp_server_frame.pack(anchor=tk.W, after=self.dhcp_note)
        else:
            self.dhcp_server_frame.pack_forget()
            if server in self._dhcp_candidates:
                self.dhcp_server_var.set(server)

    def _ensure_dhcp(self):
        """(Re)create the DHCP manager for the effective DHCP server.

        Returns the manager, or None when not connected or when no
        server was detected to have the DHCP role. The effective
        server is the picker's selection when it names a detected
        DHCP server, else the connected server when it has the role,
        else the first detected DHCP server. The WinRM session is
        lazy; the first command is what actually talks to the server.
        """
        if (self.ad_client is None or not self._dhcp_enabled
                or not self._dhcp_candidates):
            return None
        server = self.dhcp_server_var.get().strip()
        if server not in self._dhcp_candidates:
            server = self.server_var.get().strip()
            if server not in self._dhcp_candidates:
                server = self._dhcp_candidates[0]
            self.dhcp_server_var.set(server)
        if self.dhcp is not None and self._dhcp_server == server:
            return self.dhcp
        self.dhcp = DHCPManager(WinRMClient(
            host=server, username=self.creds.username,
            password=self.creds.password, port=DEFAULT_WINRM_PORT))
        self._dhcp_server = server
        return self.dhcp

    def _dhcp_on_server_change(self, _event=None):
        if self.ad_client is None:
            return
        self._ensure_dhcp()
        self._dhcp_refresh()
        # The "Managing DHCP on ..." label is built from the effective
        # DHCP server; refresh it here, or it stays stuck on the
        # previous server after a switch.
        self._update_dhcp_labels()

    def _update_dhcp_labels(self):
        """Rebuild the DHCP note/picker text from role detection.

        The text is built from the servers detected to have the DHCP
        role, never a hardcoded hostname. Before connection (no
        detection yet) the note is empty and the picker keeps the
        configured servers list.
        """
        if self.ad_client is None:
            self.dhcp_note.config(text="")
            return
        if not self._dhcp_enabled:
            self.dhcp_note.config(text=self._role_notes.get("dhcp", ""))
            return
        server = self._dhcp_server or self.dhcp_server_var.get().strip()
        self.dhcp_note.config(
            text="Managing DHCP on {}.".format(server) if server else "")
        self.dhcp_picker_label.config(text="DHCP server:")
        self.dhcp_server_combo.config(values=self._dhcp_candidates)

    # -- shared helpers ------------------------------------------------------

    def set_status(self, message):
        self.statusbar.config(text=message)

    def _error(self, exc):
        messagebox.showerror("Error", str(exc), parent=self.root)
        self.set_status("Error: {}".format(exc))

    def _fail_connect(self, title, message, status_message):
        """Leave the app cleanly disconnected and say why.

        Used when the connect-time credential validation fails: no
        managers are created, the tree stays empty, Connect stays
        enabled and the fields editable, and the failure is visible
        in the connection status label and the status bar — not only
        in the dialog — so the user can correct the credentials and
        try again.
        """
        self.creds.clear()
        self.ad_client = None
        self.dns = None
        self.dhcp = None
        self._dhcp_server = None
        self._clear_tree(self.ad_tree)
        self._clear_tree(self.ad_list)
        self._ad_current_dn = None
        self._ad_rows = []
        for var in self._search_vars:
            var.set("")
        self._set_connected(False)
        self.conn_status.config(text=status_message)
        self.set_status(status_message)
        messagebox.showerror(title, message, parent=self.root)

    def _on_close(self):
        if self.ad_client is not None:
            self.ad_client.disconnect()
        self.creds.clear()
        self.root.destroy()

    @staticmethod
    def _clear_tree(tree):
        for item in tree.get_children():
            tree.delete(item)

    @staticmethod
    def _fill_tree(tree, rows, columns):
        """Fill a Treeview from a list of dicts (keys = column names)."""
        MSATApp._clear_tree(tree)
        for row in rows:
            values = [row.get(col, "") for col in columns]
            tree.insert("", tk.END, values=values)

    def _make_search_row(self, parent, on_change):
        """A 'Search:' label + entry on its own row above a list.

        The entry starts disabled (the tab is not connected yet) and
        is enabled with the rest of the tab in _set_connected. Typing
        filters the list below it (client-side only, over rows already
        loaded); clearing the box shows every row again. Returns the
        StringVar holding the search text.
        """
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(frame, text="Search:").pack(side=tk.LEFT)
        var = tk.StringVar()
        entry = ttk.Entry(frame, textvariable=var, width=32,
                          state=tk.DISABLED)
        entry.pack(side=tk.LEFT, padx=4, fill=tk.X, expand=True)
        # Debounce the filter: rebuilding the whole Treeview on every
        # keystroke is instant for a few hundred rows, but in a large
        # DNS zone (thousands of records) it lags typing. Wait ~150 ms
        # after the last keystroke before filtering; a new keystroke
        # cancels the pending filter. The clear (×) button below still
        # filters immediately — clearing is a deliberate action.
        _pending = {"after_id": None}
        self._search_debounce_pending.append(_pending)

        def _on_debounced():
            # The timer has fired: forget its ID (so disconnect does
            # not try to cancel an already-fired timer) and run the
            # filter.
            _pending["after_id"] = None
            on_change()

        def _on_key_release(_event):
            if _pending["after_id"] is not None:
                entry.after_cancel(_pending["after_id"])
                _pending["after_id"] = None
            _pending["after_id"] = entry.after(150, _on_debounced)

        entry.bind("<KeyRelease>", _on_key_release)
        # A small clear (×) button beside the entry: empties the
        # search text and re-runs the filter, restoring the full,
        # unfiltered list. Always visible — simpler and more reliable
        # in Tkinter than showing it only when text is present.
        def _clear():
            var.set("")
            on_change()
        clear_btn = ttk.Button(frame, text="×", width=2, command=_clear,
                               state=tk.DISABLED)
        clear_btn.pack(side=tk.LEFT, padx=(0, 4))
        self._search_entries.append(entry)
        self._search_vars.append(var)
        self._search_clear_btns.append(clear_btn)
        return var

    @staticmethod
    def _refill_filtered(tree, display_rows, search_text):
        """Repopulate ``tree`` from ``display_rows``, applying a filter.

        ``display_rows`` is a list of (iid_or_None, values_tuple). A
        row is kept when ``search_text`` (case-insensitive) appears in
        any of its values; an empty search shows every row.
        """
        MSATApp._clear_tree(tree)
        needle = (search_text or "").strip().lower()
        for iid, values in display_rows:
            if needle and not any(needle in str(v).lower() for v in values):
                continue
            if iid is not None:
                tree.insert("", tk.END, iid=iid, values=values)
            else:
                tree.insert("", tk.END, values=values)

    # ======================================================================
    # AD Users & Computers
    # ======================================================================

    def _build_ad_tab(self):
        toolbar = ttk.Frame(self.ad_tab)
        toolbar.pack(fill=tk.X, pady=(0, 4))
        self.ad_toolbar_buttons = []
        for text, command in (
                ("New User", self._ad_new_user),
                ("New Computer", self._ad_new_computer),
                ("New Group", self._ad_new_group),
                ("Enable", self._ad_enable),
                ("Disable", self._ad_disable),
                ("Unlock", self._ad_unlock),
                ("Reset Password", self._ad_reset_password),
                ("Add to Group", self._ad_add_to_group),
                ("Properties", self._ad_properties),
                ("Delete", self._ad_delete),
                ("Refresh", self._ad_refresh)):
            btn = ttk.Button(toolbar, text=text, command=command,
                             state=tk.DISABLED)
            btn.pack(side=tk.LEFT, padx=2)
            self.ad_toolbar_buttons.append(btn)

        paned = ttk.PanedWindow(self.ad_tab, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        tree_frame = ttk.Frame(paned)
        self.ad_tree = ttk.Treeview(tree_frame, show="tree")
        self.ad_tree.pack(fill=tk.BOTH, expand=True)
        self.ad_tree.bind("<<TreeviewSelect>>", self._ad_on_tree_select)
        self.ad_tree.bind("<<TreeviewOpen>>", self._ad_on_tree_open)
        # Belt-and-braces for the placeholder: a triangle click does
        # not reliably select the node, so the select handler alone
        # cannot be trusted to populate it.
        self.ad_tree.bind("<Button-1>", self._ad_on_tree_click)
        paned.add(tree_frame, weight=1)

        list_frame = ttk.Frame(paned)
        # Search sits on its own row above the object list (not in the
        # toolbar): it filters the rows already loaded for the current
        # container, client-side, as you type.
        self._ad_search_var = self._make_search_row(
            list_frame, self._ad_apply_filter)
        columns = ("Name", "Type", "Description", "Status", "Locked")
        self.ad_list = ttk.Treeview(list_frame, columns=columns,
                                    show="headings")
        for col in columns:
            self.ad_list.heading(col, text=col)
        self.ad_list.column("Name", width=180)
        self.ad_list.column("Type", width=80)
        self.ad_list.column("Description", width=220)
        self.ad_list.column("Status", width=110)
        self.ad_list.column("Locked", width=60)
        self.ad_list.pack(fill=tk.BOTH, expand=True)
        self.ad_list.bind("<Double-Button-1>", self._ad_on_list_double_click)
        paned.add(list_frame, weight=2)

        self._ad_current_dn = None
        self._ad_rows = []  # canonical rows for the current container

    def _ad_ensure_tree_children(self, dn, children=None):
        """Replace a tree node's 'Loading…' placeholder with its real children.

        No-op when the node has no placeholder (already loaded) or does
        not exist in the tree. Returns True when children were loaded.
        ``children`` may be a list already fetched for this DN (the
        list view just loaded it) — passing it avoids a second LDAP
        query for the same DN.
        """
        if self.ad_client is None or not dn:
            return False
        if not self.ad_tree.exists(dn):
            return False
        node_children = self.ad_tree.get_children(dn)
        if not node_children or not node_children[0].endswith(_LOADING_SUFFIX):
            return False
        self.ad_tree.delete(node_children[0])
        self._ad_populate_tree_children(dn, children)
        return True

    def _ad_on_tree_open(self, _event):
        if self.ad_client is None:
            return
        # Defer the scan until idle: <<TreeviewOpen>> can fire before
        # the clicked node's open state has settled, so reading
        # item(node, "open") synchronously can see False for the node
        # that was just expanded and skip it. By idle time the state
        # has settled either way. Depth-independent: walk the whole
        # tree and populate every currently-open node still showing a
        # "Loading…" placeholder. Do NOT try to resolve which node was
        # just opened — focus and selection are unreliable for nested
        # nodes (the first triangle click often leaves focus on the
        # parent), so a node at depth 2+ would never be found that way.
        # The tree is at most a few hundred nodes, so a full scan on
        # each open event is cheap.
        self.root.after_idle(self._ad_populate_open_placeholders)

    def _ad_on_tree_click(self, event):
        """Belt-and-braces for the 'Loading…' placeholder.

        A click on a disclosure triangle does not reliably fire
        <<TreeviewSelect>> (the node is not selected), so the select
        handler cannot be relied on to populate it. After idle — once
        the click's open/select processing has settled — populate the
        row under the cursor if it still shows a placeholder.
        """
        if self.ad_client is None:
            return
        row = self.ad_tree.identify_row(event.y)
        if not row or row.endswith(_LOADING_SUFFIX):
            return
        self.root.after_idle(lambda: self._ad_ensure_tree_children(row))

    def _ad_populate_open_placeholders(self):
        """Populate every open tree node whose first child is the placeholder.

        One node's failure must not abort the scan: each node is
        guarded, the first error is remembered, and only after the
        whole tree has been scanned is a single error shown. (A plain
        LDAP failure inside _ad_populate_tree_children already shows
        its own dialog and does not propagate, so the error collected
        here is an unexpected one, e.g. a TclError from a node that
        vanished mid-walk.)
        """
        first_error = []

        def walk(node):
            for child in self.ad_tree.get_children(node):
                walk(child)
            if not node:
                return
            try:
                is_open = self.ad_tree.item(node, "open")
            except Exception as exc:  # noqa: BLE001 - collected below
                if not first_error:
                    first_error.append(exc)
                return
            if not is_open:
                return
            try:
                self._ad_ensure_tree_children(node)
            except Exception as exc:  # noqa: BLE001 - collected below
                if not first_error:
                    first_error.append(exc)

        try:
            walk("")
        except Exception as exc:  # noqa: BLE001 - a node vanished mid-walk
            if not first_error:
                first_error.append(exc)
        if first_error:
            self._error(first_error[0])

    def _ad_populate_tree_children(self, parent_dn, children=None):
        # Runs on the UI thread deliberately: the ldap3 connection is
        # bound on this thread and is not safe to use from a worker
        # thread (a background-thread search returns operationsError
        # from the DC). A slow DC can briefly block the UI; that is
        # preferable to a broken search. ``children`` may already
        # hold this DN's children (fetched for the list view) — only
        # query when it is None.
        if children is None:
            try:
                children = self.ad_client.list_children(parent_dn)
            except Exception as exc:  # noqa: BLE001 - shown to the user
                # Put the placeholder back so the user can retry by
                # collapsing and re-expanding the node.
                self.ad_tree.insert(parent_dn, tk.END,
                                    iid=parent_dn + _LOADING_SUFFIX,
                                    text="Loading…")
                self._error(exc)
                return
        for child in children:
            if child["type"] in ("ou", "container", "domain"):
                self.ad_tree.insert(parent_dn, tk.END, iid=child["dn"],
                                    text=_dn_label(child["dn"]))
                self.ad_tree.insert(child["dn"], tk.END,
                                    iid=child["dn"] + _LOADING_SUFFIX,
                                    text="Loading…")

    def _ad_on_tree_select(self, _event):
        sel = self.ad_tree.selection()
        if not sel:
            return
        dn = sel[0]
        if dn.endswith(_LOADING_SUFFIX):
            return
        self._ad_current_dn = dn
        # Selecting a node also loads its tree children, so a click on
        # the disclosure triangle (which selects the node) populates
        # the tree even if the open event's focus has not settled yet.
        # The list view just fetched this DN's children; hand them to
        # the tree population so it does not run the same LDAP query
        # a second time for the same DN. On a list failure (children
        # is None) the tree keeps its placeholder for a retry instead
        # of firing a second, also-failing query.
        children = self._ad_refresh_list(dn)
        if children is not None:
            self._ad_ensure_tree_children(dn, children)

    def _ad_refresh_list(self, dn):
        """Load the list for ``dn``; returns the children (None on failure)."""
        if self.ad_client is None:
            return None
        try:
            children = self.ad_client.list_children(dn)
        except Exception as exc:  # noqa: BLE001 - shown to the user
            self._error(exc)
            return None
        # Keep the full list in memory; the search box filters the
        # displayed rows from it without a new LDAP query.
        self._ad_rows = children
        self._ad_apply_filter()
        return children

    def _ad_apply_filter(self):
        """Repopulate the object list from the loaded rows, applying the search text."""
        rows = []
        for child in self._ad_rows:
            # "Locked" is its own column so a locked-out account is
            # identifiable at a glance ("Yes"); blank otherwise. Use
            # .get() — rows built by hand (e.g. in tests) may not
            # carry the key.
            locked = "Yes" if child.get("locked") else ""
            rows.append((child["dn"], (child["name"], child["type"].capitalize(),
                                        child["description"], child["status"],
                                        locked)))
        self._refill_filtered(self.ad_list, rows, self._ad_search_var.get())

    def _ad_on_list_double_click(self, _event):
        sel = self.ad_list.selection()
        if not sel:
            return
        dn = sel[0]
        values = self.ad_list.item(dn, "values")
        obj_type = values[1].lower() if len(values) > 1 else ""
        # Double-clicking a user opens its Properties dialog.
        if obj_type == "user":
            self._ad_properties()
            return
        # Double-clicking a group opens its Properties dialog.
        if obj_type == "group":
            self._ad_properties()
            return
        # Only containers can be drilled into.
        if obj_type not in ("ou", "container", "domain"):
            return
        # Navigate the list into the container, whether or not it is
        # already present in the tree. The tree is lazy-loaded, so a
        # container shown in the list is often not in the tree yet, and
        # requiring it to be there made double-click a no-op.
        self._ad_current_dn = dn
        self._ad_refresh_list(dn)
        # Keep the tree in sync when the node is already there.
        if self.ad_tree.exists(dn):
            self.ad_tree.selection_set(dn)
            self.ad_tree.see(dn)

    def _ad_selected(self):
        """(dn, name, type) of the selected list row, or None."""
        sel = self.ad_list.selection()
        if not sel:
            messagebox.showinfo("Nothing selected",
                                "Select an object in the list first.",
                                parent=self.root)
            return None
        dn = sel[0]
        values = self.ad_list.item(dn, "values")
        return dn, values[0], values[1].lower()

    def _ad_refresh(self):
        if self.ad_client is None or self._ad_current_dn is None:
            return
        self._ad_refresh_list(self._ad_current_dn)
        self.set_status("Refreshed.")

    def _ad_new_user(self):
        if self.ad_client is None:
            return
        dlg = dialogs.NewUserDialog(self.root, self._ad_current_dn or "")
        dlg.wait_window()
        if not dlg.result:
            return
        data = dlg.result
        try:
            # must_change goes straight into create_user, which sets
            # pwdLastSet = 0 after the password — the old code called
            # reset_password() here instead, which wrote unicodePwd a
            # second time for the same password.
            dn = self.ad_client.create_user(
                data["ou"], data["sam"], data["given"], data["sn"],
                data["display"], data["password"],
                must_change=data["must_change"])
        except Exception as exc:  # noqa: BLE001
            self._error(exc)
            return
        self._ad_refresh()
        self.set_status("Created user {}.".format(data["sam"]))

    def _ad_new_computer(self):
        if self.ad_client is None:
            return
        dlg = dialogs.NewComputerDialog(self.root, self._ad_current_dn or "")
        dlg.wait_window()
        if not dlg.result:
            return
        data = dlg.result
        try:
            self.ad_client.create_computer(data["ou"], data["name"],
                                           data["description"])
        except Exception as exc:  # noqa: BLE001
            self._error(exc)
            return
        self._ad_refresh()
        self.set_status("Created computer {}.".format(data["name"]))

    def _ad_new_group(self):
        if self.ad_client is None:
            return
        dlg = dialogs.NewGroupDialog(self.root, self._ad_current_dn or "")
        dlg.wait_window()
        if not dlg.result:
            return
        data = dlg.result
        try:
            self.ad_client.create_group(data["ou"], data["name"], data["sam"],
                                        data["group_type"], data["description"])
        except Exception as exc:  # noqa: BLE001
            self._error(exc)
            return
        self._ad_refresh()
        self.set_status("Created group {}.".format(data["name"]))

    def _ad_enable(self):
        sel = self._ad_selected()
        if not sel:
            return
        dn, name, obj_type = sel
        if obj_type not in ("user", "computer"):
            messagebox.showinfo("Not applicable", "Only users and computers "
                                "can be enabled.", parent=self.root)
            return
        try:
            self.ad_client.enable_object(dn)
        except Exception as exc:  # noqa: BLE001
            self._error(exc)
            return
        self._ad_refresh()
        self.set_status("Enabled {}.".format(name))

    def _ad_disable(self):
        sel = self._ad_selected()
        if not sel:
            return
        dn, name, obj_type = sel
        if obj_type not in ("user", "computer"):
            messagebox.showinfo("Not applicable", "Only users and computers "
                                "can be disabled.", parent=self.root)
            return
        if not messagebox.askyesno("Disable", "Disable {}?".format(name),
                                   parent=self.root):
            return
        try:
            self.ad_client.disable_object(dn)
        except Exception as exc:  # noqa: BLE001
            self._error(exc)
            return
        self._ad_refresh()
        self.set_status("Disabled {}.".format(name))

    def _ad_unlock(self):
        sel = self._ad_selected()
        if not sel:
            return
        dn, name, obj_type = sel
        if obj_type != "user":
            messagebox.showinfo("Not applicable", "Only users can be unlocked.",
                                parent=self.root)
            return
        try:
            self.ad_client.unlock_user(dn)
        except Exception as exc:  # noqa: BLE001
            self._error(exc)
            return
        self._ad_refresh()
        self.set_status("Unlocked {}.".format(name))

    def _ad_reset_password(self):
        sel = self._ad_selected()
        if not sel:
            return
        dn, name, obj_type = sel
        if obj_type != "user":
            messagebox.showinfo("Not applicable",
                                "Only user passwords can be reset here.",
                                parent=self.root)
            return
        dlg = dialogs.ResetPasswordDialog(self.root, name)
        dlg.wait_window()
        if not dlg.result:
            return
        try:
            self.ad_client.reset_password(dn, dlg.result["password"],
                                          dlg.result["must_change"])
        except Exception as exc:  # noqa: BLE001
            self._error(exc)
            return
        self.set_status("Password reset for {}.".format(name))

    def _ad_add_to_group(self):
        sel = self._ad_selected()
        if not sel or self.ad_client is None:
            return
        dn, name, obj_type = sel
        if obj_type not in ("user", "computer"):
            messagebox.showinfo("Not applicable",
                                "Only users and computers can be added to a group.",
                                parent=self.root)
            return
        base_dn = self.ad_client.get_default_naming_context()
        dlg = dialogs.AddToGroupDialog(
            self.root, lambda q: self.ad_client.search_groups(base_dn, q))
        dlg.wait_window()
        if not dlg.result:
            return
        group = dlg.result
        try:
            self.ad_client.add_group_member(group["dn"], dn)
        except Exception as exc:  # noqa: BLE001
            self._error(exc)
            return
        self.set_status("Added {} to group {}.".format(name, group["name"]))

    def _ad_properties(self):
        """Open the Properties dialog for the selected user or group."""
        sel = self._ad_selected()
        if not sel or self.ad_client is None:
            return
        dn, name, obj_type = sel
        if obj_type == "user":
            self._ad_user_properties(dn, name)
        elif obj_type == "group":
            self._ad_group_properties(dn, name)
        else:
            messagebox.showinfo("Not applicable",
                                "Select a user or group first.",
                                parent=self.root)

    def _ad_user_properties(self, dn, name):
        """Open the User Properties dialog and write back its changes."""
        try:
            attributes = self.ad_client.get_object_attributes(dn)
        except Exception as exc:  # noqa: BLE001
            self._error(exc)
            return
        dlg = dialogs.UserPropertiesDialog(self.root, name, attributes)
        dlg.wait_window()
        if not dlg.result:
            return
        try:
            self.ad_client.modify_object(dn, dlg.result)
        except Exception as exc:  # noqa: BLE001
            self._error(exc)
            return
        self._ad_refresh()
        self.set_status("Updated {}.".format(name))

    def _ad_group_properties(self, dn, name):
        """Open the Group Properties dialog and write back its changes.

        Membership changes are applied immediately inside the dialog;
        only the General/Attribute Editor attribute changes are
        written back here.
        """
        try:
            attributes = self.ad_client.get_object_attributes(dn)
            member_dns = (attributes.get("member") or {}).get("values") or []
            members = self.ad_client.resolve_members(member_dns)
        except Exception as exc:  # noqa: BLE001
            self._error(exc)
            return
        base_dn = self.ad_client.get_default_naming_context()
        dlg = dialogs.GroupPropertiesDialog(
            self.root, name, attributes, self.ad_client, base_dn, dn, members)
        dlg.wait_window()
        if dlg.result:
            try:
                self.ad_client.modify_object(dn, dlg.result)
            except Exception as exc:  # noqa: BLE001
                self._error(exc)
                return
        if dlg.result or dlg.membership_changes:
            self._ad_refresh()
            parts = []
            if dlg.result:
                parts.append("Updated {}.".format(name))
            for action, label in dlg.membership_changes:
                parts.append("{} '{}' {} the group.".format(
                    "Added" if action == "added" else "Removed", label,
                    "to" if action == "added" else "from"))
            self.set_status(" ".join(parts))

    def _ad_delete(self):
        sel = self._ad_selected()
        if not sel:
            return
        dn, name, _obj_type = sel
        if not messagebox.askyesno("Delete",
                                   "Delete {}?\n{}\n\nThis cannot be undone.".format(
                                       name, dn), parent=self.root):
            return
        try:
            self.ad_client.delete_object(dn)
        except Exception as exc:  # noqa: BLE001
            self._error(exc)
            return
        self._ad_refresh()
        self.set_status("Deleted {}.".format(name))

    # ======================================================================
    # DHCP
    # ======================================================================

    def _build_dhcp_tab(self):
        self.dhcp_note = ttk.Label(
            self.dhcp_tab,
            font=("TkDefaultFont", 9, "italic"))
        self.dhcp_note.pack(anchor=tk.W)
        # Shown only when the connected server has no DHCP role: pick
        # which detected DHCP server to manage. Hidden otherwise —
        # DHCP then uses the connected server. The values are
        # replaced by the detected DHCP servers on connect.
        self.dhcp_server_frame = ttk.Frame(self.dhcp_tab)
        self.dhcp_picker_label = ttk.Label(self.dhcp_server_frame)
        self.dhcp_picker_label.pack(side=tk.LEFT)
        self.dhcp_server_var = tk.StringVar(
            value=self.settings["default_server"])
        self.dhcp_server_combo = ttk.Combobox(
            self.dhcp_server_frame, textvariable=self.dhcp_server_var,
            values=self.settings["servers"], width=12,
            state="readonly")
        self.dhcp_server_combo.pack(side=tk.LEFT, padx=4)
        self.dhcp_server_combo.bind("<<ComboboxSelected>>",
                                    self._dhcp_on_server_change)
        self._update_dhcp_labels()
        toolbar = ttk.Frame(self.dhcp_tab)
        toolbar.pack(fill=tk.X, pady=4)
        self.dhcp_toolbar_buttons = []
        for text, command in (
                ("Refresh", self._dhcp_refresh),
                ("Add Reservation", self._dhcp_add_reservation),
                ("Edit Reservation", self._dhcp_edit_reservation),
                ("Remove Reservation", self._dhcp_remove_reservation),
                ("Superscopes", self._dhcp_superscopes)):
            btn = ttk.Button(toolbar, text=text, command=command,
                             state=tk.DISABLED)
            btn.pack(side=tk.LEFT, padx=2)
            self.dhcp_toolbar_buttons.append(btn)

        # Search sits on its own row above the scopes list (not in the
        # toolbar). One box filters scopes, leases and reservations.
        self._dhcp_search_var = self._make_search_row(
            self.dhcp_tab, self._dhcp_apply_filter)
        self._dhcp_search_entry = self._search_entries[-1]
        self._dhcp_search_clear_btn = self._search_clear_btns[-1]

        scope_cols = ("ScopeId", "Name", "SubnetMask", "State",
                      "StartRange", "EndRange", "LeaseDuration")
        self.dhcp_scopes = ttk.Treeview(self.dhcp_tab, columns=scope_cols,
                                        show="headings", height=8)
        for col in scope_cols:
            self.dhcp_scopes.heading(col, text=col)
        self.dhcp_scopes.pack(fill=tk.X, pady=2)
        self.dhcp_scopes.bind("<<TreeviewSelect>>", self._dhcp_on_scope_select)

        paned = ttk.PanedWindow(self.dhcp_tab, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)
        lease_frame = ttk.Frame(paned)
        ttk.Label(lease_frame, text="Leases").pack(anchor=tk.W)
        lease_cols = ("IPAddress", "HostName", "ClientId", "AddressState",
                      "LeaseExpiryTime", "ClientType")
        self.dhcp_leases = ttk.Treeview(lease_frame, columns=lease_cols,
                                        show="headings", height=10)
        for col in lease_cols:
            self.dhcp_leases.heading(col, text=col)
        self.dhcp_leases.column("IPAddress", width=110)
        self.dhcp_leases.column("LeaseExpiryTime", width=150)
        self.dhcp_leases.pack(fill=tk.BOTH, expand=True)
        paned.add(lease_frame, weight=1)

        res_frame = ttk.Frame(paned)
        ttk.Label(res_frame, text="Reservations").pack(anchor=tk.W)
        res_cols = ("IPAddress", "Name", "ClientId", "Description", "Type")
        self.dhcp_reservations = ttk.Treeview(res_frame, columns=res_cols,
                                              show="headings", height=10)
        for col in res_cols:
            self.dhcp_reservations.heading(col, text=col)
        self.dhcp_reservations.column("IPAddress", width=110)
        self.dhcp_reservations.pack(fill=tk.BOTH, expand=True)
        self.dhcp_reservations.bind(
            "<Double-Button-1>", lambda _e: self._dhcp_edit_reservation())
        paned.add(res_frame, weight=1)

        self._dhcp_current_scope = None
        # Canonical rows; the search box filters the displayed trees
        # from these without a new WinRM query.
        self._dhcp_scopes_rows = []
        self._dhcp_leases_rows = []
        self._dhcp_reservations_rows = []

    def _dhcp_apply_filter(self):
        """Repopulate scopes, leases and reservations from the loaded rows, applying the search text."""
        search = self._dhcp_search_var.get()
        scope_cols = ("ScopeId", "Name", "SubnetMask", "State",
                      "StartRange", "EndRange", "LeaseDuration")
        rows = [(None, tuple(row.get(col, "") for col in scope_cols))
                for row in self._dhcp_scopes_rows]
        self._refill_filtered(self.dhcp_scopes, rows, search)
        lease_cols = ("IPAddress", "HostName", "ClientId", "AddressState",
                      "LeaseExpiryTime", "ClientType")
        rows = [(None, tuple(row.get(col, "") for col in lease_cols))
                for row in self._dhcp_leases_rows]
        self._refill_filtered(self.dhcp_leases, rows, search)
        res_cols = ("IPAddress", "Name", "ClientId", "Description", "Type")
        rows = [(None, tuple(row.get(col, "") for col in res_cols))
                for row in self._dhcp_reservations_rows]
        self._refill_filtered(self.dhcp_reservations, rows, search)

    def _dhcp_refresh(self, quiet=False):
        if self.ad_client is not None and not self._dhcp_enabled:
            # The role was missing — re-run discovery in case it was
            # installed since. If a DHCP server is found now, the
            # tab is enabled and loading continues below.
            if self._discover_dhcp(refresh=True):
                self._sync_dhcp_server_row()
                self._apply_role_gating()
                self.set_status("DHCP Server role detected — DHCP tab enabled.")
            else:
                self.set_status(self._role_notes.get(
                    "dhcp", "DHCP Server role is not installed."))
                if not quiet:
                    messagebox.showinfo(
                        "DHCP role not installed",
                        self._role_notes.get("dhcp", ""), parent=self.root)
                return self._role_notes.get("dhcp",
                                            "DHCP Server role is not installed.")
        dhcp = self._ensure_dhcp()
        if dhcp is None:
            return True
        try:
            scopes = dhcp.list_scopes()
        except Exception as exc:  # noqa: BLE001
            if quiet:
                self.set_status("DHCP scope list failed: {} (see DHCP tab)".format(exc))
                return exc
            self._error(exc)
            return exc
        self._dhcp_scopes_rows = scopes
        self._dhcp_apply_filter()
        self.set_status("Loaded {} DHCP scope(s).".format(len(scopes)))
        return True

    def _dhcp_refresh_scope(self, scope_id):
        """Reload the leases and reservations for one scope.

        Uses the scope id directly — not the tree selection — so a
        refresh after an add/edit/remove still works when a search
        filter is active: filtering rebuilds the scopes tree and
        wipes the selection, which used to make the post-change
        refresh a no-op and leave the lists stale. Also sets
        ``_dhcp_current_scope`` so the scope stays current.
        """
        if not scope_id:
            return
        dhcp = self._ensure_dhcp()
        if dhcp is None:
            return
        self._dhcp_current_scope = scope_id
        try:
            leases = dhcp.list_leases(scope_id)
            reservations = dhcp.list_reservations(scope_id)
        except Exception as exc:  # noqa: BLE001
            self._error(exc)
            return
        self._dhcp_leases_rows = leases
        self._dhcp_reservations_rows = reservations
        self._dhcp_apply_filter()
        self.set_status("Scope {}: {} lease(s), {} reservation(s).".format(
            scope_id, len(leases), len(reservations)))

    def _dhcp_on_scope_select(self, _event):
        sel = self.dhcp_scopes.selection()
        if not sel:
            return
        scope_id = self.dhcp_scopes.item(sel[0], "values")[0]
        self._dhcp_refresh_scope(scope_id)

    def _dhcp_add_reservation(self):
        dhcp = self._ensure_dhcp()
        if dhcp is None or not self._dhcp_current_scope:
            messagebox.showinfo("No scope selected",
                                "Select a scope first.", parent=self.root)
            return
        dlg = dialogs.AddReservationDialog(self.root, self._dhcp_current_scope)
        dlg.wait_window()
        if not dlg.result:
            return
        data = dlg.result
        try:
            dhcp.add_reservation(self._dhcp_current_scope, data["ip"],
                                 data["mac"], data["name"],
                                 data["description"])
        except Exception as exc:  # noqa: BLE001
            self._error(exc)
            return
        self._dhcp_refresh_scope(self._dhcp_current_scope)
        self.set_status("Added reservation {} ({}).".format(data["ip"], data["name"]))

    def _dhcp_edit_reservation(self):
        dhcp = self._ensure_dhcp()
        if dhcp is None or not self._dhcp_current_scope:
            messagebox.showinfo("No scope selected",
                                "Select a scope first.", parent=self.root)
            return
        sel = self.dhcp_reservations.selection()
        if not sel:
            messagebox.showinfo("Nothing selected",
                                "Select a reservation first.", parent=self.root)
            return
        values = self.dhcp_reservations.item(sel[0], "values")
        reservation = {"IPAddress": values[0], "Name": values[1],
                       "ClientId": values[2],
                       "Description": values[3] if len(values) > 3 else ""}
        dlg = dialogs.EditReservationDialog(
            self.root, self._dhcp_current_scope, reservation)
        dlg.wait_window()
        if not dlg.result:
            return
        data = dlg.result
        try:
            # The old values go along so a failed MAC-change re-create
            # can roll the old reservation back (see
            # DHCPManager.update_reservation).
            outcome = dhcp.update_reservation(
                self._dhcp_current_scope, reservation["ClientId"],
                data["ip"], data["mac"], data["name"], data["description"],
                old_ip_address=reservation["IPAddress"],
                old_name=reservation["Name"],
                old_description=reservation["Description"])
        except Exception as exc:  # noqa: BLE001
            self._error(exc)
            return
        self._dhcp_refresh_scope(self._dhcp_current_scope)
        if outcome == "recreated":
            self.set_status(
                "Recreated reservation {} ({}) with the new MAC {}.".format(
                    data["ip"], data["name"], data["mac"]))
        else:
            self.set_status("Updated reservation {} ({}).".format(
                data["ip"], data["name"]))

    def _dhcp_remove_reservation(self):
        dhcp = self._ensure_dhcp()
        if dhcp is None or not self._dhcp_current_scope:
            messagebox.showinfo("No scope selected",
                                "Select a scope first.", parent=self.root)
            return
        sel = self.dhcp_reservations.selection()
        if not sel:
            messagebox.showinfo("Nothing selected",
                                "Select a reservation first.", parent=self.root)
            return
        values = self.dhcp_reservations.item(sel[0], "values")
        ip, name, mac = values[0], values[1], values[2]
        if not messagebox.askyesno("Remove Reservation",
                                   "Remove reservation {} ({})?".format(ip, name),
                                   parent=self.root):
            return
        try:
            dhcp.remove_reservation(self._dhcp_current_scope, mac)
        except Exception as exc:  # noqa: BLE001
            self._error(exc)
            return
        self._dhcp_refresh_scope(self._dhcp_current_scope)
        self.set_status("Removed reservation {}.".format(ip))

    def _dhcp_superscopes(self):
        dhcp = self._ensure_dhcp()
        if dhcp is None:
            return
        try:
            superscopes = dhcp.list_superscopes()
        except Exception as exc:  # noqa: BLE001
            self._error(exc)
            return
        if not superscopes:
            messagebox.showinfo("Superscopes", "No superscopes on this server.",
                                parent=self.root)
            return
        lines = ["{}: {}".format(s.get("Name"), s.get("ScopeIds"))
                 for s in superscopes]
        messagebox.showinfo("Superscopes", "\n".join(lines), parent=self.root)

    # ======================================================================
    # DNS
    # ======================================================================

    def _build_dns_tab(self):
        # Note shown when the DNS role is missing on the connected
        # server (role detection); empty when the tab is enabled.
        self.dns_note = ttk.Label(
            self.dns_tab,
            font=("TkDefaultFont", 9, "italic"))
        self.dns_note.pack(anchor=tk.W)
        toolbar = ttk.Frame(self.dns_tab)
        toolbar.pack(fill=tk.X, pady=(0, 4))
        self.dns_toolbar_buttons = []
        for text, command in (
                ("Refresh", self._dns_refresh),
                ("Add Record", self._dns_add_record),
                ("Edit Record", self._dns_edit_record),
                ("Remove Record", self._dns_remove_record)):
            btn = ttk.Button(toolbar, text=text, command=command,
                             state=tk.DISABLED)
            btn.pack(side=tk.LEFT, padx=2)
            self.dns_toolbar_buttons.append(btn)

        # Search sits on its own row above the zone/record lists (not
        # in the toolbar). One box filters zones and records.
        self._dns_search_var = self._make_search_row(
            self.dns_tab, self._dns_apply_filter)
        self._dns_search_entry = self._search_entries[-1]
        self._dns_search_clear_btn = self._search_clear_btns[-1]

        paned = ttk.PanedWindow(self.dns_tab, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)
        zone_frame = ttk.Frame(paned)
        zone_cols = ("ZoneName", "ZoneType", "IsDsIntegrated",
                     "IsReverseLookupZone", "DynamicUpdate")
        self.dns_zones = ttk.Treeview(zone_frame, columns=zone_cols,
                                      show="headings", height=15)
        for col in zone_cols:
            self.dns_zones.heading(col, text=col)
        self.dns_zones.column("ZoneName", width=170)
        self.dns_zones.pack(fill=tk.BOTH, expand=True)
        self.dns_zones.bind("<<TreeviewSelect>>", self._dns_on_zone_select)
        paned.add(zone_frame, weight=1)

        rec_frame = ttk.Frame(paned)
        rec_cols = ("HostName", "RecordType", "Data", "TTL", "TimeStamp")
        self.dns_records = ttk.Treeview(rec_frame, columns=rec_cols,
                                        show="headings", height=15)
        for col in rec_cols:
            self.dns_records.heading(col, text=col)
        self.dns_records.column("HostName", width=150)
        self.dns_records.column("RecordType", width=80)
        self.dns_records.column("Data", width=220)
        self.dns_records.pack(fill=tk.BOTH, expand=True)
        self.dns_records.bind("<Double-Button-1>",
                              lambda _e: self._dns_edit_record())
        paned.add(rec_frame, weight=2)

        self._dns_current_zone = None
        self._dns_record_data = {}  # tree iid -> full record dict
        # Canonical rows; the search box filters the displayed trees
        # from these without a new WinRM query.
        self._dns_zones_rows = []
        self._dns_records_rows = []

    def _dns_apply_filter(self):
        """Repopulate zones and records from the loaded rows, applying the search text."""
        search = self._dns_search_var.get()
        zone_cols = ("ZoneName", "ZoneType", "IsDsIntegrated",
                     "IsReverseLookupZone", "DynamicUpdate")
        rows = [(None, tuple(row.get(col, "") for col in zone_cols))
                for row in self._dns_zones_rows]
        self._refill_filtered(self.dns_zones, rows, search)
        # Records keep their canonical-index iid ("rec-N") so
        # _dns_record_data still maps a selected row to its record.
        self._clear_tree(self.dns_records)
        self._dns_record_data = {}
        needle = (search or "").strip().lower()
        for i, rec in enumerate(self._dns_records_rows):
            values = (rec.get("HostName", ""), rec.get("RecordType", ""),
                      rec.get("Data", ""), rec.get("TTL", ""),
                      rec.get("TimeStamp", "") or "")
            if needle and not any(needle in str(v).lower() for v in values):
                continue
            iid = "rec-{}".format(i)
            self._dns_record_data[iid] = rec
            self.dns_records.insert("", tk.END, iid=iid, values=values)

    def _dns_refresh(self, quiet=False):
        if self.dns is None:
            return True
        if self.ad_client is not None and not self._dns_enabled:
            # The role was missing — re-check the connected server in
            # case it was installed since. If it is present now, the
            # tab is enabled and loading continues below.
            server = self.server_var.get().strip()
            roles = self._detect_roles(server, refresh=True)
            if roles is not None and roles["DNS"]:
                self._dns_enabled = True
                self._role_notes.pop("dns", None)
                self._apply_role_gating()
                self.set_status("DNS Server role detected — DNS tab enabled.")
            else:
                self.set_status(self._role_notes.get(
                    "dns", "DNS Server role is not installed."))
                if not quiet:
                    messagebox.showinfo(
                        "DNS role not installed",
                        self._role_notes.get("dns", ""), parent=self.root)
                return self._role_notes.get(
                    "dns", "DNS Server role is not installed.")
        try:
            zones = self.dns.list_zones()
        except Exception as exc:  # noqa: BLE001
            if quiet:
                self.set_status("DNS zone list failed: {} (see DNS tab)".format(exc))
                return exc
            self._error(exc)
            return exc
        self._dns_zones_rows = zones
        self._dns_apply_filter()
        self.set_status("Loaded {} DNS zone(s).".format(len(zones)))
        return True

    def _dns_refresh_zone(self, zone):
        """Reload the records for one zone.

        Uses the zone name directly — not the tree selection — so a
        refresh after an add/edit/remove still works when a search
        filter is active: filtering rebuilds the zones tree and wipes
        the selection, which used to make the post-change refresh a
        no-op and leave the records stale. Also sets
        ``_dns_current_zone`` so the zone stays current.
        """
        if not zone or self.dns is None:
            return
        self._dns_current_zone = zone
        try:
            records = self.dns.list_records(zone)
        except Exception as exc:  # noqa: BLE001
            self._error(exc)
            return
        self._dns_records_rows = records
        self._dns_apply_filter()
        self.set_status("Zone {}: {} record(s).".format(zone, len(records)))

    def _dns_on_zone_select(self, _event):
        sel = self.dns_zones.selection()
        if not sel or self.dns is None:
            return
        zone = self.dns_zones.item(sel[0], "values")[0]
        self._dns_refresh_zone(zone)

    def _dns_add_record(self):
        if self.dns is None or not self._dns_current_zone:
            messagebox.showinfo("No zone selected",
                                "Select a zone first.", parent=self.root)
            return
        dlg = dialogs.AddRecordDialog(self.root, self._dns_current_zone)
        dlg.wait_window()
        if not dlg.result:
            return
        data = dlg.result
        zone = self._dns_current_zone
        try:
            if data["type"] == "A":
                self.dns.add_a_record(zone, data["name"], data["data"], data["ttl"])
            elif data["type"] == "CNAME":
                self.dns.add_cname_record(zone, data["name"], data["data"], data["ttl"])
            elif data["type"] == "PTR":
                self.dns.add_ptr_record(zone, data["name"], data["data"], data["ttl"])
            elif data["type"] == "MX":
                self.dns.add_mx_record(zone, data["name"], data["data"],
                                       data["preference"], data["ttl"])
        except Exception as exc:  # noqa: BLE001
            self._error(exc)
            return
        self._dns_refresh_zone(self._dns_current_zone)
        self.set_status("Added {} record {} in {}.".format(
            data["type"], data["name"], zone))

    def _dns_edit_record(self):
        if self.dns is None or not self._dns_current_zone:
            messagebox.showinfo("No zone selected",
                                "Select a zone first.", parent=self.root)
            return
        sel = self.dns_records.selection()
        if not sel:
            messagebox.showinfo("Nothing selected",
                                "Select a record first.", parent=self.root)
            return
        rec = self._dns_record_data.get(sel[0])
        if not rec:
            return
        if (rec.get("RecordType") or "").upper() not in (
                "A", "AAAA", "CNAME", "PTR", "MX", "TXT"):
            messagebox.showinfo(
                "Cannot edit record",
                "Editing {} records is not supported.".format(
                    rec.get("RecordType")), parent=self.root)
            return
        dlg = dialogs.EditRecordDialog(self.root, self._dns_current_zone, rec)
        dlg.wait_window()
        if not dlg.result:
            return
        data = dlg.result
        zone = self._dns_current_zone
        try:
            self.dns.update_record(zone, rec.get("HostName"),
                                   rec.get("RecordType"), rec.get("RemoveData"),
                                   data["data"], data.get("preference"),
                                   data.get("ttl"))
        except Exception as exc:  # noqa: BLE001
            self._error(exc)
            return
        self._dns_refresh_zone(self._dns_current_zone)
        self.set_status("Updated {} record {} in {}.".format(
            rec.get("RecordType"), rec.get("HostName"), zone))

    def _dns_remove_record(self):
        if self.dns is None or not self._dns_current_zone:
            messagebox.showinfo("No zone selected",
                                "Select a zone first.", parent=self.root)
            return
        sel = self.dns_records.selection()
        if not sel:
            messagebox.showinfo("Nothing selected",
                                "Select a record first.", parent=self.root)
            return
        rec = self._dns_record_data.get(sel[0])
        if not rec:
            return
        if not messagebox.askyesno(
                "Remove Record",
                "Remove {} record '{}' ({}) from {}?".format(
                    rec.get("RecordType"), rec.get("HostName"),
                    rec.get("Data"), self._dns_current_zone),
                parent=self.root):
            return
        try:
            self.dns.remove_record(self._dns_current_zone, rec.get("HostName"),
                                   rec.get("RecordType"), rec.get("RemoveData"))
        except Exception as exc:  # noqa: BLE001
            self._error(exc)
            return
        self._dns_refresh_zone(self._dns_current_zone)
        self.set_status("Removed {} record {}.".format(
            rec.get("RecordType"), rec.get("HostName")))

    # ======================================================================
    # Directory Info (sites, trusts, forest data — read-only)
    # ======================================================================

    def _build_info_tab(self):
        toolbar = ttk.Frame(self.info_tab)
        toolbar.pack(fill=tk.X, pady=(0, 4))
        self.info_refresh_btn = ttk.Button(toolbar, text="Refresh",
                                           command=self._info_refresh,
                                           state=tk.DISABLED)
        self.info_refresh_btn.pack(side=tk.LEFT, padx=2)

        ttk.Label(self.info_tab, text="Forest / Domain").pack(anchor=tk.W)
        self.info_text = tk.Text(self.info_tab, height=8, wrap=tk.WORD)
        self.info_text.pack(fill=tk.X, pady=2)
        self.info_text.config(state=tk.DISABLED)

        paned = ttk.PanedWindow(self.info_tab, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)
        sites_frame = ttk.Frame(paned)
        ttk.Label(sites_frame, text="Sites & Subnets").pack(anchor=tk.W)
        self.info_sites = ttk.Treeview(sites_frame, show="tree")
        self.info_sites.pack(fill=tk.BOTH, expand=True)
        paned.add(sites_frame, weight=1)

        trusts_frame = ttk.Frame(paned)
        ttk.Label(trusts_frame, text="Trusted Domains").pack(anchor=tk.W)
        trust_cols = ("Name", "Direction", "Type")
        self.info_trusts = ttk.Treeview(trusts_frame, columns=trust_cols,
                                        show="headings", height=10)
        for col in trust_cols:
            self.info_trusts.heading(col, text=col)
        self.info_trusts.pack(fill=tk.BOTH, expand=True)
        paned.add(trusts_frame, weight=1)

    def _info_refresh(self, quiet=False):
        if self.ad_client is None:
            return True
        # Each source is loaded independently: a failure in one must
        # not abort the others. A rootDSE failure is noted in the info
        # text (never a modal — it is a common, non-fatal shortfall);
        # a sites/subnets/trusts failure is also noted inline, and on
        # an explicit Refresh (quiet=False) it additionally shows the
        # error dialog. During connect (quiet=True) nothing here pops
        # a dialog.
        root_dse, root_dse_error = {}, None
        try:
            root_dse = self.ad_client.get_root_dse()
        except Exception as exc:  # noqa: BLE001
            root_dse_error = exc
        sites, subnets, trusts = [], [], []
        load_error = None
        for setter, loader in (("sites", self.ad_client.list_sites),
                               ("subnets", self.ad_client.list_subnets),
                               ("trusts", self.ad_client.list_trusted_domains)):
            try:
                result = loader()
            except Exception as exc:  # noqa: BLE001
                if load_error is None:
                    load_error = exc
                continue
            if setter == "sites":
                sites = result
            elif setter == "subnets":
                subnets = result
            else:
                trusts = result
        lines = []
        for label, key in (("Domain", "defaultNamingContext"),
                           ("Root domain", "rootDomainNamingContext"),
                           ("Configuration", "configurationNamingContext"),
                           ("Forest functionality", "forestFunctionality"),
                           ("Domain functionality", "domainFunctionality"),
                           ("Server", "dnsHostName")):
            value = root_dse.get(key)
            if value is not None:
                lines.append("{}: {}".format(label, value))
        naming = root_dse.get("namingContexts")
        if naming:
            if isinstance(naming, list):
                lines.append("Naming contexts: {}".format(", ".join(naming)))
            else:
                lines.append("Naming contexts: {}".format(naming))
        if root_dse_error is not None:
            lines.append("RootDSE unavailable: {}".format(root_dse_error))
        if load_error is not None:
            lines.append("Sites/subnets/trusts unavailable: {}".format(load_error))
        self.info_text.config(state=tk.NORMAL)
        self.info_text.delete("1.0", tk.END)
        self.info_text.insert(tk.END, "\n".join(lines) or "(no forest data returned)")
        self.info_text.config(state=tk.DISABLED)

        self._clear_tree(self.info_sites)
        site_iids = {}
        for site in sites:
            iid = site["dn"]
            site_iids[iid] = iid
            self.info_sites.insert("", tk.END, iid=iid, text=site["name"])
        for subnet in subnets:
            site_dn = subnet.get("site") or ""
            parent = site_iids.get(site_dn, "")
            label = subnet["name"]
            if subnet.get("description"):
                label += " — {}".format(subnet["description"])
            self.info_sites.insert(parent, tk.END, text=label)

        self._clear_tree(self.info_trusts)
        for trust in trusts:
            self.info_trusts.insert("", tk.END, values=(
                trust.get("name", ""), trust.get("direction", ""),
                trust.get("trust_type", "")))
        first_error = root_dse_error or load_error
        if first_error is None:
            self.set_status("Loaded directory info: {} site(s), {} subnet(s), "
                            "{} trust(s).".format(len(sites), len(subnets),
                                                 len(trusts)))
            return True
        if not quiet and load_error is not None:
            self._error(load_error)
        self.set_status("Directory info partly unavailable: {}".format(first_error))
        return first_error
