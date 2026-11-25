# MSAT — macOS Server Administration Tools

MSAT is a graphical application for macOS that manages the Windows Server
components of an Active Directory environment — the same jobs the Windows
RSAT tools do, from a MacBook. It is written in Python with Tkinter, and
it keeps your credentials in memory only: they are never written to disk,
logged, or stored in the macOS Keychain.

> **Built with Muse** — this app was developed with AI assistance (Meta's
> Muse assistant). See [AI disclosure](#ai-disclosure) and
> [AI_DISCLOSURE.md](AI_DISCLOSURE.md).

| Tab | What it manages | How it talks to the server |
| --- | --- | --- |
| AD Users & Computers | Users, computers, groups, OUs | LDAP over LDAPS (636) |
| DHCP | Scopes, leases, reservations, superscopes | PowerShell over WinRM (5985) |
| DNS | Zones and records | PowerShell over WinRM (5985) |
| Directory Info | Forest/domain data, sites & subnets, trusts | LDAP over LDAPS (636) |

Group Policy is **not** included (removed in v1.4) — GPO work is done in
the Group Policy Management Console on a domain controller.

## Features

- **One global connection bar** for the whole app: server, domain,
  username, password (masked), Connect / Disconnect, and a status
  label. AD, DHCP and DNS all run on the same domain controllers, so
  you connect once. Pressing Enter while the password field has
  focus connects, the same as clicking Connect. Connect turns blue
  while a connection is underway; once connected it returns to
  gray and Disconnect is blue instead, so the blue button always
  shows the current state. If the connection fails, both return
  to gray. Disconnect also clears the password field, so the
  password is not left sitting in the UI after you disconnect,
  and cancels any search filter still waiting to run.
- **Credential validation up front.** Connect gates on the LDAP bind
  and a small validation search before anything is marked connected.
  If the username or password is wrong, the app stays disconnected
  and says so plainly — a dialog titled "Invalid credentials"
  ("Invalid credentials — the username or password is incorrect.
  Check your credentials and try again."), and the connection status
  label and status bar both read "Connection failed: invalid
  credentials". Correct the credentials and click Connect again.
- **Role detection.** On connect, the app examines the installed
  roles on the connected server (over WinRM) and enables each tab
  only where its role is present: AD and Directory Info are always
  on (a successful LDAP bind means AD DS is present); DNS is on
  only when the DNS Server role is installed on the connected
  server; DHCP is on when any configured server has the DHCP Server
  role, and the DHCP tab manages the first one found (connected
  server first, then the other configured servers in order). A tab
  whose role is missing is gated — its tools are disabled and a
  note names the server and the missing role; its Refresh button
  stays enabled, so installing the role and clicking Refresh
  enables the tab. If role detection itself fails (WinRM down,
  timeout), the connection is not broken and no tab is disabled —
  the app falls back to all tabs enabled and says so in the status
  bar.
- **AD tree browsing:** the left pane is the OU tree; clicking an OU
  lists its contents on the right. Expanding a node loads its
  children on the first try, at any depth. Double-click an OU in the
  right-hand list to drill into it. The list has a **Locked** column
  that shows "Yes" for a user account that is currently locked out
  (AD's `lockoutTime` is non-zero; AD clears it to 0 when the
  lockout expires) and is blank otherwise, so locked accounts are
  identifiable at a glance; the Status column also reads
  "Enabled, Locked" / "Disabled, Locked" for those accounts.
- **User and Group Properties:** double-click a user or group (or
  select one and click **Properties**). A General tab edits the common
  fields; for a user it also shows a read-only "Locked out" row
  (Yes/No) for the account's current lockout state, which is never
  written back. An Attribute Editor lists every attribute (binary
  attributes such as `objectGUID` / `objectSid` shown as hex,
  read-only), with a search box that filters by attribute name or
  value. Only changed attributes are written back. Groups also get a
  **Members** tab (Add / Remove, applied immediately); the `member`
  attribute is read-only in the Attribute Editor.
- **AD actions:** New User / Computer / Group, Enable / Disable,
  Unlock, Reset Password, Add to Group, **Move…**, Delete (with
  confirmation). Move relocates a user, computer or group to
  another OU (same name, new parent — no rename, and containers
  themselves cannot be moved); pick the destination OU in the
  picker, which marks the current parent so it cannot be chosen.
  Creating a user is atomic: if setting the password fails (for
  example the password does not meet the complexity policy), the
  half-created account is removed again, so you can fix the
  password and retry instead of hitting "object already exists".
  Right-clicking an object in the AD list shows a context menu
  with the same actions as the toolbar (including Move…), and
  right-clicking a row selects it first; menu items are
  enabled/disabled to match the toolbar buttons.
- **DHCP:** scopes with leases and reservations, superscopes.
  Reservations can be added and edited in place (IP, name,
  description); changing the MAC recreates the reservation
  (remove + re-add) and the dialog says so.
- **DNS:** zones and records. Records can be added (A, CNAME, PTR,
  MX), edited in place (A, AAAA, CNAME, PTR, MX, TXT — data and TTL;
  name and type are the identity and are read-only), and deleted.
  The edit uses `Set-DnsServerResourceRecord` (fetch, clone, modify,
  write back), so it is atomic — a failed edit leaves the original
  record untouched.
- **Directory Info (read-only):** forest/domain naming contexts and
  functional levels, AD sites with their subnets, and trusted domains.
  All naming contexts are shown, not just the first.
- **Search:** the AD, DHCP and DNS tabs each have a Search box above
  their lists, and the Properties Attribute Editor has one too. It
  filters the rows already loaded, as you type (case-insensitive);
  clearing it shows everything again. Each search box has a small
  **×** button beside it that clears the search text and restores
  the full list. The filter waits a short moment after you stop
  typing before rebuilding the list, so typing stays smooth in
  large zones. Adding, editing or removing a DHCP reservation or
  DNS record refreshes that scope or zone even while a search
  filter is active, so the list no longer goes stale after a change.
- **Update check:** shortly after launch the app quietly checks
  GitHub Releases for a newer published version. Help → Check for
  Updates… runs the same check on demand. Nothing happens when you
  are up to date or the check cannot reach GitHub. When a newer
  release exists, a dialog shows the new version against yours and
  the release notes, and offers to download the release zip into
  ~/Downloads — you install it yourself (unzip over the project
  folder, or replace MSAT.app in /Applications). The app never
  replaces itself in place, and your settings
  (`~/.msat/settings.json`) are never touched.
- **Tab load failures are non-modal:** if a tab fails to load while
  connecting, the failure is reported in the status bar instead of a
  dialog, and the other tabs keep working. Retry from the tab's own
  Refresh button.

## Requirements

- macOS.
- **Python 3.15 via Homebrew** (`brew install python`).
- **Tkinter** — Homebrew Python ships *without* Tkinter. Install it
  before running setup, or `./setup.sh` fails with
  `ModuleNotFoundError: _tkinter`:
  ```bash
  brew install python-tk@3.15
  ```
- Network access from the Mac to the domain controllers:
  - **LDAPS 636** (Active Directory)
  - **WinRM 5985** (DHCP / DNS) — the target server must allow WinRM
    with NTLM authentication.
- An AD account with the rights for the jobs you want to do (Domain
  Admin, or delegated rights for the specific objects).

### Defaults and Settings

The app ships with generic placeholder defaults — it is not tied to
any real environment:

- Domain: **example.local**
- Servers: **dc1, dc2, dc3** (the server dropdown lists them and
  defaults to dc1). There is a single servers list: role detection
  at connection time sorts out what each server does, so there is
  no separate list per role.

All of these are defaults shown in the connection bar — every field
is editable, so you can point the app at your own environment right
away. To save your own defaults, click **Settings…** in the
connection bar: enter your domain, add servers to the list with the
**+** button (type a hostname and click **+**, or press Enter), remove
one by selecting it and clicking **−**, and pick the default server
from the dropdown (its options are exactly the servers in the list).
The default is automatic when you do not pick one: a single server
becomes the default, and with several servers the first entry is the
default. They are stored in `~/.msat/settings.json` — a `.msat` directory in
your home directory, outside the repo and outside the app bundle —
and used as the connection bar's defaults on the next launch. That
location works the same whether the app is run from source or
installed as MSAT.app in `/Applications`, because it is never
stored inside the app bundle. Settings hold **only** the domain and
server list — never credentials. Your username and password are
entered each time you connect and are never written to disk.

## Installation

```bash
git clone https://github.com/michaelhrunyon/msat.git
cd msat
./setup.sh        # creates .venv, installs dependencies, checks Tkinter
./run.sh          # starts the app
```

Or manually:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python src/main.py
```

The virtual environment holds only the runtime dependencies
(`ldap3`, `pywinrm`) — no app code lives in it. Deleting the whole
project folder and re-cloning is safe; `./setup.sh` recreates the
venv.

## Usage

Enter the server, domain, username and password in the connection bar
at the top and click **Connect**. When validation succeeds, the tabs
whose roles were detected load and their toolbars become active
(AD and Directory Info always; DNS/DHCP only where the role is
present — see Role detection above). LDAPS uses port 636;
WinRM uses port 5985.

Click **Disconnect** when you are done — it disconnects everything
and wipes the stored credentials. Closing the app wipes them too.

Double-click to work faster: an OU in the right-hand list drills
into it; a user or group opens Properties; a DHCP reservation opens
Edit Reservation; a DNS record opens Edit Record.

See [docs/USER_GUIDE.md](docs/USER_GUIDE.md) for a walkthrough of
each tab, including role detection, the DHCP server picker, and
troubleshooting.

## Build a double-clickable .app (on the Mac)

```bash
./build_app.sh    # must be run on macOS; produces dist/MSAT.app
```

Drag `dist/MSAT.app` to `/Applications`. The bundle is **unsigned**,
so the first launch needs a right-click → Open (Gatekeeper). The
build script refuses to run on Linux — PyInstaller can only build a
macOS bundle on macOS.

### App icon

The app icon is a custom RSAT-inspired directory-tree design (a
parent user node branching to child users, in RSAT blue, as a macOS
squircle). The `.icns` bundle (`msat.icns`) is built from the
1024×1024 source PNG (`msat-icon.png`). Both are binary assets, so
they ship in the **release zip, not in this repo** — copy them into
the project root before running `./build_app.sh` (`msat.spec`
references `msat.icns`). To change the icon, replace `msat-icon.png`,
rebuild `msat.icns` from it (7 sizes: 16–1024), and re-run
`./build_app.sh`.

## Security model

- **Credentials are collected once, in the connection bar at the top
  of the window** (server, domain, username, password masked). They
  are held in memory only, in a single `CredentialStore` shared by
  all four tabs — the tools all run on the same domain controllers,
  so there is one connection, not one per tab. The store never
  touches the disk: no file I/O, no logging, no macOS Keychain, no
  config file.
- **Disconnect (or closing the app) wipes them.** When the process
  exits the memory is gone.
- **AD traffic is always LDAPS (port 636).** Password changes use the
  `unicodePwd` attribute, which AD only accepts over an encrypted
  connection. Note: the DC's certificate is *not* validated (ldap3's
  default) — this is deliberate for internal AD where DCs use
  self-signed certificates. If your DCs have properly chained
  certificates, validation can be enabled in `ldap_client.py`.
- **WinRM uses HTTP (5985) + NTLM.** pywinrm encrypts the
  WS-Management messages under NTLM, so credentials and PowerShell
  traffic are protected even though the transport is HTTP.
- **ldap3 connections are not thread-safe**, so all LDAP work is
  synchronous on the main UI thread — there is no background-thread
  LDAP anywhere in the app.

## Project layout

```
src/main.py                 entry point (creates the Tk root)
src/msat/
  constants.py              environment defaults (domain, servers, ports)
  credentials.py            in-memory credential store (no disk I/O, ever)
  settings.py               user-defined defaults (~/.msat/settings.json)
  ldap_client.py            AD over LDAPS (ldap3): browse/search/create/
                            enable/disable/unlock/password reset/groups/
                            sites/subnets/trusts; object attributes
                            (get/modify, incl. binary-as-hex); credential
                            validation (bind + test search)
  winrm_client.py           WinRM + PowerShell (pywinrm), JSON parsing,
                            role detection (DNS/DHCP roles per server)
  dhcp.py                   DHCP cmdlets (scopes/leases/reservations)
  dns.py                    DNS cmdlets (zones/records)
  dialogs.py                modal dialogs (connect, new user/computer/
                            group, reset password, add/edit record,
                            user/group properties, ...)
  app.py                    Tkinter main window (4 tabs + status bar)
tests/                      pytest suite (ldap3 mock + fake WinRM + GUI)
docs/USER_GUIDE.md          full walkthrough of each tab
msat.spec                   PyInstaller spec for the .app bundle
build_app.sh                builds dist/MSAT.app (macOS only)
setup.sh / run.sh           venv setup / launcher
```

Run the tests with:

```bash
.venv/bin/python -m pytest tests/ -q
# GUI tests need a display; on Linux use:
xvfb-run -a .venv/bin/python -m pytest tests/ -q
```

## Current status

**v1.8.10** — tested against a live Active Directory environment (3 DCs). 249 tests passing.

- **Timeout disconnect now clears everything:** when the DC closes the connection (idle timeout / dropped), the app returns to the login screen and clears all shown data — AD, DHCP, DNS and Directory Info — and wipes the password, exactly like clicking Disconnect. Previously the Directory Info refresh noted a dead connection inline and left the data visible.

## Known limitations

- **Group Policy was removed in v1.4.** GPO work is done in the Group
  Policy Management Console on a domain controller (RDP), not in MSAT.
- **WinRM must be enabled on the target server** with NTLM allowed.
  If the server only allows Kerberos, or WinRM is blocked by the
  firewall, the DHCP / DNS tools cannot reach it.
- The app is **unsigned**; see the Gatekeeper note above.

## AI disclosure

MSAT was built by **vibe coding with Muse** — Meta's AI assistant
(model: Muse Spark 1.3). The AI wrote the code, tests, documentation,
and the app icon, working from the maintainer's direction. The
maintainer (Michael Runyon) defined every feature, reviewed and tested
each release against a live Active Directory environment
(3 domain controllers), and is responsible for the project — including
its bugs. AI output is not a substitute for that review: the code is
covered by a 124-test suite and by live testing, and security-sensitive
parts (credentials, LDAP/WinRM handling) were checked against vendor
documentation before release.

Contributors: if you use AI assistance on a contribution, say so in
your pull request and use the `Assisted-by:` commit trailer (see
[AI_DISCLOSURE.md](AI_DISCLOSURE.md) and
[CONTRIBUTING.md](CONTRIBUTING.md)). The human submitting a change is
responsible for it, AI-assisted or not.
