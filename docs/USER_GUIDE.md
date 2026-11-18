# MSAT User Guide

## Connecting

There is **one connection for the whole app** — AD, DHCP and DNS
all run on the same domain controllers, so you connect
once.

> **Group Policy is not in MSAT** (removed in v1.4). GPO work is
done in the Group Policy Management Console on a domain controller
(RDP). Use the connection bar at the top of the window:

- **Server** — pick from the dropdown (`dc1`, `dc2`,
  `dc3`) or type any hostname. Defaults to `dc1`.
- **Domain** — defaults to `example.local`.
- **Username** — `admin`, `admin@example.local` or `EXAMPLE\admin`
  all work.
- **Password** — masked; held in memory only.

Click **Connect** — or press Enter while the password field has
focus, which does the same thing (it is a no-op once connected).
Credentials are validated up front: the LDAP
bind is checked and a small search is run before anything is
marked connected. If the username or password is wrong, the app
stays disconnected and says so plainly — a dialog titled
"Invalid credentials" ("Invalid credentials — the username or
password is incorrect. Check your credentials and try again."),
and the connection status label and status bar both read
"Connection failed: invalid credentials". Correct the credentials
and click **Connect** again.

**Role detection.** Once the credentials check out, the app
examines the installed roles on the connected server (over WinRM)
and enables each tab only where its role is present: AD and
Directory Info are always on (a successful LDAP bind means AD DS
is present); DNS is on only when the DNS Server role is installed
on the connected server; DHCP is on when any configured server
has the DHCP Server role — the DHCP tab manages the first one
found (connected server first, then the other configured servers
in order), and if the connected server has no DHCP role, a picker
lets you choose among the servers that do. A tab whose role is
missing is gated: its tools are disabled and a note names the
server and the missing role; its **Refresh** button stays enabled,
so installing the role and clicking Refresh enables the tab.
Role detection runs again on every connect (disconnect and
reconnect to re-check a different server). If detection itself
fails (WinRM down, timeout), the connection is not broken and no
tab is disabled — the app falls back to all tabs enabled and says
so in the status bar.

When validation succeeds, the tabs whose roles were detected load
(AD tree, DHCP scopes, DNS zones, directory info) and their
toolbars become active. LDAPS uses port 636; WinRM uses port 5985.

If one tab fails to load while connecting (for example the DNS
zone list fails), the app does **not** pop up an error dialog — the
failure is reported in the status bar at the bottom and the other
tabs still work. Retry that tab later with its own **Refresh**
button, where a failure does show the error.

Click **Disconnect** when you are done — it disconnects everything
and wipes the stored credentials. Closing the app wipes them too.

If a connection fails, the app shows the error (wrong password, server
unreachable, WinRM not enabled, …) — check the server name, the port,
and that the account has the needed rights.

## Settings

Click **Settings…** in the connection bar (while disconnected) to
save your own connection defaults: the AD domain, the servers, and
the default server. The servers list is a macOS-style list editor:
type a hostname in the entry and click **+** (or press Enter) to add
it — duplicates are ignored — and select a row and click **−** to
remove it (the **−** button is disabled when nothing is selected).
The default server is a dropdown whose options are exactly the
servers in the list. It is automatic when you do not pick one: a
single server becomes the default, and with several servers the
first entry is the default. An explicit pick is kept while that
server stays in the list; removing it falls back to the first
entry. Saving writes them to
`~/.msat/settings.json` — a `.msat` directory in your home
directory — and refreshes the connection bar (server dropdown,
domain field, default selection) from the new values. That location
works the same whether the app is run from source or installed as
MSAT.app in `/Applications`, because it is never stored inside the
app bundle (a .app bundle must not be written to).

Settings hold **only** the domain and servers list — never
credentials. Your username and password are entered each time you
connect and are never written to disk. The app ships with generic
placeholder defaults (`example.local`, `dc1`/`dc2`/`dc3`) until you
set your own; if you delete the settings file, the app falls back
to those placeholders. A settings file saved by v1.7.0 (at the old
`~/.config/msat/settings.json` location) is still honoured when
the new location has no file, and the next save writes to the new
location.

## Updating MSAT

Shortly after launch the app checks GitHub Releases for a newer
published version. The check is silent when you are up to date or
when GitHub cannot be reached — no dialog, no status-bar message.
Help → **Check for Updates…** runs the same check on demand and
always says what it found ("You have the latest version" when you
are current, or that GitHub could not be reached).

When a newer release exists, a dialog shows the new version against
the one you are running and the release notes from GitHub, with
three choices:

- **Download** — downloads the release zip into `~/Downloads`
  (`msat-vX.Y.Z.zip`) and shows the saved path and the install
  steps in the dialog.
- **View on GitHub** — opens the release page in your browser.
- **Later** — dismisses the dialog; nothing is downloaded.

MSAT never updates itself in place: a running .app cannot replace
itself, and overwriting a running program's source files is fragile.
To install a downloaded release, unzip it over the project folder
(from source: re-run `./setup.sh` if needed, then relaunch) or
replace MSAT.app in `/Applications`. Your settings are never
touched — they live in `~/.msat/settings.json`, outside the app
folder and outside the app bundle.

## AD Users & Computers

- **Browse:** the left pane is the OU tree. Click an OU to list its
  contents on the right (Name, Type, Description, Status, Locked).
  OUs load their children when you expand them. Double-click an OU
  in the right-hand list to navigate into it. The **Locked** column
  shows "Yes" for a user account that is currently locked out
  (AD's `lockoutTime` is non-zero; AD clears it to 0 when the
  lockout expires) and is blank otherwise, so locked accounts are
  identifiable at a glance. The Status column also reads
  "Enabled, Locked" / "Disabled, Locked" for those accounts.
- **Search:** the Search box above the right-hand list filters the
  rows already loaded for the current container as you type
  (case-insensitive, matches Name, Type, Description, Status or
  Locked). Clearing it shows everything again. It does not run a
  new search against the server. The small **×** button beside the
  box clears the search text and restores the full list.
- **Properties:** double-click a user or a group (or select one and
  click **Properties**) to open its properties. For a user, the
  **General** tab edits the common attributes (display name,
  first/last name, email, telephone, title, department, company,
  description, office); sAMAccountName is shown read-only. A
  read-only **Locked out** row on the General tab shows Yes/No for
  the account's current lockout state — it is never written back,
  since lockout is managed by AD itself. For a
  group, the **General** tab edits display name, description and
  email (username, group type and DN read-only), and a **Members**
  tab lists the current members with **Add…** and **Remove** —
  membership changes apply immediately, and the main window status
  bar confirms them. The **Attribute Editor** tab lists every
  attribute — double-click one to edit its value(s), one value per
  line for multi-valued attributes such as `proxyAddresses`;
  leaving it empty clears the attribute. The Search box above the
  list filters attributes by name or value as you type; the small
  **×** button beside it clears the search and shows all attributes
  again. Binary
  attributes (`objectGUID`, `objectSid`, `msExchMailboxGuid`, …)
  are shown as hex and cannot be edited; in a group, `member` is
  also read-only here — use the Members tab. Only attributes you
  change are written back when you click **Save**.
- **New User:** fills in the OU you have selected. The account is
  created disabled, the password is set, then it is enabled. Tick
  "User must change password at next logon" to force a change.
- **New Computer:** creates the computer account (sAMAccountName is
  the name with a trailing `$`).
- **New Group:** pick the group type (Global security is the usual
  default).
- **Enable / Disable:** works on the selected user or computer.
- **Unlock:** clears a lockout on the selected user.
- **Reset Password:** sets a new password; optionally forces a change
  at next logon.
- **Add to Group:** select a user or computer, search for a group by
  name, pick it, and the object is added as a member.
- **Delete:** asks for confirmation first. This cannot be undone.
- **Refresh:** reloads the current OU.

## DHCP

- Scopes load automatically once connected. The DHCP tab manages
  the first configured server found with the DHCP Server role
  (connected server first); if the connected server has no DHCP
  role, a picker lets you choose among the servers that do (see
  "Role detection" under Connecting).
- **Search:** the Search box above the scopes list filters scopes,
  leases and reservations as you type (case-insensitive, matches
  any visible column). Clearing it shows everything again. The
  small **×** button beside the box clears the search text and
  restores the full list.
- **Select a scope** to see its leases (left) and reservations (right).
- **Add Reservation:** needs a scope selected. Enter the IP, the MAC
  address (colons, dashes or plain hex all work), a name, and an
  optional description.
- **Edit Reservation:** select a reservation and click **Edit
  Reservation** (or double-click it) to change its IP address, name
  or description in place. Changing the MAC recreates the
  reservation (remove + re-add); the dialog says so.
- **Remove Reservation:** select a reservation, confirm, and it is
  deleted.
- **Superscopes:** shows the superscopes on the server and the scopes
  they contain.
- **Refresh:** reloads the scope list.

## DNS

- Zones load automatically once connected. The DNS tab is enabled
  only when the connected server has the DNS Server role (see
  "Role detection" under Connecting); otherwise the tab is gated
  with a note naming the missing role.
- **Search:** the Search box above the lists filters zones and
  records as you type (case-insensitive, matches any visible
  column). Clearing it shows everything again. The small **×**
  button beside the box clears the search text and restores the
  full list.
- **Select a zone** to see its records (hostname, type, data, TTL).
- **Add Record:** choose the type — A (IPv4), CNAME (alias), PTR
  (reverse), MX (mail). For the zone apex use `@` as the record name.
  For PTR records, select the reverse zone (e.g.
  `1.168.192.in-addr.arpa`) and enter the last octet as the name.
  TTL is optional (leave blank for the zone default).
- **Edit Record:** select a record and click **Edit Record** (or
  double-click it) to change its data and TTL in place — A, AAAA,
  CNAME, PTR, MX and TXT. The record name and type are the identity
  and are read-only. The edit is atomic (`Set-DnsServerResourceRecord`),
  so a failed edit leaves the original record untouched.
- **Remove Record:** select a record and confirm.
- **Refresh:** reloads the zone list.

## Directory Info

Read-only. Once connected it shows:

- **Forest / Domain:** naming contexts, functional levels, server.
- **Sites & Subnets:** AD sites with their subnets underneath.
- **Trusted Domains:** domain trusts and their direction.

## Troubleshooting

- **"Could not connect over LDAPS":** check the server name, that
  port 636 is reachable (`nc -vz dc1 636`), and the username /
  password. Password changes and resets require LDAPS.
- **"Could not connect over WinRM":** check port 5985
  (`nc -vz dc1 5985`), that WinRM is enabled on the server,
  and that NTLM is allowed for the account.
- **A cmdlet reports "not recognized":** the PowerShell module is
  missing on the target — DHCP needs the DhcpServer module, DNS the
  DnsServer module. Both ship with the corresponding server roles.
- **"Access is denied" on a write:** the account lacks the right for
  that object. AD writes need delegated permissions or Domain Admin;
  DHCP/DNS writes need the matching admin rights on the server.
- **A tab is gated ("role is not installed"):** the connected server
  (for DNS) or every configured server (for DHCP) lacks that role.
  Install the role on a server, then click the tab's **Refresh** to
  re-check — the tab enables itself when the role is found. Or
  disconnect and connect to a server that has the role.
- **"Role detection unavailable":** the app could not check the
  roles (WinRM down, timeout) and fell back to all tabs enabled.
  The tabs still work; check WinRM on the connected server if the
  message keeps appearing.
- **Nothing happens after Connect:** the status bar at the bottom
  always says what the app just did (or what failed). Check it first.
