# Security policy

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.** MSAT
handles Active Directory credentials and sends PowerShell to domain
controllers, so a flaw here can matter. Report it privately so it can
be fixed before it is disclosed:

- Use GitHub's **private vulnerability reporting** on this repository
  (Security tab → "Report a vulnerability"), or
- Email the maintainer (Michael Runyon) directly.

Include a description of the issue, how to reproduce it, and what
impact you think it has. You will get a reply, and a fix (or a
workaround) before any public disclosure.

## Security model (summary)

- Credentials are held **in memory only** and wiped on Disconnect or
  on exit. They are never written to disk, logged, or stored in the
  macOS Keychain.
- AD traffic is always **LDAPS (port 636)**. Password changes use the
  `unicodePwd` attribute, which AD only accepts over an encrypted
  connection. Note: the DC's certificate is *not* validated (ldap3's
  default) — deliberate for internal AD where DCs use self-signed
  certificates.
- WinRM uses **HTTP (5985) + NTLM**; pywinrm encrypts the
  WS-Management messages under NTLM.
- The app is **unsigned**; first launch needs right-click → Open.

See the "Security model" section of [README.md](README.md) for the
full description.

## AI-generated code and security

This project was built with AI assistance (see
[AI_DISCLOSURE.md](AI_DISCLOSURE.md)). AI tools can produce subtly
broken access controls and reproduce vulnerable patterns, so
security-sensitive code in this repo was checked against vendor
documentation and tested live before release — and it should be
re-checked by anyone who modifies it. If you find a flaw, report it
as above; AI-generated security reports should be independently
verified before submission.
