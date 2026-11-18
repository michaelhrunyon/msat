# AI disclosure

## What was used

MSAT was built by **vibe coding with Muse** — Meta's AI assistant
(model: Muse Spark 1.3). "Vibe coding" here means AI-assisted
development: the maintainer described what the app should do, and the
AI wrote the code, tests, documentation, and the app icon, iterating
on the maintainer's feedback and corrections.

## What the AI did

- Wrote the Python/Tkinter application (AD, DHCP, DNS, Directory Info
  tabs), the WinRM/LDAP clients, the dialogs, and the test suite.
- Wrote the documentation (`README.md`, `docs/USER_GUIDE.md`).
- Generated the app icon (RSAT-inspired directory-tree design).
- Researched vendor documentation (Microsoft, Fortinet, Veeam) to
  ground technical answers, and flagged where a source was not
  official.

## What the human did

The maintainer (Michael Runyon) is responsible for this project. He:

- Defined every feature and requirement, and set the constraints
  (credentials in memory only, no Group Policy, DHCP on DC1/DC2 only,
  ldap3 stays synchronous on the main thread because it is not
  thread-safe).
- Reviewed and corrected the AI's work at each step — including
  catching wrong assumptions and wrong commands, which were fixed
  from vendor documentation rather than repeated.
- Tested every release against a live Active Directory environment
  (a live Active Directory environment, 3 domain controllers) and approved it before it
  shipped.
- Owns the repository, the releases, and the decisions.

## Responsibility

AI output is not a substitute for human review. The code is covered by
a 94-test suite and by live testing, and security-sensitive parts
(credential handling, LDAP/WinRM, PowerShell sent to domain
controllers) were checked against vendor documentation before release.
Even so, the maintainer — not the AI — is responsible for the code,
including its bugs. If you use this software, you accept it as-is
(see [LICENSE](LICENSE)); test it in your own environment before
relying on it, and never run it against production with credentials
you cannot afford to have mishandled.

## For contributors

If you use AI assistance on a contribution:

- Say so in your pull request description (what tool, and what it
  did).
- Add an `Assisted-by:` trailer to your commit message, in the form
  used by several open-source projects (e.g. Nextcloud, the Linux
  kernel):
  `Assisted-by: Muse (Muse Spark 1.3)`
- You — the human submitting the change — are responsible for it,
  AI-assisted or not. You must be able to read, explain, debug, and
  stand behind the code. Do not submit AI-generated code you do not
  understand. Security-sensitive changes (authentication, credential
  handling, access control, anything sent to a domain controller)
  need extra care and explicit review.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution process.
