# Contributing to MSAT

## How to contribute

1. Fork the repository and create a branch for your change.
2. Make the change, add or update tests, and run the suite:
   ```bash
   .venv/bin/python -m pytest tests/ -q
   # GUI tests need a display; on Linux use:
   xvfb-run -a .venv/bin/python -m pytest tests/ -q
   ```
3. Open a pull request against `main`, describing what changed and
   why. Keep the change focused; one concern per PR.
4. The maintainer reviews and merges. Be prepared to explain your
   change — including any part an AI tool wrote.

## AI assistance

AI-assisted contributions are welcome, with disclosure:

- State in your pull request description that AI assistance was used,
  naming the tool and what it did.
- Add an `Assisted-by:` trailer to your commit message, e.g.:
  `Assisted-by: Muse (Muse Spark 1.3)`
- You — the human submitting the change — are responsible for it.
  You must be able to read, explain, debug, and stand behind the
  code. Do not submit AI-generated code you do not understand.
- Security-sensitive changes (authentication, credential handling,
  access control, anything sent to a domain controller) need extra
  care and explicit review. Verify commands and behavior against
  vendor documentation; do not present an unverified assumption as
  fact.

See [AI_DISCLOSURE.md](AI_DISCLOSURE.md).

## Ground rules

- **Never guess.** Technical claims, commands, and syntax must be
  verified against official vendor documentation (Microsoft for AD /
  DHCP / DNS / PowerShell). If a source is not official, say so.
- **ldap3 is not thread-safe.** All LDAP work stays synchronous on
  the main UI thread. There must be zero `threading` references in
  `src/msat/`.
- **Credentials are memory-only.** Never write them to disk, log
  them, or put them in a test fixture with a real value.
- **Four tabs only.** Group Policy was removed in v1.4 and stays
  removed.
- Keep the window usable at 1280×800 (minimum 1200×650).
- Do not commit `.venv/`, `__pycache__/`, `.pytest_cache/`,
  `dist/`, `build/`, or `.DS_Store` (see `.gitignore`).

## License

By contributing, you agree that your contribution is released under
the MIT License (see [LICENSE](LICENSE)).
