"""Shared test fixtures: make ``src/`` importable and provide a fake WinRM client."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest  # noqa: E402

from msat.winrm_client import PSResult, parse_ps_json  # noqa: E402


class FakeWinRMClient:
    """Stand-in for WinRMClient: returns canned JSON per script substring."""

    def __init__(self):
        self.scripts = []
        self.handlers = []  # (substring, stdout) pairs, first match wins
        self.error_handlers = []  # (substring, stderr) pairs, first match wins

    def when(self, substring, stdout):
        self.handlers.append((substring, stdout))
        return self

    def when_error(self, substring, stderr=""):
        """Make a matching script fail (non-zero exit), like a cmdlet
        that does not exist on the target."""
        self.error_handlers.append((substring, stderr))
        return self

    def run_ps(self, script):
        self.scripts.append(script)
        for substring, stderr in self.error_handlers:
            if substring in script:
                return PSResult("", stderr, 1)
        for substring, stdout in self.handlers:
            if substring in script:
                return PSResult(stdout, "", 0)
        return PSResult("", "", 0)

    def run_ps_json(self, script, what="PowerShell command"):
        result = self.run_ps(script)
        result.check(what)
        return parse_ps_json(result.stdout)


@pytest.fixture
def fake_winrm():
    return FakeWinRMClient()
