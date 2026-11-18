"""Tests for the WinRM client and the PowerShell-JSON parser."""

import pytest

from msat.winrm_client import WinRMClient, WinRMError, parse_ps_json


class _FakeResult:
    def __init__(self, stdout=b"", stderr=b"", status_code=0):
        self.std_out = stdout
        self.std_err = stderr
        self.status_code = status_code


class _FakeSession:
    def __init__(self, result=None):
        self.result = result or _FakeResult(b"DC1\r\n")
        self.scripts = []

    def run_ps(self, script):
        self.scripts.append(script)
        return self.result


def test_parse_ps_json_empty_and_null():
    assert parse_ps_json("") == []
    assert parse_ps_json("   ") == []
    assert parse_ps_json("null") == []


def test_parse_ps_json_single_object_wrapped_in_list():
    assert parse_ps_json('{"a": 1}') == [{"a": 1}]


def test_parse_ps_json_array_returned_as_is():
    assert parse_ps_json('[{"a": 1}, {"a": 2}]') == [{"a": 1}, {"a": 2}]


def test_parse_ps_json_invalid_raises():
    with pytest.raises(WinRMError):
        parse_ps_json("not json at all")


def test_run_ps_returns_decoded_result():
    client = WinRMClient("dc1", "u", "p", session=_FakeSession())
    result = client.run_ps("Get-Process")
    assert result.ok
    assert result.stdout.strip() == "DC1"
    assert result.status_code == 0


def test_connect_validates_with_computername():
    session = _FakeSession()
    client = WinRMClient("dc1", "u", "p", session=session)
    assert client.connect() == "DC1"
    assert client.connected
    assert "$env:COMPUTERNAME" in session.scripts[0]


def test_connect_failure_raises_winrm_error():
    session = _FakeSession(_FakeResult(b"", b"Access is denied", 1))
    client = WinRMClient("dc1", "u", "p", session=session)
    with pytest.raises(WinRMError):
        client.connect()


def test_run_ps_json_parses_output():
    session = _FakeSession(_FakeResult(b'[{"Name": "Office"}]'))
    client = WinRMClient("dc1", "u", "p", session=session)
    assert client.run_ps_json("Get-Something | ConvertTo-Json") == [{"Name": "Office"}]


def test_run_ps_json_failing_command_raises():
    session = _FakeSession(_FakeResult(b"", b"cmdlet not found", 1))
    client = WinRMClient("dc1", "u", "p", session=session)
    with pytest.raises(WinRMError):
        client.run_ps_json("Get-Nope | ConvertTo-Json", "List things")
