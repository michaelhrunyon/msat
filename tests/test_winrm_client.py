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


# -- detect_server_roles -----------------------------------------------------

class _FakeRoleClient:
    """Stand-in for WinRMClient.run_ps_json for role detection."""

    def __init__(self, service_rows=None, feature_rows=None, fail_services=False):
        self.service_rows = service_rows
        self.feature_rows = feature_rows
        self.fail_services = fail_services
        self.calls = []

    def run_ps_json(self, script, what="PowerShell command"):
        self.calls.append(script)
        if "Get-Service" in script:
            if self.fail_services:
                raise WinRMError("Get-Service failed")
            return self.service_rows or []
        if "Get-WindowsFeature" in script:
            return self.feature_rows or []
        raise WinRMError("unexpected script")


def test_detect_server_roles_case_insensitive_service_names():
    """The Get-Service path normalizes names to uppercase (v1.8.5):
    a service reported as 'dhcpserver' or 'DhcpServer' still counts
    as the DHCP role, matching the Get-WindowsFeature fallback."""
    from msat.winrm_client import detect_server_roles
    client = _FakeRoleClient(service_rows=[{"Name": "dns"},
                                           {"Name": "DhcpServer"}])
    assert detect_server_roles(client) == {"DNS": True, "DHCP": True}
    client = _FakeRoleClient(service_rows=[{"Name": "DNS"},
                                           {"Name": "dhcpserver"}])
    assert detect_server_roles(client) == {"DNS": True, "DHCP": True}
    client = _FakeRoleClient(service_rows=[{"Name": "DNS"}])
    assert detect_server_roles(client) == {"DNS": True, "DHCP": False}


def test_detect_server_roles_falls_back_to_windows_feature():
    """When Get-Service fails, Get-WindowsFeature is used instead."""
    from msat.winrm_client import detect_server_roles
    client = _FakeRoleClient(
        feature_rows=[{"Name": "dns", "Installed": True},
                      {"Name": "dhcp", "Installed": False}],
        fail_services=True)
    assert detect_server_roles(client) == {"DNS": True, "DHCP": False}
    assert any("Get-WindowsFeature" in call for call in client.calls)
