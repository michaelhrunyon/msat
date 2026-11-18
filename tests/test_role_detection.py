"""Tests for role detection (detect_server_roles).

Role detection asks a server which of the DNS / DHCP server roles
are installed, via WinRM PowerShell. These tests run against the
fake WinRM client (canned JSON) — no live server is needed.
"""

import json

import pytest

from msat.winrm_client import WinRMError, detect_server_roles


def _services_json(names):
    return json.dumps([{"Name": name} for name in names])


def _features_json(installed):
    """installed: dict of feature name -> bool."""
    return json.dumps([{"Name": name, "Installed": flag}
                       for name, flag in installed.items()])


def test_detect_both_roles_present(fake_winrm):
    fake_winrm.when("Get-Service", _services_json(["DNS", "DHCPServer"]))
    assert detect_server_roles(fake_winrm) == {"DNS": True, "DHCP": True}


def test_detect_dns_only(fake_winrm):
    fake_winrm.when("Get-Service", _services_json(["DNS"]))
    assert detect_server_roles(fake_winrm) == {"DNS": True, "DHCP": False}


def test_detect_dhcp_only(fake_winrm):
    fake_winrm.when("Get-Service", _services_json(["DHCPServer"]))
    assert detect_server_roles(fake_winrm) == {"DNS": False, "DHCP": True}


def test_detect_neither_role(fake_winrm):
    fake_winrm.when("Get-Service", _services_json([]))
    assert detect_server_roles(fake_winrm) == {"DNS": False, "DHCP": False}


def test_detect_empty_output_means_neither_role(fake_winrm):
    # No handler: the service query returns nothing at all.
    assert detect_server_roles(fake_winrm) == {"DNS": False, "DHCP": False}


def test_detect_falls_back_to_windows_feature(fake_winrm):
    # The service check fails (cmdlet unavailable); the feature list
    # says DNS is installed and DHCP is not.
    fake_winrm.when_error("Get-Service", "Get-Service : not recognized")
    fake_winrm.when("Get-WindowsFeature",
                    _features_json({"DNS": True, "DHCP": False}))
    assert detect_server_roles(fake_winrm) == {"DNS": True, "DHCP": False}


def test_detect_falls_back_to_windows_feature_both(fake_winrm):
    fake_winrm.when_error("Get-Service", "Get-Service : not recognized")
    fake_winrm.when("Get-WindowsFeature",
                    _features_json({"DNS": True, "DHCP": True}))
    assert detect_server_roles(fake_winrm) == {"DNS": True, "DHCP": True}


def test_detect_raises_when_both_checks_fail(fake_winrm):
    fake_winrm.when_error("Get-Service", "Get-Service : not recognized")
    fake_winrm.when_error("Get-WindowsFeature",
                          "Get-WindowsFeature : not recognized")
    with pytest.raises(WinRMError):
        detect_server_roles(fake_winrm)
