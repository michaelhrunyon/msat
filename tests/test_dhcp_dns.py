"""Tests for the DHCP and DNS managers (fake WinRM, canned JSON)."""

import json

import pytest

from msat.dhcp import DHCPManager, normalize_mac, validate_ipv4
from msat.dns import DNSManager

SCOPES_JSON = json.dumps([{
    "ScopeId": "192.168.1.0", "SubnetMask": "255.255.255.0",
    "Name": "Office", "State": "Active",
    "StartRange": "192.168.1.10", "EndRange": "192.168.1.200",
    "LeaseDuration": "1.00:00:00",
}])
LEASES_JSON = json.dumps([{
    "IPAddress": "192.168.1.10", "HostName": "PC-01",
    "ClientId": "00-11-22-33-44-55", "AddressState": "Active",
    "LeaseExpiryTime": "2026-11-14T10:00:00.0000000", "ClientType": "DHCP",
}])
RESERVATIONS_JSON = json.dumps([{
    "IPAddress": "192.168.1.50", "Name": "Printer",
    "ClientId": "AA-BB-CC-DD-EE-FF", "Description": "Front printer",
    "Type": "DHCP",
}])
SUPERSCOPES_JSON = json.dumps([{
    "Name": "Super1", "ScopeIds": "192.168.1.0; 192.168.2.0",
}])
ZONES_JSON = json.dumps([{
    "ZoneName": "example.local", "ZoneType": "Primary",
    "IsAutoCreated": False, "IsDsIntegrated": True,
    "IsReverseLookupZone": False, "IsPaused": False,
    "DynamicUpdate": "Secure",
}])
RECORDS_JSON = json.dumps([
    {"HostName": "dc1", "RecordType": "A", "TimeStamp": None,
     "TTL": 3600.0, "Data": "192.168.1.10", "RemoveData": "192.168.1.10"},
    {"HostName": "www", "RecordType": "CNAME", "TimeStamp": None,
     "TTL": 3600.0, "Data": "web.example.local", "RemoveData": "web.example.local"},
    {"HostName": "@", "RecordType": "MX", "TimeStamp": None,
     "TTL": 3600.0, "Data": "10 mail.example.local",
     "RemoveData": "mail.example.local"},
])


# -- helpers -------------------------------------------------------------------

def test_normalize_mac_accepts_common_forms():
    assert normalize_mac("00:11:22:33:44:55") == "00-11-22-33-44-55"
    assert normalize_mac("001122334455") == "00-11-22-33-44-55"
    assert normalize_mac("00-11-22-33-44-55") == "00-11-22-33-44-55"
    assert normalize_mac("aa-bb-cc-dd-ee-ff") == "AA-BB-CC-DD-EE-FF"


def test_normalize_mac_rejects_bad_input():
    for bad in ("", "00:11:22", "zz-11-22-33-44-55", "00-11-22-33-44-55-66"):
        with pytest.raises(ValueError):
            normalize_mac(bad)


def test_validate_ipv4():
    assert validate_ipv4("192.168.1.10") == "192.168.1.10"
    for bad in ("999.1.1.1", "not-an-ip", "192.168.1"):
        with pytest.raises(ValueError):
            validate_ipv4(bad)


def test_validate_ipv6_rejects_ipv4():
    """validate_ipv6 accepts only IPv6 (v1.8.5): the old code used
    ipaddress.ip_address(), which also accepts IPv4, so an IPv4
    address passed client validation when editing an AAAA record
    and only failed server-side."""
    from msat.dns import validate_ipv6
    assert validate_ipv6("2001:db8::1") == "2001:db8::1"
    assert validate_ipv6("::1") == "::1"
    for bad in ("192.168.1.10", "999.1.1.1", "not-an-ip", "2001:db8:::1"):
        with pytest.raises(ValueError):
            validate_ipv6(bad)


# -- DHCP -----------------------------------------------------------------------

def test_dhcp_list_scopes(fake_winrm):
    fake_winrm.when("Get-DhcpServerv4Scope", SCOPES_JSON)
    scopes = DHCPManager(fake_winrm).list_scopes()
    assert len(scopes) == 1
    assert scopes[0]["ScopeId"] == "192.168.1.0"
    assert scopes[0]["Name"] == "Office"
    assert "Get-DhcpServerv4Scope" in fake_winrm.scripts[0]
    assert "ConvertTo-Json" in fake_winrm.scripts[0]


def test_dhcp_list_leases_and_reservations(fake_winrm):
    fake_winrm.when("Get-DhcpServerv4Lease", LEASES_JSON)
    fake_winrm.when("Get-DhcpServerv4Reservation", RESERVATIONS_JSON)
    mgr = DHCPManager(fake_winrm)
    leases = mgr.list_leases("192.168.1.0")
    assert leases[0]["HostName"] == "PC-01"
    assert leases[0]["LeaseExpiryTime"].startswith("2026-11-14")
    reservations = mgr.list_reservations("192.168.1.0")
    assert reservations[0]["Name"] == "Printer"
    assert "192.168.1.0" in fake_winrm.scripts[0]


def test_dhcp_list_superscopes(fake_winrm):
    fake_winrm.when("Get-DhcpServerv4Superscope", SUPERSCOPES_JSON)
    supers = DHCPManager(fake_winrm).list_superscopes()
    assert supers[0]["Name"] == "Super1"


def test_dhcp_add_reservation_builds_cmdlet(fake_winrm):
    mgr = DHCPManager(fake_winrm)
    assert mgr.add_reservation("192.168.1.0", "192.168.1.50",
                               "00:11:22:33:44:55", "Printer", "Front")
    script = fake_winrm.scripts[0]
    assert "Add-DhcpServerv4Reservation" in script
    assert "'192.168.1.50'" in script
    assert "'00-11-22-33-44-55'" in script


def test_dhcp_add_reservation_validates_input(fake_winrm):
    mgr = DHCPManager(fake_winrm)
    with pytest.raises(ValueError):
        mgr.add_reservation("192.168.1.0", "999.1.1.1", "00:11:22:33:44:55", "X")
    with pytest.raises(ValueError):
        mgr.add_reservation("192.168.1.0", "192.168.1.50", "bad-mac", "X")


def test_dhcp_remove_reservation(fake_winrm):
    mgr = DHCPManager(fake_winrm)
    assert mgr.remove_reservation("192.168.1.0", "aa:bb:cc:dd:ee:ff")
    script = fake_winrm.scripts[0]
    assert "Remove-DhcpServerv4Reservation" in script
    assert "'AA-BB-CC-DD-EE-FF'" in script
    # Must not prompt interactively in a remote session.
    assert "$ConfirmPreference = 'None'" in script


def test_dhcp_empty_result_is_empty_list(fake_winrm):
    fake_winrm.when("Get-DhcpServerv4Scope", "")
    assert DHCPManager(fake_winrm).list_scopes() == []


# -- DNS -------------------------------------------------------------------------

def test_dns_list_zones(fake_winrm):
    fake_winrm.when("Get-DnsServerZone", ZONES_JSON)
    zones = DNSManager(fake_winrm).list_zones()
    assert zones[0]["ZoneName"] == "example.local"
    assert zones[0]["ZoneType"] == "Primary"


def test_dns_list_records(fake_winrm):
    fake_winrm.when("Get-DnsServerResourceRecord", RECORDS_JSON)
    records = DNSManager(fake_winrm).list_records("example.local")
    assert len(records) == 3
    mx = [r for r in records if r["RecordType"] == "MX"][0]
    assert mx["Data"] == "10 mail.example.local"
    # The remove value for MX is the exchange host alone.
    assert mx["RemoveData"] == "mail.example.local"


def test_dns_add_a_record(fake_winrm):
    mgr = DNSManager(fake_winrm)
    assert mgr.add_a_record("example.local", "pc01", "192.168.1.10")
    script = fake_winrm.scripts[0]
    assert "Add-DnsServerResourceRecordA" in script
    assert "'pc01'" in script and "'192.168.1.10'" in script


def test_dns_add_a_record_with_ttl(fake_winrm):
    DNSManager(fake_winrm).add_a_record("example.local", "pc01",
                                        "192.168.1.10", ttl_seconds=3600)
    assert "[TimeSpan]::FromSeconds(3600)" in fake_winrm.scripts[0]


def test_dns_add_cname_ptr_mx(fake_winrm):
    mgr = DNSManager(fake_winrm)
    mgr.add_cname_record("example.local", "www", "web.example.local")
    assert "Add-DnsServerResourceRecordCName" in fake_winrm.scripts[0]
    mgr.add_ptr_record("1.168.192.in-addr.arpa", "10", "pc01.example.local")
    assert "Add-DnsServerResourceRecordPtr" in fake_winrm.scripts[1]
    mgr.add_mx_record("example.local", "@", "mail.example.local", 10)
    assert "Add-DnsServerResourceRecordMX" in fake_winrm.scripts[2]
    assert "-Preference 10" in fake_winrm.scripts[2]


def test_dns_remove_record_uses_force_and_record_data(fake_winrm):
    mgr = DNSManager(fake_winrm)
    assert mgr.remove_record("example.local", "@", "MX", "mail.example.local")
    script = fake_winrm.scripts[0]
    assert "Remove-DnsServerResourceRecord" in script
    assert "-Force" in script
    assert "'mail.example.local'" in script


def test_dns_update_a_record_in_place(fake_winrm):
    """A-record edit uses Set-DnsServerResourceRecord (atomic, no remove)."""
    mgr = DNSManager(fake_winrm)
    assert mgr.update_record("example.local", "dc1", "A", "192.168.1.10",
                             "192.168.1.11", ttl_seconds=3600)
    assert len(fake_winrm.scripts) == 1
    script = fake_winrm.scripts[0]
    assert "Set-DnsServerResourceRecord" in script
    assert "Get-DnsServerResourceRecord" in script
    assert "$old.Clone()" in script
    # The old IP selects the exact record; the new IP is written.
    assert "'192.168.1.10'" in script
    assert "[System.Net.IPAddress]::Parse('192.168.1.11')" in script
    assert "[TimeSpan]::FromSeconds(3600)" in script
    assert "Remove-DnsServerResourceRecord" not in script


def test_dns_update_mx_record_with_preference(fake_winrm):
    mgr = DNSManager(fake_winrm)
    assert mgr.update_record("example.local", "@", "MX", "mail.example.local",
                             "mail2.example.local", preference=20,
                             ttl_seconds=3600)
    script = fake_winrm.scripts[0]
    assert "Set-DnsServerResourceRecord" in script
    assert "$_.RecordData.MailExchange -eq 'mail.example.local'" in script
    assert "$new.RecordData.MailExchange = 'mail2.example.local'" in script
    assert "$new.RecordData.Preference = 20" in script


def test_dns_update_txt_record(fake_winrm):
    mgr = DNSManager(fake_winrm)
    assert mgr.update_record("example.local", "@", "TXT", "v=spf1 -all",
                             "v=spf1 include:example.com -all")
    script = fake_winrm.scripts[0]
    assert "Set-DnsServerResourceRecord" in script
    assert "$new.RecordData.DescriptiveText = @(" in script


def test_dns_update_record_validates_input(fake_winrm):
    mgr = DNSManager(fake_winrm)
    with pytest.raises(ValueError):
        mgr.update_record("example.local", "dc1", "A", "192.168.1.10",
                          "999.1.1.1")
    with pytest.raises(ValueError):
        mgr.update_record("example.local", "@", "MX", "mail.example.local",
                          "mail2.example.local")
    with pytest.raises(ValueError):
        mgr.update_record("example.local", "dc1", "SOA", "ns1.example.local",
                          "ns2.example.local")


def test_dns_single_zone_object_is_wrapped(fake_winrm):
    # ConvertTo-Json emits a bare object (not an array) for one zone.
    fake_winrm.when("Get-DnsServerZone",
                    '{"ZoneName": "example.local", "ZoneType": "Primary"}')
    zones = DNSManager(fake_winrm).list_zones()
    assert len(zones) == 1 and zones[0]["ZoneName"] == "example.local"


def test_dhcp_update_reservation_in_place(fake_winrm):
    """Same MAC: one Set-DhcpServerv4Reservation, no remove/re-add."""
    mgr = DHCPManager(fake_winrm)
    outcome = mgr.update_reservation("192.168.1.0", "AA-BB-CC-DD-EE-FF",
                                     "192.168.1.60", "aa:bb:cc:dd:ee:ff",
                                     "Printer 2", "Moved printer")
    assert outcome == "updated"
    assert len(fake_winrm.scripts) == 1
    script = fake_winrm.scripts[0]
    assert "Set-DhcpServerv4Reservation" in script
    assert "'192.168.1.60'" in script
    assert "'AA-BB-CC-DD-EE-FF'" in script
    assert "'Printer 2'" in script
    assert "'Moved printer'" in script
    assert "Add-DhcpServerv4Reservation" not in script
    assert "Remove-DhcpServerv4Reservation" not in script


def test_dhcp_update_reservation_mac_change_recreates(fake_winrm):
    """Changed MAC: remove the old reservation, add one with the new MAC."""
    mgr = DHCPManager(fake_winrm)
    outcome = mgr.update_reservation("192.168.1.0", "AA-BB-CC-DD-EE-FF",
                                     "192.168.1.60", "11:22:33:44:55:66",
                                     "Printer 2", "Moved printer")
    assert outcome == "recreated"
    assert len(fake_winrm.scripts) == 2
    assert "Remove-DhcpServerv4Reservation" in fake_winrm.scripts[0]
    assert "'AA-BB-CC-DD-EE-FF'" in fake_winrm.scripts[0]
    assert "Add-DhcpServerv4Reservation" in fake_winrm.scripts[1]
    assert "'11-22-33-44-55-66'" in fake_winrm.scripts[1]
    assert "'192.168.1.60'" in fake_winrm.scripts[1]


def test_dhcp_update_reservation_validates_input(fake_winrm):
    mgr = DHCPManager(fake_winrm)
    with pytest.raises(ValueError):
        mgr.update_reservation("192.168.1.0", "AA-BB-CC-DD-EE-FF",
                               "999.1.1.1", "AA-BB-CC-DD-EE-FF", "X")
    with pytest.raises(ValueError):
        mgr.update_reservation("192.168.1.0", "AA-BB-CC-DD-EE-FF",
                               "192.168.1.60", "bad-mac", "X")


def test_dhcp_update_reservation_mac_change_validates_before_remove(
        fake_winrm):
    """A MAC change validates the new values BEFORE removing the old
    reservation (v1.8.5): the old code removed first, so a bad new
    IP deleted the reservation and then failed to re-create it."""
    mgr = DHCPManager(fake_winrm)
    with pytest.raises(ValueError):
        mgr.update_reservation("192.168.1.0", "AA-BB-CC-DD-EE-FF",
                               "999.1.1.1", "11:22:33:44:55:66", "X")
    # Nothing was sent to the server at all — no remove happened.
    assert fake_winrm.scripts == []
    with pytest.raises(ValueError):
        mgr.update_reservation("192.168.1.0", "AA-BB-CC-DD-EE-FF",
                               "192.168.1.60", "bad-mac", "X")
    assert fake_winrm.scripts == []


def test_dhcp_update_reservation_mac_change_rollback_restores_old(
        fake_winrm):
    """When the re-create fails server-side, the old reservation is
    re-added (v1.8.5) and the original error is raised."""
    from msat.winrm_client import WinRMError
    # Fail only the re-create (it carries the new IP); the remove
    # and the rollback re-add (old IP) succeed.
    fake_winrm.when_error("192.168.1.60", "IP address is already in use")
    mgr = DHCPManager(fake_winrm)
    with pytest.raises(WinRMError) as excinfo:
        mgr.update_reservation("192.168.1.0", "AA-BB-CC-DD-EE-FF",
                               "192.168.1.60", "11:22:33:44:55:66",
                               "Printer 2", "Moved printer",
                               old_ip_address="192.168.1.50",
                               old_name="Printer",
                               old_description="Front printer")
    assert "restored" in str(excinfo.value)
    assert len(fake_winrm.scripts) == 3
    assert "Remove-DhcpServerv4Reservation" in fake_winrm.scripts[0]
    assert "Add-DhcpServerv4Reservation" in fake_winrm.scripts[1]
    assert "'192.168.1.60'" in fake_winrm.scripts[1]
    # The rollback re-adds the OLD reservation.
    assert "Add-DhcpServerv4Reservation" in fake_winrm.scripts[2]
    assert "'192.168.1.50'" in fake_winrm.scripts[2]
    assert "'AA-BB-CC-DD-EE-FF'" in fake_winrm.scripts[2]
    assert "'Printer'" in fake_winrm.scripts[2]


def test_dhcp_update_reservation_mac_change_rollback_failure_reported(
        fake_winrm):
    """When the re-create AND the rollback both fail, the error says
    the old reservation could not be restored (v1.8.5)."""
    from msat.winrm_client import WinRMError
    fake_winrm.when_error("Add-DhcpServerv4Reservation", "server error")
    mgr = DHCPManager(fake_winrm)
    with pytest.raises(WinRMError) as excinfo:
        mgr.update_reservation("192.168.1.0", "AA-BB-CC-DD-EE-FF",
                               "192.168.1.60", "11:22:33:44:55:66",
                               "Printer 2", "Moved printer",
                               old_ip_address="192.168.1.50",
                               old_name="Printer",
                               old_description="Front printer")
    assert "could NOT be restored" in str(excinfo.value)
    # Remove + failed re-create + failed rollback attempt.
    assert len(fake_winrm.scripts) == 3


def test_dhcp_update_reservation_mac_change_no_old_values_no_rollback(
        fake_winrm):
    """Without the old values, a failed re-create just raises (the
    caller that has them — the UI — always passes them)."""
    from msat.winrm_client import WinRMError
    fake_winrm.when_error("192.168.1.60", "IP address is already in use")
    mgr = DHCPManager(fake_winrm)
    with pytest.raises(WinRMError):
        mgr.update_reservation("192.168.1.0", "AA-BB-CC-DD-EE-FF",
                               "192.168.1.60", "11:22:33:44:55:66",
                               "Printer 2", "Moved printer")
    # Remove + failed re-create; no rollback attempted (no old values).
    assert len(fake_winrm.scripts) == 2
