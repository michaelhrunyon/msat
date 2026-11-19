"""DNS management via the DnsServer PowerShell module over WinRM.

The cmdlets run on the WinRM target itself (the DNS server), so no
``-ComputerName`` is needed — the session IS the server.

DNS runs on the servers that have the DNS Server role installed;
role detection at connection time decides whether the DNS tab is
enabled for the connected server.

Record listing flattens each record into a plain dict with a ``Data``
field (human-readable value) and a ``RemoveData`` field (the exact
value ``Remove-DnsServerResourceRecord -RecordData`` needs to match
that record — for MX this is the mail-exchange host alone, without
the preference number).
"""

from .winrm_client import ps_quote
from .dhcp import validate_ipv4  # reuse the IPv4 validator


def validate_ipv6(address):
    """Return the address if it is a valid IPv6 address, else ValueError.

    Uses IPv6Address, not ip_address: the latter also accepts IPv4
    addresses, so an IPv4 address passed validation here and only
    failed server-side when editing an AAAA record.
    """
    import ipaddress
    try:
        return str(ipaddress.IPv6Address(address))
    except ValueError:
        raise ValueError("Invalid IPv6 address: {}".format(address))

_RECORDS_SCRIPT = """
Get-DnsServerResourceRecord -ZoneName {zone} | ForEach-Object {{
    $rec = $_
    $data = switch ($rec.RecordType) {{
        'A'     {{ $rec.RecordData.IPv4Address.IPAddressToString }}
        'AAAA'  {{ $rec.RecordData.IPv6Address.IPAddressToString }}
        'CNAME' {{ $rec.RecordData.HostNameAlias }}
        'PTR'   {{ $rec.RecordData.PtrDomainName }}
        'MX'    {{ "$($rec.RecordData.Preference) $($rec.RecordData.MailExchange)" }}
        'NS'    {{ $rec.RecordData.NameServer }}
        'SOA'   {{ $rec.RecordData.PrimaryServer }}
        'SRV'   {{ "$($rec.RecordData.Priority) $($rec.RecordData.Weight) $($rec.RecordData.Port) $($rec.RecordData.DomainName)" }}
        'TXT'   {{ ($rec.RecordData.DescriptiveText -join ' ') }}
        default {{ $rec.RecordData.ToString() }}
    }}
    $removeData = switch ($rec.RecordType) {{
        'A'     {{ $rec.RecordData.IPv4Address.IPAddressToString }}
        'AAAA'  {{ $rec.RecordData.IPv6Address.IPAddressToString }}
        'CNAME' {{ $rec.RecordData.HostNameAlias }}
        'PTR'   {{ $rec.RecordData.PtrDomainName }}
        'MX'    {{ $rec.RecordData.MailExchange }}
        'NS'    {{ $rec.RecordData.NameServer }}
        'SOA'   {{ $rec.RecordData.PrimaryServer }}
        'SRV'   {{ $rec.RecordData.DomainName }}
        'TXT'   {{ ($rec.RecordData.DescriptiveText -join ' ') }}
        default {{ $rec.RecordData.ToString() }}
    }}
    [PSCustomObject]@{{
        HostName   = $rec.HostName
        RecordType = $rec.RecordType.ToString()
        TimeStamp  = if ($rec.TimeStamp) {{ $rec.TimeStamp.ToString('o') }} else {{ $null }}
        TTL        = $rec.TimeToLive.TotalSeconds
        Data       = $data
        RemoveData = $removeData
    }}
}} | ConvertTo-Json -Compress
"""


class DNSManager:
    """DNS operations on one server, via a WinRMClient."""

    def __init__(self, winrm_client):
        self.client = winrm_client

    # -- read ------------------------------------------------------------

    def list_zones(self):
        """All DNS zones on the server."""
        script = (
            "Get-DnsServerZone | Select-Object ZoneName, "
            "@{N='ZoneType';E={$_.ZoneType.ToString()}}, "
            "IsAutoCreated, IsDsIntegrated, IsReverseLookupZone, IsPaused, "
            "@{N='DynamicUpdate';E={$_.DynamicUpdate.ToString()}} "
            "| ConvertTo-Json -Compress"
        )
        return self.client.run_ps_json(script, "List DNS zones")

    def list_records(self, zone_name):
        """All resource records in one zone (flattened, see module doc)."""
        script = _RECORDS_SCRIPT.format(zone=ps_quote(zone_name))
        return self.client.run_ps_json(script, "List DNS records")

    # -- write -----------------------------------------------------------

    @staticmethod
    def _ttl_clause(ttl_seconds):
        if ttl_seconds is None:
            return ""
        return " -TimeToLive ([TimeSpan]::FromSeconds({}))".format(int(ttl_seconds))

    def add_a_record(self, zone_name, name, ipv4_address, ttl_seconds=None):
        script = (
            "Add-DnsServerResourceRecordA -ZoneName {} -Name {} "
            "-IPv4Address {}{}"
        ).format(ps_quote(zone_name), ps_quote(name),
                 ps_quote(validate_ipv4(ipv4_address)),
                 self._ttl_clause(ttl_seconds))
        self.client.run_ps(script).check("Add DNS A record")
        return True

    def add_cname_record(self, zone_name, name, host_name_alias, ttl_seconds=None):
        script = (
            "Add-DnsServerResourceRecordCName -ZoneName {} -Name {} "
            "-HostNameAlias {}{}"
        ).format(ps_quote(zone_name), ps_quote(name),
                 ps_quote(host_name_alias), self._ttl_clause(ttl_seconds))
        self.client.run_ps(script).check("Add DNS CNAME record")
        return True

    def add_ptr_record(self, zone_name, name, ptr_domain_name, ttl_seconds=None):
        script = (
            "Add-DnsServerResourceRecordPtr -ZoneName {} -Name {} "
            "-PtrDomainName {}{}"
        ).format(ps_quote(zone_name), ps_quote(name),
                 ps_quote(ptr_domain_name), self._ttl_clause(ttl_seconds))
        self.client.run_ps(script).check("Add DNS PTR record")
        return True

    def add_mx_record(self, zone_name, name, mail_exchange, preference,
                      ttl_seconds=None):
        script = (
            "Add-DnsServerResourceRecordMX -ZoneName {} -Name {} "
            "-MailExchange {} -Preference {}{}"
        ).format(ps_quote(zone_name), ps_quote(name),
                 ps_quote(mail_exchange), int(preference),
                 self._ttl_clause(ttl_seconds))
        self.client.run_ps(script).check("Add DNS MX record")
        return True

    def remove_record(self, zone_name, name, record_type, record_data):
        """Delete one record (the UI already confirmed with the user)."""
        script = (
            "$ConfirmPreference = 'None'; "
            "Remove-DnsServerResourceRecord -ZoneName {} -RRType {} "
            "-Name {} -RecordData {} -Force"
        ).format(ps_quote(zone_name), ps_quote(record_type),
                 ps_quote(name), ps_quote(record_data))
        self.client.run_ps(script).check("Remove DNS record")
        return True

    # -- edit ------------------------------------------------------------
    # Set-DnsServerResourceRecord needs the old and the new record
    # objects: fetch the existing record, clone it, apply the new
    # data/TTL, and write it back. The change is atomic — unlike
    # remove + re-add, the record is never missing, so a failed edit
    # leaves the original untouched. ``match`` selects the exact
    # record whose data equals the old value (several records may
    # share a name/type, e.g. round-robin A records).

    _SET_MATCH = {
        "A": "$_.RecordData.IPv4Address.IPAddressToString -eq {old}",
        "AAAA": "$_.RecordData.IPv6Address.IPAddressToString -eq {old}",
        "CNAME": "$_.RecordData.HostNameAlias -eq {old}",
        "PTR": "$_.RecordData.PtrDomainName -eq {old}",
        "MX": "$_.RecordData.MailExchange -eq {old}",
        "TXT": "($_.RecordData.DescriptiveText -join ' ') -eq {old}",
    }

    @staticmethod
    def _set_mutations(record_type, new_data, preference):
        """PowerShell lines applying the new data to the cloned $new record."""
        if record_type == "A":
            return ["$new.RecordData.IPv4Address = "
                    "[System.Net.IPAddress]::Parse({})".format(
                        ps_quote(validate_ipv4(new_data)))]
        if record_type == "AAAA":
            return ["$new.RecordData.IPv6Address = "
                    "[System.Net.IPAddress]::Parse({})".format(
                        ps_quote(validate_ipv6(new_data)))]
        if record_type == "CNAME":
            return ["$new.RecordData.HostNameAlias = {}".format(
                ps_quote(new_data))]
        if record_type == "PTR":
            return ["$new.RecordData.PtrDomainName = {}".format(
                ps_quote(new_data))]
        if record_type == "MX":
            if preference is None:
                raise ValueError("MX preference is required.")
            return ["$new.RecordData.MailExchange = {}".format(
                        ps_quote(new_data)),
                    "$new.RecordData.Preference = {}".format(int(preference))]
        if record_type == "TXT":
            return ["$new.RecordData.DescriptiveText = @({})".format(
                ps_quote(new_data))]
        raise ValueError("Editing {} records is not supported.".format(
            record_type))

    def update_record(self, zone_name, name, record_type, old_data, new_data,
                      preference=None, ttl_seconds=None):
        """Update a record's data and/or TTL in place.

        ``name`` and ``record_type`` are the identity and are not
        changed. ``old_data`` is the record's current RemoveData
        value; it selects the exact record when several share the
        name/type. ``new_data`` is the new value (IPv4 address for
        A, IPv6 for AAAA, alias for CNAME, target for PTR, mail
        exchange host for MX, text for TXT). ``preference`` is the
        new MX preference (required for MX). ``ttl_seconds`` is the
        new TTL; None leaves the TTL unchanged. Returns True.
        """
        rtype = (record_type or "").upper()
        if rtype not in self._SET_MATCH:
            raise ValueError("Editing {} records is not supported.".format(
                record_type))
        match = self._SET_MATCH[rtype].format(old=ps_quote(old_data))
        lines = [
            "$old = Get-DnsServerResourceRecord -ZoneName {} -Name {} "
            "-RRType {} | Where-Object {{ {} }} | Select-Object -First 1".format(
                ps_quote(zone_name), ps_quote(name), ps_quote(rtype), match),
            "if (-not $old) { throw " + ps_quote(
                "DNS record not found: {} ({}) in {}".format(
                    name, rtype, zone_name)) + " }",
            "$new = $old.Clone()",
        ]
        lines.extend(self._set_mutations(rtype, new_data, preference))
        if ttl_seconds is not None:
            lines.append("$new.TimeToLive = [TimeSpan]::FromSeconds({})".format(
                int(ttl_seconds)))
        lines.append(
            "Set-DnsServerResourceRecord -ZoneName {} "
            "-OldInputObject $old -NewInputObject $new".format(
                ps_quote(zone_name)))
        script = "\n".join(lines)
        self.client.run_ps(script).check("Update DNS record")
        return True
