"""DHCP management via the DhcpServer PowerShell module over WinRM.

The cmdlets run on the WinRM target itself (the DHCP server), so no
``-ComputerName`` is needed — the session IS the server.

Which servers have the DHCP role is detected at connection time
(role detection); the DHCP tab manages the first server found with
the role.
"""

import ipaddress
import re

from .winrm_client import WinRMError, ps_quote

_MAC_RE = re.compile(r"^[0-9A-Fa-f]{12}$")


def normalize_mac(mac):
    """'00:11:22:33:44:55' / '001122334455' -> '00-11-22-33-44-55'.

    The DHCP cmdlets store ClientId in dash-separated uppercase form.
    Raises ValueError on anything that is not 12 hex digits.
    """
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", mac or "")
    if not _MAC_RE.match(cleaned):
        raise ValueError(
            "Not a valid MAC address: {!r} (expected 12 hex digits)".format(mac))
    cleaned = cleaned.upper()
    return "-".join(cleaned[i:i + 2] for i in range(0, 12, 2))


def validate_ipv4(address):
    """Return the address as a string, or raise ValueError."""
    try:
        return str(ipaddress.IPv4Address(address))
    except ipaddress.AddressValueError as exc:
        raise ValueError("Not a valid IPv4 address: {!r}".format(address)) from exc


class DHCPManager:
    """DHCP operations on one server, via a WinRMClient."""

    def __init__(self, winrm_client):
        self.client = winrm_client

    # -- read ------------------------------------------------------------

    def list_scopes(self):
        """All IPv4 scopes: id, name, mask, state, range, lease duration."""
        script = (
            "Get-DhcpServerv4Scope | Select-Object "
            "@{N='ScopeId';E={$_.ScopeId.IPAddressToString}}, "
            "@{N='SubnetMask';E={$_.SubnetMask.IPAddressToString}}, "
            "Name, State, "
            "@{N='StartRange';E={$_.StartRange.IPAddressToString}}, "
            "@{N='EndRange';E={$_.EndRange.IPAddressToString}}, "
            "@{N='LeaseDuration';E={$_.LeaseDuration.ToString()}} "
            "| ConvertTo-Json -Compress"
        )
        return self.client.run_ps_json(script, "List DHCP scopes")

    def list_superscopes(self):
        """Superscopes and the scope ids they contain."""
        script = (
            "Get-DhcpServerv4Superscope | Select-Object Name, "
            "@{N='ScopeIds';E={($_.ScopeId | ForEach-Object "
            "{ $_.IPAddressToString }) -join '; '}} "
            "| ConvertTo-Json -Compress"
        )
        return self.client.run_ps_json(script, "List DHCP superscopes")

    def list_leases(self, scope_id):
        """Leases in one scope."""
        script = (
            "Get-DhcpServerv4Lease -ScopeId {} | Select-Object "
            "@{{N='IPAddress';E={{$_.IPAddress.IPAddressToString}}}}, "
            "HostName, ClientId, AddressState, "
            "@{{N='LeaseExpiryTime';E={{if ($_.LeaseExpiryTime) "
            "{{ $_.LeaseExpiryTime.ToString('o') }} else {{ $null }}}}}}, "
            "@{{N='ClientType';E={{$_.ClientType.ToString()}}}} "
            "| ConvertTo-Json -Compress"
        ).format(ps_quote(validate_ipv4(scope_id)))
        return self.client.run_ps_json(script, "List DHCP leases")

    def list_reservations(self, scope_id):
        """Reservations in one scope."""
        script = (
            "Get-DhcpServerv4Reservation -ScopeId {} | Select-Object "
            "@{{N='IPAddress';E={{$_.IPAddress.IPAddressToString}}}}, "
            "Name, ClientId, Description, "
            "@{{N='Type';E={{$_.Type.ToString()}}}} "
            "| ConvertTo-Json -Compress"
        ).format(ps_quote(validate_ipv4(scope_id)))
        return self.client.run_ps_json(script, "List DHCP reservations")

    # -- write -----------------------------------------------------------

    def add_reservation(self, scope_id, ip_address, mac_address, name,
                        description=None):
        """Create a reservation. Returns nothing on success."""
        parts = [
            "Add-DhcpServerv4Reservation",
            "-ScopeId", ps_quote(validate_ipv4(scope_id)),
            "-IPAddress", ps_quote(validate_ipv4(ip_address)),
            "-ClientId", ps_quote(normalize_mac(mac_address)),
            "-Name", ps_quote(name),
        ]
        if description:
            parts += ["-Description", ps_quote(description)]
        result = self.client.run_ps(" ".join(parts))
        result.check("Add DHCP reservation")
        return True

    def remove_reservation(self, scope_id, mac_address):
        """Delete a reservation (the UI already confirmed with the user)."""
        script = (
            "$ConfirmPreference = 'None'; "
            "Remove-DhcpServerv4Reservation -ScopeId {} -ClientId {}"
        ).format(ps_quote(validate_ipv4(scope_id)),
                 ps_quote(normalize_mac(mac_address)))
        result = self.client.run_ps(script)
        result.check("Remove DHCP reservation")
        return True

    def update_reservation(self, scope_id, old_mac_address, ip_address,
                           mac_address, name, description=None,
                           old_ip_address=None, old_name=None,
                           old_description=None):
        """Update a reservation, identified by ScopeId + ClientId (MAC).

        IPAddress, Name and Description are changed in place with
        Set-DhcpServerv4Reservation. The cmdlet identifies the
        reservation by ScopeId + ClientId, so the MAC itself cannot be
        changed that way: when the new MAC differs from the old one,
        the reservation is removed and re-created with the new MAC.
        Returns "updated" or "recreated" so the UI can say which
        happened.

        The new values are validated BEFORE the old reservation is
        removed, so a bad new IP or MAC cannot delete the reservation
        and then fail to re-create it. If the re-create still fails
        server-side (e.g. an IP conflict the client cannot see) and
        the caller passed the old values (``old_ip_address``,
        ``old_name``, ``old_description``), the old reservation is
        re-added — a best-effort rollback — and the original error
        is raised, noting whether the restore succeeded.
        """
        old_mac = normalize_mac(old_mac_address)
        new_mac = normalize_mac(mac_address)
        # Validate everything new BEFORE touching the old reservation.
        validate_ipv4(scope_id)
        validate_ipv4(ip_address)
        if new_mac != old_mac:
            self.remove_reservation(scope_id, old_mac)
            try:
                self.add_reservation(scope_id, ip_address, new_mac, name,
                                     description)
            except Exception as exc:
                if old_ip_address is None:
                    raise
                try:
                    self.add_reservation(scope_id, old_ip_address,
                                         old_mac, old_name, old_description)
                except Exception as rollback_exc:
                    raise WinRMError(
                        "Update DHCP reservation failed: {}. The old "
                        "reservation could NOT be restored: {}".format(
                            exc, rollback_exc)) from exc
                raise WinRMError(
                    "Update DHCP reservation failed: {}. The old "
                    "reservation was restored.".format(exc)) from exc
            return "recreated"
        parts = [
            "Set-DhcpServerv4Reservation",
            "-ScopeId", ps_quote(validate_ipv4(scope_id)),
            "-ClientId", ps_quote(old_mac),
            "-IPAddress", ps_quote(validate_ipv4(ip_address)),
            "-Name", ps_quote(name),
            "-Description", ps_quote(description or ""),
        ]
        result = self.client.run_ps(" ".join(parts))
        result.check("Update DHCP reservation")
        return "updated"
