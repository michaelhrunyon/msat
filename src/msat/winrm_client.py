"""WinRM client — runs PowerShell on a Windows server via pywinrm.

Transport: WinRM HTTP (port 5985) with NTLM authentication. pywinrm
encrypts the WS-Management messages when NTLM is used, so the
credentials and the PowerShell traffic are protected even over HTTP.

The client returns structured data where possible: callers send a
PowerShell script whose last step is ``ConvertTo-Json -Compress`` and
use :meth:`WinRMClient.run_ps_json` to get parsed Python objects.
"""

import json

import winrm

from .constants import DEFAULT_WINRM_PORT


class WinRMError(Exception):
    """Raised when a WinRM connection or a remote command fails."""


class PSResult:
    """Result of one remote PowerShell invocation."""

    def __init__(self, stdout, stderr, status_code):
        self.stdout = stdout
        self.stderr = stderr
        self.status_code = status_code

    @property
    def ok(self):
        return self.status_code == 0

    def check(self, what="PowerShell command"):
        """Raise WinRMError unless the command succeeded."""
        if not self.ok:
            detail = (self.stderr or self.stdout or "").strip()
            raise WinRMError(
                "{} failed (exit code {}). {}".format(what, self.status_code, detail)
            )
        return self


class WinRMClient:
    """A WinRM session to one Windows server.

    ``session`` may be injected (tests) — otherwise a real
    ``winrm.Session`` is created. The session is lazy: nothing is sent
    on the wire until the first command runs, so :meth:`connect`
    validates the session by running a trivial command.
    """

    def __init__(self, host, username, password, port=DEFAULT_WINRM_PORT,
                 transport="ntlm", session=None):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.transport = transport
        if session is not None:
            self.session = session
        else:
            endpoint = "http://{}:{}/wsman".format(host, port)
            self.session = winrm.Session(
                endpoint,
                auth=(username, password),
                transport=transport,
                server_cert_validation="ignore",
            )
        self._connected = False

    def connect(self):
        """Validate the session (raises WinRMError on failure)."""
        try:
            result = self.run_ps("Write-Output $env:COMPUTERNAME")
            result.check("WinRM connection test")
        except Exception as exc:  # noqa: BLE001 - re-wrap for the UI
            raise WinRMError(
                "Could not connect to {} over WinRM (port {}): {}".format(
                    self.host, self.port, exc
                )
            ) from exc
        self._connected = True
        return result.stdout.strip()

    @property
    def connected(self):
        return self._connected

    def disconnect(self):
        """WinRM is stateless per call; just forget the session."""
        self._connected = False

    def run_ps(self, script):
        """Run a PowerShell script; return a :class:`PSResult`."""
        try:
            result = self.session.run_ps(script)
        except Exception as exc:  # noqa: BLE001 - re-wrap for the UI
            raise WinRMError(
                "WinRM request to {} failed: {}".format(self.host, exc)
            ) from exc
        return PSResult(
            stdout=result.std_out.decode("utf-8", "replace"),
            stderr=result.std_err.decode("utf-8", "replace"),
            status_code=result.status_code,
        )

    def run_ps_json(self, script, what="PowerShell command"):
        """Run a script that ends in ``ConvertTo-Json`` and parse it.

        Returns a list of dicts (a single object is wrapped in a list;
        empty / ``null`` output returns ``[]``). Raises WinRMError when
        the command fails or the output is not valid JSON.
        """
        result = self.run_ps(script)
        result.check(what)
        return parse_ps_json(result.stdout)


def detect_server_roles(client):
    """Detect the DNS and DHCP server roles on one server.

    Returns ``{"DNS": bool, "DHCP": bool}``. The primary check is
    the role services — DNS Server service ``"DNS"`` and DHCP Server
    service ``"DHCPServer"`` — via ``Get-Service``; a service that
    is not installed is simply absent from the result, so a missing
    role is ``False``, not an error. If the service check itself
    fails (the cmdlet is unavailable, the command errors), it falls
    back to ``Get-WindowsFeature`` and its ``Installed`` property.
    Raises :class:`WinRMError` when neither check can run (WinRM
    unreachable, authentication failure, ...). Never returns a
    partial or ambiguous result silently.
    """
    service_script = (
        "Get-Service -Name DNS, DHCPServer -ErrorAction SilentlyContinue "
        "| Select-Object Name | ConvertTo-Json -Compress"
    )
    try:
        rows = client.run_ps_json(service_script, "Detect server roles")
    except WinRMError:
        feature_script = (
            "Get-WindowsFeature -Name DNS, DHCP | Select-Object Name, "
            "Installed | ConvertTo-Json -Compress"
        )
        rows = client.run_ps_json(feature_script, "Detect server roles")
        names = {str(row.get("Name", "")).upper()
                 for row in rows if row.get("Installed")}
        return {"DNS": "DNS" in names, "DHCP": "DHCP" in names}
    names = {str(row.get("Name", "")).upper() for row in rows}
    return {"DNS": "DNS" in names, "DHCP": "DHCPSERVER" in names}


def ps_quote(value):
    """Quote a value for safe embedding in a PowerShell single-quoted string.

    Single quotes inside the value are doubled, which is PowerShell's
    escaping rule for single-quoted strings.
    """
    return "'" + str(value).replace("'", "''") + "'"


def parse_ps_json(text):
    """Parse PowerShell ``ConvertTo-Json`` output into a Python list.

    * ``""`` / whitespace / ``null`` -> ``[]``
    * a single JSON object -> ``[object]``
    * a JSON array -> the array itself
    """
    text = (text or "").strip()
    if not text or text.lower() == "null":
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise WinRMError("Could not parse PowerShell output as JSON: {}".format(exc)) from exc
    if data is None:
        return []
    if isinstance(data, list):
        return data
    return [data]
