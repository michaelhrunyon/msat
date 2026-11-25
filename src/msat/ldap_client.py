"""Active Directory client — LDAP over LDAPS (port 636) via ``ldap3``.

All directory operations go through this class: browsing OUs, searching
and managing users / computers / groups, password resets, and the
read-only directory information (sites, subnets, trusts, forest data).

AD-specific details handled here:
  * Password changes use the ``unicodePwd`` attribute, which AD only
    accepts over an encrypted connection (LDAPS) as a *quoted*
    UTF-16LE string.
  * ``userAccountControl`` flags: 512 = normal account, 514 = disabled
    (512 + 2), 66048 = normal + password-never-expires (512 + 65536),
    4096 = workstation trust account (computer).
  * Unlocking a user means writing ``lockoutTime = 0``.
  * "User must change password at next logon" means ``pwdLastSet = 0``.
  * Computer objects also carry ``objectClass=user`` in AD, so the
    object *type* is decided by checking ``computer`` first.
"""

from ldap3 import ALL, BASE, LEVEL, SUBTREE, Connection, Server
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE
from ldap3.core.exceptions import (
    LDAPException, LDAPSessionTerminatedByServerError,
    LDAPSocketReceiveError, LDAPSocketSendError)
from ldap3.strategy.mockSync import MockSyncStrategy
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn

from .constants import DEFAULT_LDAPS_PORT

# userAccountControl bits (AD).
UAC_ACCOUNT_DISABLE = 0x0002
UAC_NORMAL_ACCOUNT = 0x0200          # 512
UAC_WORKSTATION_TRUST = 0x1000       # 4096
UAC_DONT_EXPIRE_PASSWORD = 0x10000   # 65536

# groupType values (AD).
GROUP_TYPES = {
    "Global security": -2147483646,
    "Domain local security": -2147483644,
    "Universal security": -2147483640,
    "Global distribution": 2,
    "Domain local distribution": 4,
    "Universal distribution": 8,
}


class ADError(Exception):
    """Raised when an AD operation fails."""


class ADConnectionError(ADError):
    """Raised when the LDAP connection / bind fails."""


class ADConnectionLostError(ADError):
    """The DC closed an established LDAP connection mid-session
    (idle timeout, dropped socket). The app treats this as "signed
    out — please reconnect" instead of showing the raw socket error."""


class ADInvalidCredentialsError(ADConnectionError):
    """The username or password was rejected by the DC (result 49)."""


# ldap3 errors that mean the DC closed the connection mid-session,
# as opposed to a failed bind or a bad filter: a send failure
# (Broken pipe), a receive failure (connection reset), or the server
# terminating the session.
_CONNECTION_LOST_ERRORS = (LDAPSocketSendError, LDAPSocketReceiveError,
                           LDAPSessionTerminatedByServerError)


def _raise_ldap_error(exc, what):
    """Raise the right ADError for an LDAP operation failure.

    A dead connection becomes ADConnectionLostError, so the app can
    return to the login screen with a plain message instead of
    showing the raw socket error ("LDAP search failed: socket
    sending error[Errno 32] Broken pipe"). Everything else keeps
    the existing "<what> failed: <detail>" message.
    """
    if isinstance(exc, _CONNECTION_LOST_ERRORS):
        raise ADConnectionLostError(
            "The connection to the domain controller was closed "
            "(it timed out or was dropped). Please reconnect.") from exc
    raise ADError("{} failed: {}".format(what, exc)) from exc


def domain_to_dn(domain):
    """'example.local' -> 'DC=example,DC=local'."""
    return ",".join("DC={}".format(part) for part in domain.split(".") if part)


def encode_password(password):
    """AD wants unicodePwd as a quoted UTF-16LE byte string."""
    return ('"' + password + '"').encode("utf-16-le")


def _decode(value):
    """Decode a bytes value to str (ldap3 may return either)."""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value


def _display_value(value):
    """One LDAP value as a display string.

    Returns (text, is_binary). Binary values — undecodable bytes, or
    text full of control characters — are shown as hex so the UI can
    display them without crashing or showing garbage. Non-string
    scalars (ldap3 returns datetime.datetime for datetime-valued
    attributes such as whenCreated / whenChanged / lastLogon) are
    converted with str() first — a datetime is not iterable, so it
    must never reach the control-character check as-is.
    """
    if isinstance(value, bytes):
        try:
            text = value.decode("utf-8")
        except UnicodeDecodeError:
            return value.hex(), True
    elif isinstance(value, str):
        text = value
    else:
        text = str(value)
    if any((ord(c) < 32 and c not in "\t\n\r") or ord(c) == 127
           for c in text):
        return text.encode("utf-8", "replace").hex(), True
    return text, False


# Attributes whose values are binary blobs (GUIDs, SIDs, certificates,
# photos, ...). They are shown as hex and are never editable, even if
# a particular value happens to decode as UTF-8.
BINARY_ATTRIBUTES = frozenset({
    "objectguid", "objectsid", "msexchmailboxguid", "msexcharchiveguid",
    "msexchmailboxsecuritydescriptor", "msmqsigncertificates", "msmqdigest",
    "usercertificate", "usersmimecertificate", "thumbnailphoto", "jpegphoto",
    "msds-consistencyguid", "msds-keycredentiallink",
    "unicodepwd", "dbcs-pwd", "ntpwdhistory", "lmpwdhistory",
    "mspki-certificate", "mspki-credentialroamingtokens",
})


def _first(attributes, name, default=None):
    """First value of a (possibly multi-valued) LDAP attribute."""
    values = attributes.get(name)
    if not values:
        return default
    if isinstance(values, (list, tuple)):
        return _decode(values[0]) if values else default
    return _decode(values)


def _to_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _first_rdn(dn):
    """First RDN component of a DN, verbatim.

    'CN=Doe\\, John,OU=Users,DC=...' -> 'CN=Doe\\, John'. The split
    is at the first comma not escaped by a backslash — a comma counts
    as escaped when preceded by an odd run of backslashes, since
    '\\\\' is itself an escaped backslash. The RDN is returned
    exactly as it appears in the DN (no re-escaping), which is what
    modify_dn needs for a pure move: same RDN, new parent.
    """
    if not dn:
        return ""
    backslashes = 0
    for i, ch in enumerate(dn):
        if ch == "\\":
            backslashes += 1
        elif ch == ",":
            if backslashes % 2 == 0:
                return dn[:i]
            backslashes = 0
        else:
            backslashes = 0
    return dn


def parent_dn(dn):
    """DN of the parent container: the DN minus its first RDN.

    'CN=jdoe,OU=Users,DC=example,DC=local' ->
    'OU=Users,DC=example,DC=local'. A DN with no parent (a bare
    RDN) gives ''.
    """
    if not dn:
        return ""
    rdn = _first_rdn(dn)
    rest = dn[len(rdn):]
    if rest.startswith(","):
        return rest[1:]
    return ""


def _rdn_value(dn):
    """First RDN value of a DN ('OU=IT,DC=...' -> 'IT')."""
    if not dn:
        return ""
    first = dn.split(",", 1)[0]
    if "=" in first:
        return first.split("=", 1)[1].replace("\\,", ",")
    return first


def object_type_from_classes(object_classes):
    """Decide the ADUC-style type from an object's objectClass list.

    Order matters: computer objects also carry ``user`` in AD.
    """
    classes = {str(c).lower() for c in (object_classes or [])}
    if "computer" in classes:
        return "computer"
    if "group" in classes:
        return "group"
    if "user" in classes:
        return "user"
    if "organizationalunit" in classes:
        return "ou"
    if "domain" in classes:
        return "domain"
    if "container" in classes or "builtindomain" in classes:
        return "container"
    return "object"


def is_locked_out(attributes):
    """True when a get_object_attributes() dict shows a lockout.

    ``attributes`` maps attr -> {"values": [str, ...], "binary": bool}
    (the shape get_object_attributes() returns). lockoutTime is a
    Windows FILETIME: non-zero means the account is currently locked
    out (AD clears it to 0 when the lockout expires); a missing
    attribute or "0" means not locked.
    """
    info = attributes.get("lockoutTime") or {}
    values = info.get("values") or []
    if not values:
        return False
    return _to_int(values[0]) != 0


class ADClient:
    """An LDAPS connection to one domain controller.

    ``connection`` may be injected (tests use ldap3's MOCK_SYNC
    strategy); otherwise a real connection is built in :meth:`connect`.
    """

    LIST_ATTRS = [
        "objectClass", "name", "sAMAccountName", "description",
        "userAccountControl", "lockoutTime", "groupType",
        "distinguishedName", "objectCategory", "displayName",
    ]

    def __init__(self, server=None, domain=None, username=None, password=None,
                 port=DEFAULT_LDAPS_PORT, connection=None):
        self.server = server
        self.domain = domain
        self.username = username
        self.password = password
        self.port = port
        self.conn = connection
        self._connected = False
        self._root_dse = {}

    # -- connection ----------------------------------------------------

    @staticmethod
    def qualify_username(username, domain):
        """Turn a bare sAMAccountName into a UPN for the LDAP bind.

        Names that already carry a form AD understands (UPN, DOMAIN\\user
        or a full DN) are passed through unchanged.
        """
        if not username:
            return username
        if "@" in username or "\\" in username or "=" in username:
            return username
        if domain:
            return "{}@{}".format(username, domain)
        return username

    def connect(self):
        """Bind to the DC over LDAPS (raises ADConnectionError).

        NOTE: ldap3's Connection defaults to raise_exceptions=False,
        so bind() returns False on a failed bind instead of raising.
        The return value MUST be checked — the old code did not, so
        a bad password silently "connected" and the first real search
        failed with a cryptic operationsError.
        """
        if self.conn is None:
            server = Server(self.server, port=self.port, use_ssl=True,
                            get_info=ALL, connect_timeout=10)
            bind_user = self.qualify_username(self.username, self.domain)
            self.conn = Connection(server, user=bind_user,
                                   password=self.password, auto_bind=False)
            try:
                bound = self.conn.bind()
            except LDAPException as exc:
                raise ADConnectionError(
                    "Could not connect to {} over LDAPS (port {}): {}".format(
                        self.server, self.port, exc)
                ) from exc
            if not bound or not self.conn.bound:
                raise self._bind_error()
        else:
            # Injected connection (tests): bind if not already bound.
            try:
                if not getattr(self.conn, "bound", False):
                    bound = self.conn.bind()
                else:
                    bound = True
            except LDAPException as exc:
                raise ADConnectionError("Mock bind failed: {}".format(exc)) from exc
            if not bound:
                raise self._bind_error()
        self._connected = True
        # Cache the naming contexts; fall back to the domain if the
        # rootDSE read is unavailable for any reason.
        try:
            self._root_dse = self.get_root_dse()
        except ADError:
            self._root_dse = {}
        return True

    def _bind_error(self):
        """The error for a failed bind, distinguishing bad credentials."""
        result = {}
        try:
            result = self.conn.result or {}
        except Exception:  # noqa: BLE001 - mock connections lack .result
            result = {}
        code = result.get("result") if isinstance(result, dict) else None
        desc = result.get("description", "") if isinstance(result, dict) else ""
        if code == 49 or "invalidcredentials" in str(desc).lower().replace(" ", ""):
            return ADInvalidCredentialsError(
                "Invalid credentials — the username or password is "
                "incorrect for {}.".format(self.server))
        return ADConnectionError(
            "Could not connect to {} over LDAPS (port {}): {}".format(
                self.server, self.port, desc or "bind failed"))

    def disconnect(self):
        if self.conn is not None:
            try:
                self.conn.unbind()
            except LDAPException:
                pass
        self._connected = False

    def validate_connection(self):
        """Prove the bound connection can actually search.

        A successful bind alone does not prove the credentials are
        usable — a stale or restricted credential can bind yet fail
        every search (the DC answers operationsError), which used to
        surface later as a cryptic tree-loading error. Run one small
        base-scope search on the domain DN before the UI treats the
        connection as live.
        Raises ADInvalidCredentialsError when the server reports
        invalid credentials, otherwise ADError.
        """
        self._require_connection()
        dn = self.get_default_naming_context()
        if not dn:
            dn = domain_to_dn(self.domain) if self.domain else ""
        try:
            self._search(dn, "(objectClass=*)", ["distinguishedName"],
                         scope=BASE)
        except ADError as exc:
            if self._is_invalid_credentials(exc):
                raise ADInvalidCredentialsError(
                    "Invalid credentials — the username or password is "
                    "incorrect for {}.".format(self.server)
                ) from exc
            raise
        return True

    def _is_invalid_credentials(self, exc):
        """True when an LDAP failure means the credentials were rejected."""
        try:
            result = self.conn.result or {}
        except Exception:  # noqa: BLE001 - mock connections lack .result
            result = {}
        if isinstance(result, dict) and result.get("result") == 49:
            return True
        text = str(exc).lower().replace(" ", "")
        return "invalidcredentials" in text

    @property
    def connected(self):
        return self._connected

    def _require_connection(self):
        if not self._connected or self.conn is None:
            raise ADConnectionError("Not connected to Active Directory.")

    # -- low-level helpers ----------------------------------------------

    def _search(self, base_dn, search_filter, attributes, scope=SUBTREE):
        """Run a search; return [{'dn': ..., 'attributes': {...}}].

        A search that matches nothing is a successful empty result, not
        an error — so success is judged by the LDAP result code (0),
        not by the boolean ldap3 returns (its mock strategy returns
        False for empty result sets).

        Real connections use a paged search (500 entries per page):
        Active Directory's default MaxPageSize is 1,000, so a single
        unpaged search silently truncates (or errors on) any OU or
        search returning more than 1,000 objects. The paged search
        returns raw response dicts, which are converted to the same
        {'dn', 'attributes'} shape as the unpaged path. Mock
        connections (tests, MOCK_SYNC) keep the plain unpaged search:
        the mock strategy does not model paged results.
        """
        self._require_connection()
        if isinstance(self.conn.strategy, MockSyncStrategy):
            return self._search_unpaged(base_dn, search_filter, attributes,
                                       scope)
        try:
            responses = self.conn.extend.standard.paged_search(
                base_dn, search_filter, search_scope=scope,
                attributes=attributes, paged_size=500, generator=False)
        except LDAPException as exc:
            _raise_ldap_error(exc, "LDAP search")
        code = self.conn.result.get("result")
        if code is not None and code != 0:
            raise ADError("LDAP search failed: {}".format(
                self.conn.result.get("description", "unknown error")))
        return [{"dn": entry["dn"], "attributes": entry["attributes"]}
                for entry in responses
                if entry.get("type") == "searchResEntry"]

    def _search_unpaged(self, base_dn, search_filter, attributes,
                        scope=SUBTREE):
        """The single unpaged search, used only for mock connections.

        Kept separate so the paged path above stays the one real
        servers use, while tests (ldap3 MOCK_SYNC) keep the plain
        search the mock models. Success is judged by the LDAP result
        code (0), not by the boolean ldap3 returns.
        """
        self._require_connection()
        try:
            ok = self.conn.search(base_dn, search_filter,
                                  search_scope=scope, attributes=attributes)
        except LDAPException as exc:
            _raise_ldap_error(exc, "LDAP search")
        code = self.conn.result.get("result")
        if code is None:
            if not ok:
                raise ADError("LDAP search failed: {}".format(
                    self.conn.result.get("description", "unknown error")))
        elif code != 0:
            raise ADError("LDAP search failed: {}".format(
                self.conn.result.get("description", "unknown error")))
        return [{"dn": e.entry_dn, "attributes": e.entry_attributes_as_dict}
                for e in self.conn.entries]

    def _modify(self, dn, changes, what):
        self._require_connection()
        try:
            ok = self.conn.modify(dn, changes)
        except LDAPException as exc:
            _raise_ldap_error(exc, what)
        if not ok:
            raise ADError("{} failed: {}".format(
                what, self.conn.result.get("description", "unknown error")))

    def _add(self, dn, object_classes, attributes, what):
        self._require_connection()
        try:
            ok = self.conn.add(dn, object_classes, attributes)
        except LDAPException as exc:
            _raise_ldap_error(exc, what)
        if not ok:
            raise ADError("{} failed: {}".format(
                what, self.conn.result.get("description", "unknown error")))

    @staticmethod
    def entry_to_dict(entry):
        """Normalise one search result for the UI."""
        attrs = entry["attributes"]
        classes = attrs.get("objectClass") or []
        if isinstance(classes, str):
            classes = [classes]
        classes = [_decode(c) for c in classes]
        obj_type = object_type_from_classes(classes)
        uac = _to_int(_first(attrs, "userAccountControl", 0))
        lockout = _to_int(_first(attrs, "lockoutTime", 0))
        status = ""
        if obj_type in ("user", "computer"):
            status = "Disabled" if (uac & UAC_ACCOUNT_DISABLE) else "Enabled"
            if obj_type == "user" and lockout != 0:
                status += ", Locked"
        return {
            "dn": entry["dn"],
            "type": obj_type,
            "name": _first(attrs, "name") or _first(attrs, "sAMAccountName") or _rdn_value(entry["dn"]),
            "sam": _first(attrs, "sAMAccountName", ""),
            "description": _first(attrs, "description", ""),
            "display_name": _first(attrs, "displayName", ""),
            "uac": uac,
            "status": status,
            # True only for a user whose lockoutTime is non-zero
            # (AD clears it to 0 when the lockout expires). The list
            # shows this in its own "Locked" column.
            "locked": obj_type == "user" and lockout != 0,
            "group_type": _to_int(_first(attrs, "groupType", 0)),
            "attributes": attrs,
        }

    # -- forest / domain information ------------------------------------

    def get_root_dse(self):
        """Read the rootDSE (naming contexts, functional levels, ...).

        Prefers the server info ldap3 already fetched when the Server
        was created with get_info=ALL (``server.info.other``). A manual
        base-scope search on "" is unreliable: the empty base can be
        resolved to the domain DN, where the RootDSE-only attributes
        (defaultNamingContext, ...) are rejected as invalid attribute
        types (LDAP error 17). Falls back to the manual search when the
        server info is empty (e.g. in tests, where the mock has none).
        """
        self._require_connection()
        try:
            info = getattr(getattr(self.conn, "server", None), "info", None)
            other = getattr(info, "other", None) or {}
            naming_contexts = getattr(info, "naming_contexts", None) or []
        except Exception:  # noqa: BLE001 - fall back to the search
            other, naming_contexts = {}, []
        keys = ("defaultNamingContext", "configurationNamingContext",
                "rootDomainNamingContext", "forestFunctionality",
                "domainFunctionality", "dnsHostName", "serverName",
                "namingContexts")
        attrs = {}
        for key in keys:
            if key in other:
                attrs[key] = other[key]
        if "namingContexts" not in attrs and naming_contexts:
            attrs["namingContexts"] = list(naming_contexts)
        if attrs:
            return self._root_dse_values(attrs)
        entries = self._search("", "(objectClass=*)",
                               ["defaultNamingContext", "configurationNamingContext",
                                "rootDomainNamingContext", "forestFunctionality",
                                "domainFunctionality", "dnsHostName", "serverName",
                                "namingContexts"],
                               scope=BASE)
        if not entries:
            return {}
        attrs = entries[0]["attributes"]
        return self._root_dse_values(attrs)

    @staticmethod
    def _root_dse_values(attrs):
        """Collapse rootDSE attributes to single values — except
        ``namingContexts``, which stays a list.

        Every other rootDSE attribute is single-valued, so _first()
        is right for them. namingContexts is multi-valued by
        definition (every naming context the DC hosts); collapsing
        it to its first element hides the rest, even though the
        Directory Info tab explicitly joins a list of them.
        """
        result = {}
        for key, values in attrs.items():
            if key == "namingContexts":
                if isinstance(values, (list, tuple)):
                    result[key] = [_decode(v) for v in values]
                elif values is None:
                    result[key] = []
                else:
                    result[key] = [_decode(values)]
            else:
                result[key] = _first(attrs, key)
        return result

    def get_default_naming_context(self):
        """The domain DN, from the rootDSE or computed from the domain."""
        nc = self._root_dse.get("defaultNamingContext")
        if nc:
            return nc
        if self.domain:
            return domain_to_dn(self.domain)
        return ""

    def get_configuration_naming_context(self):
        nc = self._root_dse.get("configurationNamingContext")
        if nc:
            return nc
        return "CN=Configuration,{}".format(self.get_default_naming_context())

    # -- browsing / searching -------------------------------------------

    def list_children(self, dn):
        """Direct children of an OU / container / domain (one level)."""
        search_filter = ("(|(objectClass=organizationalUnit)"
                         "(objectClass=container)(objectClass=builtinDomain)"
                         "(objectClass=user)(objectClass=computer)"
                         "(objectClass=group))")
        entries = self._search(dn, search_filter, self.LIST_ATTRS, scope=LEVEL)
        # Real AD never returns the base object itself for a one-level
        # search; ldap3's mock strategy does, so filter it out here.
        base = dn.lower()
        return [self.entry_to_dict(e) for e in entries
                if e["dn"].lower() != base]

    def get_object(self, dn, attributes=None):
        """All (or the requested) attributes of one object."""
        entries = self._search(dn, "(objectClass=*)",
                               attributes or ["*"], scope=BASE)
        if not entries:
            raise ADError("Object not found: {}".format(dn))
        return self.entry_to_dict(entries[0])

    def get_object_attributes(self, dn):
        """All attributes of one object, for the Properties dialog.

        Returns ``{attr: {"values": [str, ...], "binary": bool}}``.
        Multi-valued attributes stay lists; binary values are shown
        as hex and flagged ``binary`` so the UI shows them read-only
        and never writes them back.
        """
        entries = self._search(dn, "(objectClass=*)", ["*"], scope=BASE)
        if not entries:
            raise ADError("Object not found: {}".format(dn))
        out = {}
        for attr, values in entries[0]["attributes"].items():
            if not isinstance(values, (list, tuple)):
                values = [values]
            display = []
            is_binary = attr.lower() in BINARY_ATTRIBUTES
            for value in values:
                text, was_binary = _display_value(value)
                display.append(text)
                is_binary = is_binary or was_binary
            out[attr] = {"values": display, "binary": is_binary}
        return out

    def modify_object(self, dn, changes):
        """Apply attribute changes: ``{attr: new_value_or_list_or_None}``.

        REPLACE for a new value/list, DELETE for None/empty (clear the
        attribute). Only the attributes in ``changes`` are touched, so
        the caller should pass only attributes that actually changed.
        """
        modify = {}
        for attr, value in changes.items():
            if value is None or value == "" or value == []:
                modify[attr] = [(MODIFY_DELETE, [])]
            else:
                values = value if isinstance(value, list) else [value]
                modify[attr] = [(MODIFY_REPLACE, values)]
        if modify:
            self._modify(dn, modify, "Update attributes on {}".format(dn))

    def search_users(self, base_dn, query):
        """Users whose name / sAMAccountName matches ``query``.

        Computer objects also carry objectClass=user in AD, so they
        are excluded with (!(objectClass=computer)). The query is
        escaped per RFC 4515 (hex escapes: \\28, \\29, \\2a, \\5c,
        \\00) — the backslash literals the old code used are not
        valid filter escapes and fail or misbehave against AD.
        """
        q = escape_filter_chars(query)
        search_filter = ("(&(objectClass=user)(!(objectClass=computer))"
                         "(|(name=*{0}*)(sAMAccountName=*{0}*)(displayName=*{0}*)))"
                         .format(q))
        entries = self._search(base_dn, search_filter, self.LIST_ATTRS)
        return [self.entry_to_dict(e) for e in entries]

    def search_computers(self, base_dn, query):
        q = escape_filter_chars(query)
        search_filter = ("(&(objectClass=computer)"
                         "(|(name=*{0}*)(sAMAccountName=*{0}*)))".format(q))
        entries = self._search(base_dn, search_filter, self.LIST_ATTRS)
        return [self.entry_to_dict(e) for e in entries]

    def search_groups(self, base_dn, query):
        q = escape_filter_chars(query)
        search_filter = ("(&(objectClass=group)"
                         "(|(name=*{0}*)(sAMAccountName=*{0}*)))".format(q))
        entries = self._search(base_dn, search_filter, self.LIST_ATTRS)
        return [self.entry_to_dict(e) for e in entries]

    def search_objects(self, base_dn, query):
        """Users, computers, groups, OUs and containers under
        ``base_dn`` (whole subtree) whose name / sAMAccountName /
        displayName matches ``query``.

        Used by the AD tab search: typing in the search box searches
        every OU below the selected node, not just the direct children
        shown in the list. Computer objects also carry
        objectClass=user in AD; they are classified by
        entry_to_dict (computer wins), so no exclusion is needed here.
        """
        q = escape_filter_chars(query)
        search_filter = (
            "(&(|(objectClass=organizationalUnit)(objectClass=container)"
            "(objectClass=builtinDomain)(objectClass=user)"
            "(objectClass=computer)(objectClass=group))"
            "(|(name=*{0}*)(sAMAccountName=*{0}*)(displayName=*{0}*)))"
            .format(q))
        entries = self._search(base_dn, search_filter, self.LIST_ATTRS)
        return [self.entry_to_dict(e) for e in entries]

    def resolve_members(self, member_dns):
        """Resolve member DNs to display info with a single search.

        Returns a list of entry_to_dict dicts in the same order as
        ``member_dns``. A DN that cannot be resolved (deleted object,
        foreign security principal, cross-domain member) is returned
        with its RDN as the name and an empty type, so the UI can
        still list it instead of dropping it silently.
        """
        dns = [dn for dn in (member_dns or []) if dn]
        if not dns:
            return []

        # DNs are filter values here, so they need RFC 4515 escaping
        # (hex escapes). The old hand-rolled escaper used backslash
        # literals, which break on a DN containing an escaped comma
        # such as CN=Doe\, John — the backslash itself must be
        # escaped as \5c, and ldap3's escape_filter_chars does that.
        parts = "".join("(distinguishedName={})".format(
            escape_filter_chars(dn)) for dn in dns)
        entries = self._search(self.get_default_naming_context(),
                               "(|{})".format(parts), self.LIST_ATTRS)
        by_dn = {}
        for entry in entries:
            info = self.entry_to_dict(entry)
            by_dn[info["dn"].lower()] = info
        out = []
        for dn in dns:
            info = by_dn.get(dn.lower())
            if info is None:
                label = _rdn_value(dn)
                info = {"dn": dn, "type": "", "name": label, "sam": "",
                        "description": "", "display_name": label, "uac": 0,
                        "status": "", "locked": False, "group_type": 0,
                        "attributes": {}}
            out.append(info)
        return out

    # -- creating objects -----------------------------------------------

    def create_user(self, ou_dn, sam_account_name, given_name="", sn="",
                    display_name="", password=None, upn=None,
                    user_account_control=UAC_NORMAL_ACCOUNT,
                    must_change=False):
        """Create a user, then set its password and enable it.

        AD will not let an account be enabled without a password, so
        the object is created disabled (514), the password is set, and
        then the requested userAccountControl value is applied. Without
        a password the account is left disabled. When ``must_change``
        is set, pwdLastSet is written to 0 here — in the same call —
        so the caller does not reset the password a second time just
        to force a change at next logon (that wrote unicodePwd twice).

        The CN is RDN-escaped: a display name containing a comma
        (e.g. "Doe, John") would otherwise break the DN.
        """
        cn = display_name or sam_account_name
        dn = "CN={},{}".format(escape_rdn(cn), ou_dn)
        attrs = {
            "sAMAccountName": sam_account_name,
            "userPrincipalName": upn or "{}@{}".format(sam_account_name, self.domain or ""),
            "givenName": given_name,
            "sn": sn,
            "displayName": display_name or cn,
            "userAccountControl": UAC_NORMAL_ACCOUNT | UAC_ACCOUNT_DISABLE,  # 514
        }
        self._add(dn, ["top", "person", "organizationalUser", "user"],
                  attrs, "Create user {}".format(sam_account_name))
        if password:
            try:
                self.set_password(dn, password)
                self.set_user_account_control(dn, user_account_control)
                if must_change:
                    self._modify(dn, {"pwdLastSet": [(MODIFY_REPLACE, [0])]},
                                 "Set 'must change password' for {}".format(dn))
            except Exception as exc:
                # The add already succeeded, so a failed post-add step
                # (e.g. a password rejected by complexity policy)
                # would leave a disabled orphan behind — and a retry
                # would then fail with "object already exists". Roll
                # back by deleting the new object, then re-raise the
                # original error. If the delete itself fails, say so
                # in the error, so the admin knows an orphan may exist.
                try:
                    self.delete_object(dn)
                except ADError as cleanup_exc:
                    raise ADError(
                        "{}; rollback also failed ({}), so a disabled "
                        "user object may remain in AD".format(
                            exc, cleanup_exc)) from exc
                raise
        return dn

    def create_computer(self, ou_dn, name, description=""):
        """Create a computer account (workstation trust, UAC 4096).

        The CN is RDN-escaped, so a name containing a comma does not
        break the DN.
        """
        dn = "CN={},{}".format(escape_rdn(name), ou_dn)
        attrs = {
            "sAMAccountName": name.upper() + "$",
            "userAccountControl": UAC_WORKSTATION_TRUST,
        }
        if description:
            attrs["description"] = description
        self._add(dn, ["top", "person", "organizationalUser", "user", "computer"],
                  attrs, "Create computer {}".format(name))
        return dn

    def create_group(self, ou_dn, name, sam_account_name, group_type=-2147483646,
                     description=""):
        """Create a group. ``group_type`` may be an int or a friendly name.

        The CN is RDN-escaped, so a name containing a comma does not
        break the DN.
        """
        if isinstance(group_type, str):
            group_type = GROUP_TYPES.get(group_type, -2147483646)
        dn = "CN={},{}".format(escape_rdn(name), ou_dn)
        attrs = {
            "sAMAccountName": sam_account_name,
            "groupType": group_type,
        }
        if description:
            attrs["description"] = description
        self._add(dn, ["top", "group"], attrs,
                  "Create group {}".format(sam_account_name))
        return dn

    # -- account state ----------------------------------------------------

    def set_user_account_control(self, dn, uac):
        self._modify(dn, {"userAccountControl": [(MODIFY_REPLACE, [uac])]},
                     "Set userAccountControl on {}".format(dn))

    def enable_object(self, dn):
        """Clear the ACCOUNTDISABLE bit, preserving the other flags."""
        current = self.get_object(dn)["uac"]
        self.set_user_account_control(dn, current & ~UAC_ACCOUNT_DISABLE)

    def disable_object(self, dn):
        """Set the ACCOUNTDISABLE bit, preserving the other flags."""
        current = self.get_object(dn)["uac"]
        self.set_user_account_control(dn, current | UAC_ACCOUNT_DISABLE)

    def unlock_user(self, dn):
        """Clear a lockout (lockoutTime = 0)."""
        self._modify(dn, {"lockoutTime": [(MODIFY_REPLACE, [0])]},
                     "Unlock {}".format(dn))

    def set_password(self, dn, new_password):
        """Reset a password (unicodePwd, quoted UTF-16LE, over LDAPS)."""
        self._modify(dn, {"unicodePwd": [(MODIFY_REPLACE, [encode_password(new_password)])]},
                     "Reset password for {}".format(dn))

    def reset_password(self, dn, new_password, must_change=False):
        """Reset a password, optionally forcing a change at next logon."""
        self.set_password(dn, new_password)
        if must_change:
            self._modify(dn, {"pwdLastSet": [(MODIFY_REPLACE, [0])]},
                         "Set 'must change password' for {}".format(dn))

    # -- attributes / membership / delete ---------------------------------

    def add_group_member(self, group_dn, member_dn):
        self._modify(group_dn, {"member": [(MODIFY_ADD, [member_dn])]},
                     "Add member to {}".format(group_dn))

    def remove_group_member(self, group_dn, member_dn):
        self._modify(group_dn, {"member": [(MODIFY_DELETE, [member_dn])]},
                     "Remove member from {}".format(group_dn))

    def delete_object(self, dn):
        self._require_connection()
        try:
            ok = self.conn.delete(dn)
        except LDAPException as exc:
            _raise_ldap_error(exc, "Delete {}".format(dn))
        if not ok:
            raise ADError("Delete {} failed: {}".format(
                dn, self.conn.result.get("description", "unknown error")))

    def move_object(self, dn, new_parent_dn):
        """Move a leaf object to another OU/container (same RDN, no rename).

        Uses ModifyDN with the object's current RDN and the new
        superior, so the name is unchanged — only the parent changes.
        Moving to the object's current parent is rejected up front:
        real AD would treat it as a successful no-op, and the ldap3
        mock loses the entry on a same-parent ModifyDN, so never
        issue one. Returns the object's new DN.
        """
        self._require_connection()
        new_parent_dn = (new_parent_dn or "").strip()
        if parent_dn(dn).lower() == new_parent_dn.lower():
            raise ADError("{} is already in {}.".format(dn, new_parent_dn))
        rdn = _first_rdn(dn)
        try:
            ok = self.conn.modify_dn(dn, rdn, new_superior=new_parent_dn)
        except LDAPException as exc:
            _raise_ldap_error(exc, "Move {}".format(dn))
        if not ok:
            raise ADError("Move {} failed: {}".format(
                dn, self.conn.result.get("description", "unknown error")))
        return "{},{}".format(rdn, new_parent_dn)

    # -- sites, subnets, trusts (read-only directory info) ----------------

    def list_sites(self):
        """AD sites (from the Configuration partition)."""
        base = "CN=Sites,{}".format(self.get_configuration_naming_context())
        entries = self._search(base, "(objectClass=site)",
                               ["cn", "description"], scope=LEVEL)
        return [{"dn": e["dn"],
                 "name": _first(e["attributes"], "cn", ""),
                 "description": _first(e["attributes"], "description", "")}
                for e in entries]

    def list_subnets(self):
        """AD subnets and the site each belongs to."""
        base = "CN=Subnets,CN=Sites,{}".format(self.get_configuration_naming_context())
        entries = self._search(base, "(objectClass=subnet)",
                               ["cn", "siteObject", "description", "location"],
                               scope=LEVEL)
        return [{"dn": e["dn"],
                 "name": _first(e["attributes"], "cn", ""),
                 "site": _first(e["attributes"], "siteObject", ""),
                 "description": _first(e["attributes"], "description", ""),
                 "location": _first(e["attributes"], "location", "")}
                for e in entries]

    def list_trusted_domains(self):
        """Domain trusts (from CN=System in the domain partition)."""
        base = "CN=System,{}".format(self.get_default_naming_context())
        entries = self._search(base, "(objectClass=trustedDomain)",
                               ["cn", "trustDirection", "trustType",
                                "trustAttributes", "flatName"], scope=LEVEL)
        directions = {1: "Inbound", 2: "Outbound", 3: "Bidirectional"}
        out = []
        for e in entries:
            attrs = e["attributes"]
            direction = _to_int(_first(attrs, "trustDirection", 0))
            out.append({
                "dn": e["dn"],
                "name": _first(attrs, "cn", ""),
                "flat_name": _first(attrs, "flatName", ""),
                "direction": directions.get(direction, str(direction)),
                "trust_type": _to_int(_first(attrs, "trustType", 0)),
                "trust_attributes": _to_int(_first(attrs, "trustAttributes", 0)),
            })
        return out
