"""Tests for the AD LDAP client, using ldap3's MOCK_SYNC strategy.

Note: ldap3's mock cannot represent the rootDSE (an empty DN is
rejected), so get_root_dse() is tested by monkeypatching the client's
internal _search instead. Everything else runs against the mock.
"""

import pytest
from ldap3 import ALL, Connection, MOCK_SYNC, Server

from msat.ldap_client import (
    ADClient, ADConnectionError, encode_password,
)

DOMAIN_DN = "DC=example,DC=local"
CONFIG_DN = "CN=Configuration,DC=example,DC=local"


def _stored_values(entry, attr):
    """Attribute values from a raw mock entry, decoded to str.

    ldap3's mock strategy stores values written via add/modify as
    bytes; values from the original add_entry calls stay as str.
    """
    values = entry.get(attr) or []
    return [v.decode("utf-8", "replace") if isinstance(v, bytes) else v
            for v in values]


def _build_mock_conn():
    server = Server("mock-dc", get_info=ALL)
    conn = Connection(server, user="cn=admin,dc=example,dc=local",
                      password="Secret123", client_strategy=MOCK_SYNC)
    add = conn.strategy.add_entry
    add("cn=admin,dc=example,dc=local",
        {"objectClass": ["person", "user"], "userPassword": "Secret123"})
    add(DOMAIN_DN, {"objectClass": ["domain", "top"], "dc": "example"})
    add("OU=IT," + DOMAIN_DN,
        {"objectClass": ["organizationalUnit", "top"], "ou": "IT"})
    add("OU=Users," + DOMAIN_DN,
        {"objectClass": ["organizationalUnit", "top"], "ou": "Users"})
    add("CN=System," + DOMAIN_DN,
        {"objectClass": ["container", "top"], "cn": "System"})
    add("CN=jdoe,OU=Users," + DOMAIN_DN,
        {"objectClass": ["top", "person", "organizationalUser", "user"],
         "sAMAccountName": "jdoe", "userAccountControl": "512",
         "lockoutTime": "0", "givenName": "John", "sn": "Doe",
         "displayName": "John Doe", "description": "Test user",
         "name": "John Doe", "mail": "jdoe@example.local",
         "proxyAddresses": ["SMTP:jdoe@example.local",
                            "smtp:jdoe@mail.example.local"],
         "objectGUID": [bytes(range(16))]})
    add("CN=locked,OU=Users," + DOMAIN_DN,
        {"objectClass": ["top", "person", "organizationalUser", "user"],
         "sAMAccountName": "locked", "userAccountControl": "512",
         "lockoutTime": "133000000000000000", "name": "Locked User"})
    add("CN=disabled,OU=Users," + DOMAIN_DN,
        {"objectClass": ["top", "person", "organizationalUser", "user"],
         "sAMAccountName": "disabled", "userAccountControl": "514",
         "lockoutTime": "0", "name": "Disabled User"})
    add("CN=WS01,OU=IT," + DOMAIN_DN,
        {"objectClass": ["top", "person", "organizationalUser", "user", "computer"],
         "sAMAccountName": "WS01$", "userAccountControl": "4096",
         "name": "WS01"})
    add("CN=Admins,OU=IT," + DOMAIN_DN,
        {"objectClass": ["top", "group"], "sAMAccountName": "Admins",
         "groupType": "-2147483646", "name": "Admins"})
    # Sites / subnets (Configuration partition).
    add("CN=Sites," + CONFIG_DN,
        {"objectClass": ["container", "top"], "cn": "Sites"})
    add("CN=Site1,CN=Sites," + CONFIG_DN,
        {"objectClass": ["site", "top"], "cn": "Site1",
         "description": "Main site"})
    add("CN=Subnets,CN=Sites," + CONFIG_DN,
        {"objectClass": ["container", "top"], "cn": "Subnets"})
    add("CN=192.168.1.0/24,CN=Subnets,CN=Sites," + CONFIG_DN,
        {"objectClass": ["subnet", "top"], "cn": "192.168.1.0/24",
         "siteObject": "CN=Site1,CN=Sites," + CONFIG_DN,
         "description": "Office LAN"})
    # Trusted domain.
    add("CN=TRUSTED,CN=System," + DOMAIN_DN,
        {"objectClass": ["trustedDomain", "top"], "cn": "TRUSTED",
         "flatName": "TRUSTED", "trustDirection": "3", "trustType": "2",
         "trustAttributes": "0"})
    return conn


@pytest.fixture
def client():
    conn = _build_mock_conn()
    ad = ADClient(connection=conn, domain="example.local")
    ad.connect()
    return ad


# -- helpers ---------------------------------------------------------------

def test_encode_password_is_quoted_utf16le():
    assert encode_password("Passw0rd!") == '"Passw0rd!"'.encode("utf-16-le")


def test_qualify_username():
    assert ADClient.qualify_username("michael", "example.local") == "michael@example.local"
    assert ADClient.qualify_username("michael@example.local", "example.local") == "michael@example.local"
    assert ADClient.qualify_username("EXAMPLE\\michael", "example.local") == "EXAMPLE\\michael"
    # A full DN is passed through unchanged.
    assert ADClient.qualify_username("cn=admin,dc=example,dc=local", "example.local") == \
        "cn=admin,dc=example,dc=local"


# -- connection / rootDSE ----------------------------------------------------

def test_connect_and_default_naming_context(client):
    # rootDSE is unavailable in the mock, so the domain DN is computed.
    assert client.connected
    assert client.get_default_naming_context() == DOMAIN_DN


def test_validate_connection_succeeds_on_searchable_connection(client):
    assert client.validate_connection() is True


def test_validate_connection_maps_invalid_credentials(client, monkeypatch):
    from msat.ldap_client import ADError, ADInvalidCredentialsError

    def failing_search(*a, **k):
        raise ADError("LDAP search failed: invalidCredentials")

    monkeypatch.setattr(client, "_search", failing_search)
    with pytest.raises(ADInvalidCredentialsError):
        client.validate_connection()


def test_validate_connection_other_errors_propagate(client, monkeypatch):
    from msat.ldap_client import ADError, ADInvalidCredentialsError

    def failing_search(*a, **k):
        raise ADError("LDAP search failed: operationsError")

    monkeypatch.setattr(client, "_search", failing_search)
    with pytest.raises(ADError) as excinfo:
        client.validate_connection()
    assert not isinstance(excinfo.value, ADInvalidCredentialsError)


def test_connect_wrong_password_raises_invalid_credentials():
    """bind() returns False (no exception) on a bad password; connect()
    must notice and raise ADInvalidCredentialsError, not 'connect'."""
    from msat.ldap_client import ADInvalidCredentialsError

    server = Server("mock-dc", get_info=ALL)
    conn = Connection(server, user="cn=admin,dc=example,dc=local",
                      password="WrongPassword", client_strategy=MOCK_SYNC)
    conn.strategy.add_entry(
        "cn=admin,dc=example,dc=local",
        {"objectClass": ["person", "user"], "userPassword": "Secret123"})
    ad = ADClient(server="mock-dc", domain="example.local",
                  username="admin", password="WrongPassword", connection=conn)
    with pytest.raises(ADInvalidCredentialsError):
        ad.connect()
    assert not ad.connected


def test_get_root_dse_parses_entries(client, monkeypatch):
    canned = [{"dn": "", "attributes": {
        "defaultNamingContext": [DOMAIN_DN],
        "configurationNamingContext": [CONFIG_DN],
        "rootDomainNamingContext": [DOMAIN_DN],
        "forestFunctionality": ["7"],
        "domainFunctionality": ["7"],
        "dnsHostName": ["dc1.example.local"],
        "namingContexts": [DOMAIN_DN, CONFIG_DN],
    }}]
    monkeypatch.setattr(client, "_search", lambda *a, **k: canned)
    root_dse = client.get_root_dse()
    assert root_dse["defaultNamingContext"] == DOMAIN_DN
    assert root_dse["forestFunctionality"] == "7"
    assert root_dse["dnsHostName"] == "dc1.example.local"


def test_get_object_missing_raises(client):
    with pytest.raises(Exception):
        client.get_object("CN=nope," + DOMAIN_DN)


# -- browsing / searching ----------------------------------------------------

def test_list_children_of_domain(client):
    children = client.list_children(DOMAIN_DN)
    names = {c["name"] for c in children}
    assert {"IT", "Users", "System"} <= names
    types = {c["name"]: c["type"] for c in children}
    assert types["IT"] == "ou"
    assert types["System"] == "container"


def test_list_children_of_ou(client):
    children = client.list_children("OU=Users," + DOMAIN_DN)
    by_name = {c["name"]: c for c in children}
    assert by_name["John Doe"]["type"] == "user"
    assert by_name["John Doe"]["status"] == "Enabled"
    assert by_name["Locked User"]["status"] == "Enabled, Locked"
    assert by_name["Disabled User"]["status"] == "Disabled"


def test_computer_is_not_listed_as_user(client):
    children = client.list_children("OU=IT," + DOMAIN_DN)
    by_name = {c["name"]: c for c in children}
    assert by_name["WS01"]["type"] == "computer"
    assert by_name["Admins"]["type"] == "group"


def test_search_users_excludes_computers(client):
    results = client.search_users(DOMAIN_DN, "doe")
    assert [r["sam"] for r in results] == ["jdoe"]
    results = client.search_users(DOMAIN_DN, "WS01")
    assert results == []


def test_search_groups(client):
    results = client.search_groups(DOMAIN_DN, "Adm")
    assert [r["sam"] for r in results] == ["Admins"]


def test_search_computers(client):
    results = client.search_computers(DOMAIN_DN, "WS0")
    assert [r["sam"] for r in results] == ["WS01$"]


# -- account state -------------------------------------------------------------

def test_disable_then_enable_user(client):
    dn = "CN=jdoe,OU=Users," + DOMAIN_DN
    client.disable_object(dn)
    assert client.get_object(dn)["uac"] == 514
    assert client.get_object(dn)["status"] == "Disabled"
    client.enable_object(dn)
    assert client.get_object(dn)["uac"] == 512
    assert client.get_object(dn)["status"] == "Enabled"


def test_disable_preserves_other_uac_bits(client):
    # 66048 = normal + password-never-expires; disabling must keep 65536.
    client.set_user_account_control("CN=jdoe,OU=Users," + DOMAIN_DN, 66048)
    client.disable_object("CN=jdoe,OU=Users," + DOMAIN_DN)
    assert client.get_object("CN=jdoe,OU=Users," + DOMAIN_DN)["uac"] == 66050


def test_unlock_user(client):
    dn = "CN=locked,OU=Users," + DOMAIN_DN
    client.unlock_user(dn)
    assert client.get_object(dn)["status"] == "Enabled"


def test_reset_password_sets_unicode_pwd_and_pwd_last_set(client):
    dn = "CN=jdoe,OU=Users," + DOMAIN_DN
    client.reset_password(dn, "NewPass123!", must_change=True)
    entry = client.conn.strategy.entries[dn]
    assert entry["unicodePwd"] == [encode_password("NewPass123!")]
    assert _stored_values(entry, "pwdLastSet") == ["0"]


# -- create / membership / delete ------------------------------------------------

def test_create_user_is_enabled_with_password(client):
    dn = client.create_user("OU=Users," + DOMAIN_DN, "jsmith",
                            given_name="Jane", sn="Smith",
                            display_name="Jane Smith", password="Temp1234!")
    created = client.get_object(dn)
    assert created["sam"] == "jsmith"
    assert created["uac"] == 512
    entry = client.conn.strategy.entries[dn]
    assert entry["unicodePwd"] == [encode_password("Temp1234!")]
    assert _stored_values(entry, "userPrincipalName") == ["jsmith@example.local"]


def test_create_user_without_password_stays_disabled(client):
    dn = client.create_user("OU=Users," + DOMAIN_DN, "nopass")
    assert client.get_object(dn)["uac"] == 514


def test_create_computer(client):
    dn = client.create_computer("OU=IT," + DOMAIN_DN, "WS02",
                                description="Front desk")
    created = client.get_object(dn)
    assert created["type"] == "computer"
    assert created["uac"] == 4096
    assert created["sam"] == "WS02$"


def test_create_group(client):
    dn = client.create_group("OU=IT," + DOMAIN_DN, "HelpDesk",
                             "HelpDesk", "Global security")
    entry = client.conn.strategy.entries[dn]
    assert _stored_values(entry, "groupType") == ["-2147483646"]


def test_group_membership_add_remove(client):
    group_dn = "CN=Admins,OU=IT," + DOMAIN_DN
    user_dn = "CN=jdoe,OU=Users," + DOMAIN_DN
    client.add_group_member(group_dn, user_dn)
    assert user_dn in _stored_values(
        client.conn.strategy.entries[group_dn], "member")
    client.remove_group_member(group_dn, user_dn)
    assert user_dn not in _stored_values(
        client.conn.strategy.entries[group_dn], "member")


def test_delete_object(client):
    dn = client.create_user("OU=Users," + DOMAIN_DN, "todelete", password="Temp1234!")
    client.delete_object(dn)
    assert dn not in client.conn.strategy.entries


def test_set_attributes(client):
    dn = "CN=jdoe,OU=Users," + DOMAIN_DN
    client.set_attributes(dn, {"description": "Updated", "title": "Analyst"})
    entry = client.conn.strategy.entries[dn]
    assert _stored_values(entry, "description") == ["Updated"]
    assert _stored_values(entry, "title") == ["Analyst"]


def test_display_value_hex_for_binary():
    from msat.ldap_client import _display_value
    assert _display_value(bytes(range(16))) == (
        "000102030405060708090a0b0c0d0e0f", True)
    assert _display_value(b"abc") == ("abc", False)
    assert _display_value("plain") == ("plain", False)


def test_display_value_datetime_is_not_iterable():
    """ldap3 returns datetime objects for datetime-valued attributes.

    Regression test (v1.4): _display_value set text = value for a
    non-bytes value and then iterated it, raising TypeError:
    'datetime.datetime' object is not iterable, which crashed the
    Properties dialog on any user with whenCreated/whenChanged.
    """
    import datetime

    from msat.ldap_client import _display_value
    text, is_binary = _display_value(
        datetime.datetime(2024, 1, 15, 10, 30, 0))
    assert isinstance(text, str)
    assert "2024-01-15" in text
    assert is_binary is False


def test_get_object_attributes_with_datetime(client, monkeypatch):
    """get_object_attributes handles a datetime-valued attribute."""
    import datetime

    dn = "CN=jdoe,OU=Users," + DOMAIN_DN
    when = datetime.datetime(2024, 1, 15, 10, 30, 0)
    monkeypatch.setattr(client, "_search", lambda *a, **k: [{
        "dn": dn,
        "attributes": {"displayName": ["John Doe"],
                       "whenCreated": [when],
                       "whenChanged": [when]}}])
    attrs = client.get_object_attributes(dn)
    assert attrs["whenCreated"]["values"] == [str(when)]
    assert attrs["whenCreated"]["binary"] is False
    assert attrs["whenChanged"]["values"] == [str(when)]
    # Datetime values are plain display strings: every value is a str.
    for info in attrs.values():
        assert all(isinstance(v, str) for v in info["values"])


def test_get_object_attributes(client):
    attrs = client.get_object_attributes("CN=jdoe,OU=Users," + DOMAIN_DN)
    assert attrs["displayName"]["values"] == ["John Doe"]
    assert attrs["displayName"]["binary"] is False
    assert attrs["mail"]["values"] == ["jdoe@example.local"]
    assert attrs["proxyAddresses"]["values"] == [
        "SMTP:jdoe@example.local", "smtp:jdoe@mail.example.local"]
    # objectGUID is binary: shown as hex, flagged read-only.
    assert attrs["objectGUID"]["binary"] is True
    assert attrs["objectGUID"]["values"] == [
        "000102030405060708090a0b0c0d0e0f"]


def test_modify_object_replace_delete_create(client):
    dn = "CN=jdoe,OU=Users," + DOMAIN_DN
    client.modify_object(dn, {"title": ["Senior Analyst"],
                              "description": None,
                              "telephoneNumber": ["555-1234"]})
    attrs = client.get_object_attributes(dn)
    assert attrs["title"]["values"] == ["Senior Analyst"]
    assert "description" not in attrs  # DELETE removed it entirely
    assert attrs["telephoneNumber"]["values"] == ["555-1234"]
    # An empty change dict sends nothing and raises nothing.
    client.modify_object(dn, {})


# -- sites / subnets / trusts -----------------------------------------------------

def test_list_sites_and_subnets(client, monkeypatch):
    # The Configuration partition reads use the cached rootDSE; point
    # the client at the mock's configuration DN directly.
    monkeypatch.setattr(client, "_root_dse",
                        {"configurationNamingContext": CONFIG_DN})
    sites = client.list_sites()
    assert [s["name"] for s in sites] == ["Site1"]
    subnets = client.list_subnets()
    assert [s["name"] for s in subnets] == ["192.168.1.0/24"]
    assert subnets[0]["site"] == "CN=Site1,CN=Sites," + CONFIG_DN


def test_list_trusted_domains(client):
    trusts = client.list_trusted_domains()
    assert len(trusts) == 1
    assert trusts[0]["name"] == "TRUSTED"
    assert trusts[0]["direction"] == "Bidirectional"
    assert trusts[0]["trust_type"] == 2


def test_resolve_members(client, monkeypatch):
    """resolve_members maps DNs to display info in order, one search.

    Unresolvable DNs fall back to their RDN so the UI can still list
    them instead of dropping them silently.
    """
    jdoe_dn = "CN=jdoe,OU=Users," + DOMAIN_DN
    admins_dn = "CN=Admins,OU=IT," + DOMAIN_DN
    ghost_dn = "CN=Ghost,OU=Users," + DOMAIN_DN
    calls = []

    def fake_search(base_dn, search_filter, attributes, scope=None):
        calls.append((base_dn, search_filter))
        return [
            {"dn": jdoe_dn, "attributes": {
                "objectClass": ["top", "person", "organizationalUser", "user"],
                "name": ["John Doe"], "sAMAccountName": ["jdoe"],
                "displayName": ["John Doe"], "userAccountControl": ["512"],
                "lockoutTime": ["0"]}},
            {"dn": admins_dn, "attributes": {
                "objectClass": ["top", "group"],
                "name": ["Admins"], "sAMAccountName": ["Admins"],
                "groupType": ["-2147483646"]}},
        ]

    monkeypatch.setattr(client, "_search", fake_search)
    resolved = client.resolve_members([jdoe_dn, admins_dn, ghost_dn])
    assert len(resolved) == 3  # order preserved, nothing dropped
    assert resolved[0]["name"] == "John Doe"
    assert resolved[0]["sam"] == "jdoe"
    assert resolved[0]["type"] == "user"
    assert resolved[1]["name"] == "Admins"
    assert resolved[1]["type"] == "group"
    # Ghost cannot be resolved: RDN fallback, empty type.
    assert resolved[2]["name"] == "Ghost"
    assert resolved[2]["type"] == ""
    assert resolved[2]["dn"] == ghost_dn
    # A single search over the domain, naming each DN once.
    assert len(calls) == 1
    base, search_filter = calls[0]
    assert base == DOMAIN_DN
    assert "distinguishedName=" + jdoe_dn in search_filter
    assert "distinguishedName=" + admins_dn in search_filter
    assert "distinguishedName=" + ghost_dn in search_filter
    assert client.resolve_members([]) == []
