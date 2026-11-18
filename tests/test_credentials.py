"""Tests for the in-memory credential store.

The store must never touch the disk: these tests assert the values are
held and wiped, and that repr() never leaks the password.
"""

import os
import tempfile

from msat.credentials import CredentialStore


def test_set_and_is_set():
    store = CredentialStore()
    assert not store.is_set
    store.set("dc1", "example.local", "michael", "Secret123", 636)
    assert store.is_set
    assert store.server == "dc1"
    assert store.domain == "example.local"
    assert store.username == "michael"
    assert store.password == "Secret123"
    assert store.port == 636


def test_clear_wipes_everything():
    store = CredentialStore()
    store.set("dc1", "example.local", "michael", "Secret123", 636)
    store.clear()
    assert not store.is_set
    assert store.server is None
    assert store.domain is None
    assert store.username is None
    assert store.password is None
    assert store.port is None


def test_repr_never_contains_password():
    store = CredentialStore()
    store.set("dc1", "example.local", "michael", "Secret123", 636)
    assert "Secret123" not in repr(store)
    assert "michael" not in repr(store)


def test_no_disk_writes():
    """The store has no file I/O: a temp dir stays empty after use."""
    with tempfile.TemporaryDirectory() as tmp:
        store = CredentialStore()
        store.set("dc1", "example.local", "michael", "Secret123", 636)
        store.clear()
        assert os.listdir(tmp) == []
