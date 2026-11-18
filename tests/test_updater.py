"""Tests for the GitHub Releases update check (msat.updater), the
update dialog, and the Help-menu / startup wiring in the main window.

All network access is mocked — no real HTTP calls. GUI tests run
under xvfb (Linux) like the rest of the GUI suite.
"""

import json
import socket
import tkinter as tk
import urllib.error

import pytest

from msat import updater
from msat.app import MSATApp
from msat.constants import APP_VERSION
from msat.dialogs import UpdateDialog
from msat.settings import default_settings


# -- version parsing / comparison ------------------------------------------

@pytest.mark.parametrize("tag,expected", [
    ("v1.8.3", (1, 8, 3)),
    ("1.8.3", (1, 8, 3)),
    ("v1.8", (1, 8)),
    ("V2.0.0", (2, 0, 0)),
    ("v10.20.30", (10, 20, 30)),
    ("", (0,)),
    ("v", (0,)),
    ("abc", (0,)),
    ("1.x", (0,)),
    ("1.8.3-beta", (0,)),
    (None, (0,)),
])
def test_parse_version(tag, expected):
    assert updater.parse_version(tag) == expected


@pytest.mark.parametrize("latest,current,expected", [
    ("v1.8.3", "1.8.2", True),    # newer
    ("v1.8.2", "1.8.2", False),   # equal
    ("v1.8.1", "1.8.2", False),   # older
    ("1.8.3", "1.8.2", True),     # no "v" prefix on the tag
    ("v1.9", "1.8.2", True),      # shorter tag, still newer
    ("v1.8", "1.8.2", False),     # shorter tag, older
    ("garbage", "1.8.2", False),  # malformed latest never offers
    ("v1.8.3", "garbage", True),  # malformed current loses to a real tag
])
def test_is_newer(latest, current, expected):
    assert updater.is_newer(latest, current) is expected


# -- get_latest_release (urllib mocked) ------------------------------------

class _FakeResponse:
    """Minimal urlopen response: status + read(), usable as a context
    manager."""

    def __init__(self, status=200, body=b""):
        self.status = status
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _release_payload(**overrides):
    payload = {
        "tag_name": "v1.8.3",
        "name": "MSAT v1.8.3",
        "body": "## v1.8.3\n\n- Update check.",
        "html_url": "https://github.com/michaelhrunyon/msat/releases/tag/v1.8.3",
        "assets": [
            {"name": "msat-v1.8.3.zip",
             "browser_download_url": "https://github.com/michaelhrunyon/msat/"
                                     "releases/download/v1.8.3/msat-v1.8.3.zip"},
            {"name": "notes.txt",
             "browser_download_url": "https://example.invalid/notes.txt"},
        ],
    }
    payload.update(overrides)
    return payload


def _fake_urlopen_with(payload, status=200):
    def fake_urlopen(request, timeout=None):
        assert timeout == 5
        return _FakeResponse(status, json.dumps(payload).encode("utf-8"))
    return fake_urlopen


def test_get_latest_release_success(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen",
                        _fake_urlopen_with(_release_payload()))
    release = updater.get_latest_release()
    assert release["tag"] == "v1.8.3"
    assert release["name"] == "MSAT v1.8.3"
    assert "Update check" in release["body"]
    assert release["html_url"].endswith("/releases/tag/v1.8.3")
    # The zip asset wins over the non-zip asset.
    assert release["zip_url"].endswith("msat-v1.8.3.zip")


def test_get_latest_release_no_zip_asset(monkeypatch):
    payload = _release_payload(assets=[])
    monkeypatch.setattr("urllib.request.urlopen",
                        _fake_urlopen_with(payload))
    release = updater.get_latest_release()
    assert release is not None
    assert release["zip_url"] is None


def test_get_latest_release_http_error(monkeypatch):
    def fake_urlopen(request, timeout=None):
        raise urllib.error.HTTPError("https://api.github.com/x", 404,
                                     "Not Found", {}, None)
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    assert updater.get_latest_release() is None


def test_get_latest_release_url_error(monkeypatch):
    def fake_urlopen(request, timeout=None):
        raise urllib.error.URLError("no route to host")
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    assert updater.get_latest_release() is None


def test_get_latest_release_timeout(monkeypatch):
    def fake_urlopen(request, timeout=None):
        raise socket.timeout("timed out")
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    assert updater.get_latest_release() is None


def test_get_latest_release_malformed_json(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda request, timeout=None: _FakeResponse(200, b"{not json"))
    assert updater.get_latest_release() is None


def test_get_latest_release_non_dict_json(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda request, timeout=None: _FakeResponse(200, b"[1, 2, 3]"))
    assert updater.get_latest_release() is None


def test_get_latest_release_non_200(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda request, timeout=None: _FakeResponse(500, b"{}"))
    assert updater.get_latest_release() is None


def test_get_latest_release_missing_tag(monkeypatch):
    payload = _release_payload()
    del payload["tag_name"]
    monkeypatch.setattr("urllib.request.urlopen",
                        _fake_urlopen_with(payload))
    assert updater.get_latest_release() is None


# -- download_release_zip (urllib mocked) ----------------------------------

def test_download_release_zip_writes_file(monkeypatch, tmp_path):
    data = b"PK\x03\x04fake zip bytes"
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda request, timeout=None: _FakeResponse(200, data))
    dest = tmp_path / "msat-v1.8.3.zip"
    result = updater.download_release_zip(
        "https://example.invalid/msat-v1.8.3.zip", str(dest))
    assert result == str(dest)
    assert dest.read_bytes() == data


def test_download_release_zip_default_path(monkeypatch, tmp_path):
    data = b"PK\x03\x04fake zip bytes"
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda request, timeout=None: _FakeResponse(200, data))
    monkeypatch.setattr("os.path.expanduser", lambda path: str(tmp_path))
    result = updater.download_release_zip(
        "https://github.com/michaelhrunyon/msat/releases/download/"
        "v1.8.3/msat-v1.8.3.zip")
    assert result == str(tmp_path / "msat-v1.8.3.zip")
    assert (tmp_path / "msat-v1.8.3.zip").read_bytes() == data


def test_download_release_zip_failure_returns_none(monkeypatch, tmp_path):
    def fake_urlopen(request, timeout=None):
        raise urllib.error.URLError("boom")
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    dest = tmp_path / "msat-v1.8.3.zip"
    assert updater.download_release_zip("https://example.invalid/x.zip",
                                        str(dest)) is None
    assert not dest.exists()


def test_download_release_zip_no_url():
    assert updater.download_release_zip(None) is None
    assert updater.download_release_zip("") is None


# -- GUI: menu, manual/automatic check, dialog -----------------------------

@pytest.fixture
def root():
    try:
        r = tk.Tk()
    except tk.TclError as exc:
        pytest.skip("No display available: {}".format(exc))
    yield r
    try:
        r.destroy()
    except tk.TclError:
        pass


@pytest.fixture(autouse=True)
def generic_settings(monkeypatch):
    """Pin the connection-bar defaults to the generic placeholders,
    so a real ~/.msat/settings.json cannot change the test app."""
    monkeypatch.setattr("msat.app.load_settings",
                        lambda path=None: default_settings())


def _fake_release(tag="v9.9.9", zip_url="https://example.invalid/msat.zip"):
    return {"tag": tag, "name": "MSAT " + tag, "body": "## notes\n\n- Fix.",
            "html_url": "https://example.invalid/releases/" + tag,
            "zip_url": zip_url}


def test_help_menu_has_check_for_updates(root):
    app = MSATApp(root)
    assert app._menubar.entrycget(0, "label") == "Help"
    assert app._help_menu.entrycget(0, "label") == "Check for Updates…"


def test_manual_check_up_to_date_reports_latest(root, monkeypatch):
    app = MSATApp(root)
    monkeypatch.setattr("msat.app.updater.get_latest_release",
                        lambda: _fake_release(tag="v" + APP_VERSION))
    seen = []
    monkeypatch.setattr("msat.app.messagebox.showinfo",
                        lambda *args, **kwargs: seen.append(args))
    app._manual_update_check()
    assert len(seen) == 1
    assert "latest version" in seen[0][1]


def test_manual_check_unreachable_reports_failure(root, monkeypatch):
    app = MSATApp(root)
    monkeypatch.setattr("msat.app.updater.get_latest_release",
                        lambda: None)
    seen = []
    monkeypatch.setattr("msat.app.messagebox.showinfo",
                        lambda *args, **kwargs: seen.append(args))
    app._manual_update_check()
    assert len(seen) == 1
    assert "Could not reach GitHub" in seen[0][1]


def test_manual_check_newer_opens_update_dialog(root, monkeypatch):
    app = MSATApp(root)
    release = _fake_release()
    monkeypatch.setattr("msat.app.updater.get_latest_release",
                        lambda: release)
    opened = []

    def fake_dialog(parent, rel, current):
        # wait_window() needs a real widget: schedule its destruction
        # on idle so the nested wait returns instead of blocking.
        opened.append((rel, current))
        win = tk.Toplevel(parent)
        win.after_idle(win.destroy)
        return win

    monkeypatch.setattr("msat.app.dialogs.UpdateDialog", fake_dialog)
    app._manual_update_check()
    assert opened == [(release, APP_VERSION)]


def test_automatic_check_is_silent_when_up_to_date(root, monkeypatch):
    app = MSATApp(root)
    monkeypatch.setattr("msat.app.updater.get_latest_release",
                        lambda: _fake_release(tag="v" + APP_VERSION))
    opened = []
    monkeypatch.setattr("msat.app.dialogs.UpdateDialog",
                        lambda *args: opened.append(args))
    seen = []
    monkeypatch.setattr("msat.app.messagebox.showinfo",
                        lambda *args, **kwargs: seen.append(args))
    app._check_for_updates(manual=False)
    assert opened == []
    assert seen == []


def test_automatic_check_is_silent_when_unreachable(root, monkeypatch):
    app = MSATApp(root)
    monkeypatch.setattr("msat.app.updater.get_latest_release",
                        lambda: None)
    opened = []
    monkeypatch.setattr("msat.app.dialogs.UpdateDialog",
                        lambda *args: opened.append(args))
    seen = []
    monkeypatch.setattr("msat.app.messagebox.showinfo",
                        lambda *args, **kwargs: seen.append(args))
    app._check_for_updates(manual=False)
    assert opened == []
    assert seen == []


def test_update_dialog_shows_versions_and_notes(root):
    release = _fake_release(tag="v9.9.9")
    dlg = UpdateDialog(root, release, "1.8.3")
    try:
        assert "v9.9.9" in dlg.title_label.cget("text")
        assert "1.8.3" in dlg.title_label.cget("text")
        assert "Fix." in dlg.notes_text.get("1.0", tk.END)
        assert dlg.notes_text.cget("state") == tk.DISABLED
    finally:
        dlg.destroy()


def test_update_dialog_download_reports_path_and_steps(root, monkeypatch):
    release = _fake_release(tag="v9.9.9")
    monkeypatch.setattr("msat.dialogs.updater.download_release_zip",
                        lambda url: "/Users/test/Downloads/msat-v9.9.9.zip")
    dlg = UpdateDialog(root, release, "1.8.3")
    try:
        dlg._on_download()
        status = dlg.status_label.cget("text")
        assert "/Users/test/Downloads/msat-v9.9.9.zip" in status
        assert "replace MSAT.app" in status
        assert "~/.msat/settings.json" in status
        assert dlg.download_btn.instate(["disabled"])
    finally:
        dlg.destroy()


def test_update_dialog_download_without_zip_asset(root, monkeypatch):
    release = _fake_release(tag="v9.9.9", zip_url=None)
    monkeypatch.setattr("msat.dialogs.updater.download_release_zip",
                        lambda url: None)
    dlg = UpdateDialog(root, release, "1.8.3")
    try:
        dlg._on_download()
        assert "no downloadable zip" in dlg.status_label.cget("text")
        assert dlg.download_btn.instate(["!disabled"])
    finally:
        dlg.destroy()


def test_update_dialog_view_on_github(root, monkeypatch):
    release = _fake_release(tag="v9.9.9")
    opened = []
    monkeypatch.setattr("msat.dialogs.webbrowser.open",
                        lambda url: opened.append(url))
    dlg = UpdateDialog(root, release, "1.8.3")
    try:
        dlg._on_view()
        assert opened == [release["html_url"]]
    finally:
        dlg.destroy()
