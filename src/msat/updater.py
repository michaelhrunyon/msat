"""Check GitHub Releases for a newer MSAT version.

Scope (deliberate): this only *finds* a newer published release and
downloads its release zip. It never replaces the running app in place
— a running .app bundle cannot reliably replace itself, and
overwriting the source files of a running program is fragile. After
downloading, the user installs the new version by hand (unzip over
the project folder, or replace MSAT.app in /Applications); the
update dialog states those steps.

Only the standard library is used (``urllib.request``, ``json``) —
no new dependencies. Every function here is failure-proof: any
network error, timeout, non-200 response, bad JSON or missing field
returns ``None`` instead of raising, so a failed check is always
silent for the caller.

No background threads are used anywhere in this module (or in MSAT at all):
the check runs synchronously on the UI thread with a short timeout,
deferred with ``after()`` at startup so the main window appears
first.
"""

import json
import os
import urllib.error
import urllib.request

# The app's own upstream repository. This is public, generic project
# metadata — it is not environment- or company-specific information.
GITHUB_REPO = "michaelhrunyon/msat"
RELEASES_API_URL = "https://api.github.com/repos/{}/releases/latest".format(GITHUB_REPO)

# Short timeout for the release check; the zip download gets longer.
_CHECK_TIMEOUT_SECONDS = 5
_DOWNLOAD_TIMEOUT_SECONDS = 60


def parse_version(tag):
    """'v1.8.3' -> (1, 8, 3); '1.8' -> (1, 8); malformed -> (0,).

    The leading "v" (GitHub release tags are "vX.Y.Z") is stripped.
    Anything that is not a dotted run of integers is malformed and
    yields (0,), which compares below every real version — a bogus
    tag can never be offered as an update.
    """
    if tag is None:
        return (0,)
    text = str(tag).strip()
    if text[:1] in ("v", "V"):
        text = text[1:]
    if not text:
        return (0,)
    parts = []
    for piece in text.split("."):
        piece = piece.strip()
        if not piece.isdigit():
            return (0,)
        parts.append(int(piece))
    return tuple(parts) if parts else (0,)


def is_newer(latest_tag, current_version):
    """True only when the latest release tag is strictly newer than
    the running version. Equal, older and malformed tags are False."""
    return parse_version(latest_tag) > parse_version(current_version)


def get_latest_release():
    """Fetch the latest published GitHub release, or None.

    Returns a dict with ``tag`` (e.g. "v1.8.3"), ``name``, ``body``
    (release notes), ``html_url`` and ``zip_url`` (the
    ``browser_download_url`` of the asset whose name ends in ".zip",
    or None when the release carries no zip asset). Returns None on
    ANY failure — network error, timeout, non-200, bad JSON, missing
    fields — and never raises.
    """
    try:
        request = urllib.request.Request(
            RELEASES_API_URL,
            headers={"Accept": "application/vnd.github+json",
                     "User-Agent": "MSAT-update-check"},
        )
        with urllib.request.urlopen(request,
                                    timeout=_CHECK_TIMEOUT_SECONDS) as response:
            if response.status != 200:
                return None
            payload = json.loads(response.read().decode("utf-8"))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    tag = payload.get("tag_name")
    if not tag:
        return None
    zip_url = None
    for asset in payload.get("assets") or []:
        name = asset.get("name") or ""
        if name.endswith(".zip"):
            zip_url = asset.get("browser_download_url")
            break
    return {
        "tag": tag,
        "name": payload.get("name") or tag,
        "body": payload.get("body") or "",
        "html_url": payload.get("html_url") or "",
        "zip_url": zip_url,
    }


def download_release_zip(zip_url, dest_path=None):
    """Download the release zip to ``dest_path``.

    ``dest_path`` defaults to ``~/Downloads/<asset filename>`` — for
    our releases that is ``~/Downloads/msat-vX.Y.Z.zip``. Returns the
    path on success, None on any failure (no URL, network error,
    timeout, non-200, write error). Never raises.
    """
    if not zip_url:
        return None
    if dest_path is None:
        filename = zip_url.rstrip("/").rsplit("/", 1)[-1] or "msat-update.zip"
        dest_path = os.path.join(os.path.expanduser("~/Downloads"), filename)
    try:
        request = urllib.request.Request(
            zip_url, headers={"User-Agent": "MSAT-update-check"})
        with urllib.request.urlopen(
                request, timeout=_DOWNLOAD_TIMEOUT_SECONDS) as response:
            if response.status != 200:
                return None
            data = response.read()
        parent = os.path.dirname(dest_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(dest_path, "wb") as handle:
            handle.write(data)
    except Exception:
        return None
    return dest_path
