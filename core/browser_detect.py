"""
Best-effort discovery of installed Chrome / Edge / Brave / Opera / Firefox
/ Safari profiles on the current machine. This is offered purely as a
convenience picker in each module's toolbar — the user still explicitly
chooses which discovered file (or a manually browsed one) to open.

Nothing here reads file contents; it only checks for the *existence* of
known profile paths per OS, so it is safe to run at any time.

IMPORTANT (web edition): this scans the filesystem of the MACHINE RUNNING
THE DJANGO SERVER, not the examiner's browser. It only makes sense when
the suite is deployed locally on an investigator's own workstation. On a
shared/remote server this feature should stay disabled (see
Evidence "Server-side scan" view, gated behind a settings flag).
"""
from __future__ import annotations
import configparser
import os
import platform
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List


@dataclass
class DetectedProfile:
    browser: str          # e.g. "Chrome"
    profile_name: str     # e.g. "Default", "Profile 1", "default-release"
    history_path: Path | None = None
    logins_path: Path | None = None
    cookies_path: Path | None = None


def _chromium_family_roots() -> dict[str, Path]:
    system = platform.system()
    home = Path.home()
    roots: dict[str, Path] = {}

    if system == "Windows":
        local = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
        roots["Chrome"] = local / "Google" / "Chrome" / "User Data"
        roots["Edge"] = local / "Microsoft" / "Edge" / "User Data"
        roots["Brave"] = local / "BraveSoftware" / "Brave-Browser" / "User Data"
        roots["Opera"] = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming")) / "Opera Software" / "Opera Stable"
    elif system == "Darwin":
        support = home / "Library" / "Application Support"
        roots["Chrome"] = support / "Google" / "Chrome"
        roots["Edge"] = support / "Microsoft Edge"
        roots["Brave"] = support / "BraveSoftware" / "Brave-Browser"
        roots["Opera"] = support / "com.operasoftware.Opera"
    else:  # Linux and everything else
        config = home / ".config"
        roots["Chrome"] = config / "google-chrome"
        roots["Edge"] = config / "microsoft-edge"
        roots["Brave"] = config / "BraveSoftware" / "Brave-Browser"
        roots["Opera"] = config / "opera"
    return roots


def detect_chromium_family() -> List[DetectedProfile]:
    found: List[DetectedProfile] = []
    for browser, root in _chromium_family_roots().items():
        if not root.exists():
            continue
        # Opera keeps its profile files directly in root; Chrome-style
        # browsers use "Default" / "Profile N" subfolders.
        candidate_dirs = [root] if browser == "Opera" else None
        if candidate_dirs is None:
            try:
                candidate_dirs = [p for p in root.iterdir() if p.is_dir() and
                                   (p.name == "Default" or p.name.startswith("Profile "))]
            except OSError:
                candidate_dirs = []
        for pdir in candidate_dirs:
            hist = pdir / "History"
            logins = pdir / "Login Data"
            cookies = pdir / "Cookies" if (pdir / "Cookies").exists() else pdir / "Network" / "Cookies"
            if hist.exists() or logins.exists() or cookies.exists():
                found.append(DetectedProfile(
                    browser=browser,
                    profile_name=pdir.name,
                    history_path=hist if hist.exists() else None,
                    logins_path=logins if logins.exists() else None,
                    cookies_path=cookies if cookies.exists() else None,
                ))
    return found


def detect_firefox() -> List[DetectedProfile]:
    system = platform.system()
    home = Path.home()
    if system == "Windows":
        root = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming")) / "Mozilla" / "Firefox"
    elif system == "Darwin":
        root = home / "Library" / "Application Support" / "Firefox"
    else:
        root = home / ".mozilla" / "firefox"

    ini_path = root / "profiles.ini"
    found: List[DetectedProfile] = []
    if not ini_path.exists():
        return found

    parser = configparser.ConfigParser()
    try:
        parser.read(ini_path, encoding="utf-8")
    except Exception:
        return found

    for section in parser.sections():
        if not section.startswith("Profile"):
            continue
        path_val = parser.get(section, "Path", fallback=None)
        is_relative = parser.get(section, "IsRelative", fallback="1") == "1"
        if not path_val:
            continue
        profile_dir = (root / path_val) if is_relative else Path(path_val)
        if not profile_dir.exists():
            continue
        places = profile_dir / "places.sqlite"
        logins = profile_dir / "logins.json"
        cookies = profile_dir / "cookies.sqlite"
        found.append(DetectedProfile(
            browser="Firefox",
            profile_name=profile_dir.name,
            history_path=places if places.exists() else None,
            logins_path=logins if logins.exists() else None,
            cookies_path=cookies if cookies.exists() else None,
        ))
    return found


def detect_safari() -> List[DetectedProfile]:
    if platform.system() != "Darwin":
        return []
    hist = Path.home() / "Library" / "Safari" / "History.db"
    if hist.exists():
        return [DetectedProfile(browser="Safari", profile_name="Default", history_path=hist)]
    return []


def detect_all() -> List[DetectedProfile]:
    profiles: List[DetectedProfile] = []
    try:
        profiles += detect_chromium_family()
    except Exception:
        pass
    try:
        profiles += detect_firefox()
    except Exception:
        pass
    try:
        profiles += detect_safari()
    except Exception:
        pass
    return profiles
