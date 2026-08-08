import json
import os
import platform
import plistlib
import sys

from .browser_cleaner import BROWSER_CACHE_TARGETS, CHROMIUM_CACHE_SUBDIRS
from .diagnostics import configure_logging
from .memory import get_memory_stats
from .security_audit import run_security_audit
from .silicon import get_hardware_profile
from .utils import is_safe_to_delete, run_command
from .version import BUILD, BUNDLE_IDENTIFIER, VERSION


def run_self_test(resource_root: str) -> int:
    checks = []

    def add(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    gui_dir = os.path.join(resource_root, "gui")
    required_assets = ("index.html", "style.css", "app.js", "brand-mark.png")
    assets_ok = all(
        os.path.isfile(os.path.join(gui_dir, name))
        and os.path.getsize(os.path.join(gui_dir, name)) > 0
        for name in required_assets
    )
    add(
        "gui_assets",
        assets_ok,
        gui_dir,
    )

    icon_path = os.path.join(resource_root, "hollyoptimizer_app_icon.png")
    add(
        "app_icon",
        os.path.isfile(icon_path) and os.path.getsize(icon_path) > 0,
        icon_path,
    )

    try:
        from Foundation import NSFileManager

        available = hasattr(
            NSFileManager.defaultManager(), "trashItemAtURL_resultingItemURL_error_"
        )
        add("native_trash_api", available)
    except Exception as exc:
        add("native_trash_api", False, type(exc).__name__)

    try:
        from AppKit import NSWorkspace

        add(
            "native_package_api",
            hasattr(NSWorkspace.sharedWorkspace(), "isFilePackageAtPath_"),
        )
    except Exception as exc:
        add("native_package_api", False, type(exc).__name__)

    try:
        from Foundation import NSURLIsUbiquitousItemKey

        add("icloud_metadata_key", bool(NSURLIsUbiquitousItemKey))
    except Exception as exc:
        add("icloud_metadata_key", False, type(exc).__name__)

    for command in (
        ["/usr/sbin/sysctl", "-n", "hw.memsize"],
        ["/usr/bin/vm_stat"],
        ["/bin/ps", "-A", "-o", "pid="],
    ):
        code, stdout, stderr = run_command(command, timeout=10)
        add(f"command_{os.path.basename(command[0])}", code == 0 and bool(stdout), stderr[:120])

    memory = get_memory_stats()
    add(
        "memory_stats",
        memory["total_bytes"] > 0 and 0 <= memory["percent"] <= 100,
        f"percent={memory['percent']}",
    )

    policy_ok = (
        not is_safe_to_delete("/System/Library/CoreServices/Finder.app")
        and not is_safe_to_delete(os.path.expanduser("~/Documents/important.db"))
        and not is_safe_to_delete(
            os.path.expanduser("~/Pictures/Library.photoslibrary/original.jpg")
        )
        and is_safe_to_delete("/Applications/ThirdParty.app", intent="app_bundle")
    )
    add("path_policy", policy_ok)

    browser_roots = {
        os.path.expanduser(root)
        for target in BROWSER_CACHE_TARGETS.values()
        for root in target["roots"]
    }

    def _is_cache_root(root: str) -> bool:
        """Every configured root must be a cache location, never profile data."""
        if "/Library/Caches/" in root or "/Data/Library/Caches" in root:
            return True
        # Chromium keeps its caches inside the profile directory, so the root
        # is only accepted when its final segments name a known cache store.
        return any(root.endswith("/" + sub) for sub in CHROMIUM_CACHE_SUBDIRS)

    # Locations holding history, cookies, credentials, bookmarks, extensions or
    # site storage must never appear, at any depth, in a cache root.
    forbidden_segments = (
        "/History", "/Cookies", "/Login Data", "/Bookmarks", "/Extensions",
        "/Local Storage", "/IndexedDB", "/Web Data", "/Preferences",
        "/Service Worker/Database", "/Sessions", "/Favicons",
    )
    browser_policy_ok = (
        bool(browser_roots)
        and all(_is_cache_root(root) for root in browser_roots)
        and not any(
            segment in root for root in browser_roots for segment in forbidden_segments
        )
        and os.path.expanduser("~/Library/Safari") not in browser_roots
        and not any("Application Support/Firefox" in root for root in browser_roots)
    )
    add(
        "browser_cache_policy",
        browser_policy_ok,
        f"{len(browser_roots)} raízes em {len(BROWSER_CACHE_TARGETS)} navegadores",
    )

    try:
        security = run_security_audit()
        security_ids = {check["id"] for check in security.get("checks", [])}
        add(
            "security_audit_read_only",
            security.get("read_only") is True
            and security_ids
            == {"filevault", "firewall", "gatekeeper", "sip", "automatic_updates"},
        )
    except Exception as exc:
        add("security_audit_read_only", False, type(exc).__name__)

    try:
        profile = get_hardware_profile()
        add(
            "hardware_profile",
            bool(profile["chip"] != "Indisponível" and profile["total_cores"] > 0),
            f"{profile['chip']} · {profile['core_summary']} · {profile['memory_human']}",
        )
    except Exception as exc:
        add("hardware_profile", False, type(exc).__name__)

    try:
        log_path = configure_logging()
        add("rotating_log", os.path.isfile(log_path), os.path.dirname(log_path))
    except Exception as exc:
        add("rotating_log", False, type(exc).__name__)

    if getattr(sys, "frozen", False):
        info_path = os.path.join(os.path.dirname(os.path.dirname(sys.executable)), "Info.plist")
        try:
            with open(info_path, "rb") as handle:
                info = plistlib.load(handle)
            add(
                "bundle_identifier",
                info.get("CFBundleIdentifier") == BUNDLE_IDENTIFIER,
            )
            add("bundle_version", info.get("CFBundleShortVersionString") == VERSION)
            add("bundle_build", info.get("CFBundleVersion") == str(BUILD))
        except Exception as exc:
            add("bundle_metadata", False, type(exc).__name__)

    report = {
        "ok": all(check["ok"] for check in checks),
        "frozen": bool(getattr(sys, "frozen", False)),
        "architecture": platform.machine(),
        "checks": checks,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["ok"] else 1
