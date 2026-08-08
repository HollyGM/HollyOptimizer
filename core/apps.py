import os
import re
import threading
import time

from .diagnostics import record_issue
from .utils import (
    clear_path_caches,
    format_size,
    is_safe_scan_candidate,
    measure_and_validate_tree,
    move_to_trash,
    read_plist,
    run_command,
    snapshot_path_identity,
)

# Common system directories that we should NEVER touch
SYSTEM_WHITELIST = {
    "addressbook", "app store", "apple", "applepushservice", "bluetooth",
    "callhistorydb", "callhistorytransactions", "clouddocs", "console",
    "crashreporter", "differentialprivacy", "facetime", "fileprovider",
    "icloud", "ilifemediabrowser", "itunes", "logs", "mail", "messages",
    "quick look", "screen sharing", "syncservices", "system", "terminal",
    "com.apple.tcc", "com.apple.spotlight", "com.apple.sharedfilelist",
    "helper", "localbarrier", "preferences", "caches", "application support"
}

# Known vendor folders that contain subfolders for specific apps
VENDOR_FOLDERS = {"google", "adobe", "microsoft", "mozilla"}

_BUNDLE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]*(?:\.[a-z0-9][a-z0-9_-]*){1,}$", re.IGNORECASE)
_SCAN_LOCK = threading.RLock()
_LAST_LEFTOVER_PATHS = {}

def _normalize_name(value: str) -> str:
    return "".join(ch for ch in value.casefold() if ch.isalnum())

def _is_active_identifier(clean_name: str, active_ids: set, normalized_names: set, identifier_suffixes: set) -> bool:
    if any(
        clean_name == active_id
        or clean_name.startswith(active_id + ".")
        or active_id.startswith(clean_name + ".")
        for active_id in active_ids
    ):
        return True

    normalized = _normalize_name(clean_name)
    if not normalized:
        return False
    return normalized in normalized_names or normalized in identifier_suffixes


def _validate_candidate(path: str) -> tuple[int, int]:
    """
    Enforces the safety gate across a leftover candidate and sizes it in the
    same traversal. Replaces the previous per-descendant identity manifest,
    which walked the tree once to record mtimes and again to measure it, and
    then rejected the item whenever ordinary cache writes moved those mtimes.
    """
    return measure_and_validate_tree(path, feature="leftovers")


def _candidate_entries(base_dir: str, target_type: str):
    """Yields conservative top-level and known-vendor cache candidates."""
    for item in sorted(os.listdir(base_dir), key=str.casefold):
        if item.startswith("."):
            continue
        item_path = os.path.join(base_dir, item)
        if not is_safe_scan_candidate(item_path, require_user_owned=True):
            continue

        item_lower = item.casefold()
        clean_name = item_lower
        if target_type == "saved_state" and clean_name.endswith(".savedstate"):
            clean_name = clean_name[:-11]

        if target_type == "cache" and item_lower in VENDOR_FOLDERS and os.path.isdir(item_path):
            try:
                children = sorted(os.listdir(item_path), key=str.casefold)
            except (PermissionError, FileNotFoundError, OSError) as exc:
                record_issue("leftovers", exc, item_path)
                continue
            for child_name in children:
                if child_name.startswith("."):
                    continue
                child_path = os.path.join(item_path, child_name)
                if not is_safe_scan_candidate(child_path, require_user_owned=True):
                    continue
                child_clean = child_name.casefold()
                if not re.fullmatch(r"[a-z0-9][a-z0-9 ._+@-]{1,}", child_clean, re.IGNORECASE):
                    continue
                yield (
                    child_path,
                    child_clean,
                    f"Cache de produto dentro do fornecedor conhecido {item}",
                    "Revisar",
                )
            continue

        if _BUNDLE_ID_PATTERN.fullmatch(clean_name):
            yield (
                item_path,
                clean_name,
                "Identificador reverso sem aplicativo instalado correspondente",
                "Alta",
            )

_APPS_CACHE_LOCK = threading.RLock()
_APPS_CACHE = {"expires_at": 0.0, "value": None}
# Deleting leftovers one at a time re-ran a full /Applications walk plus an
# mdfind query per item. The installed-app set barely moves during a cleanup
# session, so it is reused briefly.
_APPS_CACHE_TTL_SECONDS = 30.0


def find_installed_apps(*, allow_cached: bool = False) -> tuple[set, set]:
    """
    Scans the Applications directories and returns:
    1. A set of lowercase Bundle Identifiers (e.g. {'org.mozilla.firefox'}).
    2. A set of lowercase App Names (e.g. {'firefox', 'google chrome'}).
    """
    if allow_cached:
        with _APPS_CACHE_LOCK:
            if _APPS_CACHE["value"] is not None and time.monotonic() < _APPS_CACHE["expires_at"]:
                return _APPS_CACHE["value"]

    active_ids = set()
    active_names = set()
    discovered_apps = set()

    search_paths = [
        "/Applications",
        "/System/Applications",
        os.path.expanduser("~/Applications")
    ]

    for base_path in search_paths:
        if not os.path.exists(base_path):
            continue
        
        # Scan up to 2 levels deep (to find things like /Applications/Utilities/Console.app)
        try:
            for root, dirs, _ in os.walk(base_path, followlinks=False):
                # Calculate depth
                depth = root.replace(base_path, "").count(os.sep)
                if depth > 2:
                    # Don't go too deep to save time
                    dirs.clear()
                    continue

                for d in list(dirs):
                    if d.endswith(".app"):
                        discovered_apps.add(os.path.join(root, d))

                        # Remove this directory from recursion so we don't scan inside the .app bundle
                        dirs.remove(d)
        except Exception as exc:
            record_issue("leftovers", exc, base_path)
            continue

    # Spotlight broadens protection to apps outside the standard folders. A
    # Spotlight failure only makes the scan more conservative later on.
    code, stdout, _ = run_command([
        "/usr/bin/mdfind", "kMDItemContentType == 'com.apple.application-bundle'"
    ], timeout=60)
    if code == 0 and stdout:
        for path in stdout.splitlines():
            if path.endswith(".app") and os.path.isdir(path):
                discovered_apps.add(path)

    for app_path in discovered_apps:
        active_names.add(os.path.basename(app_path)[:-4].lower())
        plist = read_plist(os.path.join(app_path, "Contents", "Info.plist"))
        bundle_id = plist.get("CFBundleIdentifier")
        if isinstance(bundle_id, str) and bundle_id:
            active_ids.add(bundle_id.lower())
        for key in ("CFBundleName", "CFBundleDisplayName"):
            value = plist.get(key)
            if isinstance(value, str) and value:
                active_names.add(value.lower())

    result = (active_ids, active_names)
    with _APPS_CACHE_LOCK:
        _APPS_CACHE["value"] = result
        _APPS_CACHE["expires_at"] = time.monotonic() + _APPS_CACHE_TTL_SECONDS
    return result

def scan_leftovers() -> list[dict]:
    """
    Scans typical system library locations for files left behind by uninstalled applications.
    Returns a list of dictionaries with info about each leftover.
    """
    clear_path_caches()
    active_ids, active_names = find_installed_apps()
    leftovers = []

    normalized_names = {_normalize_name(name) for name in active_names}
    identifier_suffixes = {_normalize_name(active_id.rsplit(".", 1)[-1]) for active_id in active_ids}

    # Safety-first policy: only caches and saved state are eligible. Application
    # Support, Preferences and Containers can contain irreplaceable user data and
    # are handled only by the explicit app uninstaller.
    scan_targets = [
        {"dir": os.path.expanduser("~/Library/Caches"), "type": "cache"},
        {"dir": os.path.expanduser("~/Library/Saved Application State"), "type": "saved_state"},
    ]

    for target in scan_targets:
        base_dir = target["dir"]
        target_type = target["type"]

        if not os.path.exists(base_dir) or not os.path.isdir(base_dir):
            continue

        try:
            for item_path, clean_name, evidence, confidence in _candidate_entries(
                base_dir, target_type
            ):
                item = os.path.basename(item_path)
                if clean_name in SYSTEM_WHITELIST or clean_name.startswith("com.apple."):
                    continue

                is_active = _is_active_identifier(clean_name, active_ids, normalized_names, identifier_suffixes)

                if not is_active:
                    try:
                        # One traversal both validates the candidate and sizes it.
                        size_bytes, file_count = _validate_candidate(item_path)
                    except (OSError, ValueError) as exc:
                        # A single unsafe or unreadable candidate must not
                        # truncate the rest of the directory listing.
                        record_issue("leftovers", exc, item_path)
                        continue

                    # Only report if it actually has size or files (ignore empty folders if they aren't clutter)
                    if size_bytes > 0 or file_count > 0:
                        leftovers.append({
                            "name": item,
                            "path": item_path,
                            "type": target_type,
                            "size_bytes": size_bytes,
                            "size_human": format_size(size_bytes),
                            "count": file_count,
                            "identifier": clean_name,
                            "evidence": evidence,
                            "confidence": confidence,
                            "_identity": snapshot_path_identity(item_path),
                        })
        except Exception as exc:
            record_issue("leftovers", exc, base_dir)
            continue

    with _SCAN_LOCK:
        _LAST_LEFTOVER_PATHS.clear()
        _LAST_LEFTOVER_PATHS.update({
            os.path.realpath(item["path"]): {
                "identity": item["_identity"],
                "identifier": item["identifier"],
            }
            for item in leftovers
        })

    for item in leftovers:
        item.pop("_identity", None)

    return leftovers

def delete_leftover(path: str) -> tuple[bool, str]:
    """
    Moves a leftover file or directory to the macOS Trash.
    Returns (success, message).
    """
    resolved = os.path.realpath(os.path.expanduser(path))
    with _SCAN_LOCK:
        expected = _LAST_LEFTOVER_PATHS.get(resolved)
        if expected is None:
            return False, "Item bloqueado: não pertence à varredura de sobras mais recente."
    if os.path.realpath(os.path.expanduser(path)) != os.path.abspath(os.path.expanduser(path)):
        return False, "Item bloqueado: links simbólicos não são aceitos."
    try:
        # Rewalk the complete candidate at action time. This preserves the
        # symlink/package/cloud gates while allowing ordinary cache writes that
        # happened after the scan.
        _validate_candidate(path)
    except (OSError, ValueError) as exc:
        return False, f"Não foi possível revalidar a sobra: {exc}"

    active_ids, active_names = find_installed_apps(allow_cached=True)
    normalized_names = {_normalize_name(name) for name in active_names}
    identifier_suffixes = {
        _normalize_name(active_id.rsplit(".", 1)[-1]) for active_id in active_ids
    }
    if _is_active_identifier(
        expected["identifier"], active_ids, normalized_names, identifier_suffixes
    ):
        return False, "Item bloqueado porque o aplicativo correspondente está instalado."

    return move_to_trash(
        path,
        expected_identity=expected["identity"],
        allow_content_changes=True,
    )
