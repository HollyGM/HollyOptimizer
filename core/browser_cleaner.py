import glob
import os
import threading

from .diagnostics import record_issue
from .utils import (
    clear_path_caches,
    format_size,
    is_safe_scan_candidate,
    is_safe_to_delete,
    measure_and_validate_tree,
    move_to_trash,
    run_command,
    snapshot_path_identity,
)

# Cache directories a Chromium profile keeps under Application Support.
# Everything else in a profile — History, Cookies, Login Data, Bookmarks,
# Extensions, Local Storage, IndexedDB, Service Worker/Database — is user data
# and stays out of scope. Under Service Worker only the two regenerable stores
# are listed; the sibling "Database" holds the registrations themselves.
CHROMIUM_CACHE_SUBDIRS = (
    "Cache",
    "Code Cache",
    "GPUCache",
    "DawnCache",
    "DawnGraphiteCache",
    "DawnWebGPUCache",
    "GrShaderCache",
    "ShaderCache",
    "Service Worker/CacheStorage",
    "Service Worker/ScriptCache",
)

# key, display name, .app names, process names, ~/Library/Caches subdir,
# ~/Library/Application Support subdir
_CHROMIUM_FAMILY = (
    ("chrome", "Google Chrome", ("Google Chrome",), ("Google Chrome",),
     "Google/Chrome", "Google/Chrome"),
    ("chrome_beta", "Google Chrome Beta", ("Google Chrome Beta",), ("Google Chrome Beta",),
     "Google/Chrome Beta", "Google/Chrome Beta"),
    ("chrome_canary", "Google Chrome Canary", ("Google Chrome Canary",), ("Google Chrome Canary",),
     "Google/Chrome Canary", "Google/Chrome Canary"),
    ("chromium", "Chromium", ("Chromium",), ("Chromium",),
     "Chromium", "Chromium"),
    ("edge", "Microsoft Edge", ("Microsoft Edge",), ("Microsoft Edge",),
     "Microsoft Edge", "Microsoft Edge"),
    ("brave", "Brave Browser", ("Brave Browser",), ("Brave Browser",),
     "BraveSoftware/Brave-Browser", "BraveSoftware/Brave-Browser"),
    ("vivaldi", "Vivaldi", ("Vivaldi",), ("Vivaldi",),
     "Vivaldi", "Vivaldi"),
    ("arc", "Arc", ("Arc",), ("Arc",),
     "company.thebrowser.Browser", "Arc"),
    ("opera", "Opera", ("Opera",), ("Opera",),
     "com.operasoftware.Opera", "com.operasoftware.Opera"),
    ("opera_gx", "Opera GX", ("Opera GX",), ("Opera GX",),
     "com.operasoftware.OperaGX", "com.operasoftware.OperaGX"),
)


def _chromium_roots(caches_subdir: str, support_subdir: str) -> tuple[str, ...]:
    """Builds cache roots covering every profile, not just Default."""
    roots = [f"~/Library/Caches/{caches_subdir}"]
    support = f"~/Library/Application Support/{support_subdir}"
    for sub in CHROMIUM_CACHE_SUBDIRS:
        # Browser-level caches and per-profile caches (Default, Profile 1, ...).
        roots.append(f"{support}/{sub}")
        roots.append(f"{support}/*/{sub}")
    return tuple(roots)


def _build_targets() -> dict:
    targets = {
        "safari": {
            "name": "Safari",
            "app_paths": ("/Applications/Safari.app",),
            "process_names": ("Safari",),
            "roots": (
                "~/Library/Caches/com.apple.Safari",
                "~/Library/Containers/com.apple.Safari/Data/Library/Caches",
            ),
        },
        "firefox": {
            "name": "Firefox",
            "app_paths": (
                "/Applications/Firefox.app",
                "~/Applications/Firefox.app",
                "/Applications/Firefox Developer Edition.app",
                "/Applications/Firefox Nightly.app",
            ),
            "process_names": ("firefox",),
            "roots": (
                "~/Library/Caches/Firefox/Profiles",
                "~/Library/Caches/Mozilla/Firefox/Profiles",
            ),
        },
        "zen": {
            "name": "Zen Browser",
            "app_paths": ("/Applications/Zen.app", "/Applications/Zen Browser.app"),
            "process_names": ("zen",),
            "roots": ("~/Library/Caches/zen/Profiles",),
        },
        "orion": {
            "name": "Orion",
            "app_paths": ("/Applications/Orion.app",),
            "process_names": ("Orion",),
            "roots": (
                "~/Library/Caches/com.kagi.kagimacOS",
                "~/Library/Containers/com.kagi.kagimacOS/Data/Library/Caches",
            ),
        },
    }

    for key, name, app_names, process_names, caches_subdir, support_subdir in _CHROMIUM_FAMILY:
        targets[key] = {
            "name": name,
            "app_paths": tuple(
                path
                for app in app_names
                for path in (f"/Applications/{app}.app", f"~/Applications/{app}.app")
            ),
            "process_names": process_names,
            "roots": _chromium_roots(caches_subdir, support_subdir),
        }
    return targets


BROWSER_CACHE_TARGETS = _build_targets()

_SCAN_LOCK = threading.RLock()
_LAST_SCAN_ITEMS = {}


def _expanded_roots(browser_key: str) -> tuple[str, ...]:
    """Resolves literal and glob roots to canonical existing paths."""
    resolved = []
    for entry in BROWSER_CACHE_TARGETS[browser_key]["roots"]:
        expanded = os.path.expanduser(entry)
        if any(ch in expanded for ch in "*?["):
            resolved.extend(glob.glob(expanded))
        else:
            resolved.append(expanded)
    return tuple(dict.fromkeys(os.path.realpath(path) for path in resolved))


def _is_inside_configured_cache(browser_key: str, path: str) -> bool:
    resolved = os.path.realpath(os.path.expanduser(path))
    for root in _expanded_roots(browser_key):
        try:
            if resolved != root and os.path.commonpath((resolved, root)) == root:
                return True
        except ValueError:
            continue
    return False


def _browser_is_running(browser_key: str) -> bool:
    for process_name in BROWSER_CACHE_TARGETS[browser_key]["process_names"]:
        code, stdout, _ = run_command(["/usr/bin/pgrep", "-x", process_name], timeout=5)
        if code == 0 and stdout:
            return True
    return False


def _browser_is_installed(browser_key: str) -> bool:
    target = BROWSER_CACHE_TARGETS[browser_key]
    return any(os.path.exists(os.path.expanduser(path)) for path in target["app_paths"])


def _validate_and_measure(path: str) -> tuple[int, int]:
    """Enforces the cache policy on a whole subtree and totals its size."""
    if not is_safe_to_delete(path):
        raise ValueError("Item fora da política segura de cache.")
    return measure_and_validate_tree(path, feature="browser_caches")


def _scan_browser(browser_key: str) -> tuple[dict, dict]:
    target = BROWSER_CACHE_TARGETS[browser_key]
    registered = {}
    public_items = []
    total_size = 0
    total_count = 0
    inaccessible_roots = 0

    for root in _expanded_roots(browser_key):
        if not os.path.isdir(root):
            continue
        try:
            children = sorted(os.scandir(root), key=lambda entry: entry.name.casefold())
        except (PermissionError, FileNotFoundError, OSError) as exc:
            record_issue("browser_caches", exc, root)
            inaccessible_roots += 1
            continue

        for entry in children:
            path = entry.path
            try:
                if (
                    not _is_inside_configured_cache(browser_key, path)
                    or not is_safe_scan_candidate(path, require_user_owned=True)
                    or not is_safe_to_delete(path)
                ):
                    continue

                # One traversal validates every descendant and sizes the item.
                size, count = _validate_and_measure(path)
                identity = snapshot_path_identity(path)
                resolved = os.path.realpath(path)
                if resolved in registered:
                    continue
                registered[resolved] = {"identity": identity}
                public_items.append(
                    {
                        "name": entry.name,
                        "path": resolved,
                        "size_bytes": size,
                        "size_human": format_size(size),
                        "count": count,
                    }
                )
                total_size += size
                total_count += count
            except (PermissionError, FileNotFoundError, OSError, ValueError) as exc:
                record_issue("browser_caches", exc, path)

    result = {
        "name": target["name"],
        "installed": _browser_is_installed(browser_key),
        "running": _browser_is_running(browser_key),
        "accessible": inaccessible_roots == 0,
        "inaccessible_roots": inaccessible_roots,
        "size_bytes": total_size,
        "size_human": format_size(total_size),
        "count": total_count,
        "items": public_items,
        "scope": "Somente caches temporários; dados pessoais e perfis são preservados.",
    }
    return result, registered


def scan_browser_caches() -> dict:
    """Scans the explicit cache roots of every supported browser."""
    clear_path_caches()
    results = {}
    snapshot = {}
    for browser_key in BROWSER_CACHE_TARGETS:
        results[browser_key], snapshot[browser_key] = _scan_browser(browser_key)

    with _SCAN_LOCK:
        _LAST_SCAN_ITEMS.clear()
        _LAST_SCAN_ITEMS.update(snapshot)
    return results


def clean_browser_cache(browser_key: str) -> dict:
    """Moves cache items from the latest scan to the native macOS Trash."""
    result = {
        "bytes_moved": 0,
        "files_moved": 0,
        "moved": 0,
        "failed": 0,
        "errors": [],
    }
    if browser_key not in BROWSER_CACHE_TARGETS:
        result["failed"] = 1
        result["errors"].append("Navegador inválido.")
        return result

    if _browser_is_running(browser_key):
        result["failed"] = 1
        result["errors"].append(
            f"Feche completamente o {BROWSER_CACHE_TARGETS[browser_key]['name']} antes da limpeza."
        )
        return result

    with _SCAN_LOCK:
        registered = dict(_LAST_SCAN_ITEMS.get(browser_key, {}))
        _LAST_SCAN_ITEMS[browser_key] = {}

    if not registered:
        result["failed"] = 1
        result["errors"].append("Faça uma nova varredura antes de limpar este navegador.")
        return result

    for path, expected in registered.items():
        try:
            if (
                not _is_inside_configured_cache(browser_key, path)
                or not is_safe_scan_candidate(path, require_user_owned=True)
                or not is_safe_to_delete(path)
            ):
                result["failed"] += 1
                result["errors"].append("Item bloqueado pela política de cache do navegador.")
                continue

            # Re-running the full gate is what protects the move: it rejects a
            # symlink, package or foreign-owned entry introduced after the scan.
            # The size comes from the same traversal.
            size, count = _validate_and_measure(path)

            success, message = move_to_trash(path, expected_identity=expected["identity"])
            if success:
                result["bytes_moved"] += size
                result["files_moved"] += count
                result["moved"] += 1
            else:
                result["failed"] += 1
                result["errors"].append(message)
        except (PermissionError, FileNotFoundError, OSError, ValueError) as exc:
            record_issue("browser_caches", exc, path)
            result["failed"] += 1
            result["errors"].append("Não foi possível revalidar um item de cache.")

    return result
