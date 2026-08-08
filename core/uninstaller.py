import base64
import hashlib
import os
import re
import threading

from .diagnostics import record_issue
from .utils import (
    format_size,
    get_dir_size,
    is_safe_app_bundle,
    is_safe_scan_candidate,
    move_app_to_trash_authorized,
    move_to_trash,
    read_plist,
    snapshot_path_identity,
)
from .version import APP_NAME

_REGISTRY_LOCK = threading.RLock()
_ICON_LOCK = threading.RLock()
_LAST_LISTED_APPS = {}
_RELATED_BY_APP = {}

def _safe_cache_key(bundle_id: str, app_path: str) -> str:
    raw = bundle_id or os.path.basename(app_path).removesuffix(".app")
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("._-")[:96] or "app"
    digest = hashlib.sha256(f"{app_path}\0{raw}".encode("utf-8", "surrogatepass")).hexdigest()[:12]
    return f"{slug}-{digest}"

def _registered_app(app_path: str) -> dict:
    resolved = os.path.realpath(os.path.expanduser(app_path))
    with _REGISTRY_LOCK:
        return dict(_LAST_LISTED_APPS.get(resolved, {}))

def get_image_base64(filepath: str) -> str:
    """Reads a file and returns its Base64 data URI string with correct MIME type."""
    if not filepath or not os.path.exists(filepath):
        return ""
    try:
        import mimetypes
        mime_type, _ = mimetypes.guess_type(filepath)
        mime_type = mime_type or "image/png"
        with open(filepath, "rb") as f:
            encoded = base64.b64encode(f.read()).decode("utf-8")
            return f"data:{mime_type};base64,{encoded}"
    except Exception as exc:
        record_issue("uninstaller", exc, filepath)
        return ""

# Target library directories to scan for related leftovers
LIBRARY_DIRS = [
    {"dir": os.path.expanduser("~/Library/Application Support"), "type": "suporte"},
    {"dir": os.path.expanduser("~/Library/Caches"), "type": "cache"},
    {"dir": os.path.expanduser("~/Library/Preferences"), "type": "preferencia"},
    {"dir": os.path.expanduser("~/Library/Saved Application State"), "type": "estado_salvo"},
    {"dir": os.path.expanduser("~/Library/Containers"), "type": "container"},
    {"dir": os.path.expanduser("~/Library/Group Containers"), "type": "group_container"},
    {"dir": os.path.expanduser("~/Library/Logs"), "type": "logs"},
    # Added: an app's HTTP cache, embedded WebKit data and sandbox helper
    # scripts all survive a drag-to-Trash uninstall. Session cookies
    # (*.binarycookies) sit in HTTPStorages too and stay protected by the
    # central path policy.
    {"dir": os.path.expanduser("~/Library/HTTPStorages"), "type": "cache_http"},
    {"dir": os.path.expanduser("~/Library/WebKit"), "type": "webkit"},
    {"dir": os.path.expanduser("~/Library/Application Scripts"), "type": "scripts"},
]

def extract_app_icon(app_path: str, bundle_id: str) -> str:
    """
    Extracts the highest-resolution PNG from the app's .icns file.
    Caches it in ~/Library/Caches/HollyOptimizer/Icons/<bundle_id>.png.
    Returns the path to the cached PNG, or an empty string if it fails.
    """
    cache_dir = os.path.expanduser(f"~/Library/Caches/{APP_NAME}/Icons")
    os.makedirs(cache_dir, mode=0o700, exist_ok=True)
    
    safe_id = _safe_cache_key(bundle_id, app_path)
    dest_path = os.path.join(cache_dir, f"{safe_id}.png")
    
    if os.path.exists(dest_path):
        return dest_path
        
    plist_path = os.path.join(app_path, "Contents", "Info.plist")
    plist = read_plist(plist_path)
    
    icon_file = os.path.basename(str(plist.get("CFBundleIconFile", "AppIcon.icns")))
    if not icon_file.endswith(".icns"):
        icon_file += ".icns"
        
    resources_dir = os.path.join(app_path, "Contents", "Resources")
    icns_path = os.path.join(resources_dir, icon_file)
    
    if not os.path.exists(icns_path):
        if os.path.exists(resources_dir) and os.path.isdir(resources_dir):
            for f in os.listdir(resources_dir):
                if f.endswith(".icns"):
                    icns_path = os.path.join(resources_dir, f)
                    break
                    
    if not os.path.exists(icns_path):
        return ""
        
    from .utils import run_command
    code, stdout, stderr = run_command(["/usr/bin/sips", "-s", "format", "png", "-z", "64", "64", icns_path, "--out", dest_path])
    
    if code == 0 and os.path.exists(dest_path):
        return dest_path
        
    return ""

def list_installed_apps() -> list[dict]:
    """
    Lists third-party installed apps in /Applications and ~/Applications.
    Filters out system apps in /System/Applications (SIP protected).
    """
    apps = []
    search_paths = [
        "/Applications",
        os.path.expanduser("~/Applications")
    ]
    
    for base_path in search_paths:
        if not os.path.exists(base_path) or not os.path.isdir(base_path):
            continue

        # Vendors ship suites in a subfolder (e.g. /Applications/SafeNet/...),
        # and macOS itself uses /Applications/Utilities. A flat listing of the
        # top level left those apps unmanageable, so descend a few levels while
        # never recursing into a bundle.
        discovered = []
        try:
            for root, dirs, _ in os.walk(base_path, followlinks=False):
                depth = root[len(base_path):].count(os.sep)
                if depth >= 3:
                    dirs.clear()
                    continue
                for name in list(dirs):
                    if name.endswith(".app"):
                        discovered.append((name, os.path.join(root, name)))
                        dirs.remove(name)
        except Exception as exc:
            record_issue("uninstaller", exc, base_path)
            continue

        for item, app_path in discovered:
            # One unreadable or racing bundle must not truncate the listing.
            try:
                if not is_safe_app_bundle(app_path):
                    continue

                # Read Info.plist
                plist_path = os.path.join(app_path, "Contents", "Info.plist")
                plist = read_plist(plist_path)

                bundle_id = plist.get("CFBundleIdentifier", "")
                version = plist.get("CFBundleShortVersionString", plist.get("CFBundleVersion", "1.0"))

                # Get display name
                display_name = plist.get("CFBundleDisplayName", plist.get("CFBundleName", item[:-4]))

                # Missing identifiers and Apple apps are never offered for removal.
                if not bundle_id or bundle_id.startswith("com.apple."):
                    continue

                try:
                    size_bytes = get_dir_size(app_path, feature="uninstaller")[0]
                except OSError as exc:
                    record_issue("uninstaller", exc, app_path)
                    size_bytes = 0

                apps.append({
                    "name": display_name,
                    "filename": item,
                    "path": app_path,
                    "bundle_id": bundle_id,
                    "version": version,
                    "size_bytes": size_bytes,
                    "size_human": format_size(size_bytes),
                    "_identity": snapshot_path_identity(app_path),
                })
            except (OSError, ValueError) as exc:
                record_issue("uninstaller", exc, app_path)
                continue
            
    # Sort apps by name alphabetically
    apps.sort(key=lambda x: x["name"].lower())

    with _REGISTRY_LOCK:
        _LAST_LISTED_APPS.clear()
        _RELATED_BY_APP.clear()
        for app in apps:
            _LAST_LISTED_APPS[os.path.realpath(app["path"])] = dict(app)

    public_apps = []
    for app in apps:
        public = dict(app)
        public.pop("_identity", None)
        public_apps.append(public)
    return public_apps

def get_app_icon_base64(app_path: str, bundle_id: str) -> str:
    """Lazy-loads app icon as Base64 data URI (called on demand from UI)."""
    registered = _registered_app(app_path)
    if not registered or registered.get("bundle_id") != bundle_id:
        return ""
    with _ICON_LOCK:
        icon_path = extract_app_icon(registered["path"], registered["bundle_id"])
        return get_image_base64(icon_path)

def get_app_related_files(app_path: str, bundle_id: str, app_name: str) -> list[dict]:
    """
    Finds all support files in ~/Library associated with the app.
    Matches against bundle_id and app_name.
    """
    registered = _registered_app(app_path)
    if not registered or registered.get("bundle_id") != bundle_id:
        return []

    app_path = registered["path"]
    bundle_id = registered["bundle_id"]
    related_files = []
    
    # Normalize keys
    b_id = bundle_id.lower() if bundle_id else ""
    a_name = app_name.lower() if app_name else ""

    for lib in LIBRARY_DIRS:
        base_dir = lib["dir"]
        l_type = lib["type"]
        
        if not os.path.exists(base_dir) or not os.path.isdir(base_dir):
            continue
            
        try:
            for item in os.listdir(base_dir):
                item_path = os.path.join(base_dir, item)
                item_lower = item.lower()
                if not is_safe_scan_candidate(item_path):
                    continue
                
                # Check match criteria:
                # 1. Exact match with bundle identifier (e.g. com.spotify.client)
                # 2. Preference plist matching bundle ID (e.g. com.spotify.client.plist)
                # 3. Directory matching app name or filename (e.g. Spotify, or com.spotify.client.savedState)
                
                is_match = False
                clean_item = item_lower
                if clean_item.endswith(".plist"):
                    clean_item = clean_item[:-6]
                elif clean_item.endswith(".savedstate"):
                    clean_item = clean_item[:-11]

                if b_id and clean_item == b_id or a_name and clean_item == a_name:
                    is_match = True
                elif b_id and clean_item.startswith(b_id + "."):
                    # Helper and extension bundles, e.g. com.vendor.app.helper.
                    # The trailing dot keeps com.vendor.appsuite from matching
                    # com.vendor.app.
                    is_match = True

                if is_match:
                    try:
                        if os.path.isdir(item_path):
                            size_bytes, count = get_dir_size(item_path, feature="uninstaller")
                        else:
                            size_bytes = os.path.getsize(item_path)
                            count = 1
                    except OSError as exc:
                        record_issue("uninstaller", exc, item_path)
                        size_bytes, count = 0, 0
                        
                    related_files.append({
                        "name": item,
                        "path": item_path,
                        "type": l_type,
                        "size_bytes": size_bytes,
                        "size_human": format_size(size_bytes),
                        "count": count,
                        "_identity": snapshot_path_identity(item_path),
                    })
        except Exception as exc:
            record_issue("uninstaller", exc, base_dir)
            continue
            
    with _REGISTRY_LOCK:
        _RELATED_BY_APP[os.path.realpath(app_path)] = {
            os.path.realpath(item["path"]): item["_identity"] for item in related_files
        }

    for item in related_files:
        item.pop("_identity", None)
    return related_files

def uninstall_app(app_path: str, related_paths: list) -> tuple[bool, list]:
    """
    Moves the app bundle and selected support files to the macOS Trash.
    Retries verified /Applications bundles with macOS authentication when the
    native Trash API reports insufficient privileges.
    """
    logs = []
    success = True

    resolved_app = os.path.realpath(os.path.expanduser(app_path))
    registered = _registered_app(resolved_app)
    with _REGISTRY_LOCK:
        allowed_related = dict(_RELATED_BY_APP.get(resolved_app, {}))

    if not registered:
        return False, ["✗ Aplicativo bloqueado: não pertence à listagem mais recente."]

    requested_related = {os.path.realpath(os.path.expanduser(path)) for path in related_paths}
    if not requested_related.issubset(set(allowed_related)):
        return False, ["✗ Arquivos de suporte bloqueados: seleção não pertence à análise do aplicativo."]
    
    # Move the app first. This prevents removing support data while leaving an
    # app that failed to uninstall in place.
    if os.path.exists(resolved_app):
        ok, msg = move_to_trash(
            app_path,
            intent="app_bundle",
            expected_identity=registered.get("_identity"),
        )
        permission_failure = any(marker in msg.casefold() for marker in (
            "code=513",
            "code=-5000",
            "permission",
            "privilege",
            "access denied",
            "accessdenied",
            "not permitted",
        ))
        if not ok and permission_failure and resolved_app.startswith("/Applications/"):
            ok, msg = move_app_to_trash_authorized(
                resolved_app,
                expected_identity=registered.get("_identity"),
            )
        if ok:
            logs.append(f"✓ {msg}")
        else:
            return False, [f"✗ {msg}"]

    for path in sorted(requested_related):
        if os.path.exists(path):
            ok, msg = move_to_trash(path, expected_identity=allowed_related[path])
            if ok:
                logs.append(f"✓ {msg}")
            else:
                logs.append(f"✗ {msg}")
                success = False
            
    return success, logs
