import functools
import os
import plistlib
import shlex
import stat
# Necessário para comandos nativos do macOS; toda chamada usa argv e shell=False.
import subprocess  # nosec B404
import threading

from .diagnostics import record_issue
from .version import APP_NAME


class Colors:
    """ANSI color codes for premium terminal formatting."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    GRAY = '\033[90m'

def format_size(size_in_bytes: int) -> str:
    """Converts bytes to a human-readable string (KB, MB, GB, etc.)."""
    if size_in_bytes <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    size = float(size_in_bytes)
    while size >= 1024.0 and i < len(units) - 1:
        size /= 1024.0
        i += 1
    return f"{size:.2f} {units[i]}"

@functools.lru_cache(maxsize=65536)
def _expand(path: str) -> str:
    """Resolves a path to its canonical form.

    Memoised because the policy checks below re-expand ~47 constant prefixes on
    every single call, and realpath() walks each component. Cleared per scan by
    clear_path_caches().
    """
    return os.path.realpath(os.path.expanduser(path))

# Prefixes that must NEVER be deleted (system + sensitive user data)
NEVER_DELETE_PREFIXES = [
    "/System", "/usr", "/bin", "/sbin", "/etc", "/var", "/private",
    "/Applications", "/Library",
    "~/Library/Keychains",
    "~/Library/Mobile Documents",
    "~/Library/CloudDocs",
    "~/Library/Mail",
    "~/Library/Messages",
    "~/Library/Safari",
    "~/Library/Accounts",
    "~/Library/IdentityServices",
    "~/Library/Calendars",
    "~/Library/Reminders",
    "~/Library/Photos",
    "~/Library/AppleMail",
    "~/Library/Biome",
    "~/Library/CoreFollowUp",
    "~/Library/DuetExpertCenter",
    "~/Library/Metadata",
    "~/Library/PersonalizationPortrait",
    "~/Library/Suggestions",
    "~/Library/Weather",
    "~/.ssh", "~/.gnupg", "~/.config", "~/.zshrc", "~/.bash_profile",
]

APP_BUNDLE_ROOTS = ["/Applications", "~/Applications"]

# Roots under which deletion is explicitly permitted
ALLOW_DELETE_ROOTS = [
    "~/Library/Caches",
    "~/Library/Logs",
    "~/Library/Developer/Xcode/DerivedData",
    "~/Library/Containers/com.apple.mail/Data/Library/Mail Downloads",
    "~/Downloads",
    "~/Documents",
    "~/Desktop",
    "~/Pictures",
    "~/Movies",
    "~/Music",
    "~/.Trash",
    "~/Library/Application Support",
    "~/Library/Preferences",
    "~/Library/Saved Application State",
    "~/Library/Containers",
    "~/Library/Group Containers",
    "~/Library/HTTPStorages",
    "~/Library/WebKit",
    "~/Library/iTunes",
    "~/Applications",
    "~/.npm/_cacache",
    "~/.cargo/registry/cache",
    "~/.cargo/registry/src",
    "~/.gradle/caches",
]

SENSITIVE_EXTENSIONS = {".sqlite", ".sqlite3", ".sqlitedb", ".db", ".keychain", ".keychain-db"}

# Files that sit next to caches but hold live credentials or session state.
# ~/Library/HTTPStorages mixes per-app HTTP caches (directories) with
# <bundle-id>.binarycookies files: removing those signs the user out.
SENSITIVE_BASENAME_SUFFIXES = (".binarycookies",)

# macOS document bundles are directories, but deleting one of their internal
# files can corrupt the entire user document.  The suffix list is a fail-safe
# for environments where AppKit metadata is unavailable (tests, CLI builds).
PACKAGE_SUFFIXES = {
    ".app", ".bundle", ".framework", ".plugin", ".appex",
    ".photoslibrary", ".photolibrary", ".musiclibrary", ".tvlibrary",
    ".pages", ".key", ".numbers", ".rtfd", ".band", ".logicx",
    ".imovielibrary", ".fcpbundle", ".playground", ".xcworkspace",
    ".xcodeproj",
}

def validate_path_sanity(path: str) -> None:
    """Rejects paths with characters that could break shell or AppleScript."""
    if not path or not isinstance(path, str):
        raise ValueError("Caminho inválido.")
    if "\0" in path or "\n" in path or "\r" in path:
        raise ValueError("Caminho contém caracteres inválidos.")
    if len(path) > 4096:
        raise ValueError("Caminho excede tamanho máximo permitido.")

# Containers whose INTERNAL files hold databases, images or volumes that break
# when moved piecemeal. The container directory itself may still be removed as
# one unit (e.g. by the uninstaller), but never its individual components.
ATOMIC_CONTAINER_PREFIXES = [
    "~/Library/Containers/com.docker.docker",
]

def _is_never_delete(resolved: str) -> bool:
    for prefix in NEVER_DELETE_PREFIXES:
        p = _expand(prefix)
        if resolved == p or resolved.startswith(p + os.sep):
            return True

    for prefix in ATOMIC_CONTAINER_PREFIXES:
        p = _expand(prefix)
        if resolved.startswith(p + os.sep):
            return True

    prefs = _expand("~/Library/Preferences")
    if resolved.startswith(prefs + os.sep):
        basename = os.path.basename(resolved)
        if basename.startswith("com.apple."):
            return True

    home = _expand("~")
    home_library = _expand("~/Library")
    if resolved in (home, home_library):
        return True

    lowered = resolved.lower()
    _, ext = os.path.splitext(lowered)
    if ext in SENSITIVE_EXTENSIONS and "caches" not in lowered:
        return True

    if lowered.endswith(SENSITIVE_BASENAME_SUFFIXES):
        return True

    return False

def _is_under_allow_root(resolved: str) -> bool:
    for root in ALLOW_DELETE_ROOTS:
        p = _expand(root)
        # Collection roots themselves (Documents, Desktop, Containers, etc.)
        # must never be movable. Only strict descendants are eligible.
        if resolved.startswith(p + os.sep):
            return True

    return False

def _absolute_unresolved(path: str) -> str:
    """Returns an absolute path without hiding symlink components via realpath."""
    return os.path.abspath(os.path.expanduser(path))

# Scanning a browser cache means running the safety gate on every descendant.
# Measured before memoisation, the gate cost ~446 us/file — 189x a bare lstat —
# because NSWorkspace.isFilePackageAtPath_ and the NSURL iCloud query are ObjC
# bridge calls issued once per file. Both answers are properties of the
# containing *directory*, so they are cached per directory and the per-file work
# collapses to a couple of lstats. Caches are dropped at the start of every scan
# via clear_path_caches() so a run never reuses another run's view of the disk.
_PATH_CACHE_LOCK = threading.RLock()


def _component_is_symlink(path: str) -> bool:
    try:
        return stat.S_ISLNK(os.lstat(path).st_mode)
    except FileNotFoundError:
        # A missing component cannot be a symlink; the caller handles absence.
        return False
    except OSError:
        # Fail closed when the filesystem cannot prove the component safe.
        return True


@functools.lru_cache(maxsize=65536)
def _dir_has_symlink_component(directory: str) -> bool:
    """Whether `directory` or any ancestor is a symlink. Cached per directory."""
    parent = os.path.dirname(directory)
    if not directory or directory == parent:
        return False
    if _dir_has_symlink_component(parent):
        return True
    return _component_is_symlink(directory)


def has_symlink_component(path: str) -> bool:
    """Rejects a symlink at the target or in any existing ancestor component."""
    absolute = _absolute_unresolved(path)
    parent = os.path.dirname(absolute)
    if parent and parent != absolute and _dir_has_symlink_component(parent):
        return True
    return _component_is_symlink(absolute)

def _package_suffix(path: str) -> bool:
    return os.path.splitext(os.path.basename(path).casefold())[1] in PACKAGE_SUFFIXES

@functools.lru_cache(maxsize=32768)
def _is_file_package_uncached(path: str) -> bool:
    if not os.path.isdir(path):
        return False
    try:
        from AppKit import NSWorkspace

        return bool(NSWorkspace.sharedWorkspace().isFilePackageAtPath_(path))
    except Exception:
        return False

def is_file_package(path: str) -> bool:
    """Returns whether macOS treats a directory as a file/document package."""
    if _package_suffix(path):
        return True
    # Regular files short-circuit before the ObjC bridge call.
    return _is_file_package_uncached(path)

@functools.lru_cache(maxsize=32768)
def _dir_has_package_ancestor(directory: str) -> bool:
    parent = os.path.dirname(directory)
    if not directory or directory == parent or directory == _expand("~"):
        return False
    if _dir_has_package_ancestor(parent):
        return True
    return is_file_package(directory)

def has_package_ancestor(path: str, *, include_self: bool = True) -> bool:
    absolute = _absolute_unresolved(path)
    if include_self and absolute != _expand("~") and is_file_package(absolute):
        return True
    return _dir_has_package_ancestor(os.path.dirname(absolute))

@functools.lru_cache(maxsize=16384)
def _is_ubiquitous_item(path: str) -> bool:
    """Asks macOS whether a path belongs to an iCloud/FileProvider container."""
    try:
        from Foundation import NSURL, NSURLIsUbiquitousItemKey

        result = NSURL.fileURLWithPath_(path).getResourceValue_forKey_error_(
            None, NSURLIsUbiquitousItemKey, None
        )
        if isinstance(result, tuple) and len(result) > 1:
            return bool(result[0] and result[1])
    except Exception:
        return False
    return False

def is_cloud_managed_path(path: str) -> bool:
    """Detects iCloud/FileProvider items that require an explicit opt-in flow."""
    resolved = _expand(path)
    for root in ("~/Library/Mobile Documents", "~/Library/CloudDocs"):
        protected = _expand(root)
        if resolved == protected or resolved.startswith(protected + os.sep):
            return True

    # Per-item check: catches a single evicted/dataless file even when its
    # directory is local.
    try:
        flags = os.stat(path, follow_symlinks=False).st_flags
        if flags & getattr(stat, "UF_OFFLINE", 0):
            return True
    except (AttributeError, OSError):
        pass

    # Ubiquity is a property of the synced container tree: a directory that is
    # not ubiquitous does not hold ubiquitous children. Asking about the parent
    # directory therefore gives the same answer as asking about each file, at
    # one bridge call per directory instead of one per file.
    probe = resolved if os.path.isdir(resolved) else os.path.dirname(resolved)
    return _is_ubiquitous_item(probe)


def clear_path_caches() -> None:
    """Drops memoised filesystem answers so each scan starts from a fresh view."""
    with _PATH_CACHE_LOCK:
        _expand.cache_clear()
        _dir_has_symlink_component.cache_clear()
        _is_file_package_uncached.cache_clear()
        _dir_has_package_ancestor.cache_clear()
        _is_ubiquitous_item.cache_clear()


def is_user_owned_path(path: str) -> bool:
    """Returns True only when the current user owns the existing filesystem item."""
    try:
        return os.lstat(path).st_uid == os.getuid()
    except OSError:
        return False

def snapshot_path_identity(path: str) -> tuple[int, int, int, int, int]:
    """Captures identity without following links: dev, inode, mode, size, mtime."""
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode):
        raise ValueError(f"Link simbólico rejeitado: {path}")
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns)


def path_identity_matches(path: str, expected_identity, *, allow_content_changes: bool = False) -> bool:
    """Revalidates that a path still names the same filesystem object."""
    current = snapshot_path_identity(path)
    expected = tuple(expected_identity)
    if not allow_content_changes:
        return current == expected

    # Cache and log contents are expected to change while applications run.
    # Device, inode and file type must remain stable so a replaced target still
    # fails closed without treating ordinary content updates as path swaps.
    return (
        current[0] == expected[0]
        and current[1] == expected[1]
        and stat.S_IFMT(current[2]) == stat.S_IFMT(expected[2])
    )

def is_safe_scan_candidate(
    path: str,
    *,
    allow_package_self: bool = False,
    check_package_ancestors: bool = True,
    require_user_owned: bool = False,
) -> bool:
    """Shared scanner gate for links, document packages and cloud placeholders."""
    try:
        validate_path_sanity(path)
        if has_symlink_component(path):
            return False
        if check_package_ancestors and has_package_ancestor(
            path, include_self=not allow_package_self
        ):
            return False
        if require_user_owned and not is_user_owned_path(path):
            return False
        return not is_cloud_managed_path(path)
    except (OSError, ValueError):
        return False

def is_safe_app_bundle(path: str) -> bool:
    """Allows moving one complete, non-system app bundle to Trash."""
    validate_path_sanity(path)
    resolved = _expand(path)

    if not resolved.endswith(".app") or has_symlink_component(path):
        return False

    if has_package_ancestor(path, include_self=False):
        return False

    for root in APP_BUNDLE_ROOTS:
        root_path = _expand(root)
        try:
            relative = os.path.relpath(resolved, root_path)
        except ValueError:
            continue

        if relative == os.curdir or relative.startswith(os.pardir + os.sep):
            continue

        # Do not allow deleting a nested helper app independently from its host bundle.
        if any(part.endswith(".app") for part in relative.split(os.sep)[:-1]):
            return False
        return True

    return False

def is_safe_to_delete(path: str, *, intent: str = "user_data") -> bool:
    """Returns True only if the path is explicitly allowed and not on the denylist."""
    validate_path_sanity(path)
    resolved = _expand(path)

    if intent == "app_bundle":
        return is_safe_app_bundle(path)
    if intent != "user_data":
        return False

    if has_symlink_component(path):
        return False
    if has_package_ancestor(path):
        return False
    if is_cloud_managed_path(path):
        return False
    if _is_never_delete(resolved):
        return False
    return _is_under_allow_root(resolved)

def is_protected_path(path: str) -> bool:
    """Checks if a path must not be deleted (inverse of is_safe_to_delete)."""
    try:
        return not is_safe_to_delete(path)
    except ValueError:
        return True

# A concurrent second AppleEvent to the same target app, while the OS is
# still resolving the first one's Automation permission dialog, can come back
# as an immediate "user canceled" instead of queuing behind it. Every call
# site that sends Finder or System Events automation requests serializes
# through the matching lock so a background check (Permissions panel) can
# never race a real action (Esvaziar Lixeira, itens de início) against the
# same target.
FINDER_AUTOMATION_LOCK = threading.RLock()
SYSTEM_EVENTS_AUTOMATION_LOCK = threading.RLock()


def run_command(command: list[str], timeout: int = 120) -> tuple:
    """Executa um comando como argv, sem shell, e retorna código/saídas."""
    if not command or not all(isinstance(argument, str) for argument in command):
        return -1, "", "Comando inválido"
    try:
        # A lista de argumentos é encaminhada diretamente, sem interpretação de shell.
        result = subprocess.run(  # nosec B603
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            shell=False,
            timeout=timeout
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", f"Comando expirou após {timeout} segundos"
    except Exception as e:
        return -1, "", str(e)

def read_plist(filepath: str) -> dict:
    """Reads a macOS plist file (XML or binary) and returns its dict representation."""
    if not os.path.exists(filepath):
        return {}
    try:
        with open(filepath, 'rb') as f:
            return plistlib.load(f)
    except Exception:
        return {}

def get_dir_size(
    path: str,
    max_depth: int = 32,
    _depth: int = 0,
    feature: str = "filesystem",
    *,
    report_issues: bool = True,
) -> tuple[int, int]:
    """Calculates total size and file count recursively, with depth limit."""
    total_size = 0
    total_files = 0
    if not os.path.exists(path) or not os.path.isdir(path):
        return 0, 0
    if _depth > max_depth:
        return 0, 0

    try:
        for entry in os.scandir(path):
            try:
                if entry.is_dir(follow_symlinks=False):
                    size, count = get_dir_size(
                        entry.path,
                        max_depth,
                        _depth + 1,
                        feature,
                        report_issues=report_issues,
                    )
                    total_size += size
                    total_files += count
                else:
                    total_size += entry.stat(follow_symlinks=False).st_size
                    total_files += 1
            except (PermissionError, FileNotFoundError, OSError) as exc:
                if report_issues:
                    record_issue(feature, exc, entry.path)
                continue
    except (PermissionError, FileNotFoundError, OSError) as exc:
        if report_issues:
            record_issue(feature, exc, path)

    return total_size, total_files

def measure_and_validate_tree(
    path: str,
    *,
    feature: str = "filesystem",
    require_user_owned: bool = True,
) -> tuple[int, int]:
    """
    Single traversal that enforces the scan gate on every descendant while
    totalling bytes and files. Raises ValueError when any descendant fails the
    gate, so an unsafe tree can never be reported as cleanable.

    This replaces the previous pattern of snapshotting an identity manifest for
    every descendant and then walking the tree again to size it. The manifest
    compared mtimes, which made ordinary cache writes between scan and action
    indistinguishable from tampering and blocked legitimate cleanups. What
    actually protects the operation is re-running this gate at action time:
    the Trash move relocates the tree as one unit without following links, and
    move_to_trash still revalidates the root's identity.
    """
    if not is_safe_scan_candidate(path, require_user_owned=require_user_owned):
        raise ValueError(f"Item fora da política segura: {path}")

    if not os.path.isdir(path):
        return os.lstat(path).st_size, 1

    def fail_walk(error):
        raise error

    total_size = 0
    total_count = 0
    for current, dirnames, filenames in os.walk(
        path, topdown=True, onerror=fail_walk, followlinks=False
    ):
        for name in dirnames:
            child = os.path.join(current, name)
            if not is_safe_scan_candidate(child, require_user_owned=require_user_owned):
                raise ValueError("Conteúdo inseguro encontrado na subárvore.")
        for name in filenames:
            child = os.path.join(current, name)
            if not is_safe_scan_candidate(child, require_user_owned=require_user_owned):
                raise ValueError("Conteúdo inseguro encontrado na subárvore.")
            try:
                total_size += os.lstat(child).st_size
                total_count += 1
            except OSError as exc:
                record_issue(feature, exc, child)

    return total_size, total_count


def run_authorized_command(command_str: str) -> tuple[int, str, str]:
    """Runs a command with root privileges via AppleScript."""
    if "\n" in command_str or "\r" in command_str or "\0" in command_str:
        return -1, "", "Comando rejeitado: caracteres inválidos detectados."

    # Pass the shell command as an AppleScript argv item instead of interpolating it
    # into AppleScript source. Callers must still shell-quote every dynamic argument.
    applescript = (
        "on run argv\n"
        "do shell script (item 1 of argv) with administrator privileges\n"
        "end run"
    )
    return run_command(["/usr/bin/osascript", "-e", applescript, command_str], timeout=300)

def reset_auth_state():
    """Compatibility hook retained for the JavaScript API."""
    return

def move_to_trash(
    path: str,
    *,
    intent: str = "user_data",
    expected_identity=None,
    allow_content_changes: bool = False,
) -> tuple[bool, str]:
    """
    Moves a file or directory through NSFileManager's native Trash API.
    Name collisions and per-volume Trash semantics are handled by macOS.
    """
    try:
        validate_path_sanity(path)
    except ValueError as e:
        return False, str(e)

    if not os.path.lexists(path):
        return False, "Caminho não existe."

    if has_symlink_component(path):
        return False, "Links simbólicos ou ancestrais simbólicos não são removidos automaticamente."

    if not is_safe_to_delete(path, intent=intent):
        return False, f"BLOQUEADO: caminho protegido contra exclusão: {path}"

    if expected_identity is not None:
        try:
            if not path_identity_matches(
                path,
                expected_identity,
                allow_content_changes=allow_content_changes,
            ):
                return False, "Item bloqueado porque mudou desde a varredura."
        except (OSError, ValueError) as exc:
            return False, f"Não foi possível revalidar o item: {exc}"

    try:
        from Foundation import NSURL, NSFileManager

        resolved = _expand(path)
        trash_dir = _expand("~/.Trash")
        if resolved == trash_dir or resolved.startswith(trash_dir + os.sep):
            return False, "Itens que já estão na Lixeira não podem ser enviados para ela novamente."

        source_url = NSURL.fileURLWithPath_(resolved)
        result = NSFileManager.defaultManager().trashItemAtURL_resultingItemURL_error_(
            source_url, None, None
        )

        if isinstance(result, tuple):
            success = bool(result[0])
            resulting_url = result[1] if len(result) > 1 else None
            error = result[2] if len(result) > 2 else None
        else:
            success, resulting_url, error = bool(result), None, None

        if success:
            new_name = os.path.basename(str(resulting_url.path())) if resulting_url else os.path.basename(resolved)
            return True, f"Movido para a Lixeira: {new_name}"
        error_text = str(error or "")
        normalized_error = error_text.casefold()
        if any(
            marker in normalized_error
            for marker in (
                "nscocoaerrordomain code=513",
                "nsosstatuserrordomain code=-5000",
                "afpaccessdenied",
                "insufficient access privileges",
                "permission denied",
                "operation not permitted",
            )
        ):
            return False, (
                "O macOS bloqueou um item protegido ou pertencente a outro usuário. "
                "Ele foi preservado e não será removido automaticamente."
            )
        return False, "O macOS não conseguiu mover um item para a Lixeira. Ele foi preservado."
    except Exception as e:
        return False, f"Falha ao mover para a Lixeira nativa: {e!s}"


def _unique_trash_destination(path: str) -> str:
    """Returns a non-existing path in the current user's local Trash."""
    trash_dir = _expand("~/.Trash")
    basename = os.path.basename(path.rstrip(os.sep))
    stem, suffix = os.path.splitext(basename)

    for index in range(1, 10_000):
        filename = basename if index == 1 else f"{stem} {index}{suffix}"
        candidate = os.path.join(trash_dir, filename)
        if not os.path.lexists(candidate):
            return candidate
    raise RuntimeError("Não foi possível reservar um nome livre na Lixeira.")


def move_app_to_trash_authorized(
    path: str,
    *,
    expected_identity=None,
) -> tuple[bool, str]:
    """Moves one verified top-level app bundle to the user's Trash as admin."""
    try:
        validate_path_sanity(path)
    except ValueError as exc:
        return False, str(exc)

    if not os.path.lexists(path):
        return False, "O aplicativo não existe mais no caminho analisado."
    if has_symlink_component(path) or not is_safe_app_bundle(path):
        return False, "Aplicativo bloqueado pela política de segurança."

    if expected_identity is not None:
        try:
            if snapshot_path_identity(path) != tuple(expected_identity):
                return False, "Aplicativo bloqueado porque mudou desde a análise."
        except (OSError, ValueError) as exc:
            return False, f"Não foi possível revalidar o aplicativo: {exc}"

    resolved = _expand(path)
    trash_dir = _expand("~/.Trash")
    if not os.path.isdir(trash_dir) or has_symlink_component(trash_dir):
        return False, "A Lixeira do usuário não está disponível com segurança."

    try:
        destination = _unique_trash_destination(resolved)
    except RuntimeError as exc:
        return False, str(exc)

    # -n prevents a race-created destination from ever being overwritten.
    command = f"/bin/mv -n {shlex.quote(resolved)} {shlex.quote(destination)}"
    code, stdout, stderr = run_authorized_command(command)

    if code == 0 and not os.path.lexists(resolved) and os.path.lexists(destination):
        return True, f"Movido para a Lixeira com autorização administrativa: {os.path.basename(destination)}"

    if "(-128)" in stderr or "User canceled" in stderr or "cancelado" in stderr.casefold():
        return False, "Desinstalação cancelada na autenticação do macOS."

    detail = stderr or stdout
    if code == 0:
        detail = "o macOS não confirmou a movimentação"
    return False, f"Não foi possível mover o aplicativo para a Lixeira: {detail or 'erro não informado'}"

def get_disk_usage() -> dict:
    """Returns total, used, and free disk space for the root volume."""
    import shutil
    try:
        total, used, free = shutil.disk_usage("/")
        return {
            "total_bytes": total,
            "used_bytes": used,
            "free_bytes": free,
            "total_human": format_size(total),
            "used_human": format_size(used),
            "free_human": format_size(free),
            "percentage": round((used / total) * 100, 1) if total > 0 else 0
        }
    except Exception as exc:
        record_issue("system", exc, "/")
        return {}

def empty_trash() -> tuple[bool, str, bool]:
    """
    Empties the Trash exclusively through Finder automation (official semantics,
    covers per-volume Trash locations). Fails safe when Finder is unavailable:
    returns (success, message, finder_unavailable). The third element tells the
    caller that the separate, explicitly confirmed local permanent deletion is
    the only remaining option — it is NEVER run automatically from here.
    """
    finder_script = (
        'tell application "Finder"\n'
        'set beforeCount to count of items of trash\n'
        'empty trash\n'
        'set afterCount to count of items of trash\n'
        'return (beforeCount as text) & "|" & (afterCount as text)\n'
        'end tell'
    )
    with FINDER_AUTOMATION_LOCK:
        code, stdout, finder_error = run_command(
            ["/usr/bin/osascript", "-e", finder_script], timeout=300
        )
    if code == 0:
        try:
            before_count, after_count = (int(value) for value in stdout.split("|", 1))
        except (TypeError, ValueError):
            before_count, after_count = None, None
        if after_count == 0 and before_count is not None:
            if before_count == 0:
                return True, "A Lixeira já estava vazia.", False
            return True, f"Lixeira esvaziada ({before_count} itens removidos).", False
        return False, (
            "O Finder respondeu, mas não confirmou a Lixeira vazia. "
            "Nenhuma exclusão direta foi executada."
        ), False

    normalized_error = (finder_error or "").casefold()
    if "(-128)" in (finder_error or "") or "user canceled" in normalized_error or "cancelado" in normalized_error:
        return False, "Operação cancelada na autenticação do macOS.", False

    return False, (
        f"O macOS bloqueou o controle do Finder pelo {APP_NAME}, então a Lixeira não foi "
        f"alterada. Autorize o {APP_NAME} em Ajustes do Sistema > Privacidade e Segurança > "
        "Automação > Finder e tente novamente."
    ), True


def empty_trash_local_permanent() -> tuple[bool, str, bool]:
    """
    EXPLICIT fallback: permanently deletes the contents of ~/.Trash only,
    WITHOUT Finder semantics and without touching Trash folders of other
    volumes. Callers must obtain a dedicated second confirmation before
    invoking this, naming the operation "Exclusão permanente local" and the
    exact directory affected. Every failure is accounted for and reported.
    """
    trash_dir = os.path.expanduser("~/.Trash")
    try:
        if not os.path.isdir(trash_dir):
            return True, "A Lixeira local já está vazia.", False
        if has_symlink_component(trash_dir):
            return False, "A Lixeira local não está disponível com segurança.", False

        import shutil
        count = 0
        failures = []
        for item in os.listdir(trash_dir):
            item_path = os.path.join(trash_dir, item)
            try:
                if os.path.isfile(item_path) or os.path.islink(item_path):
                    os.unlink(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
                if not os.path.lexists(item_path):
                    count += 1
                else:
                    failures.append("o item permaneceu na Lixeira")
            except Exception as exc:
                failures.append(str(exc) or exc.__class__.__name__)

        if failures:
            return False, (
                f"Exclusão permanente local parcial: {count} removidos e "
                f"{len(failures)} bloqueados. Primeira falha: {failures[0]}"
            ), False

        return True, (
            f"Exclusão permanente local concluída: {count} itens removidos de ~/.Trash. "
            "Lixeiras de outros volumes não foram tocadas."
        ), False
    except Exception as exc:
        return False, f"Falha na exclusão permanente local: {exc}", False
