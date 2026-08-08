import hashlib
import os
import stat
import threading
from datetime import datetime

from . import progress as operation_progress
from .diagnostics import record_issue
from .utils import clear_path_caches, format_size, is_safe_scan_candidate, move_to_trash

# Default directories to scan for duplicates. Movies and Music are included
# because media is where duplicates are largest, and the large-file scanner
# already covered them.
DEFAULT_SCAN_DIRS = [
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Pictures"),
    os.path.expanduser("~/Movies"),
    os.path.expanduser("~/Music"),
]

# Directories and file types to exclude from duplicate scanning
EXCLUDED_DIRS = {'.ssh', '.gnupg', '.git', '.config', '.Trash', '.venv',
                 'node_modules', '__pycache__', '.DS_Store', 'iCloud Drive (Archive)',
                 'Keychains', 'Mobile Documents', 'CloudDocs'}
EXCLUDED_EXTENSIONS = {'.app', '.dmg', '.pkg', '.iso', '.vmdk', '.sparseimage',
                       '.sqlite', '.sqlite3', '.sqlitedb', '.db', '.keychain-db'}

_SCAN_LOCK = threading.RLock()
_LAST_SCAN_GROUPS = {}


def _open_regular_nofollow(filepath: str):
    """Opens one regular file without following a last-moment symlink swap."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(filepath, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError(f"Item não é um arquivo regular: {filepath}")
        return os.fdopen(descriptor, "rb")
    except Exception:
        os.close(descriptor)
        raise


def get_file_partial_hash(filepath: str) -> str:
    """Reads the first 1KB of a file and returns its SHA-256 hash."""
    hasher = hashlib.sha256()
    try:
        with _open_regular_nofollow(filepath) as f:
            buf = f.read(1024)
            hasher.update(buf)
        return hasher.hexdigest()
    except (OSError, ValueError):
        return ""


def get_file_full_hash(filepath: str, operation: str = "") -> str:
    """Reads the entire file in chunks and returns its SHA-256 hash."""
    hasher = hashlib.sha256()
    try:
        with _open_regular_nofollow(filepath) as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                if operation and operation_progress.is_cancelled(operation):
                    return ""
                hasher.update(chunk)
        return hasher.hexdigest()
    except (OSError, ValueError):
        return ""


def _stable_full_hash(path: str, operation: str) -> tuple[str, tuple | None]:
    """Hashes only a file whose filesystem identity stayed stable throughout."""
    try:
        before = _identity(path)
        full_hash = get_file_full_hash(path, operation)
        after = _identity(path)
    except OSError:
        return "", None
    if not full_hash or before != after:
        return "", None
    return full_hash, after


def scan_duplicates(scan_paths: list | None = None) -> list[dict]:
    """
    Scans the paths for duplicate files.
    Returns a list of duplicate groups.
    Each group: {
        "size_bytes": int,
        "size_human": str,
        "hash": str,
        "files": [ { "name": str, "path": str, "modified": str }, ... ]
    }
    """
    if scan_paths is None:
        scan_paths = DEFAULT_SCAN_DIRS

    clear_path_caches()
    operation_progress.start("duplicates", "Catalogando arquivos…")
    processed = 0

    # Step 1: Find all files and group them by size
    size_groups = {}
    seen_inodes = set()
    for base_path in scan_paths:
        if operation_progress.is_cancelled("duplicates"):
            break
        if (
            not os.path.exists(base_path)
            or not os.path.isdir(base_path)
            or not is_safe_scan_candidate(base_path)
        ):
            continue

        try:
            for root, dirs, files in os.walk(base_path, followlinks=False):
                if operation_progress.is_cancelled("duplicates"):
                    dirs.clear()
                    break
                # Skip excluded directories
                dirs[:] = [
                    d for d in dirs
                    if d not in EXCLUDED_DIRS
                    and not d.startswith('.')
                    and is_safe_scan_candidate(os.path.join(root, d))
                ]
                
                for f in files:
                    processed += 1
                    if processed % 100 == 0:
                        operation_progress.update("duplicates", processed, f"{processed} arquivos catalogados")
                    if operation_progress.is_cancelled("duplicates"):
                        break
                    if f.startswith('.') or os.path.splitext(f)[1].lower() in EXCLUDED_EXTENSIONS:
                        continue

                    file_path = os.path.join(root, f)
                    if os.path.islink(file_path):
                        continue
                    if any(part.endswith('.app') for part in file_path.split(os.sep)):
                        continue
                    # Package directories were pruned before descent. Keep the
                    # per-file gate focused on links and cloud-backed content.
                    if not is_safe_scan_candidate(
                        file_path, check_package_ancestors=False
                    ):
                        continue
                        
                    try:
                        file_stat = os.stat(file_path, follow_symlinks=False)
                        inode_key = (file_stat.st_dev, file_stat.st_ino)
                        if inode_key in seen_inodes:
                            # Multiple hard links are one physical file, not recoverable copies.
                            continue
                        seen_inodes.add(inode_key)
                        size = file_stat.st_size
                        if size > 0: # Ignore empty files
                            size_groups.setdefault(size, []).append(file_path)
                    except (PermissionError, FileNotFoundError, OSError) as exc:
                        record_issue("duplicates", exc, file_path)
                        continue
        except Exception as exc:
            record_issue("duplicates", exc, base_path)
            continue

    # Filter out groups that have only 1 file
    potential_duplicates = {size: paths for size, paths in size_groups.items() if len(paths) > 1}

    # Step 2: For matching sizes, compute partial hash (first 1KB) to filter further
    partial_groups = {}
    operation_progress.update("duplicates", processed, "Calculando assinaturas parciais…")
    for size, paths in potential_duplicates.items():
        for path in paths:
            if operation_progress.is_cancelled("duplicates"):
                break
            p_hash = get_file_partial_hash(path)
            if p_hash:
                # Key is (size, partial_hash)
                partial_groups.setdefault((size, p_hash), []).append(path)

    # Filter out groups that have only 1 file after partial hash
    matching_partials = {key: paths for key, paths in partial_groups.items() if len(paths) > 1}

    # Step 3: Compute full hash to confirm exact duplicates
    final_groups = {}
    operation_progress.update("duplicates", processed, "Confirmando conteúdo com SHA-256…")
    for (size, _partial_hash), paths in matching_partials.items():
        for path in paths:
            if operation_progress.is_cancelled("duplicates"):
                break
            full_hash, identity = _stable_full_hash(path, "duplicates")
            if full_hash and identity and identity[2] == size:
                final_groups.setdefault((size, full_hash), {})[path] = identity

    # Step 4: Format results
    result_groups = []
    for (size, full_hash), stable_files in final_groups.items():
        if len(stable_files) > 1:
            file_list = []
            for path in stable_files:
                try:
                    mtime = os.path.getmtime(path)
                    mtime_str = datetime.fromtimestamp(mtime).strftime("%d/%m/%Y %H:%M")
                except OSError:
                    mtime_str = "N/A"
                    
                file_list.append({
                    "name": os.path.basename(path),
                    "path": path,
                    "modified": mtime_str
                })
                
            result_groups.append({
                "size_bytes": size,
                "size_human": format_size(size),
                "hash": full_hash,
                "files": file_list,
                "_identities": dict(stable_files),
            })

    cancelled = operation_progress.is_cancelled("duplicates")
    if cancelled:
        result_groups = []

    # Sort groups by size descending
    result_groups.sort(key=lambda x: x["size_bytes"], reverse=True)

    with _SCAN_LOCK:
        _LAST_SCAN_GROUPS.clear()
        for group in result_groups:
            # These identities were captured immediately around the full hash.
            # Recording them later would allow a changed file to be accepted as
            # the group's preserved copy with a hash from an older state.
            files = {
                os.path.realpath(path): identity
                for path, identity in group["_identities"].items()
            }
            _LAST_SCAN_GROUPS[group["hash"]] = {
                "size_bytes": group["size_bytes"],
                "files": files,
            }

    for group in result_groups:
        group.pop("_identities", None)

    operation_progress.finish("duplicates", "Cancelado" if cancelled else "Concluído")
    return result_groups

def delete_duplicate_file(path: str) -> tuple[bool, str]:
    """Legacy single-file removal is blocked because it cannot preserve a keeper."""
    return False, "Remoção individual bloqueada: use a operação segura por grupo de duplicados."

def _identity(path: str) -> tuple[int, int, int, int, int]:
    """Cheap unchanged signal: device, inode, size, mtime and ctime."""
    info = os.stat(path, follow_symlinks=False)
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _verify_unchanged(path: str, expected_identity) -> None:
    """Proves a file is byte-identical to what the scan hashed, without I/O."""
    if os.path.islink(path):
        raise ValueError(f"Link simbólico rejeitado: {path}")
    info = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"Item não é um arquivo regular: {path}")
    if _identity(path) != tuple(expected_identity):
        raise ValueError(f"Arquivo foi alterado desde a varredura: {path}")


def _snapshot_file(path: str, expected_hash: str, expected_size: int) -> dict:
    """Full re-read used only on files that are about to be destroyed."""
    if os.path.islink(path):
        raise ValueError(f"Link simbólico rejeitado: {path}")

    file_stat = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(file_stat.st_mode):
        raise ValueError(f"Item não é um arquivo regular: {path}")
    if file_stat.st_size != expected_size:
        raise ValueError(f"Arquivo foi alterado desde a varredura: {path}")

    current_hash = get_file_full_hash(path)
    if not current_hash or current_hash != expected_hash:
        raise ValueError(f"Conteúdo mudou desde a varredura: {path}")

    return {
        "dev": file_stat.st_dev,
        "ino": file_stat.st_ino,
        "mode": file_stat.st_mode,
        "size": file_stat.st_size,
        "mtime_ns": file_stat.st_mtime_ns,
        "ctime_ns": file_stat.st_ctime_ns,
        "disk_bytes": file_stat.st_blocks * 512,
    }

def delete_duplicate_files(selections: list[dict]) -> dict:
    """
    Safely removes duplicate selections produced by the most recent scan.
    Every group must keep at least one revalidated file.
    """
    result = {"bytes_freed": 0, "deleted": 0, "errors": []}
    if not isinstance(selections, list):
        result["errors"].append("Seleção de duplicados inválida.")
        return result

    requested_by_hash = {}
    for item in selections:
        if not isinstance(item, dict):
            result["errors"].append("Entrada de duplicado inválida.")
            continue
        group_hash = str(item.get("hash", ""))
        path = item.get("path")
        if not group_hash or not isinstance(path, str):
            result["errors"].append("Hash ou caminho ausente na seleção.")
            continue
        requested_by_hash.setdefault(group_hash, set()).add(os.path.realpath(path))

    with _SCAN_LOCK:
        scan_snapshot = {
            group_hash: {"size_bytes": group["size_bytes"], "files": dict(group["files"])}
            for group_hash, group in _LAST_SCAN_GROUPS.items()
        }

    for group_hash, targets in requested_by_hash.items():
        group = scan_snapshot.get(group_hash)
        if not group:
            result["errors"].append("Grupo desconhecido ou varredura expirada.")
            continue

        registered = set(group["files"])
        if not targets.issubset(registered):
            result["errors"].append("A seleção contém caminho que não pertence ao grupo varrido.")
            continue

        keepers = registered - targets
        if not keepers:
            result["errors"].append("Grupo bloqueado: pelo menos uma cópia deve ser preservada.")
            continue

        # The surviving copies only need to be proven unchanged since the scan
        # hashed them; device, inode, size and mtime establish that without
        # re-reading gigabytes. Files that are about to be destroyed still get
        # a full SHA-256 re-read below.
        try:
            for keeper in sorted(keepers):
                _verify_unchanged(keeper, group["files"][keeper])
        except (OSError, ValueError) as exc:
            result["errors"].append(
                f"Cópia preservada não pôde ser revalidada, grupo ignorado: {exc}"
            )
            continue

        try:
            snapshots = {
                path: _snapshot_file(path, group_hash, group["size_bytes"])
                for path in sorted(targets)
            }
        except (OSError, ValueError) as exc:
            result["errors"].append(str(exc))
            continue

        for path in sorted(targets):
            previous = snapshots[path]
            try:
                if _identity(path) != (
                    previous["dev"],
                    previous["ino"],
                    previous["size"],
                    previous["mtime_ns"],
                    previous["ctime_ns"],
                ):
                    result["errors"].append(f"Arquivo mudou durante a operação: {path}")
                    continue
            except OSError as exc:
                result["errors"].append(f"Falha ao revalidar {path}: {exc}")
                continue

            expected_identity = (
                previous["dev"],
                previous["ino"],
                previous["mode"],
                previous["size"],
                previous["mtime_ns"],
            )
            success, message = move_to_trash(path, expected_identity=expected_identity)
            if success:
                result["bytes_freed"] += previous["disk_bytes"]
                result["deleted"] += 1
            else:
                result["errors"].append(message)

    return result
