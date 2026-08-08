import math
import os
import threading
import time
from datetime import datetime

from . import progress as operation_progress
from .diagnostics import record_issue
from .utils import (
    clear_path_caches,
    format_size,
    is_safe_scan_candidate,
    move_to_trash,
    snapshot_path_identity,
)

# Standard directories in user's home folder to scan for large files
DEFAULT_SCAN_DIRS = [
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Movies"),
    os.path.expanduser("~/Music"),
    os.path.expanduser("~/Pictures")
]

# Directories to exclude from large file scanning
EXCLUDED_DIRS = {'.ssh', '.gnupg', '.git', '.config', '.Trash', '.venv',
                 'node_modules', '__pycache__', 'iCloud Drive (Archive)',
                 'Keychains', 'Mobile Documents', 'CloudDocs'}
# .dmg and .pkg are deliberately NOT excluded: leftover installers in
# ~/Downloads are the most common large reclaimable file on a Mac, and hiding
# them contradicted the promise of listing every file above a size threshold.
# .app stays out because a bundle is a directory, not a file, and databases
# stay out because they are live application state.
EXCLUDED_EXTENSIONS = {'.app', '.sqlite', '.sqlite3', '.sqlitedb', '.db', '.keychain-db'}

_SCAN_LOCK = threading.RLock()
_LAST_SCAN_FILES = {}

def scan_large_files(
    min_size_mb: float = 100.0, scan_paths: list | None = None
) -> list[dict]:
    """
    Scans the specified directories for files larger than min_size_mb.
    Returns a sorted list of dicts (largest first).
    """
    if (
        not isinstance(min_size_mb, (int, float))
        or isinstance(min_size_mb, bool)
        or not math.isfinite(min_size_mb)
        or not 0 < min_size_mb <= 1_000_000
    ):
        raise ValueError("O limite deve ser maior que 0 e no máximo 1.000.000 MB.")

    if scan_paths is None:
        scan_paths = DEFAULT_SCAN_DIRS
        
    min_size_bytes = int(min_size_mb * 1024 * 1024)
    large_files = []
    processed = 0
    clear_path_caches()
    operation_progress.start("large_files", "Mapeando arquivos…")
    
    for base_path in scan_paths:
        if operation_progress.is_cancelled("large_files"):
            break
        if (
            not os.path.exists(base_path)
            or not os.path.isdir(base_path)
            or not is_safe_scan_candidate(base_path)
        ):
            continue
            
        try:
            for root, dirs, files in os.walk(base_path, followlinks=False):
                if operation_progress.is_cancelled("large_files"):
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
                        operation_progress.update("large_files", processed, f"{processed} arquivos examinados")
                    if operation_progress.is_cancelled("large_files"):
                        break
                    file_path = os.path.join(root, f)
                    ext = os.path.splitext(f)[1].lower()
                    if ext in EXCLUDED_EXTENSIONS:
                        continue

                    if os.path.islink(file_path):
                        continue
                    if any(part.endswith('.app') for part in file_path.split(os.sep)):
                        continue
                    # os.walk already pruned every package directory above.
                    # Avoid repeating AppKit package checks for every file.
                    if not is_safe_scan_candidate(
                        file_path, check_package_ancestors=False
                    ):
                        continue
                        
                    try:
                        stat_info = os.stat(file_path)
                        size_bytes = stat_info.st_size
                        
                        if size_bytes >= min_size_bytes:
                            # Format dates
                            mtime = stat_info.st_mtime
                            atime = stat_info.st_atime
                            
                            mtime_str = datetime.fromtimestamp(mtime).strftime("%d/%m/%Y %H:%M")
                            atime_str = datetime.fromtimestamp(atime).strftime("%d/%m/%Y %H:%M")
                            
                            # Calculate days since last access/modification
                            days_inactive = int((time.time() - mtime) / (24 * 3600))
                            
                            large_files.append({
                                "name": f,
                                "path": file_path,
                                "size_bytes": size_bytes,
                                "size_human": format_size(size_bytes),
                                "modified": mtime_str,
                                "accessed": atime_str,
                                "days_inactive": days_inactive
                            })
                    except (PermissionError, FileNotFoundError, OSError) as exc:
                        record_issue("large_files", exc, file_path)
                        continue
        except Exception as exc:
            record_issue("large_files", exc, base_path)
            continue
            
    cancelled = operation_progress.is_cancelled("large_files")
    if cancelled:
        large_files = []

    # Sort files by size, descending
    large_files.sort(key=lambda x: x["size_bytes"], reverse=True)

    with _SCAN_LOCK:
        _LAST_SCAN_FILES.clear()
        for item in large_files:
            try:
                identity = snapshot_path_identity(item["path"])
            except (OSError, ValueError):
                continue
            _LAST_SCAN_FILES[os.path.realpath(item["path"])] = identity

    operation_progress.finish("large_files", "Cancelado" if cancelled else "Concluído")
    return large_files

def delete_large_file(path: str) -> tuple[bool, str]:
    """
    Moves a large file to the macOS Trash.
    Returns (success, message).
    """
    resolved = os.path.realpath(os.path.expanduser(path))
    with _SCAN_LOCK:
        expected = _LAST_SCAN_FILES.get(resolved)
    if not expected:
        return False, "Item bloqueado: não pertence à varredura de arquivos grandes mais recente."

    try:
        current = snapshot_path_identity(path)
    except (OSError, ValueError) as exc:
        return False, f"Não foi possível revalidar o arquivo: {exc}"

    if current != expected:
        return False, "Arquivo bloqueado porque foi alterado desde a varredura."

    return move_to_trash(path, expected_identity=expected)
