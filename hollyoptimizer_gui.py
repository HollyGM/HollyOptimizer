#!/usr/bin/env python3
import concurrent.futures
import os
import sys
import threading

import webview

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import ai_assistant
from core import progress as operation_progress
from core.apps import delete_leftover, scan_leftovers
from core.browser_cleaner import (
    BROWSER_CACHE_TARGETS,
    clean_browser_cache,
    scan_browser_caches,
)
from core.dependencies import (
    check_homebrew,
    check_npm,
    check_pip,
    clean_homebrew,
    remove_dependency,
)
from core.diagnostics import configure_logging, consume_issues
from core.duplicates import delete_duplicate_files, scan_duplicates
from core.junk import clean_target, scan_junk
from core.large_files import delete_large_file, scan_large_files
from core.memory import (
    get_memory_stats,
    get_top_ram_processes,
    kill_process,
    optimize_ram,
)
from core.network import flush_dns, run_network_diagnostic
from core.permissions import open_permission_setting, run_permissions_audit
from core.security_audit import open_security_setting, run_security_audit
from core.silicon import get_hardware_profile, scan_app_architectures
from core.startup import (
    STARTUP_DIRS,
    remove_login_item,
    scan_startup,
    toggle_startup_item,
)
from core.uninstaller import (
    get_app_icon_base64,
    get_app_related_files,
    list_installed_apps,
    uninstall_app,
)
from core.utils import (
    empty_trash,
    empty_trash_local_permanent,
    get_disk_usage,
    is_safe_app_bundle,
    is_safe_to_delete,
    reset_auth_state,
    validate_path_sanity,
)
from core.version import APP_DISPLAY_NAME

_executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=2, thread_name_prefix="hollyoptimizer"
)
_OPERATION_LOCK = threading.RLock()
_ACTIVE_HEAVY_OPERATIONS = set()

ALLOWED_PATH_ROOTS = [
    os.path.expanduser("~/Library"),
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Pictures"),
    os.path.expanduser("~/Movies"),
    os.path.expanduser("~/Music"),
    os.path.expanduser("~/Applications"),
    "/Applications",
]

STARTUP_ROOTS = [info["path"] for info in STARTUP_DIRS.values()]
APP_ROOTS = [os.path.expanduser("~/Applications"), "/Applications"]

def _is_within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath((path, os.path.realpath(root))) == os.path.realpath(root)
    except ValueError:
        return False


def _run_heavy(operation: str, fn, *args, **kwargs):
    """Runs CPU/IO-heavy work off the WebView bridge thread."""
    with _OPERATION_LOCK:
        if operation in _ACTIVE_HEAVY_OPERATIONS:
            raise RuntimeError("Esta operação já está em andamento.")
        _ACTIVE_HEAVY_OPERATIONS.add(operation)

    future = _executor.submit(fn, *args, **kwargs)
    def release(_future=None):
        with _OPERATION_LOCK:
            _ACTIVE_HEAVY_OPERATIONS.discard(operation)

    try:
        result = future.result(timeout=600)
        release()
        return result
    except concurrent.futures.TimeoutError as exc:
        if future.cancel():
            release()
        else:
            future.add_done_callback(release)
        raise RuntimeError("A operação excedeu o limite de 10 minutos; o resultado foi descartado.") from exc
    except Exception:
        release()
        raise


def _validate_path(path: str, *, allow_apps: bool = False) -> str:
    """Validates path exists, is allowed, and is safe to delete."""
    validate_path_sanity(path)
    if not is_safe_to_delete(path):
        raise ValueError(f"Caminho protegido contra exclusão: {path}")
    resolved = os.path.realpath(os.path.expanduser(path))
    if not os.path.exists(resolved):
        raise ValueError(f"Caminho não existe: {path}")

    roots = list(ALLOWED_PATH_ROOTS)
    if allow_apps:
        roots.extend(APP_ROOTS)

    if not any(_is_within(resolved, root) for root in roots):
        raise ValueError(f"Caminho fora das raízes permitidas: {path}")

    return resolved


def _validate_startup_path(filepath: str) -> str:
    validate_path_sanity(filepath)
    resolved = os.path.realpath(os.path.expanduser(filepath))
    if not os.path.exists(resolved):
        raise ValueError(f"Arquivo não encontrado: {filepath}")
    if not any(_is_within(resolved, root) for root in STARTUP_ROOTS):
        raise ValueError(f"LaunchAgent/Daemon fora das pastas permitidas: {filepath}")
    if not (resolved.endswith(".plist") or resolved.endswith(".plist.disabled")):
        raise ValueError("Apenas arquivos .plist de inicialização são permitidos.")
    return resolved


def _validate_app_path(app_path: str) -> str:
    validate_path_sanity(app_path)
    resolved = os.path.realpath(os.path.expanduser(app_path))
    if not resolved.endswith(".app") or not os.path.isdir(resolved):
        raise ValueError("Caminho de aplicativo inválido.")
    if not is_safe_app_bundle(app_path):
        raise ValueError("Aplicativo fora de /Applications ou ~/Applications.")
    return resolved


class JsApi:
    """API exposed to Javascript inside WKWebView."""

    def scan_junk(self) -> dict:
        return _run_heavy("junk", scan_junk)

    def clean_junk(self, key: str) -> dict:
        # clean_target returns a structured, non-destructive failure for an
        # unknown or inventory-only category. Do not turn a stale/malformed UI
        # selection into an exception that aborts every other selected cleanup.
        return clean_target(key)

    def scan_leftovers(self) -> list:
        return _run_heavy("leftovers", scan_leftovers)

    def delete_leftover(self, path: str) -> tuple:
        _validate_path(path)
        return delete_leftover(path)

    def check_brew(self) -> dict:
        return _run_heavy("brew_check", check_homebrew)

    def check_npm(self) -> dict:
        return _run_heavy("npm_check", check_npm)

    def check_pip(self) -> dict:
        return _run_heavy("pip_check", check_pip)

    def clean_homebrew(self, autoremove: bool, cleanup: bool) -> list:
        return _run_heavy("brew_clean", clean_homebrew, clean_orphans=autoremove, clean_cache=cleanup)

    def remove_dependency(self, manager: str, package: str) -> dict:
        return _run_heavy("dependency_remove", remove_dependency, manager, package)

    def scan_startup(self) -> list:
        return _run_heavy("startup", scan_startup)

    def toggle_startup(self, filepath: str, disable: bool) -> tuple:
        _validate_startup_path(filepath)
        return toggle_startup_item(filepath, disable)

    def remove_login_item(self, name: str) -> tuple:
        # Membership in the latest scan is enforced inside remove_login_item;
        # a login item has no filesystem path to validate here.
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Nome de item de início inválido.")
        return remove_login_item(name)

    def scan_large_files(self, min_size_mb: float) -> list:
        return _run_heavy("large_files", scan_large_files, min_size_mb=min_size_mb)

    def delete_large_file(self, path: str) -> tuple:
        _validate_path(path)
        return delete_large_file(path)

    def list_installed_apps(self) -> list:
        return _run_heavy("installed_apps", list_installed_apps)

    def get_app_icon_base64(self, app_path: str, bundle_id: str) -> str:
        _validate_app_path(app_path)
        return get_app_icon_base64(app_path, bundle_id)

    def get_app_related_files(self, app_path: str, bundle_id: str, app_name: str) -> list:
        _validate_app_path(app_path)
        return get_app_related_files(app_path, bundle_id, app_name)

    def uninstall_app(self, app_path: str, related_paths: list) -> tuple:
        _validate_app_path(app_path)
        validated_related = []
        for path in (related_paths or []):
            validated_related.append(_validate_path(path))
        return uninstall_app(app_path, validated_related)

    def scan_duplicates(self) -> list:
        return _run_heavy("duplicates", scan_duplicates)

    def delete_duplicate_files(self, selections: list) -> dict:
        validated = []
        for item in (selections or []):
            if not isinstance(item, dict):
                raise ValueError("Seleção de duplicado inválida.")
            path = _validate_path(item.get("path"))
            validated.append({"hash": item.get("hash"), "path": path})
        return delete_duplicate_files(validated)

    def flush_dns(self) -> tuple:
        return flush_dns()

    def run_network_diagnostic(self) -> dict:
        return run_network_diagnostic()

    def get_memory_stats(self) -> dict:
        return get_memory_stats()

    def get_top_ram_processes(self) -> list:
        return get_top_ram_processes()

    def kill_ram_process(self, pid: int) -> tuple:
        return kill_process(pid)

    def optimize_ram(self) -> tuple:
        return optimize_ram()

    def scan_browser_caches(self) -> dict:
        return _run_heavy("browser_caches", scan_browser_caches)

    def clean_browser_cache(self, browser_key: str) -> dict:
        if browser_key not in BROWSER_CACHE_TARGETS:
            raise ValueError(f"Navegador inválido: {browser_key}")
        return clean_browser_cache(browser_key)

    def run_security_audit(self) -> dict:
        return _run_heavy("security_audit", run_security_audit)

    def get_hardware_profile(self) -> dict:
        return get_hardware_profile()

    def scan_app_architectures(self) -> dict:
        # Auditoria somente leitura: não existe ação correspondente de escrita.
        return _run_heavy("silicon_audit", scan_app_architectures)

    def open_security_setting(self, check_id: str) -> tuple:
        return open_security_setting(check_id)

    def run_permissions_audit(self) -> dict:
        return _run_heavy("permissions_audit", run_permissions_audit)

    def open_permission_setting(self, check_id: str) -> tuple:
        return open_permission_setting(check_id)

    def ai_summary_available(self) -> bool:
        return ai_assistant.is_available()

    def get_ai_summary(self, facts: str) -> dict:
        if not isinstance(facts, str):
            raise ValueError("Resumo inválido.")
        return _run_heavy("ai_summary", ai_assistant.summarize, facts)

    def reset_auth_state(self) -> None:
        reset_auth_state()

    def get_scan_issues(self, feature: str = "") -> dict:
        return consume_issues(feature)

    def get_operation_progress(self, operation: str) -> dict:
        return operation_progress.snapshot(operation)

    def cancel_operation(self, operation: str) -> bool:
        return operation_progress.cancel(operation)

    def get_disk_usage(self) -> dict:
        return get_disk_usage()

    def empty_trash(self) -> tuple:
        return _run_heavy("empty_trash", empty_trash)

    def empty_trash_local_permanent(self) -> tuple:
        # Destructive by design; the GUI must collect a dedicated second
        # confirmation naming "Exclusão permanente local" before calling this.
        return _run_heavy("empty_trash", empty_trash_local_permanent)


def main():
    configure_logging()
    if hasattr(sys, '_MEIPASS'):
        current_dir = sys._MEIPASS
    else:
        current_dir = os.path.dirname(os.path.abspath(__file__))

    html_path = os.path.join(current_dir, "gui", "index.html")
    icon_path = os.path.join(current_dir, "hollyoptimizer_app_icon.png")
    ai_assistant.configure(current_dir)

    if "--self-test" in sys.argv:
        from core.self_test import run_self_test
        raise SystemExit(run_self_test(current_dir))

    if not os.path.exists(html_path):
        print(f"Erro: Arquivos de interface gráfica não localizados em {html_path}")
        sys.exit(1)

    api = JsApi()
    webview.create_window(
        title=APP_DISPLAY_NAME,
        url=html_path,
        js_api=api,
        width=1050,
        height=720,
        resizable=True,
        min_size=(950, 650)
    )

    try:
        webview.start(
            debug=False,
            icon=icon_path if os.path.isfile(icon_path) else None,
        )
    finally:
        _executor.shutdown(wait=False, cancel_futures=True)


if __name__ == "__main__":
    main()
