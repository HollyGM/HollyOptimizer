import concurrent.futures
import glob
import os
import threading

from .browser_cleaner import BROWSER_CACHE_TARGETS
from .diagnostics import record_issue
from .utils import (
    clear_path_caches,
    format_size,
    get_dir_size,
    is_safe_scan_candidate,
    is_safe_to_delete,
    move_to_trash,
    run_command,
    snapshot_path_identity,
)
from .version import APP_NAME, BUNDLE_IDENTIFIER

# Junk targets are described by one or more roots. A root may be a literal path
# or a glob, which is what makes per-application sandbox caches reachable:
# every sandboxed app keeps its cache inside its own container, so there is no
# single directory to point at.
#
# "cleanable": False marks inventory-only categories: they are measured and
# shown for manual review, but clean_target() refuses to touch them.
# "user_owned": False marks system locations that are only ever measured.


def _only_directories(path: str) -> bool:
    return os.path.isdir(path)


JUNK_TARGETS = {
    "user_cache": {
        "name": "Cache do Usuário",
        "description": "Arquivos temporários criados por aplicativos em execução.",
        "roots": ["~/Library/Caches"],
        "cleanable": True,
    },
    "container_caches": {
        "name": "Caches de Apps Sandboxed",
        "description": "Caches dentro dos contêineres de apps da App Store e do sistema.",
        "roots": ["~/Library/Containers/*/Data/Library/Caches"],
        "cleanable": True,
    },
    "group_container_caches": {
        "name": "Caches de Grupos de Apps",
        "description": "Caches compartilhados entre um app e suas extensões.",
        "roots": ["~/Library/Group Containers/*/Library/Caches"],
        "cleanable": True,
    },
    "http_storages": {
        "name": "Cache HTTP por Aplicativo",
        "description": "Respostas HTTP cacheadas por app. Cookies (.binarycookies) são preservados.",
        "roots": ["~/Library/HTTPStorages"],
        "cleanable": True,
        # Cookies live as files next to the cache directories; only directories
        # are eligible. The central path policy blocks .binarycookies as well.
        "item_filter": _only_directories,
    },
    "webkit_rule_lists": {
        "name": "Regras Compiladas do WebKit",
        "description": "Listas de bloqueio compiladas, recriadas sob demanda. Dados de site preservados.",
        "roots": ["~/Library/WebKit/*/ContentRuleLists"],
        "cleanable": True,
    },
    "saved_app_state": {
        "name": "Estado de Janelas Salvo",
        "description": "Posição e restauração de janelas. Recriado quando o app abre novamente.",
        "roots": ["~/Library/Saved Application State"],
        "cleanable": True,
    },
    "user_logs": {
        "name": "Logs de Usuário",
        "description": "Registros de eventos salvos por aplicativos em execução.",
        "roots": ["~/Library/Logs"],
        "cleanable": True,
    },
    "crash_reports": {
        "name": "Relatórios de Falha",
        "description": "Relatórios de travamento antigos guardados pelo CrashReporter.",
        "roots": ["~/Library/Application Support/CrashReporter"],
        "cleanable": True,
    },
    "xcode_derived_data": {
        "name": "Xcode DerivedData",
        "description": "Arquivos de compilação do Xcode (seguro para deletar, será recriado no próximo build).",
        "roots": ["~/Library/Developer/Xcode/DerivedData"],
        "cleanable": True,
    },
    "ios_software_updates": {
        "name": "Atualizações de iOS Baixadas",
        "description": "Imagens .ipsw baixadas para restaurar iPhone/iPad. Podem ser baixadas de novo.",
        "roots": [
            "~/Library/iTunes/iPhone Software Updates",
            "~/Library/iTunes/iPad Software Updates",
        ],
        "cleanable": True,
    },
    "mail_downloads": {
        "name": "Downloads do Mail",
        "description": "Cópias locais de anexos de e-mail abertos.",
        "roots": ["~/Library/Containers/com.apple.mail/Data/Library/Mail Downloads"],
        "cleanable": True,
    },
    "npm_cache": {
        "name": "Cache do NPM",
        "description": "Pacotes baixados via Node Package Manager.",
        "roots": ["~/.npm/_cacache"],
        "cleanable": True,
    },
    "pip_cache": {
        "name": "Cache do PIP",
        "description": "Pacotes Python cacheados.",
        "roots": ["~/Library/Caches/pip"],
        "cleanable": True,
    },
    # ---- Inventory only: measured, never cleaned automatically ----
    "ios_backups": {
        "name": "Backups de iPhone/iPad",
        "description": "Inventário: backups locais insubstituíveis. Remova pelo Finder após conferir.",
        "roots": ["~/Library/Application Support/MobileSync/Backup"],
        "cleanable": False,
    },
    "coresimulator": {
        "name": "Simuladores do Xcode",
        "description": "Inventário para revisão manual: use 'xcrun simctl delete unavailable'.",
        "roots": ["~/Library/Developer/CoreSimulator/Devices"],
        "cleanable": False,
    },
    "xcode_device_support": {
        "name": "Xcode iOS DeviceSupport",
        "description": "Inventário para revisão manual: remova versões antigas pelo Xcode ou Finder.",
        "roots": ["~/Library/Developer/Xcode/iOS DeviceSupport"],
        "cleanable": False,
    },
    "xcode_archives": {
        "name": "Xcode Archives",
        "description": "Inventário para revisão manual: .xcarchive pode ser necessário para distribuição e simbolicação.",
        "roots": ["~/Library/Developer/Xcode/Archives"],
        "cleanable": False,
    },
    "docker_containers": {
        "name": "Docker Data",
        "description": "Inventário para revisão manual: use os comandos oficiais do Docker (ex.: docker system prune).",
        "roots": ["~/Library/Containers/com.docker.docker"],
        "cleanable": False,
    },
    "system_caches": {
        "name": "Caches do Sistema",
        "description": f"Inventário: exige administrador e fica fora da limpeza automática do {APP_NAME}.",
        "roots": ["/Library/Caches"],
        "cleanable": False,
        "user_owned": False,
    },
    "system_logs": {
        "name": "Logs do Sistema",
        "description": "Inventário: exige administrador. O macOS já rotaciona estes registros.",
        "roots": ["/private/var/log"],
        "cleanable": False,
        "user_owned": False,
    },
}

_SCAN_LOCK = threading.RLock()
_LAST_SCAN_ITEMS = {}

_OWN_DATA_ROOTS = tuple(
    os.path.realpath(os.path.expanduser(path))
    for path in (
        f"~/Library/Caches/{APP_NAME}",
        f"~/Library/Caches/{BUNDLE_IDENTIFIER}",
        f"~/Library/Logs/{APP_NAME}",
    )
)


def _is_own_data(path: str) -> bool:
    """Keeps the running application's cache and open log files in place."""
    resolved = os.path.realpath(path)
    return any(
        resolved == root or resolved.startswith(root + os.sep)
        for root in _OWN_DATA_ROOTS
    )


def _expand_roots(target: dict) -> list[str]:
    """Resolves literal and glob roots to existing directories."""
    resolved = []
    for entry in target["roots"]:
        expanded = os.path.expanduser(entry)
        if any(ch in expanded for ch in "*?["):
            resolved.extend(sorted(glob.glob(expanded)))
        else:
            resolved.append(expanded)
    return [path for path in resolved if os.path.isdir(path)]


def _browser_managed_roots() -> set[str]:
    """
    Cache roots owned by the dedicated browser panel.

    The browser cleaner refuses to touch a cache while its browser is running.
    The junk cleaner used to register the same directories as ordinary children
    of ~/Library/Caches, which let a one-click cleanup trash a live browser's
    cache and silently defeat that protection. These paths are therefore
    delegated: measured and reported here, but only ever removed from the
    Navegadores tab, where the browser-is-closed check applies.
    """
    roots = set()
    for target in BROWSER_CACHE_TARGETS.values():
        for root in target["roots"]:
            roots.add(os.path.realpath(os.path.expanduser(root)))
    return roots


def _is_browser_managed(path: str, browser_roots: set[str]) -> bool:
    resolved = os.path.realpath(path)
    for root in browser_roots:
        if resolved == root or resolved.startswith(root + os.sep) or root.startswith(resolved + os.sep):
            return True
    return False


def _scan_target_items(target: dict) -> dict:
    """Measures one target and registers the items eligible for cleaning."""
    cleanable = bool(target.get("cleanable", False))
    require_user_owned = bool(target.get("user_owned", True))
    item_filter = target.get("item_filter")
    browser_roots = _browser_managed_roots() if cleanable else set()

    stats = {
        "size": 0,
        "count": 0,
        "identities": {},
        "skipped": 0,
        "skipped_bytes": 0,
        "deferred": 0,
        "deferred_bytes": 0,
    }

    for root in _expand_roots(target):
        # Inventory-only categories are measured whole: they are never removed,
        # so there is no need to gate or register their individual children.
        if not cleanable:
            # System inventory is best-effort. /Library is intentionally outside
            # automatic cleaning and often denies ordinary-user reads; that is
            # expected, not a failure of the user's junk scan. User-owned
            # inventory (Docker, Xcode, backups) still reports TCC denials so the
            # interface can guide the user to Full Disk Access when it matters.
            size, count = get_dir_size(
                root,
                feature="junk",
                report_issues=require_user_owned,
            )
            stats["size"] += size
            stats["count"] += count
            continue

        try:
            names = os.listdir(root)
        except (PermissionError, FileNotFoundError, OSError) as exc:
            record_issue("junk", exc, root)
            continue

        for name in names:
            item_path = os.path.join(root, name)
            try:
                if os.path.isdir(item_path):
                    item_size, item_count = get_dir_size(item_path, feature="junk")
                else:
                    item_size, item_count = os.path.getsize(item_path), 1

                if _is_browser_managed(item_path, browser_roots):
                    stats["deferred"] += 1
                    stats["deferred_bytes"] += item_size
                    continue

                if _is_own_data(item_path):
                    stats["skipped"] += 1
                    stats["skipped_bytes"] += item_size
                    continue

                if item_filter and not item_filter(item_path):
                    continue

                if not is_safe_scan_candidate(
                    item_path, require_user_owned=require_user_owned
                ) or not is_safe_to_delete(item_path):
                    # Previously these vanished with no trace. A cache folder
                    # whose bundle id ends in a package-like suffix (.app,
                    # .service) is treated as a document package by macOS and
                    # was silently skipped, so the reported total quietly
                    # understated the disk.
                    stats["skipped"] += 1
                    stats["skipped_bytes"] += item_size
                    continue

                identity = snapshot_path_identity(item_path)
                stats["size"] += item_size
                stats["count"] += item_count
                stats["identities"][os.path.realpath(item_path)] = identity
            except (PermissionError, FileNotFoundError, OSError, ValueError) as exc:
                record_issue("junk", exc, item_path)
                stats["skipped"] += 1

    return stats


def _time_machine_snapshots() -> dict:
    """
    Lists APFS local snapshots, the most common cause of a 'full' startup disk.

    Reported as inventory only: removing a snapshot is irreversible and cannot
    go through the Trash, and these snapshots are the only local rollback point
    until the next Time Machine backup completes. macOS thins them on its own
    under disk pressure.
    """
    code, stdout, _ = run_command(["/usr/bin/tmutil", "listlocalsnapshots", "/"], timeout=30)
    snapshots = []
    if code == 0:
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("com.apple.TimeMachine."):
                snapshots.append(line)

    if snapshots:
        description = (
            f"{len(snapshots)} snapshot(s) local(is) ocupando espaço reportado como livre. "
            "Para liberar: 'tmutil thinlocalsnapshots / 21474836480 4' no Terminal."
        )
    else:
        description = "Nenhum snapshot local do Time Machine no volume de inicialização."

    return {
        "name": "Snapshots do Time Machine",
        "description": description,
        "path": "/",
        "size_bytes": 0,
        "size_human": "—",
        "count": len(snapshots),
        "cleanable": False,
        "skipped": 0,
        "skipped_bytes": 0,
        "deferred": 0,
        "deferred_bytes": 0,
        "deferred_hint": "",
    }


def scan_junk() -> dict:
    """Scans all configured junk targets and returns their status."""
    clear_path_caches()
    results = {}
    scan_snapshot = {}

    # Every target walks a different subtree, so the scan is bound by directory
    # I/O and by the ObjC bridge calls in the safety gate, not by the GIL. Run
    # sequentially the scan used one core out of ten and took ~4.5 s; the pool
    # overlaps the waits. Concurrency is confined to measurement — the scan only
    # reads, and each worker returns its own stats dict, so no shared state is
    # mutated here. Cleaning stays strictly sequential in clean_target().
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(8, len(JUNK_TARGETS)), thread_name_prefix="junk-scan"
    ) as pool:
        measured = dict(
            zip(
                JUNK_TARGETS,
                pool.map(_scan_target_items, JUNK_TARGETS.values()),
            )
        )

    for key, target in JUNK_TARGETS.items():
        cleanable = bool(target.get("cleanable", False))
        stats = measured[key]
        roots = _expand_roots(target)

        # Inventory-only categories never feed the cleaning snapshot.
        scan_snapshot[key] = stats["identities"] if cleanable else {}

        deferred_hint = ""
        if stats["deferred_bytes"] > 0:
            deferred_hint = (
                f"{format_size(stats['deferred_bytes'])} em caches de navegador: "
                "limpe pela aba Navegadores, com o navegador fechado."
            )

        results[key] = {
            "name": target["name"],
            "description": target["description"],
            "path": roots[0] if roots else os.path.expanduser(target["roots"][0]),
            "roots": roots,
            "size_bytes": stats["size"],
            "size_human": format_size(stats["size"]),
            "count": stats["count"],
            "cleanable": cleanable,
            "skipped": stats["skipped"],
            "skipped_bytes": stats["skipped_bytes"],
            "skipped_human": format_size(stats["skipped_bytes"]),
            "deferred": stats["deferred"],
            "deferred_bytes": stats["deferred_bytes"],
            "deferred_hint": deferred_hint,
        }

    results["time_machine_snapshots"] = _time_machine_snapshots()
    scan_snapshot["time_machine_snapshots"] = {}

    with _SCAN_LOCK:
        _LAST_SCAN_ITEMS.clear()
        _LAST_SCAN_ITEMS.update(scan_snapshot)
    return results


def clean_target(target_key: str) -> dict:
    """Moves only items captured by the latest scan and reports partial failures."""
    result = {"bytes_moved": 0, "files_moved": 0, "moved": 0, "failed": 0, "errors": []}
    if target_key not in JUNK_TARGETS:
        result["errors"].append("Categoria de lixo inválida.")
        result["failed"] = 1
        return result

    target = JUNK_TARGETS[target_key]
    if not target.get("cleanable", False):
        result["errors"].append(
            f"{target['name']} é apenas inventário para revisão manual "
            "e não participa da limpeza automática."
        )
        result["failed"] = 1
        return result

    with _SCAN_LOCK:
        registered = dict(_LAST_SCAN_ITEMS.get(target_key, {}))
    if not registered:
        return result

    require_user_owned = bool(target.get("user_owned", True))
    browser_roots = _browser_managed_roots()

    for item_path, expected_identity in registered.items():
        try:
            if _is_browser_managed(item_path, browser_roots):
                result["failed"] += 1
                result["errors"].append(
                    "Cache de navegador só é removido pela aba Navegadores."
                )
                continue
            if not is_safe_scan_candidate(
                item_path, require_user_owned=require_user_owned
            ) or not is_safe_to_delete(item_path):
                result["failed"] += 1
                result["errors"].append("Item bloqueado pela política de segurança.")
                continue

            if os.path.isdir(item_path):
                item_size, item_count = get_dir_size(item_path, feature="junk")
            else:
                try:
                    item_size = os.path.getsize(item_path)
                except OSError as exc:
                    record_issue("junk", exc, item_path)
                    item_size = 0
                item_count = 1

            success, msg = move_to_trash(
                item_path,
                expected_identity=expected_identity,
                allow_content_changes=True,
            )
            if success:
                result["bytes_moved"] += item_size
                result["files_moved"] += item_count
                result["moved"] += 1
            else:
                result["failed"] += 1
                result["errors"].append(msg)
        except Exception as exc:
            record_issue("junk", exc, item_path)
            result["failed"] += 1
            result["errors"].append("Falha inesperada ao mover um item para a Lixeira.")

    return result
