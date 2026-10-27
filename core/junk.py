import concurrent.futures
import glob
import os
import threading

from . import usage as usage_detector
from .browser_cleaner import BROWSER_CACHE_TARGETS
from .diagnostics import record_issue
from .utils import (
    clear_path_caches,
    format_size,
    get_dir_size,
    is_safe_scan_candidate,
    is_safe_to_delete,
    measure_and_validate_tree,
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
#
# "usage" names the tool that owns the cache (process names from `ps`, app
# names/bundle ids from NSWorkspace, substrings of the full command line), so
# the scan can label each category "aberto agora", "usado hoje" or "parado".
# "block_when_running": True additionally refuses to clean the category while
# that tool runs — the Xcode build cache or a Homebrew download in progress
# must not be moved from under the tool.
# "item_running_check": "app_folder" applies the same idea per item, for
# categories whose roots live inside many different apps' data folders.


def _only_directories(path: str) -> bool:
    return os.path.isdir(path)


_NODE_TOOLS = {"process_names": ("node", "npm", "pnpm", "yarn", "bun", "corepack")}
_PYTHON_TOOLS = {"process_names": ("python", "python3", "pip", "pip3", "uv", "pipx")}
_XCODE = {
    "app_names": ("Xcode", "Simulator"),
    "bundle_ids": ("com.apple.dt.Xcode", "com.apple.iphonesimulator"),
    "process_names": ("xcodebuild", "swift-build", "swiftc"),
}

# Cache stores that Electron and other Chromium-based apps keep inside their
# own folder under ~/Library/Application Support/<App>. Everything else in
# that folder (Local Storage, IndexedDB, Session Storage, Preferences,
# databases) is user data and is never listed here.
_ELECTRON_CACHE_SUBDIRS = (
    "Cache",
    "Code Cache",
    "GPUCache",
    "DawnCache",
    "DawnGraphiteCache",
    "DawnWebGPUCache",
    "GraphiteDawnCache",
    "GrShaderCache",
    "ShaderCache",
    "CachedData",
    "CachedExtensionVSIXs",
)

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
    "electron_app_caches": {
        "name": "Caches de Apps Electron",
        "description": (
            "Caches de apps como VS Code, Slack, Discord, Notion e Claude. "
            "Apps abertos ficam de fora; feche-os para limpar."
        ),
        "roots": [
            f"~/Library/Application Support/*/{subdir}" for subdir in _ELECTRON_CACHE_SUBDIRS
        ],
        "cleanable": True,
        "item_running_check": "app_folder",
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
        "name": "Relatórios de Travamento",
        "description": "Relatórios .ips do CrashReporter. Só servem para depuração; o macOS gera novos quando preciso.",
        "roots": ["~/Library/Logs/DiagnosticReports", "~/Library/Logs/CrashReporter"],
        "cleanable": True,
    },
    "xcode_derived_data": {
        "name": "Xcode DerivedData",
        "description": "Arquivos de compilação do Xcode. Recriados no próximo build; bloqueado com o Xcode aberto.",
        "roots": ["~/Library/Developer/Xcode/DerivedData"],
        "cleanable": True,
        "usage": _XCODE,
        "block_when_running": True,
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
    "homebrew_cache": {
        "name": "Cache do Homebrew",
        "description": "Downloads de fórmulas e casks. O brew baixa de novo o que precisar; bloqueado durante uma instalação.",
        "roots": ["~/Library/Caches/Homebrew"],
        "cleanable": True,
        "usage": {"process_names": ("brew",), "command_markers": ("library/homebrew",)},
        "block_when_running": True,
    },
    "npm_cache": {
        "name": "Cache do NPM",
        "description": "Pacotes baixados pelo npm. Recriado na próxima instalação de pacote.",
        "roots": ["~/.npm/_cacache"],
        "cleanable": True,
        "usage": _NODE_TOOLS,
    },
    "pnpm_store": {
        "name": "Cache do pnpm",
        "description": "Store de pacotes do pnpm. Baixado de novo só quando um projeto precisar.",
        "roots": [
            "~/Library/Caches/pnpm",
            "~/Library/pnpm/store",
            "~/.pnpm-store",
            "~/.local/share/pnpm/store",
        ],
        "cleanable": True,
        "usage": _NODE_TOOLS,
    },
    "yarn_cache": {
        "name": "Cache do Yarn",
        "description": "Pacotes baixados pelo Yarn (clássico e Berry). Recriados sob demanda.",
        "roots": ["~/Library/Caches/Yarn", "~/.yarn/berry/cache", "~/.cache/yarn"],
        "cleanable": True,
        "usage": _NODE_TOOLS,
    },
    "bun_cache": {
        "name": "Cache do Bun",
        "description": "Pacotes baixados pelo Bun. Recriados na próxima instalação.",
        "roots": ["~/.bun/install/cache"],
        "cleanable": True,
        "usage": _NODE_TOOLS,
    },
    "pip_cache": {
        "name": "Cache do pip",
        "description": "Pacotes Python cacheados. O pip baixa de novo se precisar.",
        "roots": ["~/Library/Caches/pip", "~/.cache/pip"],
        "cleanable": True,
        "usage": _PYTHON_TOOLS,
    },
    "uv_cache": {
        "name": "Cache do uv",
        "description": "Pacotes e builds cacheados pelo uv (Python). Recriados sob demanda.",
        "roots": ["~/Library/Caches/uv", "~/.cache/uv"],
        "cleanable": True,
        "usage": _PYTHON_TOOLS,
    },
    "cargo_cache": {
        "name": "Cache do Cargo (Rust)",
        "description": "Pacotes .crate baixados e fontes extraídas pelo Cargo. Serão baixados novamente quando necessário.",
        "roots": ["~/.cargo/registry/cache", "~/.cargo/registry/src"],
        "cleanable": True,
        "usage": {"process_names": ("cargo", "rustc", "rust-analyzer")},
    },
    "gradle_cache": {
        "name": "Cache do Gradle",
        "description": "Dependências e artefatos de build baixados pelo Gradle (Android/Java). Bloqueado com um daemon ativo.",
        "roots": ["~/.gradle/caches"],
        "cleanable": True,
        "usage": {"process_names": ("gradle",), "command_markers": ("gradledaemon", "org.gradle")},
        "block_when_running": True,
    },
    "go_build_cache": {
        "name": "Cache de Build do Go",
        "description": "Objetos compilados pelo Go. Recriados no próximo build.",
        "roots": ["~/Library/Caches/go-build"],
        "cleanable": True,
        "usage": {"process_names": ("go", "gopls")},
    },
    "cocoapods_cache": {
        "name": "Cache do CocoaPods",
        "description": "Pods baixados. Recriados no próximo pod install.",
        "roots": ["~/Library/Caches/CocoaPods"],
        "cleanable": True,
        "usage": {"process_names": ("pod",)},
    },
    "playwright_browsers": {
        "name": "Navegadores do Playwright",
        "description": "Navegadores baixados para testes automatizados. Recriados com npx playwright install; bloqueado durante um teste.",
        "roots": ["~/Library/Caches/ms-playwright"],
        "cleanable": True,
        "usage": {"command_markers": ("ms-playwright",)},
        "block_when_running": True,
    },
    # ---- Inventory only: measured, never cleaned automatically ----
    "ai_models": {
        "name": "Modelos de IA Baixados",
        "description": "Inventário: modelos do Hugging Face, Ollama e LM Studio. Remova pela própria ferramenta, se não usar mais.",
        "roots": [
            "~/.cache/huggingface",
            "~/.ollama/models",
            "~/.lmstudio/models",
            "~/.cache/lm-studio/models",
        ],
        "cleanable": False,
        "usage": {
            "process_names": ("ollama", "python", "python3"),
            "app_names": ("Ollama", "LM Studio"),
        },
    },
    "claude_code_data": {
        "name": "Dados do Claude Code",
        "description": "Inventário: transcrições, memória e histórico das sessões do Claude Code. Gerenciado pelo próprio claude.",
        "roots": ["~/.claude"],
        "cleanable": False,
        "usage": {"process_names": ("claude",), "app_names": ("Claude",)},
    },
    "claude_desktop_vm": {
        "name": "Ambientes do Claude Desktop",
        "description": "Inventário: imagens de máquina virtual e runtimes do Claude Desktop. Baixados de novo pelo app quando necessário.",
        "roots": [
            "~/Library/Application Support/Claude/vm_bundles",
            "~/Library/Application Support/Claude/claude-code-vm",
        ],
        "cleanable": False,
        "usage": {"app_names": ("Claude",), "bundle_ids": ("com.anthropic.claudefordesktop",)},
    },
    "codex_data": {
        "name": "Dados do Codex",
        "description": "Inventário: sessões, plugins e runtimes do Codex CLI. Remova pela própria ferramenta.",
        "roots": ["~/.codex", "~/.cache/codex-runtimes"],
        "cleanable": False,
        "usage": {"process_names": ("codex",)},
    },
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
        "usage": _XCODE,
    },
    "xcode_device_support": {
        "name": "Xcode iOS DeviceSupport",
        "description": "Inventário para revisão manual: remova versões antigas pelo Xcode ou Finder.",
        "roots": ["~/Library/Developer/Xcode/iOS DeviceSupport"],
        "cleanable": False,
        "usage": _XCODE,
    },
    "xcode_archives": {
        "name": "Xcode Archives",
        "description": "Inventário para revisão manual: .xcarchive pode ser necessário para distribuição e simbolicação.",
        "roots": ["~/Library/Developer/Xcode/Archives"],
        "cleanable": False,
        "usage": _XCODE,
    },
    "docker_containers": {
        "name": "Docker Data",
        "description": "Inventário para revisão manual: use os comandos oficiais do Docker (ex.: docker system prune).",
        "roots": ["~/Library/Containers/com.docker.docker"],
        "cleanable": False,
        "usage": {"app_names": ("Docker", "Docker Desktop"), "process_names": ("com.docker.backend",)},
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
        f"~/Library/Application Support/{APP_NAME}",
    )
)


def _is_own_data(path: str) -> bool:
    """Keeps the running application's cache, history and open log files in place."""
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


def _cleanable_root_catalog() -> dict:
    """Resolved roots of every cleanable category, keyed by the target's identity."""
    catalog = {}
    for other in JUNK_TARGETS.values():
        if other.get("cleanable", False):
            catalog[id(other)] = {os.path.realpath(root) for root in _expand_roots(other)}
    return catalog


def _delegated_roots(target: dict, catalog: dict | None = None) -> set[str]:
    """
    Roots of the other cleanable categories.

    Named categories such as "Cache do pip" live inside broader ones such as
    "Cache do Usuário". Without this, the parent listed the pip directory as
    one of its own items: the total counted it twice and a cleanup of both
    categories moved it once and then failed on the second attempt. The parent
    now leaves anything that holds another category's root to that category.
    """
    catalog = _cleanable_root_catalog() if catalog is None else catalog
    roots = set()
    for identity, resolved_roots in catalog.items():
        if identity != id(target):
            roots.update(resolved_roots)
    return roots


def _is_delegated(path: str, delegated_roots: set[str]) -> bool:
    resolved = os.path.realpath(path)
    for root in delegated_roots:
        if resolved == root or root.startswith(resolved + os.sep):
            return True
    return False


def _item_running(target: dict, item_path: str, snapshot: dict | None) -> str:
    """Per-item owner check for categories spread across many apps' folders."""
    if target.get("item_running_check") != "app_folder":
        return ""
    # <Application Support>/<App>/<Cache store>/<item>  ->  <App>
    folder = os.path.dirname(os.path.dirname(item_path))
    return usage_detector.app_folder_running(folder, snapshot)


def _category_running(target: dict, snapshot: dict | None) -> str:
    spec = target.get("usage")
    if not target.get("block_when_running") or not spec:
        return ""
    return usage_detector.running_match(
        process_names=spec.get("process_names", ()),
        app_names=spec.get("app_names", ()),
        bundle_ids=spec.get("bundle_ids", ()),
        command_markers=spec.get("command_markers", ()),
        snapshot=snapshot,
    )


def _measure_informative(item_path: str) -> int:
    """Size of an item that is reported but deliberately not registered."""
    if os.path.isdir(item_path):
        return get_dir_size(item_path, feature="junk")[0]
    return os.path.getsize(item_path)


def _scan_target_items(
    target: dict,
    usage_snapshot: dict | None = None,
    root_catalog: dict | None = None,
) -> dict:
    """Measures one target and registers the items eligible for cleaning."""
    cleanable = bool(target.get("cleanable", False))
    require_user_owned = bool(target.get("user_owned", True))
    item_filter = target.get("item_filter")
    browser_roots = _browser_managed_roots() if cleanable else set()
    delegated_roots = _delegated_roots(target, root_catalog) if cleanable else set()

    stats = {
        "size": 0,
        "count": 0,
        "identities": {},
        "skipped": 0,
        "skipped_bytes": 0,
        "deferred": 0,
        "deferred_bytes": 0,
        "delegated": 0,
        "running_bytes": 0,
        "running_apps": set(),
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
                if _is_browser_managed(item_path, browser_roots):
                    stats["deferred"] += 1
                    stats["deferred_bytes"] += _measure_informative(item_path)
                    continue

                if _is_delegated(item_path, delegated_roots):
                    # Counted and cleaned by the category that owns this root.
                    stats["delegated"] += 1
                    continue

                if _is_own_data(item_path):
                    stats["skipped"] += 1
                    stats["skipped_bytes"] += _measure_informative(item_path)
                    continue

                if item_filter and not item_filter(item_path):
                    continue

                owner_running = _item_running(target, item_path, usage_snapshot)
                if owner_running:
                    # The app that owns this cache is open: report the size,
                    # never register the item. clean_target() re-checks.
                    stats["running_apps"].add(owner_running)
                    stats["running_bytes"] += _measure_informative(item_path)
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
                    stats["skipped_bytes"] += _measure_informative(item_path)
                    continue

                # Validate every descendant in the same traversal that measures
                # the candidate. A safe-looking cache directory may contain a
                # document package, cloud placeholder, symlink or foreign-owned
                # item that must keep the whole directory out of auto-cleaning.
                item_size, item_count = measure_and_validate_tree(
                    item_path,
                    feature="junk",
                    require_user_owned=require_user_owned,
                )
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
        "usage": None,
        "blocked": False,
        "blocked_hint": "",
    }


def _deferred_hint(stats: dict) -> str:
    notes = []
    if stats["deferred_bytes"] > 0:
        notes.append(
            f"{format_size(stats['deferred_bytes'])} em caches de navegador: "
            "limpe pela aba Navegadores, com o navegador fechado."
        )
    if stats["running_bytes"] > 0:
        apps = ", ".join(sorted(stats["running_apps"], key=str.casefold))
        notes.append(
            f"{format_size(stats['running_bytes'])} pertencem a apps abertos agora "
            f"({apps}): feche-os e analise de novo para incluir esses caches."
        )
    return " ".join(notes)


def scan_junk() -> dict:
    """Scans all configured junk targets and returns their status."""
    clear_path_caches()
    results = {}
    scan_snapshot = {}
    usage_snapshot = usage_detector.get_snapshot(refresh=True)
    root_catalog = _cleanable_root_catalog()

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
                pool.map(
                    lambda target: _scan_target_items(target, usage_snapshot, root_catalog),
                    JUNK_TARGETS.values(),
                ),
            )
        )

    for key, target in JUNK_TARGETS.items():
        cleanable = bool(target.get("cleanable", False))
        stats = measured[key]
        roots = _expand_roots(target)

        usage_info = usage_detector.tool_usage(target.get("usage"), roots, usage_snapshot)
        blocked = bool(target.get("block_when_running")) and usage_info["state"] == "running"
        blocked_hint = ""
        if blocked:
            blocked_hint = (
                f"{usage_info['running']} está aberto agora. Feche a ferramenta e "
                "analise de novo para limpar esta categoria."
            )

        # Inventory-only categories never feed the cleaning snapshot.
        scan_snapshot[key] = stats["identities"] if cleanable else {}

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
            "deferred": stats["deferred"] + len(stats["running_apps"]),
            "deferred_bytes": stats["deferred_bytes"] + stats["running_bytes"],
            "deferred_hint": _deferred_hint(stats),
            "delegated": stats["delegated"],
            "usage": usage_info,
            "blocked": blocked,
            "blocked_hint": blocked_hint,
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

    # The owner tool may have been opened after the scan. Re-check right before
    # moving anything, exactly like the browser panel does.
    usage_snapshot = usage_detector.get_snapshot(refresh=True)
    running = _category_running(target, usage_snapshot)
    if running:
        result["failed"] = 1
        result["errors"].append(
            f"{target['name']} está em uso ({running} aberto). "
            "Feche a ferramenta e analise novamente antes de limpar."
        )
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
            owner_running = _item_running(target, item_path, usage_snapshot)
            if owner_running:
                result["failed"] += 1
                result["errors"].append(
                    f"{owner_running} está aberto agora; feche o app antes de limpar seus caches."
                )
                continue
            if not is_safe_scan_candidate(
                item_path, require_user_owned=require_user_owned
            ) or not is_safe_to_delete(item_path):
                result["failed"] += 1
                result["errors"].append("Item bloqueado pela política de segurança.")
                continue

            # Re-run the complete subtree gate immediately before the Trash
            # move. Cache contents may change after the scan, but newly added
            # protected content must make the operation fail closed.
            item_size, item_count = measure_and_validate_tree(
                item_path,
                feature="junk",
                require_user_owned=require_user_owned,
            )

            success, msg = move_to_trash(
                item_path,
                expected_identity=expected_identity,
                allow_content_changes=True,
                feature="junk",
                size_bytes=item_size,
                file_count=item_count,
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
