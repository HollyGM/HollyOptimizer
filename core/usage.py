"""
Detecção de uso: o que está aberto agora e o que foi usado recentemente.

Antes de oferecer um cache para limpeza, vale saber se a ferramenta dona dele
está rodando (o Xcode com o DerivedData aberto, um app Electron com o cache
em uso) e há quanto tempo ela foi usada. Cada categoria recebe um selo —
"aberto agora", "usado hoje" ou "parado há N dias" — e as categorias
sensíveis ficam bloqueadas enquanto a ferramenta está em execução.

Tudo aqui é somente leitura: a lista de aplicativos vem do NSWorkspace e a de
processos do ``ps``; o último uso vem do mtime das próprias pastas.
"""

import os
import threading
import time

from .utils import run_command

_LOCK = threading.RLock()
_SNAPSHOT = {"expires_at": 0.0, "value": None}
# Uma varredura consulta dezenas de categorias em sequência; o retrato dos
# processos vale por alguns segundos para não disparar um `ps` por categoria.
_SNAPSHOT_TTL_SECONDS = 3.0
_DAY_SECONDS = 24 * 3600

# Arquivos que apps baseados em Chromium (Electron incluído) criam na pasta de
# dados enquanto estão abertos. A presença deles é o sinal mais direto de que
# o cache ao lado está em uso.
_CHROMIUM_LOCK_FILES = ("SingletonLock", "SingletonSocket", "SingletonCookie")


def normalize(value: str) -> str:
    return "".join(ch for ch in str(value or "").casefold() if ch.isalnum())


def _gui_applications() -> list[dict]:
    try:
        from AppKit import NSWorkspace

        result = []
        for app in NSWorkspace.sharedWorkspace().runningApplications():
            result.append(
                {
                    "name": str(app.localizedName() or ""),
                    "bundle_id": str(app.bundleIdentifier() or ""),
                    "pid": int(app.processIdentifier()),
                }
            )
        return result
    except Exception:
        return []


def _build_snapshot() -> dict:
    apps = _gui_applications()
    app_names = {normalize(app["name"]) for app in apps if app["name"]}
    bundle_ids = {app["bundle_id"].casefold() for app in apps if app["bundle_id"]}
    bundle_tails = {normalize(bundle.rsplit(".", 1)[-1]) for bundle in bundle_ids}

    executables = set()
    code, stdout, _ = run_command(["/bin/ps", "-A", "-o", "comm="], timeout=10)
    if code == 0:
        for line in stdout.splitlines():
            line = line.strip()
            if line:
                executables.add(os.path.basename(line).casefold())

    commands = []
    code, stdout, _ = run_command(["/bin/ps", "-A", "-o", "command="], timeout=10)
    if code == 0:
        commands = [line.strip().casefold() for line in stdout.splitlines() if line.strip()]

    return {
        "apps": apps,
        "app_names": app_names,
        "bundle_ids": bundle_ids,
        "bundle_tails": bundle_tails,
        "executables": executables,
        "commands": commands,
    }


def get_snapshot(*, refresh: bool = False) -> dict:
    """Retrato dos apps e processos em execução, reutilizado por alguns segundos."""
    with _LOCK:
        if (
            not refresh
            and _SNAPSHOT["value"] is not None
            and time.monotonic() < _SNAPSHOT["expires_at"]
        ):
            return _SNAPSHOT["value"]
    snapshot = _build_snapshot()
    with _LOCK:
        _SNAPSHOT["value"] = snapshot
        _SNAPSHOT["expires_at"] = time.monotonic() + _SNAPSHOT_TTL_SECONDS
    return snapshot


def clear_snapshot() -> None:
    with _LOCK:
        _SNAPSHOT["value"] = None
        _SNAPSHOT["expires_at"] = 0.0


def running_match(
    *,
    process_names=(),
    app_names=(),
    bundle_ids=(),
    command_markers=(),
    snapshot: dict | None = None,
) -> str:
    """Devolve o nome do que está rodando (ou texto vazio quando nada bate)."""
    snap = snapshot or get_snapshot()
    for name in process_names:
        if name.casefold() in snap["executables"]:
            return name
    for name in app_names:
        if normalize(name) in snap["app_names"]:
            return name
    for bundle in bundle_ids:
        if bundle.casefold() in snap["bundle_ids"]:
            return bundle
    for marker in command_markers:
        lowered = marker.casefold()
        if any(lowered in command for command in snap["commands"]):
            return marker
    return ""


def app_folder_running(folder: str, snapshot: dict | None = None) -> str:
    """
    Diz se o app dono de uma pasta de dados (``~/Library/Application
    Support/<App>``) está aberto: pelo arquivo de lock que apps Chromium e
    Electron mantêm enquanto rodam, ou pelo nome da pasta bater com um app em
    execução. Um lock antigo de um app que travou conta como "aberto" — o
    erro fica do lado conservador.
    """
    for lock_name in _CHROMIUM_LOCK_FILES:
        if os.path.lexists(os.path.join(folder, lock_name)):
            return os.path.basename(folder)

    basename = os.path.basename(folder.rstrip(os.sep))
    key = normalize(basename)
    if not key:
        return ""
    snap = snapshot or get_snapshot()
    if (
        key in snap["app_names"]
        or key in snap["bundle_tails"]
        or basename.casefold() in snap["bundle_ids"]
    ):
        return basename
    return ""


def last_activity_days(paths) -> int | None:
    """Dias desde a mudança mais recente nas raízes e em seus filhos diretos."""
    newest = 0.0
    for path in paths:
        try:
            newest = max(newest, os.lstat(path).st_mtime)
        except OSError:
            continue
        if not os.path.isdir(path):
            continue
        try:
            with os.scandir(path) as entries:
                for entry in entries:
                    try:
                        newest = max(newest, entry.stat(follow_symlinks=False).st_mtime)
                    except OSError:
                        continue
        except OSError:
            continue
    if not newest:
        return None
    return max(0, int((time.time() - newest) // _DAY_SECONDS))


def describe(running: str, last_days: int | None) -> dict:
    """Traduz os sinais em um selo legível para a interface."""
    if running:
        return {
            "state": "running",
            "label": "aberto agora",
            "detail": f"{running} está em execução",
            "running": running,
            "last_used_days": last_days,
        }
    if last_days is None:
        return {
            "state": "unknown",
            "label": "sem registro de uso",
            "detail": "",
            "running": "",
            "last_used_days": None,
        }
    if last_days == 0:
        label = "usado hoje"
    elif last_days == 1:
        label = "usado ontem"
    else:
        label = f"parado há {last_days} dias"
    return {
        "state": "today" if last_days == 0 else "idle",
        "label": label,
        "detail": "",
        "running": "",
        "last_used_days": last_days,
    }


def tool_usage(spec: dict | None, roots, snapshot: dict | None = None) -> dict:
    """Selo de uso de uma categoria: ``spec`` traz nomes de processos/apps."""
    spec = spec or {}
    running = ""
    if spec:
        running = running_match(
            process_names=spec.get("process_names", ()),
            app_names=spec.get("app_names", ()),
            bundle_ids=spec.get("bundle_ids", ()),
            command_markers=spec.get("command_markers", ()),
            snapshot=snapshot,
        )
    return describe(running, last_activity_days(roots))
