"""
Avisos do Dashboard: disco abaixo da meta, Lixeira cheia e apps em loop de
travamento.

Somente leitura. O objetivo é dizer, ao abrir o app, se algo precisa de
atenção antes mesmo de uma varredura — o aviso de "armazenamento quase
cheio" do macOS chega sem explicar nada; aqui ele vem com o número, a meta
escolhida pelo usuário e o atalho para a aba certa.
"""

import os
import re
import time

from .settings import load_settings
from .utils import format_size, get_dir_size, get_disk_usage

# Nome do processo nos relatórios do CrashReporter:
# "Safari-2026-10-27-081512.ips", "Code Helper (Renderer)-2026-10-27-...ips".
_CRASH_REPORT_PATTERN = re.compile(r"^(?P<name>.+?)[-_]\d{4}-\d{2}-\d{2}-\d{6}")
_CRASH_REPORT_SUFFIXES = (".ips", ".crash", ".diag")
CRASH_LOOP_THRESHOLD = 3
CRASH_LOOP_WINDOW_SECONDS = 24 * 3600
DIAGNOSTIC_REPORTS_DIR = "~/Library/Logs/DiagnosticReports"


def detect_crash_loops(
    report_dir: str | None = None,
    *,
    now: float | None = None,
    threshold: int = CRASH_LOOP_THRESHOLD,
    window_seconds: int = CRASH_LOOP_WINDOW_SECONDS,
) -> list[dict]:
    """Apps com ``threshold`` ou mais relatórios de travamento na janela."""
    directory = os.path.expanduser(report_dir or DIAGNOSTIC_REPORTS_DIR)
    now = time.time() if now is None else now
    counts: dict[str, dict] = {}
    try:
        entries = list(os.scandir(directory))
    except OSError:
        return []

    for entry in entries:
        name = entry.name
        if not name.lower().endswith(_CRASH_REPORT_SUFFIXES):
            continue
        match = _CRASH_REPORT_PATTERN.match(name)
        if not match:
            continue
        try:
            modified = entry.stat(follow_symlinks=False).st_mtime
        except OSError:
            continue
        if now - modified > window_seconds:
            continue
        process = match.group("name").strip()
        bucket = counts.setdefault(process, {"name": process, "count": 0, "latest_ts": 0.0})
        bucket["count"] += 1
        bucket["latest_ts"] = max(bucket["latest_ts"], modified)

    loops = [bucket for bucket in counts.values() if bucket["count"] >= threshold]
    loops.sort(key=lambda item: (-item["count"], item["name"].casefold()))
    return loops


def trash_summary() -> dict:
    """Tamanho e quantidade de itens em ~/.Trash (só o volume do usuário)."""
    trash_dir = os.path.expanduser("~/.Trash")
    try:
        names = [name for name in os.listdir(trash_dir) if name != ".DS_Store"]
    except OSError:
        return {"items": 0, "size_bytes": 0, "size_human": "0 B", "accessible": False}
    size, _ = get_dir_size(trash_dir, feature="trash", report_issues=False)
    return {
        "items": len(names),
        "size_bytes": size,
        "size_human": format_size(size),
        "accessible": True,
    }


def evaluate_disk(usage: dict, goal_gb: int) -> dict:
    """Classifica o espaço livre contra a meta do usuário."""
    free = int(usage.get("free_bytes", 0) or 0)
    total = int(usage.get("total_bytes", 0) or 0)
    goal_bytes = int(goal_gb) * 1024 ** 3
    critical_floor = min(5 * 1024 ** 3, int(total * 0.05)) if total else 5 * 1024 ** 3

    if not total:
        level, label = "unknown", "Espaço em disco indisponível"
    elif free < critical_floor:
        level, label = "critical", "Disco praticamente cheio"
    elif free < goal_bytes:
        level, label = "attention", "Abaixo da meta de espaço livre"
    else:
        level, label = "ok", "Espaço livre dentro da meta"

    deficit = max(0, goal_bytes - free)
    return {
        "level": level,
        "label": label,
        "free_bytes": free,
        "free_human": format_size(free),
        "total_bytes": total,
        "total_human": format_size(total),
        "goal_gb": int(goal_gb),
        "goal_bytes": goal_bytes,
        "goal_human": format_size(goal_bytes),
        "deficit_bytes": deficit,
        "deficit_human": format_size(deficit),
        "percentage": usage.get("percentage", 0),
    }


def get_dashboard_health() -> dict:
    """Retrato rápido para o Dashboard; nunca altera nada."""
    settings = load_settings()
    goal_gb = settings["free_space_goal_gb"]
    disk = evaluate_disk(get_disk_usage(), goal_gb)
    trash = trash_summary()
    crash_loops = detect_crash_loops()

    alerts = []
    if disk["level"] == "critical":
        alerts.append(
            {
                "id": "disk_critical",
                "level": "critical",
                "title": f"Disco praticamente cheio: {disk['free_human']} livres",
                "detail": (
                    "O macOS fica instável com tão pouco espaço. Faça a Varredura "
                    "Completa e esvazie a Lixeira depois de revisar."
                ),
                "nav": "junk-panel",
            }
        )
    elif disk["level"] == "attention":
        alerts.append(
            {
                "id": "disk_below_goal",
                "level": "attention",
                "title": f"{disk['free_human']} livres — abaixo da meta de {goal_gb} GB",
                "detail": (
                    f"Faltam {disk['deficit_human']} para a meta. Uma varredura mostra "
                    "o que pode ser movido para a Lixeira."
                ),
                "nav": "junk-panel",
            }
        )

    if trash["accessible"] and trash["size_bytes"] >= 1024 ** 3:
        alerts.append(
            {
                "id": "trash_large",
                "level": "info",
                "title": f"{trash['size_human']} esperando na Lixeira",
                "detail": (
                    f"{trash['items']} item(ns) já movidos ainda ocupam espaço. Esvaziar a "
                    "Lixeira é o passo que libera o disco de verdade — confira o "
                    "Histórico antes, se quiser restaurar algo."
                ),
                "nav": "history-panel",
            }
        )

    for loop in crash_loops:
        alerts.append(
            {
                "id": f"crash_loop:{loop['name']}",
                "level": "attention",
                "title": f"{loop['name']} travou {loop['count']} vezes nas últimas 24 h",
                "detail": (
                    "Um app em loop de travamento enche o disco de relatórios e "
                    "pesa na memória. Feche-o, atualize-o ou verifique se ele "
                    "está entre os itens de inicialização."
                ),
                "nav": "startup-panel",
            }
        )

    return {
        "disk": disk,
        "trash": trash,
        "crash_loops": crash_loops,
        "alerts": alerts,
        "goal_gb": goal_gb,
        "read_only": True,
    }
