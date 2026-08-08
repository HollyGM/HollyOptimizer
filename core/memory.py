import os
import re
import threading

from .utils import format_size, run_command
from .version import APP_NAME

_PROCESS_LOCK = threading.RLock()
_LAST_PROCESS_IDENTITIES = {}

_SWAP_UNITS = {"B": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}


def _parse_swap_value(raw: str) -> int:
    """Converte um campo de vm.swapusage ('1024.00M') em bytes."""
    match = re.fullmatch(r"([\d.]+)([BKMGT])?", raw.strip())
    if not match:
        return 0
    try:
        amount = float(match.group(1))
    except ValueError:
        return 0
    return int(amount * _SWAP_UNITS.get(match.group(2) or "B", 1))


def get_swap_stats() -> dict:
    """
    Lê o uso de swap do macOS.

    Em um Mac com memória unificada, swap em uso é o sinal honesto de que a RAM
    acabou: o sistema passou a escrever páginas no SSD. A porcentagem de "RAM
    usada" sozinha não distingue cache saudável de falta real de memória, mas
    swap crescente distingue — e, num MacBook Air, é também o que desgasta o SSD
    e derruba o desempenho.
    """
    stats = {
        "swap_total_bytes": 0, "swap_total_human": "0 B",
        "swap_used_bytes": 0, "swap_used_human": "0 B",
        "swap_level": "unknown", "swap_label": "Indisponível",
    }
    code, stdout, _ = run_command(["/usr/sbin/sysctl", "-n", "vm.swapusage"])
    if code != 0 or not stdout:
        return stats

    fields = dict(re.findall(r"(total|used|free)\s*=\s*([\d.]+[BKMGT]?)", stdout))
    if not fields:
        return stats

    total = _parse_swap_value(fields.get("total", "0"))
    used = _parse_swap_value(fields.get("used", "0"))

    # Limiares em bytes absolutos: 1 GB de swap incomoda em qualquer Mac, e a
    # fração do total de swap não diz nada porque o macOS cresce o arquivo sob
    # demanda.
    if used >= 4 * 1024 ** 3:
        level, label = "critical", "Swap alto — a RAM não está dando conta"
    elif used >= 1024 ** 3:
        level, label = "warning", "Swap em uso — memória apertada"
    elif used > 0:
        level, label = "normal", "Swap mínimo — normal"
    else:
        level, label = "normal", "Sem swap em uso"

    stats.update({
        "swap_total_bytes": total, "swap_total_human": format_size(total),
        "swap_used_bytes": used, "swap_used_human": format_size(used),
        "swap_level": level, "swap_label": label,
    })
    return stats

def get_memory_stats() -> dict:
    """
    Parses macOS memory usage using sysctl and vm_stat.
    Returns a dict with: total, used, free, inactive, wired, active, percent.
    All sizes in bytes, plus formatted human-readable strings.
    """
    stats = {
        "total_bytes": 0, "total_human": "0 B",
        "used_bytes": 0, "used_human": "0 B",
        "free_bytes": 0, "free_human": "0 B",
        "inactive_bytes": 0, "inactive_human": "0 B",
        "wired_bytes": 0, "wired_human": "0 B",
        "active_bytes": 0, "active_human": "0 B",
        "purgeable_bytes": 0, "purgeable_human": "0 B",
        "compressed_bytes": 0, "compressed_human": "0 B",
        "available_bytes": 0, "available_human": "0 B",
        "swap_total_bytes": 0, "swap_total_human": "0 B",
        "swap_used_bytes": 0, "swap_used_human": "0 B",
        "swap_level": "unknown", "swap_label": "Indisponível",
        "percent": 0.0,
        "pressure_level": "unknown", "pressure_label": "Indisponível",
    }
    
    # 1. Get total physical memory
    code, stdout, stderr = run_command(["/usr/sbin/sysctl", "-n", "hw.memsize"])
    if code != 0 or not stdout:
        return stats
    try:
        total_mem = int(stdout.strip())
    except ValueError:
        return stats
        
    # 2. Run vm_stat and parse lines
    code, stdout, stderr = run_command(["/usr/bin/vm_stat"])
    if code != 0 or not stdout:
        return stats
        
    lines = stdout.splitlines()
    try:
        page_size = int(os.sysconf("SC_PAGE_SIZE"))
    except (ValueError, OSError):
        page_size = 4096
    
    # First line usually contains page size, e.g. "Mach Virtual Memory Statistics: (page size of 16384 bytes)"
    match = re.search(r"page size of (\d+) bytes", lines[0])
    if match:
        page_size = int(match.group(1))
        
    vm_stats = {}
    for line in lines[1:]:
        parts = line.split(":")
        if len(parts) == 2:
            key = parts[0].strip()
            val = parts[1].strip().rstrip(".")
            try:
                vm_stats[key] = int(val)
            except ValueError:
                continue
                
    # Extract page counts
    free_pages = vm_stats.get("Pages free", 0)
    speculative_pages = vm_stats.get("Pages speculative", 0)
    active_pages = vm_stats.get("Pages active", 0)
    inactive_pages = vm_stats.get("Pages inactive", 0)
    wired_pages = vm_stats.get("Pages wired down", 0)
    purgeable_pages = vm_stats.get("Pages purgeable", 0)
    compressor_pages = vm_stats.get("Pages occupied by compressor", 0)
    
    # Calculate bytes
    # Free memory in macOS is free pages + speculative pages
    free_bytes = (free_pages + speculative_pages) * page_size
    # Inactive, Wired, Active, Purgeable
    inactive_bytes = inactive_pages * page_size
    wired_bytes = wired_pages * page_size
    active_bytes = active_pages * page_size
    purgeable_bytes = purgeable_pages * page_size
    compressed_bytes = compressor_pages * page_size
    
    # Inactive and purgeable pages are reclaimable by macOS and should not be
    # presented as hard memory consumption. This is closer to memory pressure
    # than the misleading total-minus-free calculation.
    available_bytes = min(total_mem, free_bytes + inactive_bytes + purgeable_bytes)
    used_bytes = total_mem - available_bytes
    used_bytes = max(used_bytes, 0)
        
    percent = (used_bytes / total_mem) * 100.0 if total_mem > 0 else 0.0
    
    pressure_level = "unknown"
    pressure_label = "Indisponível"
    pressure_code, pressure_stdout, _ = run_command([
        "/usr/sbin/sysctl", "-n", "kern.memorystatus_vm_pressure_level"
    ])
    if pressure_code == 0:
        try:
            pressure_value = int(pressure_stdout.strip())
            pressure_level, pressure_label = {
                1: ("normal", "Normal"),
                2: ("warning", "Elevada"),
                4: ("critical", "Crítica"),
            }.get(pressure_value, ("unknown", "Indisponível"))
        except ValueError:
            pass

    stats.update({
        "total_bytes": total_mem, "total_human": format_size(total_mem),
        "used_bytes": used_bytes, "used_human": format_size(used_bytes),
        "free_bytes": free_bytes, "free_human": format_size(free_bytes),
        "inactive_bytes": inactive_bytes, "inactive_human": format_size(inactive_bytes),
        "wired_bytes": wired_bytes, "wired_human": format_size(wired_bytes),
        "active_bytes": active_bytes, "active_human": format_size(active_bytes),
        "purgeable_bytes": purgeable_bytes, "purgeable_human": format_size(purgeable_bytes),
        "compressed_bytes": compressed_bytes, "compressed_human": format_size(compressed_bytes),
        "available_bytes": available_bytes, "available_human": format_size(available_bytes),
        "percent": round(percent, 1),
        "pressure_level": pressure_level, "pressure_label": pressure_label,
    })
    stats.update(get_swap_stats())
    return stats

def get_top_ram_processes() -> list[dict]:
    """
    Retrieves the top 10 memory consuming processes on macOS.
    Returns list of dicts with: pid, name, pmem, rss_bytes, rss_human, path.
    """
    # Include uid and process start time in the same snapshot. A PID can be
    # reused; path alone is not enough to prove that the process selected in the
    # interface is still the process receiving SIGTERM.
    code, stdout, _ = run_command(
        ["/bin/ps", "-A", "-o", "pid=,uid=,lstart=,pmem=,rss=,comm=", "-m"]
    )
    if code != 0 or not stdout:
        return []
        
    processes = []
    lines = stdout.splitlines()
    
    for line in lines[:10]:
        parts = line.strip().split(None, 9)
        if len(parts) < 10:
            continue

        pid_str, uid_str = parts[:2]
        start_time = " ".join(parts[2:7])
        pmem_str, rss_str, comm = parts[7:]
        try:
            pid = int(pid_str)
            uid = int(uid_str)
            pmem = float(pmem_str)
            rss_kb = int(rss_str)
        except ValueError:
            continue
            
        rss_bytes = rss_kb * 1024
        
        # Get a friendly name from comm path
        path = comm
        filename = os.path.basename(path)
        
        # If it's an app, e.g. /Applications/Firefox.app/Contents/MacOS/firefox, extract Firefox
        app_name = filename
        if ".app/" in path:
            match = re.search(r"/([^/]+)\.app/", path)
            if match:
                app_name = match.group(1)
                
        processes.append({
            "pid": pid,
            "uid": uid,
            "start_time": start_time,
            "name": app_name,
            "filename": filename,
            "pmem": pmem,
            "rss_bytes": rss_bytes,
            "rss_human": format_size(rss_bytes),
            "path": path
        })
        
    with _PROCESS_LOCK:
        _LAST_PROCESS_IDENTITIES.clear()
        _LAST_PROCESS_IDENTITIES.update(
            {
                process["pid"]: {
                    "uid": process["uid"],
                    "start_time": process["start_time"],
                    "path": process["path"],
                }
                for process in processes
            }
        )

    return processes

# System-critical PIDs and process names that must never be killed
PROTECTED_PIDS = {0, 1}  # kernel_task, launchd
SYSTEM_PROCESSES = {'kernel_task', 'launchd', 'WindowServer', 'loginwindow', 'opendirectoryd', 'diskarbitrationd'}

def _get_process_info(pid: int) -> tuple[int, str, str]:
    """Returns (uid, start time, executable path), or (-1, "", "")."""
    code, stdout, _ = run_command(
        ["/bin/ps", "-p", str(pid), "-o", "uid=,lstart=,comm="]
    )
    if code != 0 or not stdout:
        return -1, "", ""
    parts = stdout.strip().split(None, 6)
    if len(parts) != 7:
        return -1, "", ""
    try:
        return int(parts[0]), " ".join(parts[1:6]), parts[6]
    except ValueError:
        return -1, "", ""

def kill_process(pid: int) -> tuple[bool, str]:
    """
    Attempts to kill a process by PID.
    Blocks killing of system-critical processes.
    """
    if not isinstance(pid, int):
        return False, "PID inválido."
    if pid == os.getpid():
        return False, f"O processo do {APP_NAME} não pode encerrar a si próprio."
    if pid in PROTECTED_PIDS or pid < 50:
        return False, f"Processo {pid} é um processo do sistema protegido e não pode ser encerrado."

    with _PROCESS_LOCK:
        expected = dict(_LAST_PROCESS_IDENTITIES.get(pid, {}))
    if not expected:
        return False, "Processo bloqueado: atualize a lista antes de encerrá-lo."

    uid, start_time, process_path = _get_process_info(pid)
    comm = os.path.basename(process_path)
    if uid != os.getuid():
        return False, "Processos de outro usuário ou do sistema não podem ser encerrados."
    if (
        uid != expected.get("uid")
        or start_time != expected.get("start_time")
        or process_path != expected.get("path")
    ):
        return False, "Processo bloqueado porque o PID foi reutilizado ou mudou desde a listagem."
    if comm in SYSTEM_PROCESSES:
        return False, f"Processo '{comm}' (PID {pid}) é crítico para o sistema e não pode ser encerrado."
    if process_path.startswith(("/System/", "/usr/libexec/", "/usr/sbin/", "/sbin/")):
        return False, f"Processos do macOS não podem ser encerrados pelo {APP_NAME}."

    try:
        # SIGTERM gives applications a chance to save state and shut down cleanly.
        code, _, stderr = run_command(["/bin/kill", "-TERM", str(pid)])
        if code == 0:
            return True, f"Solicitação de encerramento enviada ao processo {pid}."
        return False, f"Falha ao encerrar o processo: {stderr or 'Erro desconhecido'}"
    except Exception as e:
        return False, str(e)

def optimize_ram() -> tuple[bool, str, int]:
    """
    Intentional no-op kept for API compatibility: manual purge is disabled
    because macOS reclaims memory caches on demand.
    Returns (success, message, bytes_freed).
    """
    return (
        False,
        "A purga manual foi desativada: o macOS já gerencia caches de memória automaticamente.",
        0,
    )
