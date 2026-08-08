import re

from .utils import run_authorized_command, run_command


def flush_dns() -> tuple[bool, str]:
    """
    Flushes the macOS DNS cache.
    Returns (success, message).
    """
    # Standard macOS command to flush DNS cache
    # First, run dscacheutil (does not require root)
    code1, stdout1, stderr1 = run_command(["/usr/bin/dscacheutil", "-flushcache"])
    
    # Second, try restarting mDNSResponder (requires root privileges)
    code2, stdout2, stderr2 = run_command(["/usr/bin/killall", "-HUP", "mDNSResponder"])
    
    if code2 != 0:
        # If it fails (likely due to permissions), trigger macOS native password prompt
        code2, stdout2, stderr2 = run_authorized_command("/usr/bin/killall -HUP mDNSResponder")
        
    if code1 == 0 and code2 == 0:
        return True, "Cache DNS limpo e mDNSResponder reiniciado com sucesso."
    elif code2 != 0 and ("canceled" in stderr2.lower() or "cancelado" in stderr2.lower()):
        return False, "Operação cancelada pelo usuário (senha incorreta ou cancelamento)."
    elif code1 == 0:
        return True, "Cache DNS limpo localmente. (Aviso: Não foi possível reiniciar o serviço mDNSResponder)."
    else:
        return False, f"Falha ao limpar cache DNS: {stderr1 or stderr2 or 'Erro desconhecido'}"

def get_ping_latency(host: str = "1.1.1.1", count: int = 3) -> float:
    """
    Pings a host and returns the average latency in milliseconds.
    Returns -1.0 if host is unreachable.
    """
    code, stdout, stderr = run_command(["/sbin/ping", "-c", str(count), "-W", "2000", host], timeout=15)
    if code != 0 or not stdout:
        return -1.0
        
    # Search for round-trip min/avg/max/stddev line
    match = re.search(r"min/avg/max/stddev = [\d\.]+/([\d\.]+)/", stdout)
    if match:
        try:
            return float(match.group(1))
        except ValueError:
            return -1.0
            
    return -1.0

def run_network_diagnostic() -> dict:
    """
    Performs a brief network latency test.
    Returns a dict with latency info and status.
    """
    latency = get_ping_latency("1.1.1.1", count=3)
    
    if latency < 0:
        # Retry with Google DNS as backup
        latency = get_ping_latency("8.8.8.8", count=3)
        
    if latency < 0:
        status = "Desconectado"
        status_color = "FAIL"
    elif latency < 50:
        status = "Excelente"
        status_color = "GREEN"
    elif latency < 150:
        status = "Bom"
        status_color = "BLUE"
    else:
        status = "Lento"
        status_color = "WARNING"
        
    return {
        "status": status,
        "status_color": status_color,
        "latency_ms": latency if latency >= 0 else None,
        "latency_human": f"{latency:.1f} ms" if latency >= 0 else "N/A"
    }
