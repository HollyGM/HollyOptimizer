"""
Auditoria proativa das autorizações macOS que o HollyOptimizer pode precisar:
Acesso Total ao Disco e Automação (Finder, System Events).

Diferente de security_audit.py (postura de segurança do macOS em geral), este
módulo responde a uma pergunta específica sobre o próprio HollyOptimizer:
quais autorizações do sistema ele já tem, e para onde levar o usuário para
concedê-las, sem exigir que ele descubra o caminho sozinho nos Ajustes do
Sistema.

Todas as funções aqui são somente leitura: nenhuma altera uma permissão,
apenas mede o estado atual e, no caso da Automação, o próprio teste
(um AppleEvent trivial) é o gesto que aciona o diálogo nativo do macOS na
primeira vez — depois disso o sistema lembra a decisão do usuário.
"""

import os

from .utils import run_command

# Full Disk Access não expõe uma API de leitura de status: o único sinal
# confiável é tentar acessar um local que o TCC protege mesmo para o próprio
# dono do arquivo. Vários locais são testados em sequência porque um usuário
# pode nunca ter aberto Mail ou Safari, o que deixaria aquele único caminho
# ausente (inconclusivo) em vez de bloqueado.
_FULL_DISK_ACCESS_PROBES = (
    "~/Library/Safari",
    "~/Library/Mail",
    "~/Library/Messages",
)

AUTOMATION_TARGETS = {
    "automation_finder": {
        "name": "Automação — Finder",
        "reason": "Necessário para esvaziar a Lixeira com a semântica oficial do Finder.",
        "script": 'tell application "Finder" to get name',
    },
    "automation_system_events": {
        "name": "Automação — System Events",
        "reason": "Necessário para listar e remover itens de início de sessão.",
        "script": 'tell application "System Events" to get name of first process',
    },
}

SETTINGS_URLS = {
    "full_disk_access": "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles",
    "automation_finder": "x-apple.systempreferences:com.apple.preference.security?Privacy_Automation",
    "automation_system_events": "x-apple.systempreferences:com.apple.preference.security?Privacy_Automation",
}


def check_full_disk_access() -> bool | None:
    """Retorna True/False quando conclusivo, ou None se não foi possível apurar."""
    inconclusive = False
    for candidate in _FULL_DISK_ACCESS_PROBES:
        path = os.path.expanduser(candidate)
        try:
            os.listdir(path)
            return True
        except PermissionError:
            return False
        except FileNotFoundError:
            inconclusive = True
            continue
        except OSError:
            inconclusive = True
            continue
    return None if inconclusive else False


def check_automation(target_key: str) -> bool | None:
    """
    Testa uma autorização de Automação com um AppleEvent inofensivo.

    Na primeira chamada, se o usuário ainda não decidiu, este é exatamente o
    gesto que aciona o diálogo nativo do macOS pedindo a autorização — não
    apenas um teste, mas o próprio caminho direto para concedê-la.
    """
    spec = AUTOMATION_TARGETS.get(target_key)
    if not spec:
        return None
    code, _stdout, stderr = run_command(["/usr/bin/osascript", "-e", spec["script"]], timeout=15)
    if code == 0:
        return True
    normalized = (stderr or "").casefold()
    if "(-1743)" in (stderr or "") or "not allowed" in normalized or "not authorized" in normalized:
        return False
    # O alvo pode estar fechado ou indisponível; isso não prova ausência de
    # autorização, então o resultado fica indefinido em vez de "negado".
    return None


def _entry(check_id: str, name: str, reason: str, granted: bool | None) -> dict:
    if granted is True:
        status, label = "ok", "Concedido"
    elif granted is False:
        status, label = "attention", "Não concedido"
    else:
        status, label = "unknown", "Não verificado"
    return {
        "id": check_id,
        "name": name,
        "status": status,
        "label": label,
        "reason": reason,
        "settings_url": SETTINGS_URLS.get(check_id, ""),
    }


def run_permissions_audit() -> dict:
    """Verifica Acesso Total ao Disco e as duas autorizações de Automação usadas pelo app."""
    checks = [
        _entry(
            "full_disk_access",
            "Acesso Total ao Disco",
            "Sem ele, varreduras em algumas pastas do seu usuário ficam parciais; "
            "o restante do aplicativo continua funcionando normalmente.",
            check_full_disk_access(),
        )
    ]
    for key, spec in AUTOMATION_TARGETS.items():
        checks.append(_entry(key, spec["name"], spec["reason"], check_automation(key)))

    attention = sum(check["status"] == "attention" for check in checks)
    unknown = sum(check["status"] == "unknown" for check in checks)
    return {
        "status": "attention" if attention else ("unknown" if unknown else "ok"),
        "summary": {
            "ok": sum(check["status"] == "ok" for check in checks),
            "attention": attention,
            "unknown": unknown,
        },
        "checks": checks,
        "read_only": True,
    }


def open_permission_setting(check_id: str) -> tuple[bool, str]:
    """Abre um painel allowlisted dos Ajustes do Sistema, sem alterar nada."""
    settings_url = SETTINGS_URLS.get(check_id)
    if not settings_url:
        return False, "Este item não possui um painel direto nos Ajustes do Sistema."
    code, _, stderr = run_command(["/usr/bin/open", settings_url], timeout=15)
    if code == 0:
        return True, "Ajustes do Sistema abertos."
    return False, f"Não foi possível abrir os Ajustes do Sistema: {stderr or 'erro desconhecido'}"
