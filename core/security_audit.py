from .utils import run_command

SECURITY_SETTINGS = {
    "full_disk_access": "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles",
    "filevault": "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?FileVault",
    "firewall": "x-apple.systempreferences:com.apple.Network-Settings.extension?Firewall",
    "gatekeeper": "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension",
    "automatic_updates": "x-apple.systempreferences:com.apple.Software-Update-Settings.extension",
}


def _result(check_id, name, enabled, detail, recommendation, settings_hint):
    if enabled is True:
        status, label = "ok", "Ativo"
    elif enabled is False:
        status, label = "attention", "Requer atenção"
    else:
        status, label = "unknown", "Não verificado"
    return {
        "id": check_id,
        "name": name,
        "status": status,
        "label": label,
        "detail": detail,
        "recommendation": "" if enabled is True else recommendation,
        "settings_hint": settings_hint,
        "action_available": check_id in SECURITY_SETTINGS,
        "action_label": "Abrir nos Ajustes do Sistema",
    }


def _run_check(command, positive_terms, negative_terms):
    code, stdout, stderr = run_command(command, timeout=30)
    detail = stdout or stderr or "O macOS não retornou informações."
    normalized = detail.casefold()
    if code != 0:
        return None, detail
    if any(term in normalized for term in negative_terms):
        return False, detail
    if any(term in normalized for term in positive_terms):
        return True, detail
    return None, detail


def run_security_audit() -> dict:
    """Reads macOS security posture without changing settings or using admin rights."""
    specifications = (
        {
            "id": "filevault",
            "name": "FileVault",
            "command": ["/usr/bin/fdesetup", "status"],
            "positive": ("filevault is on", "filevault está ativado", "filevault: on"),
            "negative": ("filevault is off", "filevault está desativado", "filevault: off"),
            "recommendation": "Ative o FileVault para proteger os dados caso o Mac seja perdido ou roubado.",
            "settings": "Ajustes do Sistema > Privacidade e Segurança > FileVault",
        },
        {
            "id": "firewall",
            "name": "Firewall",
            "command": ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
            "positive": ("firewall is enabled", "state = 1", "firewall está ativado"),
            "negative": ("firewall is disabled", "state = 0", "firewall está desativado"),
            "recommendation": "Ative o firewall para limitar conexões de entrada não autorizadas.",
            "settings": "Ajustes do Sistema > Rede > Firewall",
        },
        {
            "id": "gatekeeper",
            "name": "Gatekeeper",
            "command": ["/usr/sbin/spctl", "--status"],
            "positive": ("assessments enabled", "avaliações ativadas"),
            "negative": ("assessments disabled", "avaliações desativadas"),
            "recommendation": "Reative a verificação de aplicativos baixados pelo macOS.",
            "settings": "Ajustes do Sistema > Privacidade e Segurança > Segurança",
        },
        {
            "id": "sip",
            "name": "Proteção de Integridade do Sistema (SIP)",
            "command": ["/usr/bin/csrutil", "status"],
            "positive": ("status: enabled", "status: ativado"),
            "negative": ("status: disabled", "status: desativado"),
            "recommendation": "Reative o SIP pelo Recuperação do macOS, salvo necessidade técnica comprovada.",
            "settings": "Recuperação do macOS > Terminal > csrutil enable",
        },
        {
            "id": "automatic_updates",
            "name": "Verificação automática de atualizações",
            "command": ["/usr/sbin/softwareupdate", "--schedule"],
            "positive": (
                "automatic checking is on",
                "automatic checking for updates is turned on",
                "verificação automática está ativada",
            ),
            "negative": (
                "automatic checking is off",
                "automatic checking for updates is turned off",
                "verificação automática está desativada",
            ),
            "recommendation": "Ative a verificação automática para receber correções de segurança.",
            "settings": "Ajustes do Sistema > Geral > Atualização de Software",
        },
    )

    checks = []
    for spec in specifications:
        enabled, detail = _run_check(
            spec["command"], spec["positive"], spec["negative"]
        )
        checks.append(
            _result(
                spec["id"],
                spec["name"],
                enabled,
                detail,
                spec["recommendation"],
                spec["settings"],
            )
        )

    attention = sum(check["status"] == "attention" for check in checks)
    unknown = sum(check["status"] == "unknown" for check in checks)
    ok = sum(check["status"] == "ok" for check in checks)
    return {
        "status": "attention" if attention else ("unknown" if unknown else "ok"),
        "summary": {"ok": ok, "attention": attention, "unknown": unknown},
        "checks": checks,
        "read_only": True,
        "message": "Diagnóstico somente leitura; nenhuma configuração foi alterada.",
    }


def open_security_setting(check_id: str) -> tuple[bool, str]:
    """Opens one allowlisted macOS Settings destination without changing it."""
    settings_url = SECURITY_SETTINGS.get(check_id)
    if not settings_url:
        return False, "Este item não possui um painel direto nos Ajustes do Sistema."
    code, _, stderr = run_command(["/usr/bin/open", settings_url], timeout=15)
    if code == 0:
        return True, "Ajustes do Sistema abertos. Revise a opção antes de alterá-la."
    return False, f"Não foi possível abrir os Ajustes do Sistema: {stderr or 'erro desconhecido'}"
