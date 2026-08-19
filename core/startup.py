import os
import shlex
import threading

from .diagnostics import record_issue
from .utils import (
    SYSTEM_EVENTS_AUTOMATION_LOCK,
    read_plist,
    run_authorized_command,
    run_command,
)
from .version import APP_NAME

_SCAN_LOCK = threading.RLock()
_LAST_SCAN_ITEMS = set()
_LAST_LOGIN_ITEMS = {}
PROTECTED_LABEL_PREFIXES = ("com.apple.", "com.apple-")

STARTUP_DIRS = {
    "user_agent": {
        "name": "Agentes de Inicialização do Usuário",
        "path": os.path.expanduser("~/Library/LaunchAgents"),
        "sudo_required": False
    },
    "system_agent": {
        "name": "Agentes de Inicialização do Sistema",
        "path": "/Library/LaunchAgents",
        "sudo_required": True
    },
    "system_daemon": {
        "name": "Serviços de Segundo Plano (Daemons)",
        "path": "/Library/LaunchDaemons",
        "sudo_required": True
    }
}

# Login items registered through System Events / SMAppService. These never
# appear in LaunchAgents, so a LaunchAgents-only scan misses exactly the
# entries a user sees in Ajustes do Sistema > Geral > Itens de Início.
LOGIN_ITEM_CATEGORY = "login_item"
LOGIN_ITEM_CATEGORY_NAME = "Itens de Início de Sessão"


def _loaded_launchd_labels() -> set[str]:
    """Labels currently loaded in the user's launchd domain."""
    code, stdout, _ = run_command(["/bin/launchctl", "list"], timeout=30)
    if code != 0 or not stdout:
        return set()
    labels = set()
    for line in stdout.splitlines()[1:]:
        parts = line.rsplit("\t", 1)
        if len(parts) == 2 and parts[1].strip():
            labels.add(parts[1].strip())
    return labels


def _launchd_service_target(category: str, label: str) -> tuple[str, bool]:
    """Returns (service-target, needs_root) for launchctl bootout/bootstrap."""
    if category == "system_daemon":
        return f"system/{label}", True
    # Both ~/Library/LaunchAgents and /Library/LaunchAgents load into the
    # per-user GUI domain.
    return f"gui/{os.getuid()}/{label}", False


def _apply_launchd_state(category: str, label: str, plist_path: str, disable: bool) -> str:
    """
    Applies the enable/disable change to the running launchd session.

    Renaming the plist alone only takes effect at the next login: a job that is
    already bootstrapped keeps running. This unloads (or loads) it now so the
    action matches what the interface reports.
    """
    if not label:
        return "O item não declara um Label; o efeito ocorrerá no próximo login."

    target, needs_root = _launchd_service_target(category, label)
    if disable:
        command = ["/bin/launchctl", "bootout", target]
    else:
        command = ["/bin/launchctl", "bootstrap", target.rsplit("/", 1)[0], plist_path]

    if needs_root:
        quoted = " ".join(shlex.quote(part) for part in command)
        code, _, stderr = run_authorized_command(quoted)
    else:
        code, _, stderr = run_command(command, timeout=30)

    if code == 0:
        return "Aplicado imediatamente no launchd."

    normalized = (stderr or "").casefold()
    # Booting out a job that was never loaded is not a failure.
    if any(
        marker in normalized
        for marker in ("no such process", "not find service", "could not find specified service")
    ):
        return "O serviço não estava carregado; nada a descarregar."
    if "already bootstrapped" in normalized:
        return "O serviço já estava carregado."
    return (
        "O arquivo foi renomeado, mas o launchd recusou aplicar agora; "
        "o efeito ocorrerá no próximo login."
    )


def _scan_login_items() -> list[dict]:
    """Reads classic login items through System Events (read-only)."""
    script = (
        'tell application "System Events"\n'
        'set output to ""\n'
        'repeat with anItem in login items\n'
        'set output to output & (name of anItem) & "\t" & (path of anItem) & "\t" & '
        '((hidden of anItem) as text) & "\n"\n'
        'end repeat\n'
        'return output\n'
        'end tell'
    )
    with SYSTEM_EVENTS_AUTOMATION_LOCK:
        code, stdout, stderr = run_command(["/usr/bin/osascript", "-e", script], timeout=30)
    if code != 0:
        # Automation permission denied, or System Events unavailable. The rest
        # of the scan stays useful, so this is reported and not raised.
        record_issue("startup", PermissionError(stderr or "System Events indisponível"), "")
        return []

    items = []
    for line in stdout.splitlines():
        parts = line.split("\t")
        if not parts or not parts[0].strip():
            continue
        name = parts[0].strip()
        path = parts[1].strip() if len(parts) > 1 else ""
        hidden = (parts[2].strip().casefold() == "true") if len(parts) > 2 else False
        items.append({
            "filename": name,
            "filepath": "",
            "label": name,
            "exec_path": path,
            "category": LOGIN_ITEM_CATEGORY,
            "category_name": LOGIN_ITEM_CATEGORY_NAME,
            "is_disabled": False,
            "is_broken": bool(path) and not os.path.exists(path),
            "is_loaded": True,
            "sudo_required": False,
            "kind": LOGIN_ITEM_CATEGORY,
            "hidden": hidden,
        })
    return items


def scan_startup() -> list[dict]:
    """
    Scans launch agents, daemons and login items.
    Returns a list of dictionaries with info about each startup item.
    """
    items = []
    loaded_labels = _loaded_launchd_labels()

    for category, info in STARTUP_DIRS.items():
        base_dir = info["path"]
        category_name = info["name"]
        sudo_req = info["sudo_required"]

        if not os.path.exists(base_dir) or not os.path.isdir(base_dir):
            continue

        try:
            names = os.listdir(base_dir)
        except Exception as exc:
            record_issue("startup", exc, base_dir)
            continue

        for file in names:
            # We want to match both active (.plist) and disabled (.disabled) items
            if not file.endswith(".plist") and not file.endswith(".plist.disabled"):
                continue

            try:
                file_path = os.path.join(base_dir, file)
                is_disabled = file.endswith(".disabled")

                # Read plist content (even if disabled, it is still a plist structure)
                plist = read_plist(file_path)

                label = plist.get("Label", file.replace(".plist", "").replace(".disabled", ""))

                # Find executable path
                program = plist.get("Program")
                program_args = plist.get("ProgramArguments", [])

                exec_path = ""
                if program:
                    exec_path = program
                elif program_args and isinstance(program_args, list):
                    exec_path = program_args[0]

                # Check if the executable actually exists
                is_broken = False
                if exec_path and not exec_path.startswith("/usr/bin/") and not exec_path.startswith("/bin/") and not exec_path.startswith("/usr/sbin/") and not exec_path.startswith("/sbin/"):
                    # Only check non-system paths to be safe, since some system paths might be dynamic
                    if not os.path.exists(exec_path):
                        is_broken = True

                items.append({
                    "filename": file,
                    "filepath": file_path,
                    "label": label,
                    "exec_path": exec_path,
                    "category": category,
                    "category_name": category_name,
                    "is_disabled": is_disabled,
                    "is_broken": is_broken,
                    "is_loaded": label in loaded_labels,
                    "sudo_required": sudo_req,
                    "kind": "launchd",
                    "hidden": False,
                })
            except Exception as exc:
                # One malformed plist must not truncate the rest of the folder.
                record_issue("startup", exc, base_dir)
                continue

    login_items = _scan_login_items()
    items.extend(login_items)

    with _SCAN_LOCK:
        _LAST_SCAN_ITEMS.clear()
        _LAST_SCAN_ITEMS.update(
            os.path.realpath(item["filepath"]) for item in items if item["filepath"]
        )
        _LAST_LOGIN_ITEMS.clear()
        _LAST_LOGIN_ITEMS.update({item["label"]: item["exec_path"] for item in login_items})

    return items


def remove_login_item(name: str) -> tuple[bool, str]:
    """
    Removes one login item that belongs to the most recent scan.

    Re-adding it is a one-click operation in Ajustes do Sistema > Geral >
    Itens de Início, so this is presented as reversible but not automatic.
    """
    if not isinstance(name, str) or not name.strip():
        return False, "Nome de item inválido."

    with _SCAN_LOCK:
        if name not in _LAST_LOGIN_ITEMS:
            return False, "Item bloqueado: não pertence à varredura de inicialização mais recente."

    # The name is passed as an argv item so it is never interpolated into
    # AppleScript source.
    script = (
        "on run argv\n"
        'tell application "System Events" to delete login item (item 1 of argv)\n'
        "end run"
    )
    with SYSTEM_EVENTS_AUTOMATION_LOCK:
        code, _, stderr = run_command(["/usr/bin/osascript", "-e", script, name], timeout=30)
    if code == 0:
        with _SCAN_LOCK:
            _LAST_LOGIN_ITEMS.pop(name, None)
        return True, (
            f"'{name}' removido dos itens de início. "
            "Você pode readicioná-lo em Ajustes do Sistema > Geral > Itens de Início."
        )

    normalized = (stderr or "").casefold()
    if "(-1743)" in (stderr or "") or "not allowed" in normalized or "not authorized" in normalized:
        return False, (
            f"O macOS bloqueou o controle do System Events. Autorize o {APP_NAME} em "
            "Ajustes do Sistema > Privacidade e Segurança > Automação."
        )
    return False, f"Não foi possível remover o item: {stderr or 'erro desconhecido'}"


def toggle_startup_item(filepath: str, disable: bool) -> tuple[bool, str]:
    """
    Disables or enables a startup item by renaming its file extension and
    applying the change to the running launchd session.
    Returns (success, message).
    """
    resolved = os.path.realpath(os.path.expanduser(filepath))
    with _SCAN_LOCK:
        if resolved not in _LAST_SCAN_ITEMS:
            return False, "Item bloqueado: não pertence à varredura de inicialização mais recente."

    filepath = resolved
    if not os.path.exists(filepath):
        return False, "Arquivo não encontrado."

    plist = read_plist(filepath)
    label = str(plist.get("Label", ""))
    filename_lower = os.path.basename(filepath).casefold()
    if label.casefold().startswith(PROTECTED_LABEL_PREFIXES) or filename_lower.startswith(PROTECTED_LABEL_PREFIXES):
        return False, "Item da Apple bloqueado pela política de proteção do sistema."

    dir_path, filename = os.path.split(filepath)

    category = "user_agent"
    for key, info in STARTUP_DIRS.items():
        if os.path.realpath(info["path"]) == os.path.realpath(dir_path):
            category = key
            break

    if disable:
        if filename.endswith(".plist.disabled"):
            return True, "Já está desativado."
        if not filename.endswith(".plist"):
            return False, "Tipo de arquivo inválido."

        new_filename = filename + ".disabled"
    else:
        if filename.endswith(".plist"):
            return True, "Já está ativado."
        if not filename.endswith(".plist.disabled"):
            return False, "Tipo de arquivo inválido."

        new_filename = filename[:-9] # Remove '.disabled'

    new_filepath = os.path.join(dir_path, new_filename)

    # A pre-existing destination means an active and a disabled variant of the
    # same agent coexist. Renaming would silently destroy one of them, so the
    # conflict is surfaced for the user to resolve manually.
    conflict_message = (
        f"Conflito: '{new_filename}' já existe em {dir_path}. Nenhum arquivo foi "
        "alterado. Remova ou renomeie manualmente a cópia duplicada antes de "
        "alternar este item."
    )
    if os.path.lexists(new_filepath):
        return False, conflict_message

    def _finish(via_auth: bool) -> tuple[bool, str]:
        with _SCAN_LOCK:
            _LAST_SCAN_ITEMS.discard(filepath)
            _LAST_SCAN_ITEMS.add(os.path.realpath(new_filepath))
        # When enabling, launchd must be pointed at the freshly renamed file.
        launchd_note = _apply_launchd_state(
            category, label, new_filepath if not disable else filepath, disable
        )
        suffix = " (via autenticação)" if via_auth else ""
        return True, f"Renomeado para {new_filename}{suffix}. {launchd_note}"

    try:
        # link+unlink instead of os.rename: hard-linking fails atomically with
        # FileExistsError if the destination appears between check and action,
        # so an existing .plist can never be overwritten by a race.
        os.link(filepath, new_filepath)
        os.unlink(filepath)
        return _finish(via_auth=False)
    except FileExistsError:
        return False, conflict_message
    except PermissionError:
        src_q = shlex.quote(filepath)
        dst_q = shlex.quote(new_filepath)
        # -n never overwrites, but exits 0 even when it skips the move; the
        # explicit post-conditions below are what actually confirm the rename.
        code, stdout, stderr = run_authorized_command(f"/bin/mv -n {src_q} {dst_q}")
        if code == 0 and not os.path.lexists(filepath) and os.path.lexists(new_filepath):
            return _finish(via_auth=True)
        elif "canceled" in stderr.lower() or "cancelado" in stderr.lower():
            return False, "Operação cancelada pelo usuário."
        elif code == 0:
            return False, conflict_message
        else:
            return False, f"Permissão negada: {stderr or 'Erro de privilégios'}"
    except Exception as e:
        record_issue("startup", e, filepath)
        return False, f"Erro ao alternar estado: {e!s}"
