import concurrent.futures
import glob
import json
import os
import re
import shutil
import threading

from .utils import run_command

_PACKAGE_LOCK = threading.RLock()
_LAST_PACKAGES = {}
_PACKAGE_PATTERNS = {
    "brew": re.compile(r"^[A-Za-z0-9][A-Za-z0-9@+._-]*$"),
    "npm": re.compile(
        r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$",
        re.IGNORECASE,
    ),
    "pip": re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$"),
}
_PROTECTED_PACKAGES = {
    "brew": set(),
    "npm": {"npm", "corepack"},
    "pip": {"pip", "setuptools", "wheel"},
}

def _find_manager_executable(manager: str) -> str | None:
    """Finds package managers even when a GUI launch has a minimal PATH."""
    specifications = {
        "brew": {
            "names": ("brew",),
            "fixed": ("/opt/homebrew/bin/brew", "/usr/local/bin/brew"),
            "patterns": (),
        },
        "npm": {
            "names": ("npm",),
            "fixed": (
                "/opt/homebrew/bin/npm",
                "/usr/local/bin/npm",
                "~/.volta/bin/npm",
                "~/.asdf/shims/npm",
            ),
            "patterns": ("~/.nvm/versions/node/*/bin/npm",),
        },
        "pip": {
            "names": ("pip3", "pip"),
            "fixed": (
                "/opt/homebrew/bin/pip3",
                "/usr/local/bin/pip3",
                "/usr/bin/pip3",
                "~/Library/Python/*/bin/pip3",
            ),
            "patterns": (),
        },
    }
    spec = specifications.get(manager)
    if not spec:
        return None

    for name in spec["names"]:
        located = shutil.which(name)
        if located:
            return located

    candidates = []
    for entry in spec["fixed"]:
        expanded = os.path.expanduser(entry)
        if "*" in expanded:
            candidates.extend(sorted(glob.glob(expanded), reverse=True))
        else:
            candidates.append(expanded)
    for pattern in spec["patterns"]:
        candidates.extend(sorted(glob.glob(os.path.expanduser(pattern)), reverse=True))

    seen = set()
    for candidate in candidates:
        resolved = os.path.realpath(candidate)
        if resolved in seen:
            continue
        seen.add(resolved)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _register_packages(manager: str, executable: str, packages: list[dict]) -> None:
    removable = {
        item["name"].casefold(): item["name"]
        for item in packages
        if item.get("removable")
    }
    with _PACKAGE_LOCK:
        _LAST_PACKAGES[manager] = {
            "path": os.path.realpath(executable),
            "removable": removable,
        }


def check_homebrew() -> dict:
    """Refreshes Homebrew formulae, leaves, orphans and cleanup potential."""
    brew_path = _find_manager_executable("brew")
    if not brew_path:
        with _PACKAGE_LOCK:
            _LAST_PACKAGES.pop("brew", None)
        return {"installed": False, "packages": []}

    # These four queries are independent and each pays Homebrew's start-up cost.
    # Run sequentially the tab took ~9 s to open, every single time.
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = {
            name: pool.submit(run_command, [brew_path] + args)
            for name, args in (
                ("leaves", ["leaves"]),
                ("versions", ["list", "--formula", "--versions"]),
                ("autoremove", ["autoremove", "--dry-run"]),
                ("cleanup", ["cleanup", "--dry-run"]),
            )
        }
        outputs = {name: future.result()[1] for name, future in futures.items()}

    leaves = {line.strip() for line in outputs["leaves"].splitlines() if line.strip()}

    stdout_versions = outputs["versions"]
    packages = []
    for line in stdout_versions.splitlines():
        parts = line.split()
        if not parts:
            continue
        name = parts[0]
        version = " ".join(parts[1:]) or "desconhecida"
        packages.append(
            {
                "name": name,
                "version": version,
                "display": f"{name} {version}",
                "top_level": name in leaves,
                "removable": name in leaves,
                "removal_note": "Fórmula instalada diretamente" if name in leaves else "Dependência de outra fórmula",
            }
        )

    orphans = []
    for line in outputs["autoremove"].splitlines():
        line = line.strip()
        if not line or line.startswith(("==>", "Warning:")):
            continue
        cleaned = line.replace("Would remove:", "").replace("Would remove ", "").strip()
        if cleaned:
            orphans.append(cleaned)

    cleanup_size_human = "0 B"
    cleanup_files = []
    for line in outputs["cleanup"].splitlines():
        line = line.strip()
        if line.startswith("Would remove"):
            cleanup_files.append(line)
        size_match = re.search(
            r"free approximately ([\d.]+\s?\w+)", line, re.IGNORECASE
        )
        if size_match:
            cleanup_size_human = size_match.group(1)

    packages.sort(key=lambda item: (not item["top_level"], item["name"].casefold()))
    _register_packages("brew", brew_path, packages)
    return {
        "installed": True,
        "path": brew_path,
        "leaves": sorted(leaves),
        "packages": packages,
        "orphans": orphans,
        "cleanup_size": cleanup_size_human,
        "cleanup_files_count": len(cleanup_files),
    }


def check_npm() -> dict:
    """Refreshes globally installed NPM packages."""
    npm_path = _find_manager_executable("npm")
    if not npm_path:
        with _PACKAGE_LOCK:
            _LAST_PACKAGES.pop("npm", None)
        return {"installed": False, "packages": [], "global_packages": []}

    code, stdout, _ = run_command([npm_path, "list", "-g", "--depth=0", "--json"])
    packages = []
    if code == 0 and stdout:
        try:
            dependencies = json.loads(stdout).get("dependencies", {})
            for name, info in dependencies.items():
                version = info.get("version", "desconhecida")
                protected = name.casefold() in _PROTECTED_PACKAGES["npm"]
                packages.append(
                    {
                        "name": name,
                        "version": version,
                        "display": f"{name}@{version}",
                        "removable": not protected,
                        "removal_note": "Ferramenta base protegida" if protected else "Pacote global",
                    }
                )
        except (TypeError, ValueError, AttributeError):
            packages = []

    packages.sort(key=lambda item: item["name"].casefold())
    _register_packages("npm", npm_path, packages)
    return {
        "installed": True,
        "path": npm_path,
        "packages": packages,
        "global_packages": [item["display"] for item in packages],
    }


def check_pip() -> dict:
    """Refreshes only user-installed Pip packages, never the app environment."""
    pip_path = _find_manager_executable("pip")
    if not pip_path:
        with _PACKAGE_LOCK:
            _LAST_PACKAGES.pop("pip", None)
        return {"installed": False, "packages": [], "global_packages": []}

    code, stdout, _ = run_command([pip_path, "list", "--user", "--format=json"])
    packages = []
    if code == 0 and stdout:
        try:
            for package in json.loads(stdout):
                name = package.get("name")
                version = package.get("version")
                if not name or not version:
                    continue
                protected = name.casefold() in _PROTECTED_PACKAGES["pip"]
                packages.append(
                    {
                        "name": name,
                        "version": version,
                        "display": f"{name}=={version}",
                        "removable": not protected,
                        "removal_note": "Ferramenta base protegida" if protected else "Pacote do usuário",
                    }
                )
        except (TypeError, ValueError):
            packages = []

    packages.sort(key=lambda item: item["name"].casefold())
    _register_packages("pip", pip_path, packages)
    return {
        "installed": True,
        "path": pip_path,
        "scope": "Somente pacotes instalados no ambiente do usuário",
        "packages": packages,
        "global_packages": [item["display"] for item in packages],
    }


def remove_dependency(manager: str, package: str) -> dict:
    """Removes one package only when it belongs to the manager's latest listing."""
    if manager not in _PACKAGE_PATTERNS or not isinstance(package, str):
        return {"success": False, "message": "Gerenciador ou pacote inválido."}
    if not _PACKAGE_PATTERNS[manager].fullmatch(package):
        return {"success": False, "message": "Nome de pacote rejeitado pela política de segurança."}

    with _PACKAGE_LOCK:
        snapshot = dict(_LAST_PACKAGES.get(manager, {}))
        registered = dict(snapshot.get("removable", {}))
    exact_name = registered.get(package.casefold())
    if not exact_name:
        return {"success": False, "message": "Pacote bloqueado: atualize a lista antes de removê-lo."}

    current_path = _find_manager_executable(manager)
    if not current_path or os.path.realpath(current_path) != snapshot.get("path"):
        return {"success": False, "message": "O executável do gerenciador mudou; atualize a lista."}

    command = {
        "brew": [current_path, "uninstall", "--formula", exact_name],
        "npm": [current_path, "uninstall", "--global", exact_name],
        "pip": [current_path, "uninstall", "--yes", exact_name],
    }[manager]
    code, stdout, stderr = run_command(command, timeout=300)
    if code == 0:
        with _PACKAGE_LOCK:
            state = _LAST_PACKAGES.get(manager)
            if state:
                state.get("removable", {}).pop(exact_name.casefold(), None)
        return {
            "success": True,
            "message": f"{exact_name} removido pelo gerenciador {manager}.",
            "output": stdout,
        }
    return {
        "success": False,
        "message": f"Falha ao remover {exact_name}: {stderr or stdout or 'erro desconhecido'}",
    }


def clean_homebrew(clean_orphans: bool = False, clean_cache: bool = False) -> list[str]:
    """Runs explicit Homebrew maintenance actions."""
    logs = []
    brew_path = _find_manager_executable("brew")
    if not brew_path:
        return ["Homebrew não está instalado."]

    if clean_orphans:
        logs.append("Removendo dependências órfãs do Homebrew...")
        code, stdout, stderr = run_command([brew_path, "autoremove"])
        logs.append("✓ Órfãos removidos com sucesso." if code == 0 else f"✗ Erro ao remover órfãos: {stderr or stdout}")

    if clean_cache:
        logs.append("Limpando cache de downloads do Homebrew...")
        code, stdout, stderr = run_command([brew_path, "cleanup", "-s"])
        logs.append("✓ Cache do Homebrew limpo com sucesso." if code == 0 else f"✗ Erro ao limpar cache: {stderr or stdout}")

    return logs
