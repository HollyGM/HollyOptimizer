"""
Preferências locais do HollyOptimizer.

Um único arquivo JSON em ``~/Library/Application Support/HollyOptimizer``.
Nada aqui sai do Mac: as preferências existem só para que a interface lembre
escolhas simples, como a meta de espaço livre usada pelo aviso do Dashboard.
"""

import json
import os
import threading

from .version import APP_NAME

_LOCK = threading.RLock()

DEFAULTS = {
    # Abaixo deste espaço livre o Dashboard mostra o aviso de disco cheio.
    "free_space_goal_gb": 20,
}
FREE_SPACE_GOAL_MIN_GB = 1
FREE_SPACE_GOAL_MAX_GB = 100_000


def data_dir() -> str:
    """Pasta própria do app, criada sob demanda e legível só pelo usuário."""
    path = os.path.expanduser(f"~/Library/Application Support/{APP_NAME}")
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def write_json_atomic(path: str, payload) -> None:
    """Grava JSON por arquivo temporário + rename, para nunca deixar um JSON truncado."""
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    temporary = f"{path}.tmp-{os.getpid()}"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=1)
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def read_json(path: str, default):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


def _settings_path() -> str:
    return os.path.join(data_dir(), "settings.json")


def coerce_free_space_goal(value) -> int:
    """Aceita número ou texto numérico; fora da faixa cai no padrão."""
    try:
        if isinstance(value, bool):
            raise ValueError
        number = int(float(value))
    except (TypeError, ValueError):
        return DEFAULTS["free_space_goal_gb"]
    if not FREE_SPACE_GOAL_MIN_GB <= number <= FREE_SPACE_GOAL_MAX_GB:
        return DEFAULTS["free_space_goal_gb"]
    return number


def load_settings() -> dict:
    with _LOCK:
        data = dict(DEFAULTS)
        stored = read_json(_settings_path(), {})
        if isinstance(stored, dict):
            for key in DEFAULTS:
                if key in stored:
                    data[key] = stored[key]
        data["free_space_goal_gb"] = coerce_free_space_goal(data["free_space_goal_gb"])
        return data


def set_free_space_goal(value) -> dict:
    """Valida e persiste a meta de espaço livre; devolve as preferências atuais."""
    try:
        if isinstance(value, bool):
            raise ValueError
        number = int(float(value))
    except (TypeError, ValueError) as exc:
        raise ValueError("Meta de espaço livre inválida.") from exc
    if not FREE_SPACE_GOAL_MIN_GB <= number <= FREE_SPACE_GOAL_MAX_GB:
        raise ValueError(
            f"A meta deve ficar entre {FREE_SPACE_GOAL_MIN_GB} e {FREE_SPACE_GOAL_MAX_GB} GB."
        )
    with _LOCK:
        data = load_settings()
        data["free_space_goal_gb"] = number
        write_json_atomic(_settings_path(), data)
        return data
