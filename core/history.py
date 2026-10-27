"""
Histórico local de limpezas e varreduras, com restauração a partir da Lixeira.

Tudo que o HollyOptimizer move vai para a Lixeira nativa — ela já é a
"quarentena" do macOS, e só o usuário a esvazia. O que faltava era memória:
saber o que foi movido, quando, de onde, e poder desfazer sem procurar na
Lixeira. Este módulo registra cada movimentação (caminho original, nome que
o item recebeu na Lixeira, tamanho) e cada varredura (espaço livre e tamanho
por categoria), e oferece ``restore_move`` para devolver um item ao lugar
original enquanto ele ainda estiver na Lixeira.

O arquivo fica em ``~/Library/Application Support/HollyOptimizer`` e nunca
sai do Mac.
"""

import os
import shutil
import threading
import time
import uuid

from .settings import data_dir, read_json, write_json_atomic
from .utils import (
    _expand,
    format_size,
    has_symlink_component,
    is_safe_app_bundle,
    is_safe_to_delete,
    validate_path_sanity,
)

_LOCK = threading.RLock()
_MAX_MOVES = 600
_MAX_SCANS = 120
_BATCH = {"id": "", "label": ""}

FEATURE_NAMES = {
    "junk": "Lixo do Sistema",
    "browser_caches": "Navegadores",
    "leftovers": "Sobras de Apps",
    "large_files": "Arquivos Grandes",
    "duplicates": "Duplicados",
    "uninstaller": "Desinstalador",
}


def _history_path() -> str:
    return os.path.join(data_dir(), "history.json")


def _empty() -> dict:
    return {"version": 1, "moves": [], "scans": [], "startup_labels": []}


def _load() -> dict:
    data = read_json(_history_path(), None)
    if not isinstance(data, dict):
        return _empty()
    base = _empty()
    for key, default in base.items():
        value = data.get(key, default)
        base[key] = value if isinstance(value, type(default)) else default
    return base


def _save(data: dict) -> None:
    data["moves"] = data["moves"][-_MAX_MOVES:]
    data["scans"] = data["scans"][-_MAX_SCANS:]
    write_json_atomic(_history_path(), data)


def begin_batch(label: str) -> str:
    """Agrupa as próximas movimentações sob um rótulo (uma ação da interface)."""
    batch_id = uuid.uuid4().hex[:12]
    with _LOCK:
        _BATCH["id"] = batch_id
        _BATCH["label"] = str(label or "")[:80]
    return batch_id


def record_move(
    *,
    feature: str,
    original_path: str,
    trash_path: str,
    size_bytes: int = 0,
    file_count: int = 0,
) -> None:
    """Registra uma movimentação já concluída para a Lixeira."""
    entry = {
        "id": uuid.uuid4().hex,
        "ts": time.time(),
        "feature": str(feature or ""),
        "batch": _BATCH["id"],
        "batch_label": _BATCH["label"],
        "original_path": str(original_path),
        "trash_path": str(trash_path),
        "size_bytes": max(0, int(size_bytes or 0)),
        "file_count": max(0, int(file_count or 0)),
        "restored": False,
    }
    with _LOCK:
        data = _load()
        data["moves"].append(entry)
        _save(data)


def record_scan(
    *,
    free_bytes: int,
    total_bytes: int,
    cleanable_bytes: int,
    inventory_bytes: int,
    categories: dict,
) -> None:
    """Guarda o retrato de uma varredura: espaço livre e tamanho por categoria."""
    compact = {}
    for key, item in (categories or {}).items():
        if not isinstance(item, dict):
            continue
        compact[str(key)] = {
            "name": str(item.get("name", key)),
            "size_bytes": max(0, int(item.get("size_bytes", 0) or 0)),
            "cleanable": bool(item.get("cleanable", False)),
        }
    entry = {
        "ts": time.time(),
        "free_bytes": max(0, int(free_bytes or 0)),
        "total_bytes": max(0, int(total_bytes or 0)),
        "cleanable_bytes": max(0, int(cleanable_bytes or 0)),
        "inventory_bytes": max(0, int(inventory_bytes or 0)),
        "categories": compact,
    }
    with _LOCK:
        data = _load()
        data["scans"].append(entry)
        _save(data)


def update_startup_labels(labels) -> set | None:
    """
    Guarda os rótulos de inicialização vistos e devolve os já conhecidos.
    Devolve ``None`` na primeira varredura (não há base de comparação).
    """
    current = sorted({str(label) for label in labels if label})
    with _LOCK:
        data = _load()
        stored = data.get("startup_labels")
        known = set(stored) if stored else None
        data["startup_labels"] = sorted(set(current) | (known or set()))
        _save(data)
    return known


def _trash_dir() -> str:
    return _expand("~/.Trash")


def trash_accessible() -> bool:
    """~/.Trash is protected by the macOS privacy layer; without Full Disk
    Access the app cannot see or move items back out of it."""
    try:
        os.listdir(_trash_dir())
        return True
    except OSError:
        return False


def _move_status(entry: dict, accessible: bool = True) -> str:
    if entry.get("restored"):
        return "restored"
    if not accessible:
        return "unknown"
    trash_path = entry.get("trash_path") or ""
    if trash_path and os.path.lexists(trash_path):
        return "in_trash"
    return "gone"


def _growth(scans: list) -> list:
    """Compara as duas últimas varreduras: o que mais cresceu por categoria."""
    if len(scans) < 2:
        return []
    previous, latest = scans[-2]["categories"], scans[-1]["categories"]
    deltas = []
    for key, item in latest.items():
        before = int(previous.get(key, {}).get("size_bytes", 0))
        after = int(item.get("size_bytes", 0))
        if after > before:
            deltas.append(
                {
                    "key": key,
                    "name": item.get("name", key),
                    "before_bytes": before,
                    "after_bytes": after,
                    "delta_bytes": after - before,
                    "delta_human": format_size(after - before),
                    "after_human": format_size(after),
                }
            )
    deltas.sort(key=lambda item: item["delta_bytes"], reverse=True)
    return deltas[:6]


def list_history(*, batch_limit: int = 40, scan_limit: int = 30) -> dict:
    """Visão para a interface: lotes de limpeza, linha do tempo e crescimento."""
    with _LOCK:
        data = _load()
    accessible = trash_accessible()

    batches = {}
    order = []
    for entry in data["moves"]:
        key = entry.get("batch") or f"{entry.get('feature')}:{int(entry.get('ts', 0)) // 300}"
        if key not in batches:
            feature = entry.get("feature", "")
            batches[key] = {
                "id": key,
                "label": entry.get("batch_label") or FEATURE_NAMES.get(feature, feature or "Limpeza"),
                "ts": entry.get("ts", 0),
                "features": [],
                "items": [],
                "size_bytes": 0,
                "in_trash": 0,
                "restored": 0,
                "gone": 0,
                "unknown": 0,
            }
            order.append(key)
        batch = batches[key]
        feature = entry.get("feature", "")
        if feature and feature not in batch["features"]:
            batch["features"].append(feature)
        status = _move_status(entry, accessible)
        batch[status] += 1
        batch["size_bytes"] += int(entry.get("size_bytes", 0))
        batch["items"].append(
            {
                "id": entry["id"],
                "ts": entry.get("ts", 0),
                "feature": feature,
                "feature_name": FEATURE_NAMES.get(feature, feature),
                "original_path": entry.get("original_path", ""),
                "name": os.path.basename(entry.get("original_path", "").rstrip(os.sep)),
                "trash_name": os.path.basename(entry.get("trash_path", "").rstrip(os.sep)),
                "size_bytes": int(entry.get("size_bytes", 0)),
                "size_human": format_size(int(entry.get("size_bytes", 0))),
                "file_count": int(entry.get("file_count", 0)),
                "status": status,
            }
        )

    batch_list = []
    for key in reversed(order):
        batch = batches[key]
        batch["size_human"] = format_size(batch["size_bytes"])
        batch["items"].reverse()
        batch_list.append(batch)

    scans = []
    for scan in reversed(data["scans"][-scan_limit:]):
        scans.append(
            {
                "ts": scan.get("ts", 0),
                "free_bytes": scan.get("free_bytes", 0),
                "free_human": format_size(scan.get("free_bytes", 0)),
                "total_bytes": scan.get("total_bytes", 0),
                "cleanable_bytes": scan.get("cleanable_bytes", 0),
                "cleanable_human": format_size(scan.get("cleanable_bytes", 0)),
                "inventory_bytes": scan.get("inventory_bytes", 0),
                "inventory_human": format_size(scan.get("inventory_bytes", 0)),
            }
        )

    moved_total = sum(int(entry.get("size_bytes", 0)) for entry in data["moves"])
    return {
        "trash_accessible": accessible,
        "batches": batch_list[:batch_limit],
        "scans": scans,
        "growth": _growth(data["scans"]),
        "totals": {
            "moves": len(data["moves"]),
            "moved_bytes": moved_total,
            "moved_human": format_size(moved_total),
            "scans": len(data["scans"]),
        },
    }


def restore_move(entry_id: str) -> tuple[bool, str]:
    """
    Devolve um item da Lixeira ao caminho original registrado.

    Só restaura o que o próprio HollyOptimizer moveu: o item ainda precisa
    estar dentro de ``~/.Trash``, o caminho original precisa estar livre e
    dentro das áreas que o app administra, e nenhum componente pode ser link
    simbólico. Qualquer dúvida deixa o item onde está.
    """
    if not isinstance(entry_id, str) or not entry_id.strip():
        return False, "Registro inválido."

    with _LOCK:
        data = _load()
        entry = next((item for item in data["moves"] if item.get("id") == entry_id), None)
        if entry is None:
            return False, "Registro não encontrado no histórico."
        if entry.get("restored"):
            return False, "Este item já foi restaurado."

        trash_path = str(entry.get("trash_path") or "")
        original = str(entry.get("original_path") or "")
        try:
            validate_path_sanity(trash_path)
            validate_path_sanity(original)
        except ValueError as exc:
            return False, str(exc)

        trash_dir = _trash_dir()
        resolved_trash = os.path.realpath(trash_path)
        if not resolved_trash.startswith(trash_dir + os.sep) or resolved_trash == trash_dir:
            return False, "O item registrado não está na Lixeira do usuário."
        if not trash_accessible():
            return False, (
                "O macOS não deixa o HollyOptimizer ler a Lixeira. Conceda Acesso "
                "Total ao Disco na aba Permissões ou use “Colocar de Volta” no Finder."
            )
        if not os.path.lexists(trash_path):
            return False, "O item não está mais na Lixeira (ela foi esvaziada ou o item foi movido)."
        if has_symlink_component(trash_path):
            return False, "Item bloqueado: links simbólicos não são restaurados."

        if os.path.lexists(original):
            return False, "Já existe um item no caminho original; nada foi alterado."
        parent = os.path.dirname(original)
        if not os.path.isdir(parent) or has_symlink_component(parent):
            return False, "A pasta de origem não existe mais; restaure pelo Finder."
        try:
            allowed = is_safe_to_delete(original) or is_safe_app_bundle(original)
        except ValueError:
            allowed = False
        if not allowed:
            return False, "Caminho original fora das áreas administradas pelo HollyOptimizer."

        try:
            try:
                os.rename(trash_path, original)
            except OSError as exc:
                if getattr(exc, "errno", None) != 18:  # EXDEV: volumes diferentes
                    raise
                shutil.move(trash_path, original)
        except OSError as exc:
            return False, f"O macOS não conseguiu restaurar o item: {exc.strerror or exc}"

        entry["restored"] = True
        entry["restored_at"] = time.time()
        _save(data)

    return True, f"Restaurado: {os.path.basename(original.rstrip(os.sep))}"
