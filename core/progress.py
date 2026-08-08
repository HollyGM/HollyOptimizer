import threading
import time

_LOCK = threading.RLock()
_OPERATIONS = {}


def start(operation: str, message: str) -> None:
    with _LOCK:
        _OPERATIONS[operation] = {
            "active": True,
            "cancelled": False,
            "processed": 0,
            "message": message,
            "started_at": time.monotonic(),
        }


def update(operation: str, processed: int, message: str = "") -> None:
    with _LOCK:
        state = _OPERATIONS.get(operation)
        if not state:
            return
        state["processed"] = processed
        if message:
            state["message"] = message


def cancel(operation: str) -> bool:
    with _LOCK:
        state = _OPERATIONS.get(operation)
        if not state or not state["active"]:
            return False
        state["cancelled"] = True
        state["message"] = "Cancelamento solicitado…"
        return True


def is_cancelled(operation: str) -> bool:
    with _LOCK:
        return bool(_OPERATIONS.get(operation, {}).get("cancelled"))


def finish(operation: str, message: str = "Concluído") -> None:
    with _LOCK:
        state = _OPERATIONS.setdefault(operation, {})
        state["active"] = False
        state["message"] = message


def snapshot(operation: str) -> dict:
    with _LOCK:
        state = dict(_OPERATIONS.get(operation, {}))
    if not state:
        return {"active": False, "cancelled": False, "processed": 0, "message": ""}
    state.pop("started_at", None)
    return state
