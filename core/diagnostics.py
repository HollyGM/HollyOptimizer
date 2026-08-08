import errno
import logging
import logging.handlers
import os
import threading
from collections import Counter, defaultdict, deque

from .version import APP_NAME

_LOCK = threading.RLock()
_ISSUES = defaultdict(lambda: deque(maxlen=200))
_LOGGER = logging.getLogger("hollyoptimizer")


def configure_logging() -> str:
    """Configures a small rotating log that never records complete user paths."""
    # Serialised: record_issue() calls this on every failure, and scans now run
    # their targets in parallel. Without the lock two workers can both find no
    # handler and install a second RotatingFileHandler onto the same file, which
    # duplicates every line and lets two rotators fight over the same backups.
    with _LOCK:
        if _LOGGER.handlers:
            return _LOGGER.handlers[0].baseFilename

        log_dir = os.path.expanduser(f"~/Library/Logs/{APP_NAME}")
        os.makedirs(log_dir, mode=0o700, exist_ok=True)
        log_path = os.path.join(log_dir, "hollyoptimizer.log")
        handler = logging.handlers.RotatingFileHandler(
            log_path, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
        )
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        _LOGGER.setLevel(logging.INFO)
        _LOGGER.addHandler(handler)
        _LOGGER.propagate = False
        return log_path


def _path_scope(path: str) -> str:
    if not path:
        return "unknown"
    resolved = os.path.realpath(os.path.expanduser(path))
    home = os.path.realpath(os.path.expanduser("~"))
    if resolved == home or resolved.startswith(home + os.sep):
        relative = os.path.relpath(resolved, home).split(os.sep)
        if relative[0] == "Library" and len(relative) > 1:
            return f"~/Library/{relative[1]}"
        return f"~/{relative[0]}"
    parts = resolved.strip(os.sep).split(os.sep)
    return f"/{parts[0]}" if parts and parts[0] else "/"


def _classify(exc: BaseException) -> tuple[str, str]:
    error_number = getattr(exc, "errno", None)
    text = str(exc).lower()
    if isinstance(exc, PermissionError) or error_number in (errno.EACCES, errno.EPERM):
        if "operation not permitted" in text:
            return "tcc_denied", "O macOS bloqueou o acesso. Verifique Acesso Total ao Disco."
        return "permission_denied", "Permissão insuficiente para acessar alguns itens."
    if isinstance(exc, FileNotFoundError) or error_number == errno.ENOENT:
        return "changed_during_scan", "Alguns itens mudaram durante a varredura."
    if isinstance(exc, OSError):
        return "io_error", "Alguns itens não puderam ser lidos pelo macOS."
    return "unexpected", "Ocorreu uma falha inesperada em parte da operação."


def record_issue(feature: str, exc: BaseException, path: str = "") -> None:
    code, message = _classify(exc)
    issue = {"code": code, "message": message, "scope": _path_scope(path)}
    with _LOCK:
        # A denied container can contain hundreds of equally denied children.
        # Keep one actionable diagnostic per feature/code/scope instead of
        # flooding the log and presenting the same permission problem as
        # hundreds of independent errors.
        if issue in _ISSUES[feature]:
            return
        _ISSUES[feature].append(issue)
    configure_logging()
    _LOGGER.warning(
        "feature=%s code=%s scope=%s errno=%s",
        feature,
        code,
        issue["scope"],
        getattr(exc, "errno", "none"),
    )


def consume_issues(feature: str = "") -> dict:
    with _LOCK:
        features = [feature] if feature else list(_ISSUES)
        issues = []
        for name in features:
            while _ISSUES[name]:
                item = dict(_ISSUES[name].popleft())
                item["feature"] = name
                issues.append(item)

    counts = Counter(item["code"] for item in issues)
    messages = []
    for item in issues:
        if item["message"] not in messages:
            messages.append(item["message"])
    return {"total": len(issues), "counts": dict(counts), "messages": messages}
