"""
Ponte opcional com a Apple Intelligence on-device (Foundation Models).

O HollyOptimizer é um app Python/PyWebView; o framework FoundationModels só
tem API pública em Swift. Em vez de tentar uma ponte PyObjC inexistente, um
executável Swift isolado (tools/ai_summary) roda como subprocesso: recebe um
resumo já calculado deterministicamente em Python via stdin (JSON) e devolve,
via stdout (JSON), a mesma informação reescrita em uma frase mais natural
pelo modelo local — nunca decide o que foi escaneado ou o que é seguro
remover, apenas reformula um texto que o Python já produziu.

Todo o processamento acontece no dispositivo (SystemLanguageModel local, sem
Private Cloud Compute) e falha sempre em modo silencioso: SO antigo, hardware
incompatível, Apple Intelligence desativada, modelo baixando, binário
ausente ou timeout resultam todos em available=False, e a interface volta ao
resumo determinístico que já existia antes desta funcionalidade.
"""

import json
import os
import platform
import subprocess  # nosec B404
import sys
import threading

_LOCK = threading.RLock()
_RESOURCE_ROOT = {"value": None}

_MAX_FACTS_LENGTH = 4000
_TIMEOUT_SECONDS = 20


def configure(resource_root: str) -> None:
    """Registra a raiz de recursos do app (equivalente a sys._MEIPASS/cwd)."""
    with _LOCK:
        _RESOURCE_ROOT["value"] = resource_root


def _candidate_paths() -> list[str]:
    candidates = []
    with _LOCK:
        root = _RESOURCE_ROOT["value"]
    if root:
        candidates.append(os.path.join(root, "ai", "hollyoptimizer-ai"))
    repo_root = os.path.dirname(os.path.abspath(__file__))
    candidates.append(
        os.path.join(os.path.dirname(repo_root), "tools", "ai_summary", "hollyoptimizer-ai")
    )
    return candidates


def _locate_binary() -> str:
    for candidate in _candidate_paths():
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return ""


def is_available() -> bool:
    """Verificação rápida e barata, sem chamar o modelo: binário presente e Apple Silicon."""
    if platform.machine() != "arm64":
        return False
    return bool(_locate_binary())


def summarize(facts: str) -> dict:
    """
    Pede ao modelo on-device para reescrever `facts` em uma frase natural.

    Sempre retorna um dict com a chave "available"; nunca levanta exceção.
    """
    if not isinstance(facts, str) or not facts.strip():
        return {"available": False, "reason": "invalid_input"}
    if platform.machine() != "arm64":
        return {"available": False, "reason": "unsupported_architecture"}

    binary = _locate_binary()
    if not binary:
        return {"available": False, "reason": "helper_not_bundled"}

    payload = json.dumps({"facts": facts[:_MAX_FACTS_LENGTH]})
    try:
        result = subprocess.run(  # nosec B603
            [binary],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            shell=False,
            timeout=_TIMEOUT_SECONDS,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"available": False, "reason": type(exc).__name__}

    try:
        parsed = json.loads(result.stdout.strip() or "{}")
    except ValueError:
        return {"available": False, "reason": "invalid_helper_output"}

    if not isinstance(parsed, dict) or "available" not in parsed:
        return {"available": False, "reason": "invalid_helper_output"}
    return parsed
