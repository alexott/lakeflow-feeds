"""Databricks-style secret references: {{secrets/<scope>/<key>}} (same syntax as in Databricks configs)."""
from __future__ import annotations

import re
from typing import Any, Callable

SECRET_REF = re.compile(r"\{\{secrets/([^/{}]+)/([^/{}]+)\}\}")
_ANY_REF = re.compile(r"\{\{\s*secrets")


class SecretError(ValueError):
    pass


def substitute(value: str, lookup: Callable[[str, str], str] | None) -> str:
    def repl(m: re.Match) -> str:
        if lookup is None:
            raise SecretError(f"secret reference secrets/{m.group(1)}/{m.group(2)} needs a secret lookup")
        return lookup(m.group(1), m.group(2))

    return SECRET_REF.sub(repl, value)


def substitute_all(obj: Any, lookup: Callable[[str, str], str] | None) -> Any:
    if isinstance(obj, str):
        return substitute(obj, lookup)
    if isinstance(obj, dict):
        return {k: substitute_all(v, lookup) for k, v in obj.items()}
    if isinstance(obj, list):
        return [substitute_all(v, lookup) for v in obj]
    return obj


def has_refs(obj: Any) -> bool:
    if isinstance(obj, str):
        return bool(_ANY_REF.search(obj))
    if isinstance(obj, dict):
        return any(has_refs(v) for v in obj.values())
    if isinstance(obj, list):
        return any(has_refs(v) for v in obj)
    return False


def malformed_refs(obj: Any) -> list[str]:
    """Strings that look like a secret reference but are not {{secrets/<scope>/<key>}}."""
    if isinstance(obj, str):
        return [obj] if _ANY_REF.search(SECRET_REF.sub("", obj)) else []
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in malformed_refs(v)]
    if isinstance(obj, list):
        return [s for v in obj for s in malformed_refs(v)]
    return []
