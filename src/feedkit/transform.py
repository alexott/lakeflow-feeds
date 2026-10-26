"""Declarative per-feed transforms (spec §6.1). Runs in the operator, no Spark."""
from __future__ import annotations

import copy
import csv
import hashlib
import importlib
import io
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any, Callable

import jmespath

from feedkit.records import RawRecord, ts

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class TransformError(ValueError):
    pass


def transform_version(transform: list | dict) -> str:
    return hashlib.sha256(json.dumps(transform, sort_keys=True).encode()).hexdigest()[:12]


def _search(expr: str, rec: Any) -> Any:
    try:
        return jmespath.search(expr, rec)
    except jmespath.exceptions.JMESPathError as e:
        raise TransformError(f"bad JMESPath {expr!r}: {e}") from e


def _wrap(elem: Any) -> dict:
    return elem if isinstance(elem, dict) else {"value": elem}


# --- records -------------------------------------------------------------------

def split_records(records_spec: str | list | dict, content: bytes) -> list[RawRecord]:
    text = content.decode("utf-8-sig")
    payloads: list[dict]
    if records_spec == "lines":
        payloads = [{"line": line.strip()} for line in text.splitlines() if line.strip()]
    elif records_spec == "csv" or (isinstance(records_spec, dict) and "csv" in records_spec):
        opts = records_spec["csv"] if isinstance(records_spec, dict) else {}
        lines = [line for line in text.splitlines() if line.strip()]
        if opts.get("comment"):
            lines = [line for line in lines if not line.startswith(opts["comment"])]
        payloads = [dict(row) for row in csv.DictReader(lines, fieldnames=opts.get("fieldnames"))]
    elif records_spec == "jsonl":
        try:
            payloads = [_wrap(json.loads(line)) for line in text.splitlines() if line.strip()]
        except json.JSONDecodeError as e:
            raise TransformError(f"bad JSON line: {e}") from e
    else:
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as e:
            raise TransformError(f"source is not valid JSON: {e}") from e
        payloads = []
        for path in records_spec if isinstance(records_spec, list) else [records_spec]:
            if path == "@":
                payloads.append(_wrap(doc))
                continue
            found = _search(path, doc)
            if found is None:
                continue
            payloads.extend(_wrap(e) for e in (found if isinstance(found, list) else [found]))
    return [RawRecord(record_no=i, payload=p) for i, p in enumerate(payloads)]


# --- steps -----------------------------------------------------------------------

def _to_timestamp(v: Any) -> str | None:
    if isinstance(v, (int, float)) or (isinstance(v, str) and re.fullmatch(r"\d+(\.\d+)?", v)):
        seconds = float(v)
        if seconds > 1e12:
            seconds /= 1000.0
        return ts(datetime.fromtimestamp(seconds, tz=timezone.utc))
    try:
        return ts(str(v))
    except ValueError:
        return None


def _cidr(v: Any) -> str | None:
    try:
        return ipaddress.ip_network(str(v).strip(), strict=False).compressed
    except ValueError:
        return None


def _ip(v: Any) -> str | None:
    try:
        addr = ipaddress.ip_address(str(v).strip())
    except ValueError:
        return None
    return None if addr.is_unspecified else addr.compressed


_FUNCS: dict[str, Callable[[Any], Any]] = {
    "lower": lambda v: str(v).lower(),
    "upper": lambda v: str(v).upper(),
    "trim": lambda v: str(v).strip(),
    "strip_dots": lambda v: str(v).strip("."),
    "cidr_normalize": _cidr,
    "ip_normalize": _ip,
    "to_timestamp": _to_timestamp,
}


def _filter(arg, recs):
    if isinstance(arg, str):
        return [r for r in recs if _search(arg, r)]
    field = arg.get("field", "line")
    if "regex" in arg:
        pattern = re.compile(arg["regex"])
        return [r for r in recs if pattern.search(str(r.get(field, "")))]
    pattern = re.compile(arg["regex_not"])
    return [r for r in recs if not pattern.search(str(r.get(field, "")))]


def _explode(arg, recs):
    out = []
    for r in recs:
        if "items" in arg:
            found = _search(arg["items"], r) or {}
            base = {} if arg["items"] == "@" else {k: v for k, v in r.items() if k != arg["items"]}
            for key, value in found.items():
                out.append({**base, arg["key_as"]: key, arg["value_as"]: value})
        else:
            path = arg["path"]
            base = {k: v for k, v in r.items() if not (_IDENT.fullmatch(path) and k == path)}
            for elem in _search(path, r) or []:
                out.append({**base, arg["as"]: elem})
    return out


def _extract(arg, recs):
    out = []
    for r in recs:
        r = dict(r)
        for name, expr in arg.items():
            if name == "regex":
                m = re.search(expr["pattern"], str(r.get(expr["field"], "")))
                if m:
                    r.update(m.groupdict())
            else:
                r[name] = _search(expr, r)
        out.append(r)
    return out


def _set(arg, recs):
    return [{**r, **copy.deepcopy(arg)} for r in recs]


def _map(arg, recs):
    out, default = [], arg.get("default", "keep")
    for r in recs:
        value = r.get(arg["field"])
        if value in arg["values"]:
            out.append({**r, arg["to"]: arg["values"][value]})
        elif default == "drop":
            continue
        elif default == "keep":
            out.append({**r, arg["to"]: value})
        else:
            out.append({**r, arg["to"]: default})
    return out


def _case(arg, recs):
    out = []
    for r in recs:
        result = arg.get("else")
        for branch in arg["when"]:
            if _search(branch["if"], r):
                result = branch["then"]
                break
        out.append({**r, arg["to"]: result})
    return out


def _apply(arg, recs):
    for name in (fn for fns in arg.values() for fn in fns):
        if name not in _FUNCS:
            raise TransformError(f"unknown apply function {name!r}")
    out = []
    for r in recs:
        r = dict(r)
        for field, fns in arg.items():
            for fn in fns:
                if r.get(field) is not None:
                    r[field] = _FUNCS[fn](r[field])
        out.append(r)
    return out


def _drop_if_empty(arg, recs):
    return [r for r in recs if all(r.get(f) not in (None, "") for f in arg)]


def _output(arg, recs):
    explicit_attrs = arg.get("attrs")
    targets = {k: v for k, v in arg.items() if k != "attrs"}
    used = {expr for expr in targets.values() if _IDENT.fullmatch(expr)}
    out = []
    for r in recs:
        o = {name: _search(expr, r) for name, expr in targets.items()}
        if explicit_attrs is not None:
            o["attrs"] = {name: _search(expr, r) for name, expr in explicit_attrs.items()}
        else:
            o["attrs"] = {k: v for k, v in r.items() if k not in used}
        out.append(o)
    return out


_STEPS = {"filter": _filter, "explode": _explode, "extract": _extract, "set": _set, "map": _map,
          "case": _case, "apply": _apply, "drop_if_empty": _drop_if_empty, "output": _output}


def run_steps(steps: list[dict], records: list[dict]) -> list[dict]:
    for step in steps:
        if len(step) != 1:
            raise TransformError(f"a transform step must have exactly one key, got {sorted(step)}")
        (name, arg), = step.items()
        if name not in _STEPS:
            raise TransformError(f"unknown transform step {name!r}")
        records = _STEPS[name](arg, records)
    return records


def run_transform(spec, content: bytes) -> tuple[list[RawRecord], list[dict]]:
    if isinstance(spec.transform, dict):
        module_name, _, fn_name = spec.transform["function"].partition(":")
        fn = getattr(importlib.import_module(module_name), fn_name)
        raw_payloads, normalized = fn(content, spec)
        return [RawRecord(record_no=i, payload=p) for i, p in enumerate(raw_payloads)], normalized
    raw = split_records(spec.transform[0]["records"], content)
    normalized = run_steps(spec.transform[1:], [dict(r.payload) for r in raw])
    return raw, normalized
