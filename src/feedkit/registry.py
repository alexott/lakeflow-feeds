"""Feed registry: one YAML file per feed, validated into a FeedSpec (spec §4, §4.1, §6.1)."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from feedkit.secrets import malformed_refs

# Lakewatch parser observable kinds (lakewatch-parser-dev references/indicators.md).
OBSERVABLE_KINDS = frozenset({
    "ip", "net_addr", "domain", "hostname", "url", "hash", "email", "cve", "username",
    "actor_id", "mac", "aws_arn", "aws_account_id", "aws_instance_id", "trace_id",
    "serial_number", "resource_tag", "mitre_attack_technique",
})


class RegistryError(ValueError):
    pass


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class Pagination(_Model):
    next: str  # JMESPath to the next-page URL in each response (null/empty = last page)
    records: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")  # key of the item list; pages are concatenated under it
    max_pages: int = 50


class Cursor(_Model):
    param: str  # query parameter that takes the cursor (ISO-8601), e.g. modified_since
    first_lookback_hours: int = 24
    overlap_minutes: int = 60
    # Never query further back than this (APIs cap a window, e.g. OTX refuses > 100k indicators); after a
    # long outage the gap beyond it is skipped rather than failing forever.
    max_lookback_hours: int | None = None


class Fetch(_Model):
    operator: Literal["http_snapshot", "github_repo", "rest_paginated", "taxii21_poll", "custom", "dns_derive"]
    url: str | None = None
    format: Literal["lines", "csv", "json", "jsonl", "zip+csv", "zip+lines", "stix"] = "lines"
    zip_member: str | None = None
    method: Literal["GET", "POST"] = "GET"
    body: dict[str, Any] | None = None  # request body for POST APIs (ThreatFox get_iocs)
    body_format: Literal["json", "form"] = "json"  # form: application/x-www-form-urlencoded (MalwareBazaar)
    pagination: Pagination | None = None
    cursor: Cursor | None = None
    connection: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)  # values may hold {{secrets/<scope>/<key>}} references
    ok_when: str | None = None  # JMESPath on the JSON response; false -> the fetch fails (API error bodies with HTTP 200)
    entrypoint: str | None = None


class Period(_Model):
    source: str  # zip_mtime | last_modified | today | yesterday | field:<name>
    granularity: Literal["day"] = "day"

    @model_validator(mode="after")
    def _source(self):
        if self.source not in {"zip_mtime", "last_modified", "today", "yesterday"} and \
                not self.source.startswith("field:"):
            raise ValueError(f"unknown period source {self.source!r}")
        return self


class History(_Model):
    type: Literal["none", "snapshots", "scd2"] = "none"
    retain_days: int | None = None


class Checks(_Model):
    min_records: int = 1
    max_change_pct: float | None = None
    canaries: list[str] = Field(default_factory=list)


class Expiry(_Model):
    max_age_days: int | None = None


class FeedSpec(_Model):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    mode: Literal["append", "merge", "replace"]
    period: Period | None = None
    key: list[str] | None = None
    sequence_by: str | None = None
    # none | tombstone_field:<f>. absent_in_full_fetch needs per-feed views (Plan 3) and is rejected for now.
    deletes: str = Field(default="none", pattern=r"^(none|tombstone_field:[A-Za-z_][A-Za-z0-9_]*)$")
    history: History | None = None
    category: str
    effect: Literal["allow", "enrich", "never_allow", "block"]
    observable_type: str | None = None
    fetch: Fetch
    change_detection: Literal["etag", "last_modified", "content_hash", "json_field", "release", "cursor", "none"] = "none"
    schedule: dict[str, Any] = Field(default_factory=dict)
    sink: Literal["zerobus", "volume"] = "zerobus"
    curation: Literal["views", "sdp"] = "views"
    targets: list[Literal["tables", "datasource"]] = Field(default_factory=lambda: ["tables"])
    datasource: Literal["generic", "per_feed"] = "generic"
    transform: list[dict[str, Any]] | dict[str, str]
    fields: list[dict[str, Any]] = Field(default_factory=list)
    validate_: Checks = Field(default_factory=Checks, alias="validate")
    expiry: Expiry = Field(default_factory=Expiry)
    license: str
    status: str = "active"

    @property
    def max_change_pct(self) -> float:
        if self.validate_.max_change_pct is not None:
            return float(self.validate_.max_change_pct)
        return 20.0 if self.mode == "replace" else 50.0

    @model_validator(mode="after")
    def _rules(self):
        if self.observable_type is not None and self.observable_type not in OBSERVABLE_KINDS:
            raise ValueError(f"observable_type {self.observable_type!r} is not a Lakewatch observable kind")
        if self.mode == "append" and self.period is None:
            raise ValueError("mode: append needs period")
        if self.mode == "merge" and not self.key:
            raise ValueError("mode: merge needs key")
        if self.history is not None and self.mode != "replace":
            raise ValueError("history is only allowed for mode: replace")
        if self.expiry.max_age_days is not None and self.mode != "merge":
            raise ValueError("expiry is only for mode: merge (replace/append current state is the latest commit)")
        if self.mode == "replace" and "datasource" in self.targets:
            raise ValueError("mode: replace feeds cannot target a datasource")
        if not self.license.strip():
            raise ValueError("license must not be empty")
        if isinstance(self.transform, dict):
            if set(self.transform) != {"function"}:
                raise ValueError("a dict transform must be {function: 'module:function'}")
        else:
            if not self.transform or "records" not in self.transform[0]:
                raise ValueError("the first transform step must be records")
            uses_explode = any("explode" in step for step in self.transform)
            if uses_explode and "datasource" in self.targets and self.datasource == "per_feed":
                raise ValueError("feeds with explode can only use the generic datasource")
        bad = malformed_refs([self.fetch.url, self.fetch.headers, self.fetch.body])
        if bad:
            raise ValueError(f"malformed secret reference (use {{{{secrets/<scope>/<key>}}}}): {bad}")
        if self.fetch.operator == "custom" and not self.fetch.entrypoint:
            raise ValueError("fetch.operator: custom needs fetch.entrypoint")
        return self


def load_feed(path: str | Path) -> FeedSpec:
    path = Path(path)
    try:
        data = yaml.safe_load(path.read_text())
        return FeedSpec.model_validate(data)
    except (ValidationError, yaml.YAMLError, TypeError) as e:
        raise RegistryError(f"{path.name}: {e}") from e


def load_registry(directory: str | Path) -> dict[str, FeedSpec]:
    feeds: dict[str, FeedSpec] = {}
    for path in sorted(Path(directory).glob("*.yaml")):
        if path.name == "settings.yaml":
            continue
        spec = load_feed(path)
        if spec.name in feeds:
            raise RegistryError(f"{path.name}: duplicate feed name {spec.name!r}")
        feeds[spec.name] = spec
    return feeds
