"""Deployment settings (registry_data/settings.yaml). No secrets."""
from __future__ import annotations

from dataclasses import dataclass, fields
from pathlib import Path

import yaml


@dataclass(frozen=True)
class Settings:
    catalog: str = "cybersecurity"
    raw_schema: str = "feeds_raw"
    volume_root: str = "/Volumes/cybersecurity/feeds"
    zerobus_endpoint: str | None = None
    zerobus_batch_size: int = 1000
    workspace_id: str | None = None
    # Run-as service principal for Zerobus tokens; {{secrets/<scope>/<key>}} references.
    sp_client_id: str = "{{secrets/feeds/sp_client_id}}"
    sp_client_secret: str = "{{secrets/feeds/sp_client_secret}}"

    def raw_table(self, feed: str) -> str:
        return f"{self.catalog}.{self.raw_schema}.{feed}"

    @property
    def records_table(self) -> str:
        return f"{self.catalog}.{self.raw_schema}.records"


def load_settings(path: str | Path) -> Settings:
    data = yaml.safe_load(Path(path).read_text()) or {}
    known = {f.name for f in fields(Settings)}
    unknown = set(data) - known
    if unknown:
        raise ValueError(f"unknown settings: {sorted(unknown)}")
    return Settings(**data)
