"""
WazuhBOTS -- Base classes for alert generation.

Provides AlertBuilder (constructs Wazuh-schema JSON alerts) and
BaseScenarioGenerator (abstract class that each scenario implements).
"""

import abc
import hashlib
import json
import random
import string
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Alert builder
# ---------------------------------------------------------------------------

class AlertBuilder:
    """Build a single Wazuh alert document that matches the real schema."""

    def __init__(
        self,
        agent_id: str,
        agent_name: str,
        agent_ip: str,
        manager_name: str = "wazuh-manager",
    ):
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.agent_ip = agent_ip
        self.manager_name = manager_name

    # -- helpers --------------------------------------------------------

    @staticmethod
    def random_id(length: int = 20) -> str:
        return "".join(random.choices(string.digits, k=length))

    @staticmethod
    def ts_str(dt: datetime) -> str:
        """ISO-8601 with Z suffix."""
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def ts_millis(dt: datetime) -> str:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{random.randint(0,999):03d}Z"

    @staticmethod
    def geoip_data(country: str, city: str, lat: float, lon: float) -> dict:
        return {
            "country_name": country,
            "city_name": city,
            "location": {"lat": lat, "lon": lon},
        }

    @staticmethod
    def mitre_block(technique_ids: list[str], tactic: str | None = None) -> dict:
        m: dict[str, Any] = {"id": technique_ids}
        if tactic:
            m["tactic"] = [tactic]
        return m

    # -- core builder ---------------------------------------------------

    def build(
        self,
        timestamp: datetime,
        rule_id: str,
        rule_description: str,
        rule_level: int,
        rule_groups: list[str] | None = None,
        decoder_name: str = "json",
        location: str = "",
        srcip: str = "",
        dstip: str = "",
        srcport: str = "",
        dstport: str = "",
        srcuser: str = "",
        dstuser: str = "",
        full_log: str = "",
        data: dict | None = None,
        syscheck: dict | None = None,
        mitre: dict | None = None,
        extra: dict | None = None,
    ) -> dict:
        ts = self.ts_str(timestamp)
        ts_ms = self.ts_millis(timestamp)

        alert: dict[str, Any] = {
            "timestamp": ts,
            "@timestamp": ts_ms,
            "rule": {
                "id": str(rule_id),
                "description": rule_description,
                "level": rule_level,
                "groups": rule_groups or ["wazuhbots"],
                "firedtimes": random.randint(1, 200),
            },
            "agent": {
                "id": self.agent_id,
                "name": self.agent_name,
                "ip": self.agent_ip,
            },
            "manager": {"name": self.manager_name},
            "decoder": {"name": decoder_name},
            "id": self.random_id(),
            "full_log": full_log,
            "location": location or f"/var/log/{self.agent_name}/messages",
        }

        if srcip:
            alert["data"] = alert.get("data", {})
            alert["data"]["srcip"] = srcip
        if dstip:
            alert.setdefault("data", {})["dstip"] = dstip
        if srcport:
            alert.setdefault("data", {})["srcport"] = srcport
        if dstport:
            alert.setdefault("data", {})["dstport"] = dstport
        if srcuser:
            alert.setdefault("data", {})["srcuser"] = srcuser
        if dstuser:
            alert.setdefault("data", {})["dstuser"] = dstuser
        if data:
            alert.setdefault("data", {}).update(data)
        if syscheck:
            alert["syscheck"] = syscheck
        if mitre:
            alert["rule"]["mitre"] = mitre
        if extra:
            alert.update(extra)

        return alert


# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

def incremental_timestamps(
    start: datetime, end: datetime, count: int, jitter_seconds: int = 0
) -> list[datetime]:
    """Return *count* timestamps evenly spread between *start* and *end*."""
    if count <= 1:
        return [start]
    step = (end - start) / (count - 1)
    ts = []
    for i in range(count):
        t = start + step * i
        if jitter_seconds:
            t += timedelta(seconds=random.uniform(-jitter_seconds, jitter_seconds))
        ts.append(t)
    return ts


def random_timestamp(start: datetime, end: datetime) -> datetime:
    delta = (end - start).total_seconds()
    return start + timedelta(seconds=random.uniform(0, delta))


# ---------------------------------------------------------------------------
# Abstract base generator
# ---------------------------------------------------------------------------

class BaseScenarioGenerator(abc.ABC):
    """Every scenario generator must implement generate()."""

    scenario_id: int
    scenario_name: str
    output_dir: Path

    @abc.abstractmethod
    def generate(self) -> list[dict]:
        ...

    def write_output(self, alerts: list[dict]) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        out = self.output_dir / "wazuh-alerts.json"
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(alerts, fh, indent=None, ensure_ascii=False)
        return out
