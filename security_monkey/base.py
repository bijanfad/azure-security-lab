"""Injector abstraction + the injection ledger.

Every injector:
  * has a stable `key` (used in the coverage matrix and the ledger),
  * describes the misconfig class it simulates,
  * can `inject()` (weaken the baseline) and `revert()` (restore it),
  * is idempotent enough to be safe to re-run.

`inject()` returns a JSON-serialisable dict of "what I did" that is appended to the ledger
(results/injections.log.json). `teardown.py` replays the ledger to revert everything, so an
injector's revert should rely only on the config + the recorded detail.
"""
from __future__ import annotations

import abc
import json
from dataclasses import dataclass, field
from typing import Any

from .config import INJECTION_LOG, RESULTS_DIR


@dataclass
class InjectionRecord:
    """One entry in the ledger."""

    injector_key: str
    cloud: str
    misconfig_class: str
    target: str
    detail: dict[str, Any] = field(default_factory=dict)
    reverted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "injector_key": self.injector_key,
            "cloud": self.cloud,
            "misconfig_class": self.misconfig_class,
            "target": self.target,
            "detail": self.detail,
            "reverted": self.reverted,
        }


class Injector(abc.ABC):
    """Base class for all misconfiguration injectors."""

    #: short stable identifier, e.g. "azure-nsg-open"
    key: str = "unset"
    #: one of the misconfig classes from the coverage matrix
    misconfig_class: str = "unset"
    #: "azure" | "aws"
    cloud: str = "unset"
    #: human-readable one-liner
    description: str = ""

    @abc.abstractmethod
    def inject(self) -> InjectionRecord:
        """Apply the misconfiguration. Returns a ledger record."""

    @abc.abstractmethod
    def revert(self, record: InjectionRecord) -> None:
        """Undo the misconfiguration described by `record`."""


# --------------------------------------------------------------------------- #
# Ledger helpers — a plain JSON list on disk. Small scale, easy to inspect.
# --------------------------------------------------------------------------- #
def load_ledger() -> list[InjectionRecord]:
    if not INJECTION_LOG.exists():
        return []
    raw = json.loads(INJECTION_LOG.read_text() or "[]")
    return [
        InjectionRecord(
            injector_key=r["injector_key"],
            cloud=r["cloud"],
            misconfig_class=r["misconfig_class"],
            target=r["target"],
            detail=r.get("detail", {}),
            reverted=r.get("reverted", False),
        )
        for r in raw
    ]


def save_ledger(records: list[InjectionRecord]) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    INJECTION_LOG.write_text(json.dumps([r.to_dict() for r in records], indent=2))


def append_record(record: InjectionRecord) -> None:
    records = load_ledger()
    records.append(record)
    save_ledger(records)
