"""Env-driven configuration + safety guards for the Security Monkey.

Config comes from environment variables (see .env / Terraform `monkey_env` output). We never
hard-code credentials — Azure auth uses DefaultAzureCredential (`az login`, env SP, or managed
identity) and AWS uses the default boto3 credential chain.

The safety scope (resource group + prefix + subscription) is the single most important control
in this project: injectors MUST refuse to touch anything outside it.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# results/injections.log.json is the ledger teardown replays to revert.
REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = REPO_ROOT / "results"
INJECTION_LOG = RESULTS_DIR / "injections.log.json"


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or unsafe."""


def _require(name: str) -> str:
    val = os.environ.get(name, "").strip()
    if not val:
        raise ConfigError(
            f"Missing required env var {name!r}. "
            f"Populate it from the Terraform `monkey_env` output (see README)."
        )
    return val


@dataclass(frozen=True)
class AzureConfig:
    subscription_id: str
    resource_group: str
    prefix: str
    nsg_name: str
    storage_account: str

    @classmethod
    def from_env(cls) -> "AzureConfig":
        return cls(
            subscription_id=_require("SECLAB_AZURE_SUBSCRIPTION_ID"),
            resource_group=_require("SECLAB_AZURE_RESOURCE_GROUP"),
            prefix=os.environ.get("SECLAB_PREFIX", "seclab").strip(),
            nsg_name=_require("SECLAB_AZURE_NSG"),
            storage_account=_require("SECLAB_AZURE_STORAGE_ACCOUNT"),
        )

    def assert_in_scope(self, resource_group: str) -> None:
        """Hard guard: refuse to act on any RG that isn't the configured lab RG."""
        if resource_group.lower() != self.resource_group.lower():
            raise ConfigError(
                f"REFUSING to act on resource group {resource_group!r}; "
                f"the lab is scoped to {self.resource_group!r} only."
            )
        if not self.resource_group.lower().startswith(self.prefix.lower()):
            raise ConfigError(
                f"Lab RG {self.resource_group!r} does not start with the safety prefix "
                f"{self.prefix!r}; refusing to proceed."
            )


@dataclass(frozen=True)
class AwsConfig:
    region: str
    prefix: str

    @classmethod
    def from_env(cls) -> "AwsConfig":
        return cls(
            region=os.environ.get("SECLAB_AWS_REGION", "eu-central-1").strip(),
            prefix=os.environ.get("SECLAB_PREFIX", "seclab").strip(),
        )
