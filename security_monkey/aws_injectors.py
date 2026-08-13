"""AWS misconfiguration injectors — Phase 2.

Mirrors the Azure injectors against the AWS lab (terraform/aws/). These are scaffolded stubs:
the class metadata (key / misconfig_class / description) is real so they already show up in
`monkey.py --list` and in the coverage matrix, but `inject()`/`revert()` are not implemented
until the AWS lab module exists.

Planned implementation uses boto3 with the default credential chain (`aws configure` / env /
instance profile) — no secrets handled here.
"""
from __future__ import annotations

from .base import Injector, InjectionRecord
from .config import AwsConfig


class _NotYetImplemented(Injector):
    """Phase-2 placeholder that fails loudly if actually invoked."""

    def __init__(self, cfg: AwsConfig):
        self.cfg = cfg

    def inject(self) -> InjectionRecord:  # pragma: no cover - stub
        raise NotImplementedError(
            f"{self.key}: AWS injectors land in Phase 2 (after the Azure MVP). "
            f"See terraform/aws/README.md."
        )

    def revert(self, record: InjectionRecord) -> None:  # pragma: no cover - stub
        raise NotImplementedError(f"{self.key}: not implemented yet.")


class SecurityGroupOpenInjector(_NotYetImplemented):
    key = "aws-sg-open"
    misconfig_class = "network-exposure"
    cloud = "aws"
    description = "Adds a Security Group ingress rule allowing 0.0.0.0/0 to SSH/RDP."


class S3PublicInjector(_NotYetImplemented):
    key = "aws-s3-public"
    misconfig_class = "public-data"
    cloud = "aws"
    description = "Disables S3 Public Access Block and applies a public-read bucket policy."


class IamOverpermissiveInjector(_NotYetImplemented):
    key = "aws-iam-broad"
    misconfig_class = "over-permissive-identity"
    cloud = "aws"
    description = "Attaches an over-permissive (e.g. *:*) IAM policy to a test user/role."


INJECTOR_CLASSES: list[type[Injector]] = [
    SecurityGroupOpenInjector,
    S3PublicInjector,
    IamOverpermissiveInjector,
]


def build_injectors(cfg: AwsConfig | None = None) -> list[Injector]:
    cfg = cfg or AwsConfig.from_env()
    return [cls(cfg) for cls in INJECTOR_CLASSES]
