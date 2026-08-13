"""Security Monkey CLI — picks and applies a random misconfiguration.

Examples:
    python -m security_monkey.monkey --list
    python -m security_monkey.monkey --cloud azure --dry-run
    python -m security_monkey.monkey --cloud azure                 # random injector
    python -m security_monkey.monkey --cloud azure --only azure-nsg-open
    python -m security_monkey.monkey --cloud azure --yes           # skip confirmation

Injections are recorded to results/injections.log.json so `teardown.py` can revert them.
"""
from __future__ import annotations

import argparse
import random
import sys

from .base import Injector, append_record


def _load_injectors(cloud: str) -> list[Injector]:
    if cloud == "azure":
        from .azure_injectors import build_injectors
    elif cloud == "aws":
        from .aws_injectors import build_injectors
    else:
        raise SystemExit(f"Unknown cloud {cloud!r} (expected 'azure' or 'aws').")
    return build_injectors()


def _catalog(cloud: str) -> list[type[Injector]]:
    """Injector classes for a cloud — metadata only, no config required."""
    if cloud == "azure":
        from .azure_injectors import INJECTOR_CLASSES
    else:
        from .aws_injectors import INJECTOR_CLASSES
    return INJECTOR_CLASSES


def cmd_list() -> int:
    for cloud in ("azure", "aws"):
        print(f"\n{cloud.upper()} injectors:")
        for cls in _catalog(cloud):
            print(f"  {cls.key:<24} [{cls.misconfig_class}]  {cls.description}")
    return 0


def _confirm(prompt: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print("Refusing to inject non-interactively without --yes.", file=sys.stderr)
        return False
    return input(f"{prompt} [y/N] ").strip().lower() in ("y", "yes")


def cmd_inject(cloud: str, only: str | None, dry_run: bool, assume_yes: bool) -> int:
    injectors = _load_injectors(cloud)
    if only:
        injectors = [i for i in injectors if i.key == only]
        if not injectors:
            raise SystemExit(f"No injector with key {only!r} for cloud {cloud!r}.")

    chosen = injectors[0] if only else random.choice(injectors)

    print(f"Selected injector: {chosen.key}")
    print(f"  class:  {chosen.misconfig_class}")
    print(f"  action: {chosen.description}")

    if dry_run:
        print("\n[dry-run] No changes made. This is what WOULD be injected.")
        return 0

    if not _confirm(
        f"\nThis will WEAKEN a real cloud resource in the {cloud} lab. Proceed?",
        assume_yes,
    ):
        print("Aborted.")
        return 1

    record = chosen.inject()
    append_record(record)
    print(f"\n✅ Injected {record.injector_key} on target: {record.target}")
    print("   Recorded to results/injections.log.json — run teardown.py to revert.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="security_monkey.monkey",
        description="Inject a controlled cloud misconfiguration for detection testing.",
    )
    p.add_argument("--cloud", choices=["azure", "aws"], help="Target cloud.")
    p.add_argument("--only", help="Force a specific injector by key (see --list).")
    p.add_argument("--dry-run", action="store_true", help="Show the pick; make no changes.")
    p.add_argument("--yes", action="store_true", help="Skip the interactive confirmation.")
    p.add_argument("--list", action="store_true", help="List all injectors and exit.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list:
        return cmd_list()
    if not args.cloud:
        raise SystemExit("Specify --cloud azure|aws (or use --list).")
    return cmd_inject(args.cloud, args.only, args.dry_run, args.yes)


if __name__ == "__main__":
    raise SystemExit(main())
