"""Security Monkey CLI — picks and applies a random Azure misconfiguration.

Examples:
    python -m security_monkey.monkey --list
    python -m security_monkey.monkey --dry-run
    python -m security_monkey.monkey                       # random injector
    python -m security_monkey.monkey --only azure-nsg-open
    python -m security_monkey.monkey --yes                 # skip confirmation

Injections are recorded to results/injections.log.json so `teardown.py` can revert them.
"""
from __future__ import annotations

import argparse
import random
import sys

from .azure_injectors import INJECTOR_CLASSES, build_injectors
from .base import append_record


def cmd_list() -> int:
    print("Azure injectors:")
    for cls in INJECTOR_CLASSES:
        print(f"  {cls.key:<24} [{cls.misconfig_class}]  {cls.description}")
    return 0


def _confirm(prompt: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print("Refusing to inject non-interactively without --yes.", file=sys.stderr)
        return False
    return input(f"{prompt} [y/N] ").strip().lower() in ("y", "yes")


def cmd_inject(only: str | None, dry_run: bool, assume_yes: bool) -> int:
    injectors = build_injectors()
    if only:
        injectors = [i for i in injectors if i.key == only]
        if not injectors:
            raise SystemExit(f"No injector with key {only!r} (see --list).")

    chosen = injectors[0] if only else random.choice(injectors)

    print(f"Selected injector: {chosen.key}")
    print(f"  class:  {chosen.misconfig_class}")
    print(f"  action: {chosen.description}")

    if dry_run:
        print("\n[dry-run] No changes made. This is what WOULD be injected.")
        return 0

    if not _confirm(
        "\nThis will WEAKEN a real Azure resource in the lab. Proceed?",
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
        description="Inject a controlled Azure misconfiguration for detection testing.",
    )
    p.add_argument("--only", help="Force a specific injector by key (see --list).")
    p.add_argument("--dry-run", action="store_true", help="Show the pick; make no changes.")
    p.add_argument("--yes", action="store_true", help="Skip the interactive confirmation.")
    p.add_argument("--list", action="store_true", help="List all injectors and exit.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list:
        return cmd_list()
    return cmd_inject(args.only, args.dry_run, args.yes)


if __name__ == "__main__":
    raise SystemExit(main())
