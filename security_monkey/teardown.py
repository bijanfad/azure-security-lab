"""Revert everything the Security Monkey injected.

Replays results/injections.log.json in reverse and calls each injector's `revert()`. This
restores the secure Terraform baseline WITHOUT destroying the lab itself (run
`terraform destroy` for that).

Examples:
    python -m security_monkey.teardown
    python -m security_monkey.teardown --yes
"""
from __future__ import annotations

import argparse
import sys

from .azure_injectors import build_injectors
from .base import InjectionRecord, load_ledger, save_ledger


def cmd_teardown(assume_yes: bool) -> int:
    ledger = load_ledger()
    pending = [r for r in ledger if not r.reverted]
    if not pending:
        print("Nothing to revert. Ledger is clean.")
        return 0

    print(f"{len(pending)} injection(s) to revert:")
    for r in pending:
        print(f"  - {r.injector_key} on {r.target}")

    if not assume_yes:
        if not sys.stdin.isatty():
            print("Refusing to revert non-interactively without --yes.", file=sys.stderr)
            return 1
        if input("Revert all of the above? [y/N] ").strip().lower() not in ("y", "yes"):
            print("Aborted.")
            return 1

    injectors = {i.key: i for i in build_injectors()}
    failures: list[tuple[InjectionRecord, Exception]] = []

    # Revert most-recent-first so layered changes unwind cleanly.
    for record in reversed(pending):
        injector = injectors.get(record.injector_key)
        if injector is None:
            failures.append((record, RuntimeError("no injector for key")))
            continue
        try:
            injector.revert(record)
            record.reverted = True
            print(f"↩️  Reverted {record.injector_key} ({record.target})")
        except Exception as exc:  # noqa: BLE001 - report and continue
            failures.append((record, exc))
            print(f"⚠️  Failed to revert {record.injector_key}: {exc}", file=sys.stderr)

    save_ledger(ledger)  # persist reverted flags (records mutated in place)

    if failures:
        print(f"\n{len(failures)} revert(s) failed — inspect manually.", file=sys.stderr)
        return 1
    print("\n✅ All injections reverted. Baseline restored.")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="security_monkey.teardown",
        description="Revert Security Monkey injections recorded in the ledger.",
    )
    p.add_argument("--yes", action="store_true", help="Skip the interactive confirmation.")
    args = p.parse_args(argv)
    return cmd_teardown(args.yes)


if __name__ == "__main__":
    raise SystemExit(main())
