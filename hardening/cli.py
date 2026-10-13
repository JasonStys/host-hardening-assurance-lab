"""Assessment/drift CLI and explicitly acknowledged read-only Linux collection. Created by Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: main — line 34
# parameter: argv — line 34
# variable: parser — line 36
# variable: commands — line 39
# variable: name — line 40
# variable: command — line 41
# variable: collector — line 55
# variable: args — line 60
# variable: result — line 63
# variable: policy — line 72
# variable: exceptions — line 73
# variable: report — line 74
# variable: before — line 76
# variable: drift — line 79
# END CODE MAP

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

from .collect import collect_linux
from .contracts import load_exceptions, load_policy, load_snapshot, timestamp
from .drift import compare
from .engine import assess
from .io import Rejected, canonical
from .report import export


def main(argv: list[str] | None = None) -> int:
    """Run argv or sys.argv; stdout is JSON, stderr is a sanitized error, exits 0/1/2 document outcome."""
    parser = argparse.ArgumentParser(
        description="Jason Stys — read-only host assurance, not enforcement"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("assess", "drift"):
        command = commands.add_parser(name)
        command.add_argument("--policy", type=Path, default=Path("policies/baseline.yml"))
        command.add_argument("--snapshot", type=Path, required=True)
        command.add_argument(
            "--as-of", required=True, help="Explicit UTC clock: YYYY-MM-DDTHH:MM:SSZ"
        )
        command.add_argument("--exceptions", type=Path)
        if name == "assess":
            command.add_argument(
                "--out", type=Path, help="New directory under an existing trusted parent"
            )
        else:
            command.add_argument("--before", type=Path, required=True)
            command.add_argument("--before-as-of", required=True)
    collector = commands.add_parser("collect-linux")
    collector.add_argument("--root", type=Path, required=True)
    collector.add_argument("--host-id", required=True)
    collector.add_argument("--ack-authorized-host", action="store_true")
    collector.add_argument("--synthetic-tree", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "collect-linux":
            result = collect_linux(
                args.root,
                args.host_id,
                datetime.now(UTC).replace(microsecond=0),
                args.ack_authorized_host,
                synthetic=args.synthetic_tree,
            )
            print(canonical(result).decode(), end="")
            return 0
        policy = load_policy(args.policy)
        exceptions = load_exceptions(args.exceptions, policy)
        report = assess(policy, load_snapshot(args.snapshot), timestamp(args.as_of), exceptions)
        if args.command == "drift":
            before = assess(
                policy, load_snapshot(args.before), timestamp(args.before_as_of), exceptions
            )
            drift = compare(before, report)
            print(canonical(drift).decode(), end="")
            return int(bool(drift["regressions"] or drift["evidence_gaps"] or report.exit_code()))
        if args.out:
            export(report, args.out)
        print(canonical(report.data()).decode(), end="")
        return report.exit_code()
    except Rejected as error:
        print(f"Input/output rejected: {error}", file=sys.stderr)
        return 2
