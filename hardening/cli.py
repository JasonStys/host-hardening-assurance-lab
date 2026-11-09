"""Assessment/drift CLI and explicitly acknowledged read-only Linux collection. Created by Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: main — line 38
# parameter: argv — line 38
# variable: parser — line 40
# variable: commands — line 43
# variable: name — line 44
# variable: command — line 45
# variable: fleet — line 59
# variable: collector — line 68
# variable: args — line 73
# variable: result — line 76
# variable: policy — line 85
# variable: exceptions — line 86
# variable: result — line 90
# variable: path — line 92
# variable: report — line 101
# variable: before — line 103
# variable: drift — line 106
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
from .fleet import assess_fleet, inventory, publish
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
    fleet = commands.add_parser(
        "fleet", help="Assess an explicit inventory and route evidence refresh"
    )
    fleet.add_argument("--inventory", type=Path, required=True)
    fleet.add_argument("--snapshot", type=Path, action="append", default=[])
    fleet.add_argument("--policy", type=Path, default=Path("policies/baseline.yml"))
    fleet.add_argument("--exceptions", type=Path)
    fleet.add_argument("--as-of", required=True)
    fleet.add_argument("--out", type=Path)
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
        if args.command == "fleet":
            if len(args.snapshot) > 500:
                raise Rejected("too many snapshots")
            result = assess_fleet(
                inventory(args.inventory),
                tuple(load_snapshot(path) for path in args.snapshot),
                policy,
                timestamp(args.as_of),
                exceptions,
            )
            if args.out:
                publish(result, args.out)
            print(canonical(result).decode(), end="")
            return int(not result["all_expected_controls_pass"])
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
