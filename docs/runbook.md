# Operator runbook and help

## Safe synthetic workflow

Start with README demo commands. `examples/*` are fictional and fixed-date; use their documented clock. `--help` and subcommand `--help` explain CLI flags. Healthy fixtures pass; drifted/unknown fixtures intentionally exit 1. Keep raw configuration and non-synthetic outputs outside Git, preferably under ignored `private/`. Report/stdout contents remain local unless you choose to publish them.

Create the `out` parent yourself. A successful assessment export writes `report.json`, `report.html`, `evidence.sqlite`. Open HTML directly in a browser; no server or external fonts/scripts are required. To inspect failed checks in SQLite:

```sql
SELECT control_id,status,value_json,review
FROM finding WHERE status IN ('FAIL','UNKNOWN','EXCEPTED')
ORDER BY control_id;
```

## Authorized live Windows collection

PowerShell 7 on Windows is required. Obtain system-owner permission; use a pseudonymous ID, not a user's real name or sensitive hostname. From an owned private working directory, run the trusted reviewed script with `-AcknowledgeAuthorizedHost`; inspect stdout before saving/sharing. It queries only local `Get-NetFirewallProfile -PolicyStore ActiveStore`, `Get-MpComputerStatus` and `Get-SmbServerConfiguration`. It does not elevate, change services, policy, firewall, registry or accounts. If permissions/cmdlets are insufficient, results are unknown. Do not disable security protections to make a check run.

```powershell
pwsh -NoProfile -File scripts/collect-windows.ps1 -HostId authorized-example -AcknowledgeAuthorizedHost
```

Do not use `-Synthetic` for real collection. The result is normalized JSON to stdout; no files are automatically overwritten. Save only to a new private file using your approved workflow, then assess with an explicit current UTC clock. The script deliberately does not collect ComputerID, scan history, usernames, addresses or credentials from larger cmdlet objects.

## Authorized live Linux collection

Only on a Linux host you own/administer with explicit approval, provide `--root /` and `--ack-authorized-host`. No default root or administrator elevation is provided. The collector reads `/etc/ssh/sshd_config`, its POSIX mode and `/proc/sys/kernel/randomize_va_space`; it does not launch sshd, sysctl writes or arbitrary commands.

```bash
bash scripts/collect-linux.sh --root / --host-id authorized-example --ack-authorized-host
```

For a **trusted fixture** tree use `--synthetic-tree` as well. Live mode is refused on other OSes. Fixed collector paths reject linked components instead of following unknown external files. A symlinked OS layout is therefore unsupported and requires a separately reviewed collection method. The collector does not infer unreadable values or hide Includes/Match clauses.

## Review and deviations

1. Check origin, digest, clock and source before interpreting PASS.
2. Investigate UNKNOWN with the owner; collect fresh authorized evidence instead of guessing defaults.
3. Review FAIL against compatibility, recovery access and business needs. Guidance is prose, not an executable repair plan.
4. If a risk owner approves a deviation, create an exact host/control/current-policy record modeled on the synthetic exception. Protect the file and verify approval externally; the lab cannot authenticate it.
5. Assess again with a new output directory, compare same-host/same-policy snapshots using historical clocks, and review expiry.

Do not turn missing evidence into exceptions or treat EXCEPTED as compliant. Changing the policy requires reviewing expected values and updating the exception digest explicitly. Never auto-relax a policy until a failing host passes.

## Troubleshooting

| Symptom | Safe response |
| --- | --- |
| Demo all UNKNOWN later | Use the documented fixture clock; real evidence needs a real current UTC clock |
| Exit 1 | Inspect findings; this is evidence of non-PASS posture, not a program crash |
| Exit 2 / input rejected | Check exact fields, types, duplicates, path, size and UTC format; raw inputs are not echoed |
| Export exists | Choose a new directory; existing reports are preserved |
| Export parent missing | Create an owned parent before running; recursive creation is not implicit |
| Windows activation restricted | Invoke `.venv\Scripts\python.exe` directly; do not weaken execution policy |
| SSH ambiguous | Use reviewed effective-state evidence; do not remove Includes/MFA merely to please the parser |
| Unknown Defender/SMB | Review command availability/permission/alternative service; do not install or disable software automatically |
| Drift incompatible | Verify host/platform/policy digest and chronological clocks; do not compare unrelated baselines |

Public issue reports should use synthetic reproducers only. [Jason Stys](https://github.com/JasonStys) / [LinkedIn](https://www.linkedin.com/in/jason-stys-31b30b351/) provides project contact. This lab has no production support SLA or remotely hosted account service.
