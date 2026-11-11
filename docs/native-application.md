# Host Hardening Assurance native workbench

Created by Jason Stys · [GitHub](https://github.com/JasonStys) · [Contact](https://www.linkedin.com/in/jason-stys-31b30b351/)

The portable `HostHardeningAssuranceLab.exe` is the real project with native graphical controls: choose authorized offline evidence/policies, evaluate it, inspect/filter results and export the actual reports. Prepared fictional scenarios are optional inputs inside that same application. End users open one executable without Python, Node, Docker, credentials or setup commands. Publication and desktop-shortcut installation remain separate reviewed steps.

## Practical offline workflows

1. In **Inputs and analysis**, choose a prepared case or your supported snapshot JSON and baseline YAML. Select an operation; only its relevant fields are shown. Set an explicit evaluation UTC clock and, when applicable, scoped exception JSON. Acknowledge permission after editing; this is an operator assertion, not authenticated authority. Nothing runs automatically on startup.
2. **Assess one offline snapshot** invokes the existing policy engine. PASS is selected evidence matching the authored baseline. FAIL is a mismatch, UNKNOWN is missing/stale/future/unsupported evidence, and EXCEPTED remains a deviation. An exception does not convert unknown evidence or an approved deviation into PASS.
3. **Compare same-host drift** additionally requires an earlier snapshot and earlier clock. It uses the same host/platform/policy and original chronology checks. Evidence gaps are distinct from regressions/restoration; changing a clock or evidence quality is not proof that settings improved.
4. **Review declared inventory** accepts explicit inventory JSON and zero or more selected snapshot files. Missing expected hosts remain UNKNOWN with an owner-routed refresh queue. Duplicate, out-of-scope and wrong-platform evidence is rejected, not silently dropped. Unlike platforms remain grouped under their own policy counts.
5. In **Findings and timeline**, choose control results, drift, refresh needs or the review plan. Search literal host/control/context and select a row for complete evidence and guidance. **The review/remediation plan is inert text: the application never runs a collector, shell command, cmdlet or settings change.** It neither independently approves exceptions nor certifies effective protection.
6. Export the selected completed bundle to a new directory under a private parent. Single-host assessments export the original core JSON, inert HTML and SQLite; drift adds actual drift JSON/HTML; inventory exports the real fleet bundle. No existing file is overwritten. Failed input leaves earlier results intact.

The prepared Linux deviation case intentionally yields 2 PASS / 2 FAIL / 1 EXCEPTED. The drift case has three regressions. The declared three-host fleet supplies two healthy hosts and leaves the third missing: 10 PASS and 5 UNKNOWN, not a 100% fleet pass. Historical fixture clocks are explicit; use your actual evidence and clock for other work. These are configuration observations for ten authored controls, not full CIS/STIG coverage, overall host-security proof or permission to collect real hosts.

**Saved analyses** reopens exact retained bytes without re-collecting or re-evaluating. Explicit removal confirms the selected bundle hash and deletes only its local SQLite rows; original evidence files and prior exports remain. Back up/export what you need before removal. Logical removal does not promise forensic erasure or immediate SQLite file shrinkage. Help and readable runtime licenses are available locally.

## Lifecycle, data and privacy

The Windows profile is `%LOCALAPPDATA%\JasonStys\HostHardeningAssuranceLab`, independent of executable version and working directory. It holds a product marker, exclusive instance lock and `history.sqlite` outside Git/install paths. Unknown nonempty, linked or incompatible profiles are refused without reset. Existing CLI paths and opt-in collector contracts remain unchanged; this GUI has no collector path.

The GUI is responsive while one owned background job calls the real core. Input changes require acknowledgement again. Export/removal cannot race a running job. Close/Exit waits for that job and committed storage, then releases the lock; it does not kill or adopt another process. Back up the complete profile after clean exit and preserve it when replacing the executable. A second real process is tested reopening synthetic history; populated real-user migrations are not claimed. Removing the executable leaves the profile intact.

**Plaintext OS-owner state** is visible to permitted filesystem users/admins and local malware. No cloud account, remote authentication, production tenant boundary, hidden-from-owner storage, telemetry, automatic network access or external model was added. Protect evidence and exports. No real system was collected or changed by the native acceptance.

Limits: 20 retained runs, 128 MiB of bundle payloads, 64 MiB per bundle, 32 MiB per file, eight files per bundle and 5,000 visible matching table rows. Metadata/SQLite overhead adds space. Full bounded outputs remain exportable. Limits reject new work without automatic eviction; export and explicitly remove local analyses to manage retention. These bounds do not guarantee OS/disk response time or complete protection against local denial of service.

Windows x64 is the tested frozen target. Source CLI remains cross-platform; a source GUI requires Tk/SQLite. macOS/Linux/mobile frozen packages were not produced. Advanced `--profile PATH` selects a marked separate workspace; normal desktop use requires no arguments.

## Build and acceptance

Build in a fresh isolated **CPython 3.14.10** environment; no global Python/registry/PATH update is required. Older-runtime builds are rejected.

```text
python -m pip install --require-hashes -r requirements-dev.lock -r requirements-native.lock
python scripts/build_native.py
python scripts/test_native_app.py
```

Only exact public policies/examples/schema/resources are included. The reference SDK has Tcl/Tk 9.0.4 zipfs libraries; the collector retains the actual binary-read notices and also understands conventional 8.6 layouts. PyInstaller 6.22.3 supports this runtime. Metadata/resource validation includes the actual `python314.dll`; the frozen application and consumer receipt require patched 3.14.10 with matching DLL hash. Source commit and dirty state are explicit. This is a portable application, not MSI/NSIS or Authenticode-signing proof.

Acceptance instantiates the same real Tk controls/mainloop and drives their actual handlers with explicitly synthetic profiles. Independent oracles check scoped deviations, three drift regressions, missing-host denominators, invalid clocks, exact private export, graceful exit and a second process reopening identical bundle hashes. Only export-dialog destination selection is supplied programmatically; no core result is mocked. Provider/account environment variables and Python/Node child PATH are absent. Fixed acceptance flags cannot enter a normal profile or evaluate arbitrary scripts. Screenshots show only the owned synthetic window; independent OS accessibility automation is not claimed.

The lifecycle follows [Python's Tk threading model](https://docs.python.org/3.14/library/tkinter.html#threading-model); per-user storage avoids [PyInstaller's temporary one-file extraction](https://pyinstaller.org/en/stable/operating-mode.html#how-the-one-file-program-works). The [dated validation record](reports/native-application-2026-11-10.md) keeps candidate and hosted/release outcomes distinct.
