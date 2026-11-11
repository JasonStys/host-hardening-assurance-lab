# Installed Windows application validation 10 November 2026

By Jason Stys. This edition documents actual published **1.1.0** installed
bytes built from `fa1daf2af31dc76c0ade1069f6132071b888b3dc`. Earlier Office editions retain their
historical source baselines and byte identities.

## Observed results

All 5 downloaded assets matched provider/sidecar hashes. Actual frozen CPython 3.14.10 and Tcl/Tk 9.0.4 matched their recorded runtime identities.

Three original and refresh-review bundles survived restart exactly. Single-host and fleet workflows, missing evidence, malformed input and long-status lifecycle layout passed.

All current main workflows passed. Exact-source CodeQL analyses processed with zero open main alerts before publication.

New individual Desktop and Start-menu links target the installed accepted EXE. Shortcut metadata was read back; normal shortcut activation was not independently exercised.

## Illustrated workflow and implementation

The [four-page application guide](windows-application-guide-1.1.0.docx) contains actual installed
application screenshots, prepared inputs used within the full app, operating
steps and important code excerpts from the immutable runtime source. Every page
was inspected and the OOXML schema passed validation. The [review manifest](windows-application-guide-1.1.0.json)
records Word, screenshot, source and rendered-page identities.

## User data and limits

Download the matching Windows EXE and SHA256 sidecar from Releases. This is an unsigned portable app, not an MSI; Python installation and terminal commands are unnecessary. Keep the distribution and runtime notices together.

Open your own new or identified profile outside the installation. History is local plaintext protected by OS-owner access and an exclusive instance lock. Use Help for formats and limits; Exit application closes the owned workbench.

Only supplied snapshots are assessed. Local Windows acceptance is separate from genuine POSIX FIFO tests in hosted Linux/macOS checks. No host setting, credential or security policy was changed.

Reviewer names are assertions, not authenticated identities. These tests used isolated synthetic profiles and did not access existing user data, call external services or change Docker. Back up your complete profile before moving it.

Desktop and Start-menu target identities were verified where created. A complete
actual installed executable journey is separate from normal shortcut activation;
this report does not claim an additional manual shortcut-button test. No Docker
configuration, real credential or existing account data was used by the synthetic
acceptance. Prepared scenarios are inputs to the full product, never separate demo
applications.

This documentation commit must pass its own hosted checks. Earlier runtime results
do not certify future source changes.
