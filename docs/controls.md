# Control applicability and honest limitations

The authored ten-control policy is a **small demonstration**, not full host assurance. It must be reviewed per platform/version and business context; avoid importing a benchmark name as a certification claim.

| Platform / facts | What is checked | What is not established |
| --- | --- | --- |
| Linux SSH password/root/keyboard authentication | Explicit simple global declarations equal `no` | Effective daemon state, command-line options, MFA suitability, all auth channels, syntax validity or whether SSH is running |
| Linux SSH mode | POSIX group/other write bits absent | File owner, ACLs, parent permissions, capabilities or Windows ACL semantics |
| Linux ASLR | Read kernel `randomize_va_space` equals 2 | Binary build protections, compatibility, architecture support or exploit immunity |
| Windows three firewall profiles | Enabled properties from `ActiveStore` | Current network profile, service/filter driver health, rule sufficiency or actual packet filtering |
| Windows Defender | Reported real-time protection flag true | Malware-free state, signatures, scan coverage, alternate AV suitability or tamper resistance |
| Windows SMB1 | SMB **server** v1 configuration false | SMB client policy, all file-sharing exposure or full SMB hardening |

The Linux collector intentionally does not implement the complete OpenSSH parser. Include, Match, ChallengeResponseAuthentication alias, quoting or malformed recognized directives make all three authentication facts ambiguous. First obtained values of recognized simple global declarations win. Missing declarations are unknown: defaults are not guessed. Unrecognized other directives are ignored, so even a passing parsed declaration is not a full configuration validation. Complex installations need independently obtained and authenticated effective-state evidence from an approved collector; no command from the configuration is executed.

PowerShell handles explicit GPO enum True/False without coercing `NotConfigured`, integer 1 or null to true. Missing cmdlets, service availability and insufficient permission return unknown. Alternate endpoint protection or MFA may require documented deviations rather than blind setting changes.

Future additions could cover patch currency, disk encryption, auditd, account/privilege policy, kernel modules, secure boot and effective service checks. They need version-specific evidence contracts, approved collection and independent tests before inclusion. They are not represented as implemented features today.
