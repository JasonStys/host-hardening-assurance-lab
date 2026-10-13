# Jason Stys: parse the collector without executing host queries; allowlist its command AST.
# Parameters: none. Variables: path/tokens/errors identify parsed source; commands lists command names.
# Functions: none; parser failures or command drift fail CI, without changing host settings.
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ErrorActionPreference — line 19
# variable: path — line 20
# variable: PSScriptRoot — line 20
# variable: tokens — line 21
# variable: null — line 21
# variable: errors — line 22
# variable: tree — line 23
# variable: commands — line 25
# variable: node — line 25
# variable: true — line 25
# variable: allow — line 26
# variable: command — line 27
# END CODE MAP
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$path = Join-Path $PSScriptRoot 'collect-windows.ps1'
$tokens = $null
$errors = $null
$tree = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw 'Collector syntax is invalid' }
$commands = $tree.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true)
$allow = @('Set-StrictMode', 'Convert-Evidence', 'Get-Evidence', 'Get-NetFirewallProfile', 'Get-MpComputerStatus', 'Get-SmbServerConfiguration', 'ConvertTo-Json')
foreach ($command in $commands) {
    if ($command.GetCommandName() -notin $allow) { throw 'Collector has a command outside the read-only allowlist' }
}
Write-Output 'PowerShell parse and read-only command allowlist passed'
