# Jason Stys: opt-in read-only Windows evidence to stdout; synthetic mode never queries the host.
# Functions: Convert-Evidence normalizes typed values; Get-Evidence gathers five allowlisted facts.
# Parameters: HostId is pseudonymous; Synthetic/Scenario select fixtures; acknowledgement enables local read-only commands.
# No elevation, registry writes, remote sessions, settings changes, credentials or raw command errors.
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: true — line 38
# variable: HostId — line 40
# variable: Synthetic — line 41
# variable: Scenario — line 43
# variable: AcknowledgeAuthorizedHost — line 44
# variable: ObservedAt — line 46
# variable: ErrorActionPreference — line 49
# function: Convert-Evidence — line 51
# variable: Value — line 56
# variable: Source — line 56
# variable: Gpo — line 56
# variable: quality — line 57
# variable: result — line 58
# variable: null — line 58
# variable: label — line 63
# function: Get-Evidence — line 72
# variable: UseFixture — line 77
# variable: FixtureScenario — line 77
# variable: profiles — line 78
# variable: realtime — line 79
# variable: smb1 — line 80
# variable: false — line 85
# variable: profile — line 95
# variable: facts — line 104
# variable: name — line 105
# variable: IsWindows — line 116
# variable: clock — line 117
# variable: kind — line 118
# variable: snapshot — line 119
# END CODE MAP
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$')]
    [string]$HostId,
    [switch]$Synthetic,
    [ValidateSet('Healthy', 'Drifted', 'Unknown')]
    [string]$Scenario = 'Healthy',
    [switch]$AcknowledgeAuthorizedHost,
    [ValidatePattern('^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$')]
    [string]$ObservedAt = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Convert-Evidence {
    <# .SYNOPSIS
    Normalize Value from an allowlisted command with Source provenance; Gpo permits explicit enum True/False.
    Unrecognized, numeric, null and NotConfigured values stay unknown, never coerced to truthy booleans.
    #>
    param($Value, [string]$Source, [switch]$Gpo)
    $quality = 'unavailable'
    $result = $null
    if ($Value -is [bool]) {
        $quality = 'observed'
        $result = $Value
    } elseif ($Gpo -and $null -ne $Value) {
        $label = $Value.ToString()
        if ($label -ceq 'True' -or $label -ceq 'False') {
            $quality = 'observed'
            $result = $label -ceq 'True'
        }
    }
    return @{ value = $result; quality = $quality; source = $Source }
}

function Get-Evidence {
    <# .SYNOPSIS
    UseFixture and FixtureScenario select authored data only; otherwise read local ActiveStore, Defender and SMB state.
    Unavailable cmdlets/permissions produce null observations; no service, policy or security settings are modified.
    #>
    param([bool]$UseFixture, [string]$FixtureScenario)
    $profiles = @{}
    $realtime = $null
    $smb1 = $null
    if ($UseFixture) {
        if ($FixtureScenario -eq 'Healthy') {
            $profiles = @{ Domain = 'True'; Private = 'True'; Public = 'True' }
            $realtime = $true
            $smb1 = $false
        } elseif ($FixtureScenario -eq 'Drifted') {
            $profiles = @{ Domain = 'True'; Private = 'False'; Public = 'False' }
            $realtime = $false
            $smb1 = $true
        } else {
            $profiles = @{ Domain = 'NotConfigured'; Private = 1; Public = $null }
        }
    } else {
        try {
            foreach ($profile in (Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)) {
                if ($profile.Name -in @('Domain', 'Private', 'Public')) {
                    $profiles[$profile.Name] = $profile.Enabled
                }
            }
        } catch { $profiles = @{} }
        try { $realtime = (Get-MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled } catch { $realtime = $null }
        try { $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch { $smb1 = $null }
    }
    $facts = @{}
    foreach ($name in @('Domain', 'Private', 'Public')) {
        $facts['firewall.' + $name.ToLowerInvariant()] = Convert-Evidence -Value $profiles[$name] -Source 'Get-NetFirewallProfile:ActiveStore' -Gpo
    }
    $facts['defender.realtime'] = Convert-Evidence -Value $realtime -Source 'Get-MpComputerStatus:RealTimeProtectionEnabled'
    $facts['smb.smb1'] = Convert-Evidence -Value $smb1 -Source 'Get-SmbServerConfiguration:EnableSMB1Protocol'
    return $facts
}

if (-not $Synthetic -and -not $AcknowledgeAuthorizedHost) {
    throw 'Read-only collection requires -AcknowledgeAuthorizedHost; use -Synthetic for safe fixtures.'
}
if (-not $Synthetic -and -not $IsWindows) { throw 'Live Windows collection requires PowerShell 7 on Windows.' }
$clock = [DateTime]::ParseExact($ObservedAt, 'yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
$kind = if ($Synthetic) { 'synthetic' } else { 'authorized_read_only' }
$snapshot = @{
    schema = 1; host_id = $HostId; platform = 'windows'; observed_at = $clock.ToString('yyyy-MM-ddTHH:mm:ssZ')
    kind = $kind; collector = 'windows-cmdlets-v1'; facts = Get-Evidence -UseFixture ([bool]$Synthetic) -FixtureScenario $Scenario
}
$snapshot | ConvertTo-Json -Depth 5 -Compress
