<# 
.SYNOPSIS
  Exports an AD user inventory with key account attributes and status.

.DESCRIPTION
  Collects for all (or scoped) AD users:
  UserName, FullName, AccountType, Comment, HomeDrive, HomeDir, Profile,
  LogonScript, Workstations, PswdCanBeChanged, PswdLastSetTime, PswdRequired,
  PswdExpires, PswdExpiresTime, AcctDisabled, AcctLockedOut, AcctExpiresTime,
  LastLogonTime, LastLogonServer, LogonHours.

.PARAMETER SearchBase
  Optional distinguishedName (DN) to scope the search (e.g., "OU=Users,DC=contoso,DC=com").

.PARAMETER Server
  Optional domain controller (DNS name) to target initial queries.

.PARAMETER OutputPath
  Where to write the CSV (default: .\ADUserReport.csv)

.PARAMETER AccurateLastLogon
  If set, queries every DC to compute the exact lastLogon and its source server.

.PARAMETER NoExport
  If set, does not write CSV; outputs objects to the pipeline only.

.EXAMPLE
  .\Get-ADUserAccountInventory.ps1 -OutputPath C:\Temp\ADUsers.csv

.EXAMPLE
  .\Get-ADUserAccountInventory.ps1 -SearchBase "OU=Staff,DC=contoso,DC=com" -AccurateLastLogon

.EXAMPLE
  .\Get-ADUserAccountInventory.ps1 -Server dc1.contoso.com -OutputPath .\users.csv
#>

[CmdletBinding()]
param(
    [string]$SearchBase,
    [string]$Server,
    [string]$OutputPath = ".\ADUserReport.csv",
    [switch]$AccurateLastLogon,
    [switch]$NoExport
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-Module {
    param([Parameter(Mandatory)][string]$Name)
    if (-not (Get-Module -Name $Name -ListAvailable)) {
        throw "Required module '$Name' is not available. Install RSAT: Active Directory module, then try again."
    }
    Import-Module $Name -ErrorAction Stop | Out-Null
}

function Get-AccountTypeFromUAC {
    param([int]$UAC)
    # Common account-type flags
    $flags = [ordered]@{
        'TempDuplicate'          = 0x0100
        'Normal'                 = 0x0200
        'InterdomainTrust'       = 0x0800
        'WorkstationTrust'       = 0x1000
        'ServerTrust'            = 0x2000
    }
    foreach ($k in $flags.Keys) {
        if ($UAC -band $flags[$k]) { return $k }
    }
    # Fallback if no well-known type flag matched
    return 'Unknown'
}

function Convert-LogonHoursToText {
    <#
      Converts AD logonHours (21-byte array, 168 bits, Sunday 00:00–Sunday 23:00 UTC)
      to a readable schedule in local time (using current local UTC offset).
    #>
    param([byte[]]$Bytes)

    if (-not $Bytes -or $Bytes.Length -ne 21) { return 'All hours (no restriction or attribute missing)' }

    # Expand 168 bits -> bool[168]
    $bits = New-Object bool[] 168
    $bitIndex = 0
    foreach ($b in $Bytes) {
        for ($i=0; $i -lt 8; $i++) {
            $bits[$bitIndex] = [bool]($b -band (1 -shl (7 - $i)))
            $bitIndex++
            if ($bitIndex -ge 168) { break }
        }
    }

    # Determine if all allowed or none
    $allowedCount = ($bits | Where-Object { $_ }).Count
    if ($allowedCount -eq 168) { return 'All hours' }
    if ($allowedCount -eq 0)   { return 'No logon' }

    # Adjust for local timezone offset (approximate, uses current offset)
    $offsetHours = [int][Math]::Round([TimeZoneInfo]::Local.GetUtcOffset([datetime]::UtcNow).TotalHours)
    if ($offsetHours -ne 0) {
        # Rotate array by offsetHours (UTC -> Local)
        $rot = New-Object bool[] 168
        for ($i=0; $i -lt 168; $i++) {
            $j = ($i + $offsetHours) % 168
            if ($j -lt 0) { $j += 168 }
            $rot[$j] = $bits[$i]
        }
        $bits = $rot
    }

    $days = @('Sun','Mon','Tue','Wed','Thu','Fri','Sat')
    $parts = @()

    for ($d=0; $d -lt 7; $d++) {
        $dayBits = $bits[($d*24)..(($d*24)+23)]
        $ranges = @()
        $inRun = $false
        $start = 0

        for ($h=0; $h -lt 24; $h++) {
            if ($dayBits[$h] -and -not $inRun) {
                $inRun = $true
                $start = $h
            } elseif (-not $dayBits[$h] -and $inRun) {
                $inRun = $false
                $ranges += ('{0:00}:00-{1:00}:00' -f $start, $h)
            }
        }
        if ($inRun) { $ranges += ('{0:00}:00-24:00' -f $start) }

        if ($ranges.Count -eq 0) {
            $parts += "$($days[$d]) None"
        } elseif ($ranges.Count -eq 1 -and $ranges[0] -eq '00:00-24:00') {
            $parts += "$($days[$d]) All"
        } else {
            $parts += "$($days[$d]) " + ($ranges -join ', ')
        }
    }

    return ($parts -join '; ')
}

function Get-AccurateLastLogon {
    <#
        Queries every DC for the user's raw lastLogon attribute and returns the latest time and source server.
        Returns a hashtable with keys: LastLogonTime, LastLogonServer
    #>
    param(
        [Parameter(Mandatory)][Microsoft.ActiveDirectory.Management.ADUser]$User,
        [Parameter(Mandatory)][Microsoft.ActiveDirectory.Management.ADDomainController[]]$DomainControllers
    )

    $maxTime = [datetime]::MinValue
    $source  = $null

    foreach ($dc in $DomainControllers) {
        try {
            $u = Get-ADUser -Identity $User.DistinguishedName -Server $dc.HostName -Properties lastLogon -ErrorAction Stop
            if ($u.lastLogon -and [int64]$u.lastLogon -gt 0) {
                $t = [DateTime]::FromFileTime([int64]$u.lastLogon)
                if ($t -gt $maxTime) {
                    $maxTime = $t
                    $source  = $dc.HostName
                }
            }
        } catch {
            # Continue to next DC
            continue
        }
    }

    if ($maxTime -eq [datetime]::MinValue) {
        return @{ LastLogonTime = $null; LastLogonServer = $null }
    } else {
        return @{ LastLogonTime = $maxTime; LastLogonServer = $source }
    }
}

# Helper: safely read a property only if it exists on the object
function Get-PropValue {
    param(
        [Parameter(Mandatory)] $Object,
        [Parameter(Mandatory)][string] $PropName
    )
    if (-not $Object) { return $null }
    if ($Object.PSObject.Properties.Name -contains $PropName) {
        return $Object.$PropName
    }
    return $null
}

try {
    Test-Module -Name ActiveDirectory

    # Use -Properties * to request all properties; script will pick what exists per-object
    $getParams = @{
        Filter     = '*'
        Properties = '*'
        ErrorAction= 'Stop'
    }
    if ($SearchBase) { $getParams['SearchBase'] = $SearchBase }
    if ($Server)     { $getParams['Server']     = $Server }

    $users = Get-ADUser @getParams

    $dcs = $null
    if ($AccurateLastLogon) {
        $dcParams = @{}
        if ($Server) { $dcParams['Server'] = $Server }
        $dcs = Get-ADDomainController -Filter * @dcParams
    }

    $out = foreach ($u in $users) {
        # Safe reads
        $uacRaw = Get-PropValue -Object $u -PropName 'userAccountControl'
        $uac = if ($uacRaw) { [int]$uacRaw } else { 0 }

        # AccountType
        $acctType = Get-AccountTypeFromUAC -UAC $uac

        # Comment (prefer 'comment', fallback to 'description', then 'userComment' if present)
        $comment = $null
        $c = Get-PropValue -Object $u -PropName 'comment'
        if ($c) {
            $comment = $c
        } else {
            $d = Get-PropValue -Object $u -PropName 'description'
            if ($d) {
                $comment = $d
            } else {
                $uc = Get-PropValue -Object $u -PropName 'userComment'
                if ($uc) { $comment = $uc }
            }
        }

        # Password expiry time (constructed attribute)
        $pwdExpTime = $null
        $pwdRaw = Get-PropValue -Object $u -PropName 'msDS-UserPasswordExpiryTimeComputed'
        if ($pwdRaw) {
            try { $pwdExpTime = [DateTime]::FromFileTime([int64]$pwdRaw) } catch {}
        }

        # Accurate last logon (optional)
        $lastLogonTime   = Get-PropValue -Object $u -PropName 'LastLogonDate'
        $lastLogonServer = $null
        if ($AccurateLastLogon -and $dcs) {
            $ll = Get-AccurateLastLogon -User $u -DomainControllers $dcs
            $lastLogonTime   = $ll.LastLogonTime
            $lastLogonServer = $ll.LastLogonServer
        }

        # LogonHours -> text
        $logonBytes = Get-PropValue -Object $u -PropName 'logonHours'
        $logonHoursText = Convert-LogonHoursToText -Bytes $logonBytes

        [pscustomobject]@{
            UserName          = Get-PropValue -Object $u -PropName 'SamAccountName'
            FullName          = Get-PropValue -Object $u -PropName 'Name'
            AccountType       = $acctType
            Comment           = $comment
            HomeDrive         = Get-PropValue -Object $u -PropName 'homeDrive'
            HomeDir           = Get-PropValue -Object $u -PropName 'homeDirectory'
            Profile           = Get-PropValue -Object $u -PropName 'profilePath'
            LogonScript       = Get-PropValue -Object $u -PropName 'scriptPath'
            Workstations      = Get-PropValue -Object $u -PropName 'logonWorkstations'
            PswdCanBeChanged  = -not [bool](Get-PropValue -Object $u -PropName 'CannotChangePassword')
            PswdLastSetTime   = Get-PropValue -Object $u -PropName 'PasswordLastSet'
            PswdRequired      = -not [bool](Get-PropValue -Object $u -PropName 'PasswordNotRequired')
            PswdExpires       = -not [bool](Get-PropValue -Object $u -PropName 'PasswordNeverExpires')
            PswdExpiresTime   = $pwdExpTime
            AcctDisabled      = -not [bool](Get-PropValue -Object $u -PropName 'Enabled')
            AcctLockedOut     = [bool](Get-PropValue -Object $u -PropName 'LockedOut')
            AcctExpiresTime   = Get-PropValue -Object $u -PropName 'AccountExpirationDate'
            LastLogonTime     = $lastLogonTime
            LastLogonServer   = $lastLogonServer
            LogonHours        = $logonHoursText
        }
    }

    # Ensure we have an array so Count works predictably
    if ($out -is [System.Collections.IEnumerable] -and -not ($out -is [array])) {
        $out = ,$out
    }

    if (-not $NoExport) {
        $out | Sort-Object UserName | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutputPath
        Write-Host "Exported $($out.Count) users to: $OutputPath" -ForegroundColor Green
    } else {
        $out | Sort-Object UserName
    }
}
catch {
    Write-Error $_.Exception.Message
    throw
}
