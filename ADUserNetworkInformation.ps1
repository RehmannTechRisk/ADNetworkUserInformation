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

try {
    Test-Module -Name ActiveDirectory

    $adProps = @(
        'samAccountName','name','userAccountControl',
        'comment','description','userComment',
        'homeDrive','homeDirectory','profilePath','scriptPath','logonWorkstations',
        'CannotChangePassword','PasswordLastSet','PasswordNotRequired','PasswordNeverExpires',
        'Enabled','LockedOut','AccountExpirationDate','LastLogonDate',
        'msDS-UserPasswordExpiryTimeComputed','logonHours'
    )

    $getParams = @{
        Filter     = '*'
        Properties = $adProps
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
        # AccountType
        $acctType = Get-AccountTypeFromUAC -UAC ([int]$u.userAccountControl)

        # Comment (prefer 'comment', fallback to 'description', then 'userComment')
        $comment = if ($u.comment) { $u.comment }
                   elseif ($u.description) { $u.description }
                   else { $u.userComment }

        # Password expiry time (constructed attribute)
        $pwdExpTime = $null
        if ($u.'msDS-UserPasswordExpiryTimeComputed') {
            try { $pwdExpTime = [DateTime]::FromFileTime([int64]$u.'msDS-UserPasswordExpiryTimeComputed') } catch {}
        }

        # Accurate last logon (optional)
        $lastLogonTime   = $u.LastLogonDate
        $lastLogonServer = $null
        if ($AccurateLastLogon -and $dcs) {
            $ll = Get-AccurateLastLogon -User $u -DomainControllers $dcs
            $lastLogonTime   = $ll.LastLogonTime
            $lastLogonServer = $ll.LastLogonServer
        }

        # LogonHours -> text
        $logonHoursText = Convert-LogonHoursToText -Bytes $u.logonHours

        [pscustomobject]@{
            UserName          = $u.SamAccountName
            FullName          = $u.Name
            AccountType       = $acctType
            Comment           = $comment
            HomeDrive         = $u.homeDrive
            HomeDir           = $u.homeDirectory
            Profile           = $u.profilePath
            LogonScript       = $u.scriptPath
            Workstations      = $u.logonWorkstations
            PswdCanBeChanged  = -not [bool]$u.CannotChangePassword
            PswdLastSetTime   = $u.PasswordLastSet
            PswdRequired      = -not [bool]$u.PasswordNotRequired
            PswdExpires       = -not [bool]$u.PasswordNeverExpires
            PswdExpiresTime   = $pwdExpTime
            AcctDisabled      = -not [bool]$u.Enabled
            AcctLockedOut     = [bool]$u.LockedOut
            AcctExpiresTime   = $u.AccountExpirationDate
            LastLogonTime     = $lastLogonTime
            LastLogonServer   = $lastLogonServer
            LogonHours        = $logonHoursText
        }
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
