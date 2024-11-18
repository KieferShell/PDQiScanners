<#	
    .NOTES
        ===========================================================================
         Created on:   	2/12/2022
         Created by:   	Kiefer Easton
         Filename:     	Get-DellBIOSSettings.ps1
        ===========================================================================
    .SYNOPSIS
        PowerShell scanner for PDQ Inventory which returns Dell BIOS settings
    .DESCRIPTION
        This script is a PowerShell scanner for PDQ Inventory which scans Dell BIOS
        settings using Dell Command | Configure (DCC).
    .EXAMPLE
        .\Get-DellBIOSSettings.ps1
        .\Get-DellBIOSSettings.ps1 -DCCPath "C:\Program Files (x86)\Dell\Command Configure\X86_64\cctk.exe"
    .INPUTS
        [string] - The DCCPath paramater is a method for supplying alternate install locations for DCC
    .OUTPUTS
        Script outputs a PSObject formatted for a PDQ Inventory PowerShell scanner
    .COMPONENT
        Requires Dell Command | Configure be installed in the 32-bit Program Files (x86) directory unless
        another location is specified using the DCCPath parameter
#>

[CmdletBinding()]
param(
    [string]$DCCPath = "${Env:ProgramFiles(x86)}\Dell\Command Configure\X86_64\cctk.exe"
)

$DellBIOSSettings = @()

function Send-NullOutput {
    $DellBIOSSettings = [PSCustomObject]@{
        'Secure Boot'                = $false
        'Support Assist OS Recovery' = $false
        'Auto OS Recovery Threshold' = $null
        'BIOS Connect'               = $false
        'SATA Operation Mode'        = $null
        'Property Ownership Tag'     = $null
        'Asset Tag'                  = $null
        'Virtualization'             = $false
        'VT-d'                       = $false
        'Allow BIOS Downgrade'       = $false
        'BIOS Version'               = $null
    }
    return $DellBIOSSettings
}

function Get-DCCSettings {
    param(
        [Parameter(Mandatory)]
        [string[]]$Settings
    )

    $ParsedSettings = @()
    $ParameterArray = @()

    foreach ($Setting in $Settings) {
        $ParameterArray += "--" + $Setting
    }

    try {
        $ReturnValue = & $DCCPath $ParameterArray
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        Write-Error -Message "Dell Command Configure not found. Please verify that DCC is installed and that cctk.exe can be found at this path: $DCCPath" -Category InvalidOperation -CategoryTargetName "cctk.exe" -ErrorId 2 -RecommendedAction "Verify DCC installation and path, then rescan."
        Exit 2
    }

    foreach ($Value in $ReturnValue) {
        if ($Value.Split("=")[1] -eq "Enabled") {
            $ParsedSettings += $true
        }
        elseif ($Value.Split("=")[1] -eq "Disabled") {
            $ParsedSettings += $false
        }
        else {
            $ParsedSettings += $Value.Split("=")[1]
        }
    }

    return $ParsedSettings
}

function Get-AllDellBIOSSettings {
    $AllDellBIOSSettings = Get-DCCSettings -Settings 'SecureBoot', 'SupportAssistOSRecovery', 'AutoOSRecoveryThreshold', 'BIOSConnect', 'EmbSataRaid', 'PropOwnTag', 'Asset', 'Virtualization', 'VtForDirectIo', 'AllowBiosDowngrade', 'BiosVer'
    $DellBIOSSettings = [PSCustomObject]@{
        'Secure Boot'                = $AllDellBIOSSettings[0]
        'Support Assist OS Recovery' = $AllDellBIOSSettings[1]
        'Auto OS Recovery Threshold' = $AllDellBIOSSettings[2]
        'BIOS Connect'               = $AllDellBIOSSettings[3]
        'SATA Operation Mode'        = $AllDellBIOSSettings[4]
        'Property Ownership Tag'     = $AllDellBIOSSettings[5]
        'Asset Tag'                  = $AllDellBIOSSettings[6]
        'Virtualization'             = $AllDellBIOSSettings[7]
        'VT-d'                       = $AllDellBIOSSettings[8]
        'Allow BIOS Downgrade'       = $AllDellBIOSSettings[9]
        'BIOS Version'               = $AllDellBIOSSettings[10]
    }
    return $DellBIOSSettings
}

Get-AllDellBIOSSettings