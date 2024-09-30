<#	
    .NOTES
        ===========================================================================
         Created on:   	8/30/2021
         Created by:   	Kiefer Easton
         Filename:     	Get-CiscoVPNProfiles.ps1
        ===========================================================================
    .SYNOPSIS
        PowerShell scanner for PDQ Inventory which returns Cisco Secure Client profiles
    .DESCRIPTION
        This script is a PowerShell scanner for PDQ Inventory which scans for XML profiles in:
		'$env:ProgramData\Cisco\Cisco Secure Client\VPN\Profile' and returns the XML node data to PDQ Inventory.
    .EXAMPLE
        .\Get-CiscoVPNProfiles.ps1
    .INPUTS
        None.
    .OUTPUTS
        Script outputs a PSObject formatted for a PDQ Inventory PowerShell scanner
#>

$VPNProfiles = @()

function Send-NullOutput {
	$VPNProfiles = [PSCustomObject]@{
		'Host Name'    = $null
		'Host Address' = $null
		'User Group'   = $null
		'File Name'    = $null
	}
	return $VPNProfiles
}

$VPNProfilesPath = "$env:ProgramData\Cisco\Cisco Secure Client\VPN\Profile\*.xml"

try {
	$VPNProfileFiles = Get-ChildItem -Path $VPNProfilesPath -ErrorAction Stop
}
catch {
	Write-Verbose "The following path did not successfully complete the Get-ChildItem attempt: $VPNProfilesPath"
	return Send-NullOutput
}

foreach ($VPNProfileFile in $VPNProfileFiles) {
	[xml]$XML = Get-Content -Raw $VPNProfileFile.FullName
	$InnerVPNProfiles = $XML.documentelement.ServerList.HostEntry
	foreach ($InnerVPNProfile in $InnerVPNProfiles) {
		$VPNProfiles += [PSCustomObject]@{
			'Host Name'    = $InnerVPNProfile.HostName
			'Host Address' = $InnerVPNProfile.HostAddress
			'User Group'   = $InnerVPNProfile.UserGroup
			'File Name'    = $VPNProfileFile.Name
		}
	}
}

return $VPNProfiles