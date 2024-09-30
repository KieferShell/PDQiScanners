<#	
    .NOTES
        ===========================================================================
         Created on:   	4/27/2022
         Created by:   	Kiefer Easton
         Filename:     	Get-CiscoVPNPreferences.ps1
        ===========================================================================
    .SYNOPSIS
        PowerShell scanner for PDQ Inventory which returns Cisco Secure Client preferences
    .DESCRIPTION
        This script is a PowerShell scanner for PDQ Inventory which scans for an XML preferences file in:
		'$env:LOCALAPPDATA\Cisco\Cisco Secure Client\VPN' and returns the XML node data to PDQ Inventory.
    .EXAMPLE
        .\Get-CiscoVPNPreferences.ps1
    .INPUTS
        None.
    .OUTPUTS
        Script outputs a PSObject formatted for a PDQ Inventory PowerShell scanner
#>

function Send-NullOutput {
	$CiscoVPNPreferences = [PSCustomObject]@{
		'Default User'                            = $null
		'Default Second User'                     = $null
		'Client Certificate Thumbprint'           = $null
		'Multiple Client Certificate Thumbprints' = $null
		'Server Certificate Thumbprint'           = $null
		'Default Host Name'                       = $null
		'Default Host Address'                    = $null
		'Default Group'                           = $null
		'Proxy Host'                              = $null
		'Proxy Port'                              = $null
		'SDI Token Type'                          = $null
		'Block Untrusted Servers'                 = $false
	}
	return $CiscoVPNPreferences
}


$LoggedOnUser = (Get-WMIObject -class Win32_ComputerSystem | Select-Object username).username

if ($null -eq $LoggedOnUser) {
	Write-Verbose "No logged on user detected"
	return Send-NullOutput
}

$LoggedOnUserName = $LoggedOnUser.split("\")[1]
$PreferencesXMLPath = "$env:SystemDrive\Users\$LoggedOnUserName\AppData\Local\Cisco\Cisco Secure Client\VPN\preferences.xml"

try {
	$VPNPreferencesFile = Get-ChildItem -Path $PreferencesXMLPath -ErrorAction Stop
}
catch {
	Write-Verbose "The following path did not successfully complete the Get-ChildItem attempt: $PreferencesXMLPath"
	return Send-NullOutput
}

[xml]$XML = Get-Content -Raw $VPNPreferencesFile.FullName

[string]$DefaultUser = $XML.AnyConnectPreferences.DefaultUser
[string]$DefaultSecondUser = $XML.AnyConnectPreferences.DefaultSecondUser
[string]$ClientCertificateThumbprint = $XML.AnyConnectPreferences.ClientCertificateThumbprint
[string]$MultipleClientCertificateThumbprints = $XML.AnyConnectPreferences.MultipleClientCertificateThumbprints
[string]$ServerCertificateThumbprint = $XML.AnyConnectPreferences.ServerCertificateThumbprint
[string]$DefaultHostName = $XML.AnyConnectPreferences.DefaultHostName
[string]$DefaultHostAddress = $XML.AnyConnectPreferences.DefaultHostAddress
[string]$DefaultGroup = $XML.AnyConnectPreferences.DefaultGroup
[string]$ProxyHost = $XML.AnyConnectPreferences.ProxyHost
[string]$ProxyPort = $XML.AnyConnectPreferences.ProxyPort
[string]$SDITokenType = $XML.AnyConnectPreferences.SDITokenType
[string]$BlockUntrustedServers = $XML.AnyConnectPreferences.ControllablePreferences.BlockUntrustedServers

if ($BlockUntrustedServers -eq "true") {
	[bool]$BlockUntrustedServersBool = $true
}
else {
	[bool]$BlockUntrustedServersBool = $false
}

$CiscoVPNPreferences = [PSCustomObject]@{
	'Default User'                            = $DefaultUser
	'Default Second User'                     = $DefaultSecondUser
	'Client Certificate Thumbprint'           = $ClientCertificateThumbprint
	'Multiple Client Certificate Thumbprints' = $MultipleClientCertificateThumbprints
	'Server Certificate Thumbprint'           = $ServerCertificateThumbprint
	'Default Host Name'                       = $DefaultHostName
	'Default Host Address'                    = $DefaultHostAddress
	'Default Group'                           = $DefaultGroup
	'Proxy Host'                              = $ProxyHost
	'Proxy Port'                              = $ProxyPort
	'SDI Token Type'                          = $SDITokenType
	'Block Untrusted Servers'                 = $BlockUntrustedServersBool
}

return $CiscoVPNPreferences