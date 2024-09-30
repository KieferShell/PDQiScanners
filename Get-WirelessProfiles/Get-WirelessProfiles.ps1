<#	
	.NOTES
	===========================================================================
	 Created on:   	10/9/2023
	 Created by:   	Kiefer Easton
	 Filename:     	Get-WirelessProfiles.ps1
	===========================================================================
	.SYNOPSIS
        PowerShell scanner for PDQ Inventory which returns wireless profile details
    .DESCRIPTION
        This script is a PowerShell scanner for PDQ Inventory which examines supplied wireless profiles on workstations including these details:
        'Profile Name','SSID','Connection mode','Authentication','Encryption', and '802.1X'/'EAP' details (OneX)
    .Parameter ProfileNames
        The ProfileNames parameter accepts one or more profile names as input. You can pass a single profile name or an array of names.
        Example: 'Profile1' or @('Profile1', 'Profile2')
    .EXAMPLE
        .\Get-WirelessProfiles.ps1 -ProfileNames 'Profile1'
        .\Get-WirelessProfiles.ps1 -ProfileNames @('Profile1', 'Profile2')
    .INPUTS
        [string[]] - The ProfileNames parameter is an array of strings
    .OUTPUTS
        Script outputs an array of PSObjects formatted for a PDQ Inventory PowerShell scanner
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string[]]$ProfileNames
)

$WirelessProfilesInclSettings = @()

foreach ($ProfileName in $ProfileNames) {
    netsh wlan export profile name=$ProfileName key=clear folder=$env:TEMP | Out-Null
}

$ExportedProfiles = Get-ChildItem -Path "$env:TEMP\Wi-Fi*.xml"

foreach ($ExportedProfile in $ExportedProfiles) {
    [xml]$ProfileXML = Get-Content $ExportedProfile.FullName
    $NetworkPropertiesEapMethodType = $null
    $NetworkPropertiesThumbprint = (($ProfileXML.WLANProfile.MSM.security.OneX.EAPConfig.EapHostConfig.Config.Eap.EapType.ServerValidation.TrustedRootCA | Out-String).Trim()) -replace '\s', ''
    $NetworkPropertiesCertificate = $null
    $NetworkPropertiesSubject = $null
    $NetworkPropertiesNotAfter = $null
    $ConfigurationEapMethodType = $null
    $ConfigurationThumbprint = (($ProfileXML.WLANProfile.MSM.security.OneX.EAPConfig.EapHostConfig.Config.Eap.EapType.Eap.EapType.ServerValidation.TrustedRootCA | Out-String).Trim()) -replace '\s', ''
    $ConfigurationCertificate = $null
    $ConfigurationSubject = $null
    $ConfigurationNotAfter = $null

    if (($ProfileXML.WLANProfile.MSM.security.OneX.EAPConfig.EapHostConfig.EapMethod.Type.'#text' | Out-String).Trim() -eq "25") {
        $NetworkPropertiesEapMethodType = "Protected EAP (PEAP)"
    }
    else {
        $NetworkPropertiesEapMethodType = ($ProfileXML.WLANProfile.MSM.security.OneX.EAPConfig.EapHostConfig.EapMethod.Type.'#text' | Out-String).Trim()
    }

    if ("" -ne $NetworkPropertiesThumbprint) {
        $NetworkPropertiesCertificate = Get-ChildItem -path "Cert:\LocalMachine\Root\$NetworkPropertiesThumbprint" -ErrorAction SilentlyContinue
        $NetworkPropertiesSubject = $NetworkPropertiesCertificate.Subject
        $NetworkPropertiesNotAfter = $NetworkPropertiesCertificate.NotAfter
    }

    if (($ProfileXML.WLANProfile.MSM.security.OneX.EAPConfig.EapHostConfig.Config.Eap.EapType.Eap.Type | Out-String).Trim() -eq "13") {
        $ConfigurationEapMethodType = "Smart card or certificate"
    }
    else {
        $ConfigurationEapMethodType = ($ProfileXML.WLANProfile.MSM.security.OneX.EAPConfig.EapHostConfig.Config.Eap.EapType.Eap.Type | Out-String).Trim()
    }

    if ("" -ne $ConfigurationThumbprint) {
        $ConfigurationCertificate = Get-ChildItem -path "Cert:\LocalMachine\Root\$ConfigurationThumbprint" -ErrorAction SilentlyContinue
        $ConfigurationSubject = $ConfigurationCertificate.Subject
        $ConfigurationNotAfter = $ConfigurationCertificate.NotAfter
    }

    $WlanObject = New-Object -TypeName PSObject
    $WlanObject | Add-Member -Name 'Profile Name' -MemberType Noteproperty -Value ($ProfileXML.WLANProfile.Name | Out-String).Trim()
    $WlanObject | Add-Member -Name 'SSID' -MemberType Noteproperty -Value ($ProfileXML.WLANProfile.SSIDConfig.SSID.name | Out-String).Trim()
    $WlanObject | Add-Member -Name 'Connection mode' -MemberType Noteproperty -Value ($ProfileXML.WLANProfile.connectionMode | Out-String).Trim()
    $WlanObject | Add-Member -Name 'Authentication' -MemberType Noteproperty -Value ($ProfileXML.WLANProfile.MSM.security.authEncryption.authentication | Out-String).Trim()
    $WlanObject | Add-Member -Name 'Encryption' -MemberType Noteproperty -Value ($ProfileXML.WLANProfile.MSM.security.authEncryption.encryption | Out-String).Trim()
    $WlanObject | Add-Member -Name 'Use 802.1X' -MemberType Noteproperty -Value ($ProfileXML.WLANProfile.MSM.security.authEncryption.useOneX | Out-String).Trim()
    $WlanObject | Add-Member -Name 'Authentication mode' -MemberType Noteproperty -Value ($ProfileXML.WLANProfile.MSM.security.OneX.authMode | Out-String).Trim()
    $WlanObject | Add-Member -Name 'Network Properties - Authentication method' -MemberType Noteproperty -Value $NetworkPropertiesEapMethodType
    $WlanObject | Add-Member -Name 'Network Properties - Validate Server Certificate' -MemberType Noteproperty -Value ($ProfileXML.WLANProfile.MSM.security.OneX.EAPConfig.EapHostConfig.Config.Eap.EapType.PeapExtensions.PerformServerValidation.'#text' | Out-String).Trim()
    $WlanObject | Add-Member -Name 'Network Properties - Trusted Root CA Subject' -MemberType Noteproperty -Value $NetworkPropertiesSubject
    $WlanObject | Add-Member -Name 'Network Properties - Trusted Root CA Expiration' -MemberType Noteproperty -Value $NetworkPropertiesNotAfter
    $WlanObject | Add-Member -Name 'Network Properties - Trusted Root CA Thumbprint' -MemberType Noteproperty -Value ($ProfileXML.WLANProfile.MSM.security.OneX.EAPConfig.EapHostConfig.Config.Eap.EapType.ServerValidation.TrustedRootCA | Out-String).Trim()
    $WlanObject | Add-Member -Name 'Network Properties - Do not prompt user' -MemberType Noteproperty -Value ($ProfileXML.WLANProfile.MSM.security.OneX.EAPConfig.EapHostConfig.Config.Eap.EapType.ServerValidation.DisableUserPromptForServerValidation | Out-String).Trim()
    $WlanObject | Add-Member -Name 'Configuration - Authentication method' -MemberType Noteproperty -Value $ConfigurationEapMethodType
    $WlanObject | Add-Member -Name 'Configuration - Validate Server Certificate' -MemberType Noteproperty -Value ($ProfileXML.WLANProfile.MSM.security.OneX.EAPConfig.EapHostConfig.Config.Eap.EapType.Eap.EapType.PerformServerValidation.'#text' | Out-String).Trim()
    $WlanObject | Add-Member -Name 'Configuration - Trusted Root CA Subject' -MemberType Noteproperty -Value $ConfigurationSubject
    $WlanObject | Add-Member -Name 'Configuration - Trusted Root CA Expiration' -MemberType Noteproperty -Value $ConfigurationNotAfter
    $WlanObject | Add-Member -Name 'Configuration - Trusted Root CA Thumbprint' -MemberType Noteproperty -Value ($ProfileXML.WLANProfile.MSM.security.OneX.EAPConfig.EapHostConfig.Config.Eap.EapType.Eap.EapType.ServerValidation.TrustedRootCA | Out-String).Trim()
    $WlanObject | Add-Member -Name 'Configuration - Do not prompt user' -MemberType Noteproperty -Value ($ProfileXML.WLANProfile.MSM.security.OneX.EAPConfig.EapHostConfig.Config.Eap.EapType.Eap.EapType.ServerValidation.DisableUserPromptForServerValidation | Out-String).Trim()
    $WlanObject | Add-Member -Name 'Configuration - Simple Certificate Selection' -MemberType Noteproperty -Value ($ProfileXML.WLANProfile.MSM.security.OneX.EAPConfig.EapHostConfig.Config.Eap.EapType.Eap.EapType.CredentialsSource.CertificateStore.SimpleCertSelection | Out-String).Trim()

    $WirelessProfilesInclSettings += $WlanObject
}

if ($WirelessProfilesInclSettings.Length -eq 0) {
    $WlanObject = New-Object -TypeName PSObject
    $WlanObject | Add-Member -Name 'Profile Name' -MemberType Noteproperty -Value ""
    $WlanObject | Add-Member -Name 'SSID' -MemberType Noteproperty -Value ""
    $WlanObject | Add-Member -Name 'Connection mode' -MemberType Noteproperty -Value ""
    $WlanObject | Add-Member -Name 'Authentication' -MemberType Noteproperty -Value ""
    $WlanObject | Add-Member -Name 'Encryption' -MemberType Noteproperty -Value ""
    $WlanObject | Add-Member -Name 'Use 802.1X' -MemberType Noteproperty -Value ""
    $WlanObject | Add-Member -Name 'Authentication mode' -MemberType Noteproperty -Value ""
    $WlanObject | Add-Member -Name 'Network Properties - Authentication method' -MemberType Noteproperty -Value ""
    $WlanObject | Add-Member -Name 'Network Properties - Validate Server Certificate' -MemberType Noteproperty -Value ""
    $WlanObject | Add-Member -Name 'Network Properties - Trusted Root CA Subject' -MemberType Noteproperty -Value ""
    $WlanObject | Add-Member -Name 'Network Properties - Trusted Root CA Expiration' -MemberType Noteproperty -Value ""
    $WlanObject | Add-Member -Name 'Network Properties - Trusted Root CA Thumbprint' -MemberType Noteproperty -Value ""
    $WlanObject | Add-Member -Name 'Network Properties - Do not prompt user' -MemberType Noteproperty -Value ""
    $WlanObject | Add-Member -Name 'Configuration - Authentication method' -MemberType Noteproperty -Value ""
    $WlanObject | Add-Member -Name 'Configuration - Validate Server Certificate' -MemberType Noteproperty -Value ""
    $WlanObject | Add-Member -Name 'Configuration - Trusted Root CA Subject' -MemberType Noteproperty -Value ""
    $WlanObject | Add-Member -Name 'Configuration - Trusted Root CA Expiration' -MemberType Noteproperty -Value ""
    $WlanObject | Add-Member -Name 'Configuration - Trusted Root CA Thumbprint' -MemberType Noteproperty -Value ""
    $WlanObject | Add-Member -Name 'Configuration - Do not prompt user' -MemberType Noteproperty -Value ""
    $WlanObject | Add-Member -Name 'Configuration - Simple Certificate Selection' -MemberType Noteproperty -Value ""
    $WirelessProfilesInclSettings += $WlanObject
}

return $WirelessProfilesInclSettings