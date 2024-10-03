<#	
	.NOTES
	===========================================================================
	 Created on:   	3/14/2023
	 Created by:   	Kiefer Easton
	 Filename:     	Get-ComputerGPOs.ps1
	===========================================================================
	.SYNOPSIS
        PowerShell scanner for PDQ Inventory which returns group policy results within the computer scope
    .DESCRIPTION
        This script is a PowerShell scanner for PDQ Inventory which finds group policies within the computer scope via RSOP and returns the data as a PowerShell object array
    .EXAMPLE
        .\Get-ComputerGPOs.ps1
    .INPUTS
        None.
    .OUTPUTS
        Script outputs an array of PSObjects formatted for a PDQ Inventory PowerShell scanner
#>

$Path = $env:TEMP + [guid]::NewGuid() + ".xml"
$GPObjects = @()

function Send-NullOutput {
    $GPObjects = [PSCustomObject]@{
        'Name'                = $null
        'Filter Allowed'      = $false
        'Access Denied'       = $false
        'Revision'            = $null
        'Link Order'          = $null
        'Linked OU'           = $null
        'Multiple Linked OUs' = $null
        'Enforced'            = $false
    }
    return $GPObjects
}

function New-ResultantSetOfPolicyReport {
    Start-Process -FilePath "$env:SystemRoot\System32\gpresult.exe" -ArgumentList "/Scope:Computer", "/x $Path", "/f" -WindowStyle Hidden -Wait
    [xml] $XML = Get-Content -Raw $Path
    return ($XML.documentelement.computerresults.GPO | Where-Object { $_.Enabled -eq $true })
}

function Remove-ResultantSetOfPolicyReport {
    Remove-Item -Path $Path -Force
}

$GPOs = New-ResultantSetOfPolicyReport

foreach ($GPO in $GPOs) {
    $GPObject = New-Object -TypeName PSObject
    $GPOMultiLink = [bool]$false

    $GPOName = $GPO.Name
    $GPOFilterAllowed = $GPO.FilterAllowed
    $GPOAccessDenied = $GPO.AccessDenied
    $GPORevision = [int]$GPO.VersionDirectory
    if ($GPO.Link.LinkOrder.Count -gt 1) {
        $GPOMultiLink = $true
        $GPOLinkOrder = [int]$GPO.Link.LinkOrder[0]
    }
    else {
        $GPOLinkOrder = [int]$GPO.Link.LinkOrder
    }
    if ($GPO.Link.SOMPath.Count -gt 1) {
        $GPOMultiLink = $true
        $GPOLinkedOU = $GPO.Link.SOMPath[0]
    }
    else {
        $GPOLinkedOU = $GPO.Link.SOMPath
    }
    if ($GPO.Link.NoOverride.Count -gt 1) {
        $GPOMultiLink = $true
        $GPOEnforced = $GPO.Link.NoOverride[0]
    }
    else {
        $GPOEnforced = $GPO.Link.NoOverride
    }

    $GPObject = [PSCustomObject]@{
        'Name'                = $GPOName
        'Filter Allowed'      = ([System.Convert]::ToBoolean($GPOFilterAllowed))
        'Access Denied'       = ([System.Convert]::ToBoolean($GPOAccessDenied))
        'Revision'            = $GPORevision
        'Link Order'          = $GPOLinkOrder
        'Linked OU'           = $GPOLinkedOU
        'Multiple Linked OUs' = $GPOMultiLink
        'Enforced'            = ([System.Convert]::ToBoolean($GPOEnforced))
    }
    $GPObjects += $GPObject
}

Remove-ResultantSetOfPolicyReport

return ($GPObjects | Sort-Object -Property 'Link Order')