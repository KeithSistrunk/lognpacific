<#
.SYNOPSIS
    This PowerShell script ensures IPv6 source routing is configured to the highest protection level (Drop all packets) to satisfy STIG WN11-CC-000020.

.NOTES
    Author          : Keith Sistrunk
    LinkedIn        : linkedin.com/in/keith-sistrunk/
    GitHub          : github.com/keithsistrunk
    Date Created    : 2025-12-25
    Last Modified   : 2025-12-25
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000020

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run this script with Administrator privileges.
    Example syntax:
    PS C:\> .\remediation_WN11-CC-000020.ps1 
#>

# Registry path for IPv6 Parameters
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
$name = "DisableIPSourceRouting"
$value = 2 # Highest protection (Drop all source-routed packets)

Write-Host "Verifying IPv6 Source Routing protection level (WN11-CC-000020)..." -ForegroundColor Cyan

try {
    # Check if the registry path exists
    if (!(Test-Path $registryPath)) {
        Write-Host "Registry path does not exist. Creating path: $registryPath" -ForegroundColor Yellow
        New-Item -Path $registryPath -Force | Out-Null
    }

    # Get the current value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $name -ErrorAction SilentlyContinue

    if ($null -eq $currentValue -or $currentValue.$name -ne $value) {
        Write-Host "Current setting is non-compliant or missing. Updating $name to $value..." -ForegroundColor Yellow
        
        # Apply remediation
        New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWord -Force | Out-Null
        
        # Verification
        $verifyValue = Get-ItemProperty -Path $registryPath -Name $name
        if ($verifyValue.$name -eq $value) {
            Write-Host "Successfully configured IPv6 Source Routing to highest protection (2)." -ForegroundColor Green
        } else {
            Write-Error "Failed to update the registry value."
        }
    } else {
        Write-Host "Compliance Verified: IPv6 Source Routing is already set to highest protection ($value)." -ForegroundColor Green
    }
}
catch {
    Write-Error "An unexpected error occurred: $($_.Exception.Message)"
}
