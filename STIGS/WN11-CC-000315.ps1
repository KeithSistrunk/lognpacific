<#
.SYNOPSIS
    This PowerShell script ensures the Windows Installer "Always install with elevated privileges" feature is disabled (set to 0) to prevent unauthorized privilege escalation.

.NOTES
    Author          : Keith Sistrunk
    LinkedIn        : linkedin.com/in/keith-sistrunk/
    GitHub          : github.com/keithsistrunk
    Date Created    : 2025-12-25
    Last Modified   : 2025-12-25
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000315

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run this script with Administrator privileges.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-CC-000315).ps1 
#>

# Registry path for Computer Configuration
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
$name = "AlwaysInstallElevated"
$value = 0

Write-Host "Checking Windows Installer 'AlwaysInstallElevated' setting..." -ForegroundColor Cyan

try {
    # Ensure the registry key path exists
    if (!(Test-Path $registryPath)) {
        Write-Host "Registry path does not exist. Creating path: $registryPath" -ForegroundColor Yellow
        New-Item -Path $registryPath -Force | Out-Null
    }

    # Get the current value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $name -ErrorAction SilentlyContinue

    if ($null -eq $currentValue -or $currentValue.$name -ne $value) {
        Write-Host "Setting $name to $value (Disabled)..." -ForegroundColor Yellow
        
        # Apply remediation
        New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWord -Force | Out-Null
        
        # Verify
        $verifyValue = Get-ItemProperty -Path $registryPath -Name $name
        if ($verifyValue.$name -eq $value) {
            Write-Host "Successfully disabled Always install with elevated privileges." -ForegroundColor Green
        } else {
            Write-Error "Failed to update the registry value."
        }
    } else {
        Write-Host "The 'AlwaysInstallElevated' setting is already compliant (Disabled)." -ForegroundColor Green
    }
}
catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
}
