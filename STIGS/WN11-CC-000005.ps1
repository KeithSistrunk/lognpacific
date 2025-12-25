<#
.SYNOPSIS
    This PowerShell script ensures that camera access from the lock screen is disabled on Windows 11 to satisfy STIG WN11-CC-000005.

.NOTES
    Author          : Keith Sistrunk
    LinkedIn        : linkedin.com/in/keith-sistrunk/
    GitHub          : github.com/keithsistrunk
    Date Created    : 2025-12-25
    Last Modified   : 2025-12-25
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000005

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run this script with Administrator privileges.
    Example syntax:
    PS C:\> .\remediation_WN11-CC-000005.ps1 
#>

# Registry path for Lock Screen Camera policy
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
$name = "NoLockScreenCamera"
$value = 1 # 1 = Enabled (This enables the "No Camera" policy, effectively disabling the camera)

Write-Host "Verifying Lock Screen Camera configuration (WN11-CC-000005)..." -ForegroundColor Cyan

try {
    # Ensure the registry key path exists
    if (!(Test-Path $registryPath)) {
        Write-Host "Registry path does not exist. Creating path: $registryPath" -ForegroundColor Yellow
        New-Item -Path $registryPath -Force | Out-Null
    }

    # Get the current value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $name -ErrorAction SilentlyContinue

    if ($null -eq $currentValue -or $currentValue.$name -ne $value) {
        Write-Host "Current setting is non-compliant or missing. Disabling camera access from lock screen..." -ForegroundColor Yellow
        
        # Apply remediation
        # Setting NoLockScreenCamera to 1 prevents the camera from appearing on the lock screen
        New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWord -Force | Out-Null
        
        # Verification check
        $verifyValue = Get-ItemProperty -Path $registryPath -Name $name
        if ($verifyValue.$name -eq $value) {
            Write-Host "Successfully disabled camera access from the lock screen." -ForegroundColor Green
        } else {
            Write-Error "Failed to update the registry value."
        }
    } else {
        Write-Host "Compliance Verified: Camera access from the lock screen is already disabled." -ForegroundColor Green
    }
}
catch {
    Write-Error "An unexpected error occurred: $($_.Exception.Message)"
}
