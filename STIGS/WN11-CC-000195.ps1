<#
.SYNOPSIS
    This PowerShell script ensures that Enhanced Anti-Spoofing for facial recognition is enabled on Windows 11 to satisfy STIG WN11-CC-000195.

.NOTES
    Author          : Keith Sistrunk
    LinkedIn        : linkedin.com/in/keith-sistrunk/
    GitHub          : github.com/keithsistrunk
    Date Created    : 2025-12-25
    Last Modified   : 2025-12-25
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000195

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run this script with Administrator privileges.
    Example syntax:
    PS C:\> .\remediation_WN11-CC-000195.ps1 
#>

# Registry path for Biometrics Face Features
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\Face"
$name = "EnhancedAntiSpoofing"
$value = 1 # Enabled

Write-Host "Verifying Enhanced Anti-Spoofing for Facial Recognition (WN11-CC-000195)..." -ForegroundColor Cyan

try {
    # Ensure the registry key path exists
    if (!(Test-Path $registryPath)) {
        Write-Host "Registry path does not exist. Creating path: $registryPath" -ForegroundColor Yellow
        New-Item -Path $registryPath -Force | Out-Null
    }

    # Get the current value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $name -ErrorAction SilentlyContinue

    if ($null -eq $currentValue -or $currentValue.$name -ne $value) {
        Write-Host "Current setting is non-compliant or missing. Enabling Enhanced Anti-Spoofing..." -ForegroundColor Yellow
        
        # Apply remediation
        New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWord -Force | Out-Null
        
        # Verification check
        $verifyValue = Get-ItemProperty -Path $registryPath -Name $name
        if ($verifyValue.$name -eq $value) {
            Write-Host "Successfully enabled Enhanced Anti-Spoofing." -ForegroundColor Green
        } else {
            Write-Error "Failed to update the registry value."
        }
    } else {
        Write-Host "Compliance Verified: Enhanced Anti-Spoofing is already enabled." -ForegroundColor Green
    }
}
catch {
    Write-Error "An unexpected error occurred: $($_.Exception.Message)"
}
