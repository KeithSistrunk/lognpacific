<#
.SYNOPSIS
    This PowerShell script ensures that printing over HTTP is prevented to protect against unauthorized data transfer and potential exploits.

.NOTES
    Author          : Keith Sistrunk
    LinkedIn        : linkedin.com/in/keith-sistrunk/
    GitHub          : github.com/keithsistrunk
    Date Created    : 2025-12-25
    Last Modified   : 2025-12-25
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000110

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run this script with Administrator privileges.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-CC-000110).ps1 
#>

# Registry path for Printing Policies
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
$name = "DisableHTTPPrinting"
$value = 1

Write-Host "Checking 'Printing over HTTP' configuration (WN11-CC-000110)..." -ForegroundColor Cyan

try {
    # Ensure the registry key path exists
    if (!(Test-Path $registryPath)) {
        Write-Host "Registry path does not exist. Creating path: $registryPath" -ForegroundColor Yellow
        New-Item -Path $registryPath -Force | Out-Null
    }

    # Get the current value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $name -ErrorAction SilentlyContinue

    # Check if the value is missing or not set to 1 (Enabled)
    if ($null -eq $currentValue -or $currentValue.$name -ne $value) {
        Write-Host "Current setting is non-compliant. Enabling '$name'..." -ForegroundColor Yellow
        
        # Apply remediation
        New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWord -Force | Out-Null
        
        # Verify
        $verifyValue = Get-ItemProperty -Path $registryPath -Name $name
        if ($verifyValue.$name -eq $value) {
            Write-Host "Successfully prevented printing over HTTP." -ForegroundColor Green
        } else {
            Write-Error "Failed to update the registry value."
        }
    } else {
        Write-Host "The 'Printing over HTTP' setting is already compliant (Disabled)." -ForegroundColor Green
    }
}
catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
}
