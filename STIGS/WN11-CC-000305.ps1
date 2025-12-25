<#
.SYNOPSIS
    This PowerShell script ensures that indexing of encrypted files is turned off to satisfy STIG WN11-CC-000305.

.NOTES
    Author          : Keith Sistrunk
    LinkedIn        : linkedin.com/in/keith-sistrunk/
    GitHub          : github.com/keithsistrunk
    Date Created    : 2025-12-25
    Last Modified   : 2025-12-25
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000305

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run this script with Administrator privileges.
    Example syntax:
    PS C:\> .\remediation_WN11-CC-000305.ps1 
#>

# Registry path for Windows Search Policy
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
$name = "AllowIndexingEncryptedStoresOrItems"
$value = 0 # 0 = Disabled (Encrypted files will not be indexed)

Write-Host "Verifying Indexing of Encrypted Files (WN11-CC-000305)..." -ForegroundColor Cyan

try {
    # Ensure the registry key path exists
    if (!(Test-Path $registryPath)) {
        Write-Host "Registry path does not exist. Creating path: $registryPath" -ForegroundColor Yellow
        New-Item -Path $registryPath -Force | Out-Null
    }

    # Get the current value
    $currentValue = Get-ItemProperty -Path $registryPath -Name $name -ErrorAction SilentlyContinue

    if ($null -eq $currentValue -or $currentValue.$name -ne $value) {
        Write-Host "Current setting is non-compliant or missing. Disabling indexing of encrypted files..." -ForegroundColor Yellow
        
        # Apply remediation
        New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWord -Force | Out-Null
        
        # Verification check
        $verifyValue = Get-ItemProperty -Path $registryPath -Name $name
        if ($verifyValue.$name -eq $value) {
            Write-Host "Successfully disabled indexing of encrypted files." -ForegroundColor Green
            Write-Host "Note: The index may need to be rebuilt for changes to take full effect." -ForegroundColor Gray
        } else {
            Write-Error "Failed to update the registry value."
        }
    } else {
        Write-Host "Compliance Verified: Indexing of encrypted files is already disabled." -ForegroundColor Green
    }
}
catch {
    Write-Error "An unexpected error occurred: $($_.Exception.Message)"
}
