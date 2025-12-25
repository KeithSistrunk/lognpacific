<#
.SYNOPSIS
    This PowerShell script ensures the Windows Application event log size is at least 32768 KB and enforces the setting via the Registry Policy hive to pass STIG scans.

.NOTES
    Author          : Keith Sistrunk
    LinkedIn        : linkedin.com/in/keith.sistrunk/
    GitHub          : github.com/keithsistrunk
    Date Created    : 2025-12-25
    Last Modified   : 2025-12-25
    Version         : 2.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000500

.TESTED ON
    Date(s) Tested  : 2025-12-25
    Tested By       : Keith Sistrunk
    Systems Tested  : Windows 11
    PowerShell Ver. : 5.1 / 7.x

.USAGE
    Run this script with Administrator privileges.
    Example syntax:
    PS C:\> .\remediation_WN11-AU-000500.ps1 
#>

# 1. Define target parameters
$logName = "Application"
$minSizeKB = 32768
$minSizeBytes = $minSizeKB * 1024

# 2. Define the Policy Registry Path (Required for STIG Scanners)
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$registryName = "MaxSize"

Write-Host "Applying Remediation for WN11-AU-000500..." -ForegroundColor Cyan

try {
    # --- Part A: Functional Enforcement ---
    Write-Host "Updating functional log size via Limit-EventLog..." -ForegroundColor Gray
    Limit-EventLog -LogName $logName -MaximumSize $minSizeBytes

    # --- Part B: Registry Policy Enforcement (The Audit Fix) ---
    if (!(Test-Path $registryPath)) {
        Write-Host "Creating missing registry policy path..." -ForegroundColor Yellow
        New-Item -Path $registryPath -Force | Out-Null
    }

    Write-Host "Configuring Registry Policy 'MaxSize' to $minSizeKB..." -ForegroundColor Yellow
    New-ItemProperty -Path $registryPath -Name $registryName -Value $minSizeKB -PropertyType DWord -Force | Out-Null

    # --- Part C: Verification ---
    $verifyReg = Get-ItemProperty -Path $registryPath -Name $registryName
    $verifyLog = Get-EventLog -List | Where-Object { $_.Log -eq $logName }

    if ($verifyReg.$registryName -eq $minSizeKB -and $verifyLog.MaximumKilobytes -ge $minSizeKB) {
        Write-Host "SUCCESS: Application log size is compliant and Registry Policy is set." -ForegroundColor Green
    } else {
        Write-Warning "Remediation applied, but verification failed. Manual check required."
    }
}
catch {
    Write-Error "An unexpected error occurred: $($_.Exception.Message)"
}
