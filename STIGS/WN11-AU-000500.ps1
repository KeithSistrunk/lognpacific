<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Keith Sistrunk
    LinkedIn        : linkedin.com/in/keith-sistrunk/
    GitHub          : github.com/keithsistrunk
    Date Created    : 2025-12-25
    Last Modified   : 2025-12-25
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000500

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run this script with Administrator privileges to modify the Event Log configuration.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-AU-000500).ps1 
#>

# Define target log and minimum size (in bytes)
$logName = "Application"
$minSizeKB = 32768
$minSizeBytes = $minSizeKB * 1024

Write-Host "Checking $logName event log size..." -ForegroundColor Cyan

try {
    # Get the current log configuration
    $currentLog = Get-EventLog -List | Where-Object { $_.Log -eq $logName }

    if ($currentLog.MaximumKilobytes -lt $minSizeKB) {
        Write-Host "Current size is $($currentLog.MaximumKilobytes) KB. Updating to $minSizeKB KB..." -ForegroundColor Yellow
        
        # Set the maximum size
        Limit-EventLog -LogName $logName -MaximumSize $minSizeBytes
        
        # Verify the change
        $updatedLog = Get-EventLog -List | Where-Object { $_.Log -eq $logName }
        if ($updatedLog.MaximumKilobytes -ge $minSizeKB) {
            Write-Host "Successfully updated $logName log size to $($updatedLog.MaximumKilobytes) KB." -ForegroundColor Green
        } else {
            Write-Error "Failed to update the log size."
        }
    } else {
        Write-Host "The $logName log size is already compliant ($($currentLog.MaximumKilobytes) KB)." -ForegroundColor Green
    }
}
catch {
    Write-Error "An error occurred while configuring the event log: $($_.Exception.Message)"
}
