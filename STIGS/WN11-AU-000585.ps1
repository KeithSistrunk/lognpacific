<#
.SYNOPSIS
    This PowerShell script ensures that Windows 11 is configured to audit "Process Creation" events for Failure to satisfy STIG WN11-AU-000585.

.NOTES
    Author          : Keith Sistrunk
    LinkedIn        : linkedin.com/in/keith-sistrunk/
    GitHub          : github.com/keithsistrunk
    Date Created    : 2025-12-25
    Last Modified   : 2025-12-25
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000585

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run this script with Administrator privileges.
    Example syntax:
    PS C:\> .\remediation_WN11-AU-000585.ps1 
#>

# Define the subcategory for Process Creation
$subcategory = "Process Creation"

Write-Host "Verifying Audit Policy for: $subcategory (WN11-AU-000585)..." -ForegroundColor Cyan

try {
    # Query current audit policy status
    $currentAudit = auditpol /get /subcategory:$subcategory
    
    # Check if 'Failure' is already enabled in the output string
    if ($currentAudit -like "*Failure*") {
        Write-Host "Compliance Verified: '$subcategory' is already auditing Failures." -ForegroundColor Green
    } else {
        Write-Host "Current setting is non-compliant. Remediation in progress..." -ForegroundColor Yellow
        
        # Apply remediation. 
        # Note: If the STIG also requires Success (WN11-AU-000580), use /failure:enable /success:enable
        auditpol /set /subcategory:$subcategory /failure:enable
        
        # Verification check
        $verifyAudit = auditpol /get /subcategory:$subcategory
        if ($verifyAudit -like "*Failure*") {
            Write-Host "Successfully updated '$subcategory' to audit Failures." -ForegroundColor Green
        } else {
            Write-Error "Remediation failed. Check if a Group Policy (GPO) is preventing local audit policy changes."
        }
    }
}
catch {
    Write-Error "An unexpected error occurred: $($_.Exception.Message)"
}
