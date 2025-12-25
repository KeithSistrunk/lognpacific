<#
.SYNOPSIS
    This PowerShell script ensures that Windows 11 is configured to audit "Other Logon/Logoff Events" for Success.

.NOTES
    Author          : Keith Sistrunk
    LinkedIn        : linkedin.com/in/keith-sistrunk/
    GitHub          : github.com/keithsistrunk
    Date Created    : 2025-12-25
    Last Modified   : 2025-12-25
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000560

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run this script with Administrator privileges.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-AU-000560).ps1 
#>

# Define the category and subcategory for Auditpol
$subcategory = "Other Logon/Logoff Events"
$setting = "Success"

Write-Host "Checking Audit Policy: $subcategory (WN11-AU-000560)..." -ForegroundColor Cyan

try {
    # Query current audit policy
    $currentAudit = auditpol /get /subcategory:$subcategory
    
    # Check if 'Success' is already enabled
    if ($currentAudit -like "*Success*") {
        Write-Host "The '$subcategory' policy is already compliant (Success enabled)." -ForegroundColor Green
    } else {
        Write-Host "Current policy is non-compliant. Updating to audit Success..." -ForegroundColor Yellow
        
        # Apply the remediation
        auditpol /set /subcategory:$subcategory /success:enable
        
        # Verify the change
        $verifyAudit = auditpol /get /subcategory:$subcategory
        if ($verifyAudit -like "*Success*") {
            Write-Host "Successfully updated '$subcategory' to Success." -ForegroundColor Green
        } else {
            Write-Error "Failed to update the audit policy."
        }
    }
}
catch {
    Write-Error "An error occurred while configuring the audit policy: $($_.Exception.Message)"
}
