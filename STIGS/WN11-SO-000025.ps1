<#
.SYNOPSIS
    This PowerShell script ensures that the built-in Guest account is renamed to a non-standard name to satisfy STIG WN11-SO-000025.

.NOTES
    Author          : Keith Sistrunk
    LinkedIn        : linkedin.com/in/keith-sistrunk/
    GitHub          : github.com/keithsistrunk
    Date Created    : 2025-12-25
    Last Modified   : 2025-12-25
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-SO-000025

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run this script with Administrator privileges.
    Example syntax:
    PS C:\> .\remediation_WN11-SO-000025.ps1 
#>

# Define the new name for the Guest account
$newName = "LegacyGuest" # Change this to your organization's preferred name

Write-Host "Verifying built-in Guest account name for WN11-SO-000025..." -ForegroundColor Cyan

try {
    # Identify the Guest account by its well-known SID (ends in -501)
    $guestAccount = Get-LocalUser | Where-Object { $_.SID -like "S-1-5-*-501" }

    if ($null -eq $guestAccount) {
        Write-Error "Could not locate the built-in Guest account by SID."
        return
    }

    $currentName = $guestAccount.Name

    if ($currentName -eq "Guest") {
        Write-Host "Account is currently named 'Guest'. Renaming to '$newName'..." -ForegroundColor Yellow
        
        # Apply remediation
        Rename-LocalUser -Name "Guest" -NewName $newName
        
        # Verification
        $verifyAccount = Get-LocalUser | Where-Object { $_.SID -like "S-1-5-*-501" }
        if ($verifyAccount.Name -eq $newName) {
            Write-Host "Successfully renamed the Guest account to '$newName'." -ForegroundColor Green
        } else {
            Write-Error "Failed to rename the Guest account."
        }
    } elseif ($currentName -ne "Guest") {
        Write-Host "Compliance Verified: The Guest account has already been renamed to '$currentName'." -ForegroundColor Green
    }
}
catch {
    Write-Error "An unexpected error occurred: $($_.Exception.Message)"
}
