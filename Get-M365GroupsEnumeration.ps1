#Requires -Version 7.2
<#
.SYNOPSIS
    Enumerates Microsoft 365 Groups with members and owners
    
.DESCRIPTION
    This script discovers all Microsoft 365 Groups (excluding Teams) and enumerates
    their members and owners. Uses Microsoft Graph API with certificate-based service
    principal authentication to provide comprehensive group membership reporting.
    
.PARAMETER ClientId
    The Client ID (Application ID) of the registered application. This parameter is required.
    
.PARAMETER TenantId
    The Microsoft Entra Tenant ID where the app is registered. This parameter is required.
    
.PARAMETER CertificateThumbprint
    The thumbprint of the certificate used for authentication. This parameter is required.

.PARAMETER CloudEnvironment
    The cloud environment to connect to. Valid values are 'Commercial' or 'GCCH'. Default is 'Commercial'.

.PARAMETER IncludeTeams
    Include Teams-enabled groups in the enumeration. Default is $false (excludes Teams).

.EXAMPLE
    .\Get-M365GroupsEnumeration.ps1
    
.EXAMPLE
    .\Get-M365GroupsEnumeration.ps1 -ClientId "12345678-1234-1234-1234-123456789012" -TenantId "87654321-4321-4321-4321-210987654321" -CertificateThumbprint "ABCDEF1234567890"
    
.EXAMPLE
    .\Get-M365GroupsEnumeration.ps1 -IncludeTeams
    
.NOTES
    PowerShell Version: 7.2 minimum
    Authentication Method: Service Principal (Certificate-based) (Script-AppReg)
    Required Modules: Microsoft.Graph.Groups 2.x, Microsoft.Graph.Authentication 2.x
    Required Permissions: Group.Read.All, GroupMember.Read.All
    Certificate: Must be installed in CurrentUser\My certificate store
#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]$ClientId,
    
    [Parameter()]
    [string]$TenantId,
    
    [Parameter()]
    [string]$CertificateThumbprint,
    
    [ValidateSet('Commercial', 'GCCH')]
    [string]$CloudEnvironment,
    
    [Parameter()]
    [switch]$IncludeTeams = $false,

    [Parameter()]
    [string]$OutputDir
)

. (Join-Path $PSScriptRoot 'Shared\DiscoveryConfig.ps1')

Use-DiscoveryDefaults -CliParameters @{
    ClientId = $ClientId
    TenantId = $TenantId
    CertificateThumbprint = $CertificateThumbprint
    CloudEnvironment = $CloudEnvironment
} -Required @('ClientId', 'TenantId', 'CertificateThumbprint', 'CloudEnvironment') -Defaults @{ CloudEnvironment = 'Commercial' } -AllowedValues @{ CloudEnvironment = @('Commercial', 'GCCH') }

# Check for required modules
$requiredModules = @('Microsoft.Graph.Groups', 'Microsoft.Graph.Authentication')
foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "Required module '$module' is not installed." -ForegroundColor Yellow
        $install = Read-Host "Would you like to install it now? (Y/N)"
        if ($install -eq 'Y' -or $install -eq 'y') {
            try {
                Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
                Write-Host "Module '$module' installed successfully." -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to install module '$module': $_"
                exit 1
            }
        }
        else {
            Write-Error "Required module '$module' is not installed. Exiting."
            exit 1
        }
    }
}

# Import required modules
Import-Module Microsoft.Graph.Groups

# Function to connect to Microsoft Graph with certificate
function Connect-GraphWithCertificate {
    param (
        [string]$ClientId,
        [string]$TenantId,
        [string]$CertificateThumbprint,
        [string]$CloudEnvironment = 'Commercial'
    )
    
    try {
        $connectParams = @{
            ClientId = $ClientId
            TenantId = $TenantId
            CertificateThumbprint = $CertificateThumbprint
        }
        
        if ($CloudEnvironment -eq 'GCCH') {
            $connectParams.Environment = 'USGov'
            Write-Host "Connecting to Microsoft Graph (GCCH Environment)..." -ForegroundColor Cyan
        } else {
            Write-Host "Connecting to Microsoft Graph (Commercial Environment)..." -ForegroundColor Cyan
        }
        
        Connect-MgGraph @connectParams -NoWelcome
        Write-Host "Successfully connected to Microsoft Graph" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        exit 1
    }
}

# Function to enumerate M365 Groups with members and owners
function Get-M365GroupMembership {
    param (
        [bool]$IncludeTeams
    )
    
    Write-Host "Retrieving Microsoft 365 Groups..." -ForegroundColor Cyan
    
    try {
        # Get all M365 Groups
        $groups = Get-MgGroup -All -Filter "groupTypes/any(c:c eq 'Unified')" -Property Id,DisplayName,Mail,Description,CreatedDateTime,ResourceProvisioningOptions
        
        if (-not $IncludeTeams) {
            # Filter out Teams
            $groups = $groups | Where-Object { $_.ResourceProvisioningOptions -notcontains 'Team' }
            Write-Host "Found $($groups.Count) M365 Groups (excluding Teams)" -ForegroundColor Green
        } else {
            Write-Host "Found $($groups.Count) M365 Groups (including Teams)" -ForegroundColor Green
        }

        $dataCollection = @()
        $groupCount = $groups.Count
        $i = 1

        foreach ($group in $groups) {
            Write-Host "Processing group $i of $groupCount - $($group.DisplayName)" -ForegroundColor Yellow

            try {
                # Get group members
                $members = Get-MgGroupMember -GroupId $group.Id -All
                $memberCount = $members.Count
                $mi = 1

                foreach ($member in $members) {
                    Write-Host "  Processing member $mi of $memberCount" -ForegroundColor DarkYellow

                    # Get member details
                    $memberDetails = Get-MgUser -UserId $member.Id -Property Id,DisplayName,UserPrincipalName,Mail -ErrorAction SilentlyContinue

                    if ($memberDetails) {
                        $dataCollection += [PSCustomObject]@{
                            GroupDisplayName = $group.DisplayName
                            GroupMail = $group.Mail
                            GroupId = $group.Id
                            GroupCreatedDateTime = $group.CreatedDateTime
                            ResourceProvisioningOptions = ($group.ResourceProvisioningOptions -join ';')
                            UserDisplayName = $memberDetails.DisplayName
                            UserPrincipalName = $memberDetails.UserPrincipalName
                            UserMail = $memberDetails.Mail
                            UserId = $memberDetails.Id
                            Role = 'Member'
                        }
                    }

                    $mi++
                }

                # Get group owners
                $owners = Get-MgGroupOwner -GroupId $group.Id -All
                $ownerCount = $owners.Count
                $oi = 1

                foreach ($owner in $owners) {
                    Write-Host "  Processing owner $oi of $ownerCount" -ForegroundColor DarkYellow

                    # Get owner details
                    $ownerDetails = Get-MgUser -UserId $owner.Id -Property Id,DisplayName,UserPrincipalName,Mail -ErrorAction SilentlyContinue

                    if ($ownerDetails) {
                        $dataCollection += [PSCustomObject]@{
                            GroupDisplayName = $group.DisplayName
                            GroupMail = $group.Mail
                            GroupId = $group.Id
                            GroupCreatedDateTime = $group.CreatedDateTime
                            ResourceProvisioningOptions = ($group.ResourceProvisioningOptions -join ';')
                            UserDisplayName = $ownerDetails.DisplayName
                            UserPrincipalName = $ownerDetails.UserPrincipalName
                            UserMail = $ownerDetails.Mail
                            UserId = $ownerDetails.Id
                            Role = 'Owner'
                        }
                    }

                    $oi++
                }
            }
            catch {
                Write-Warning "Error processing group $($group.DisplayName): $_"
            }

            $i++
        }

        Write-Host "M365 Groups enumeration complete" -ForegroundColor Green
        return $dataCollection
    }
    catch {
        Write-Error "Failed to enumerate M365 Groups: $_"
        return @()
    }
}

# Main execution
try {
    $stopwatch = [system.diagnostics.stopwatch]::StartNew()

    # Connect to Microsoft Graph
    Connect-GraphWithCertificate -ClientId $ClientId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint -CloudEnvironment $CloudEnvironment

    # Get M365 Groups with membership
    $groupMembership = Get-M365GroupMembership -IncludeTeams $IncludeTeams

    # Export results
    if ($groupMembership -and $groupMembership.Count -gt 0) {
        $outputPath = Resolve-DiscoveryOutputDir -OutputDir $OutputDir

        $outputFile = Join-Path $outputPath "M365GroupsEnumeration.csv"
        $groupMembership | Export-Csv -Path $outputFile -NoTypeInformation

        Write-Host "`n=== M365 Groups Enumeration Summary ===" -ForegroundColor Cyan
        Write-Host "Total membership records: $($groupMembership.Count)" -ForegroundColor Yellow

        $uniqueGroups = $groupMembership | Select-Object -ExpandProperty GroupDisplayName -Unique
        Write-Host "Unique groups processed: $($uniqueGroups.Count)" -ForegroundColor Yellow

        $members = $groupMembership | Where-Object { $_.Role -eq 'Member' }
        Write-Host "Total member assignments: $($members.Count)" -ForegroundColor Yellow

        $owners = $groupMembership | Where-Object { $_.Role -eq 'Owner' }
        Write-Host "Total owner assignments: $($owners.Count)" -ForegroundColor Yellow

        Write-Host "Output file: $outputFile" -ForegroundColor Green
    }
    else {
        Write-Host "`nNo M365 Groups found or error occurred during enumeration." -ForegroundColor Yellow
    }

    $stopwatch.Stop()
    Write-Host "`nM365 Groups enumeration completed in $([Math]::Round($stopwatch.Elapsed.TotalMinutes, 2)) minute(s)." -ForegroundColor Green
}
catch {
    Write-Error "Script execution failed: $_"
    exit 1
}
finally {
    # Always disconnect from Microsoft Graph
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Write-Host "Disconnected from Microsoft Graph" -ForegroundColor Green
    }
    catch {
        # Ignore disconnect errors
    }
}

