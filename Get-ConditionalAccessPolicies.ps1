#Requires -Version 7.2
<#
.SYNOPSIS
    Comprehensive Azure AD Conditional Access Policies enumeration

.DESCRIPTION
    This script provides a complete dump of all Conditional Access policies including
    policy details, conditions, grant controls, and session controls for analysis
    against user populations.

.PARAMETER ClientId
    The Client ID (Application ID) of the registered application. This parameter is required.

.PARAMETER TenantId
    The Microsoft Entra Tenant ID where the app is registered. This parameter is required.

.PARAMETER CertificateThumbprint
    The thumbprint of the certificate used for authentication. This parameter is required.

.PARAMETER CloudEnvironment
    The cloud environment to connect to. Valid values are 'Commercial' or 'GCCH'. Default is 'Commercial'.

.EXAMPLE
    .\Get-ConditionalAccessPolicies.ps1

.EXAMPLE
    .\Get-ConditionalAccessPolicies.ps1 -ClientId "12345678-1234-1234-1234-123456789012" -TenantId "87654321-4321-4321-4321-210987654321" -CertificateThumbprint "ABCDEF1234567890"

.NOTES
    PowerShell Version: 7.2 minimum
    Authentication Method: Service Principal (Certificate-based) (Script-AppReg)
    Required Modules: Microsoft.Graph 2.x
    Required Permissions: Policy.Read.All
    Certificate: Must be installed in CurrentUser\My certificate store
    Estimated Runtime: Under 1 minute
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
$requiredModules = @('Microsoft.Graph.Authentication')
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
Import-Module Microsoft.Graph.Authentication

# Function to connect to Microsoft Graph
function Connect-MicrosoftGraph {
    param (
        [string]$TenantId,
        [string]$ClientId,
        [string]$CertificateThumbprint,
        [string]$CloudEnvironment = 'Commercial'
    )

    try {
        Write-Host "Connecting to Microsoft Graph ($CloudEnvironment)..." -ForegroundColor Cyan

        $cert = Get-ChildItem "Cert:\CurrentUser\My\$CertificateThumbprint"
        if (-not $cert) {
            Write-Error "Certificate with thumbprint '$CertificateThumbprint' not found in CurrentUser\My certificate store."
            exit 1
        }

        if ($CloudEnvironment -eq 'GCCH') {
            Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -Certificate $cert -Environment USGov
        } else {
            Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -Certificate $cert
        }

        Write-Host "Successfully connected to Microsoft Graph" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        exit 1
    }
}

# Function to get conditional access policies
function Get-ConditionalAccessPoliciesData {
    Write-Host "Retrieving Conditional Access policies..." -ForegroundColor Cyan

    try {
        $policies = @()
        $nextLink = '/v1.0/identity/conditionalAccess/policies'
        do {
            $response = Invoke-MgGraphRequest -Method GET -Uri $nextLink -OutputType PSObject
            if ($response.value) {
                $policies += $response.value
            }
            $nextLink = $response.'@odata.nextLink'
        } while ($nextLink)
        Write-Host "Found $($policies.Count) Conditional Access policies" -ForegroundColor Green

        $policyData = @()
        $policyCount = $policies.Count
        $i = 1

        foreach ($policy in $policies) {
            Write-Host "Processing policy $i of $policyCount - $($policy.displayName)" -ForegroundColor Yellow

            # Extract users conditions
            $usersInclude = ""
            $usersExclude = ""
            if ($policy.conditions.users) {
                if ($policy.conditions.users.includeUsers) {
                    $usersInclude = $policy.conditions.users.includeUsers -join "; "
                }
                if ($policy.conditions.users.excludeUsers) {
                    $usersExclude = $policy.conditions.users.excludeUsers -join "; "
                }
            }

            # Extract groups conditions
            $groupsInclude = ""
            $groupsExclude = ""
            if ($policy.conditions.users) {
                if ($policy.conditions.users.includeGroups) {
                    $groupsInclude = $policy.conditions.users.includeGroups -join "; "
                }
                if ($policy.conditions.users.excludeGroups) {
                    $groupsExclude = $policy.conditions.users.excludeGroups -join "; "
                }
            }

            # Extract roles conditions
            $rolesInclude = ""
            $rolesExclude = ""
            if ($policy.conditions.users) {
                if ($policy.conditions.users.includeRoles) {
                    $rolesInclude = $policy.conditions.users.includeRoles -join "; "
                }
                if ($policy.conditions.users.excludeRoles) {
                    $rolesExclude = $policy.conditions.users.excludeRoles -join "; "
                }
            }

            # Extract applications conditions
            $appsInclude = ""
            $appsExclude = ""
            if ($policy.conditions.applications) {
                if ($policy.conditions.applications.includeApplications) {
                    $appsInclude = $policy.conditions.applications.includeApplications -join "; "
                }
                if ($policy.conditions.applications.excludeApplications) {
                    $appsExclude = $policy.conditions.applications.excludeApplications -join "; "
                }
            }

            # Extract locations conditions
            $locationsInclude = ""
            $locationsExclude = ""
            if ($policy.conditions.locations) {
                if ($policy.conditions.locations.includeLocations) {
                    $locationsInclude = $policy.conditions.locations.includeLocations -join "; "
                }
                if ($policy.conditions.locations.excludeLocations) {
                    $locationsExclude = $policy.conditions.locations.excludeLocations -join "; "
                }
            }

            # Extract platforms conditions
            $platformsInclude = ""
            $platformsExclude = ""
            if ($policy.conditions.platforms) {
                if ($policy.conditions.platforms.includePlatforms) {
                    $platformsInclude = $policy.conditions.platforms.includePlatforms -join "; "
                }
                if ($policy.conditions.platforms.excludePlatforms) {
                    $platformsExclude = $policy.conditions.platforms.excludePlatforms -join "; "
                }
            }

            # Extract client app types
            $clientAppTypes = ""
            if ($policy.conditions.clientAppTypes) {
                $clientAppTypes = $policy.conditions.clientAppTypes -join "; "
            }

            # Extract grant controls
            $grantOperator = ""
            $grantControls = ""
            $customAuthFactors = ""
            $termsOfUse = ""
            $authStrength = ""
            if ($policy.grantControls) {
                $grantOperator = $policy.grantControls.operator
                if ($policy.grantControls.builtInControls) {
                    $grantControls = $policy.grantControls.builtInControls -join "; "
                }
                if ($policy.grantControls.customAuthenticationFactors) {
                    $customAuthFactors = $policy.grantControls.customAuthenticationFactors -join "; "
                }
                if ($policy.grantControls.termsOfUse) {
                    $termsOfUse = $policy.grantControls.termsOfUse -join "; "
                }
                if ($policy.grantControls.authenticationStrength) {
                    $authStrength = $policy.grantControls.authenticationStrength.id
                }
            }

            # Extract session controls
            $signInFrequency = ""
            $signInFrequencyType = ""
            $persistentBrowser = ""
            $cloudAppSecurity = ""
            if ($policy.sessionControls) {
                if ($policy.sessionControls.signInFrequency) {
                    $signInFrequency = $policy.sessionControls.signInFrequency.value
                    $signInFrequencyType = $policy.sessionControls.signInFrequency.type
                }
                if ($policy.sessionControls.persistentBrowser) {
                    $persistentBrowser = $policy.sessionControls.persistentBrowser.mode
                }
                if ($policy.sessionControls.cloudAppSecurity) {
                    $cloudAppSecurity = $policy.sessionControls.cloudAppSecurity.cloudAppSecurityType
                }
            }

            # Create policy object
            $policyObject = [PSCustomObject]@{
                PolicyId = $policy.id
                DisplayName = $policy.displayName
                State = $policy.state
                CreatedDateTime = $policy.createdDateTime
                ModifiedDateTime = $policy.modifiedDateTime
                TemplateId = $policy.templateId

                # Users conditions
                UsersInclude = $usersInclude
                UsersExclude = $usersExclude
                GroupsInclude = $groupsInclude
                GroupsExclude = $groupsExclude
                RolesInclude = $rolesInclude
                RolesExclude = $rolesExclude

                # Applications conditions
                ApplicationsInclude = $appsInclude
                ApplicationsExclude = $appsExclude

                # Locations conditions
                LocationsInclude = $locationsInclude
                LocationsExclude = $locationsExclude

                # Platforms conditions
                PlatformsInclude = $platformsInclude
                PlatformsExclude = $platformsExclude

                # Client app types
                ClientAppTypes = $clientAppTypes

                # Grant controls
                GrantOperator = $grantOperator
                GrantControls = $grantControls
                CustomAuthenticationFactors = $customAuthFactors
                TermsOfUse = $termsOfUse
                AuthenticationStrength = $authStrength

                # Session controls
                SignInFrequency = $signInFrequency
                SignInFrequencyType = $signInFrequencyType
                PersistentBrowser = $persistentBrowser
                CloudAppSecurity = $cloudAppSecurity
            }

            $policyData += $policyObject
            $i++
        }

        Write-Host "Conditional Access policies enumeration complete" -ForegroundColor Green
        return $policyData
    }
    catch {
        Write-Error "Failed to retrieve Conditional Access policies: $_"
        return @()
    }
}

# Main execution
try {
    $stopwatch = [system.diagnostics.stopwatch]::StartNew()

    # Connect to Microsoft Graph
    Connect-MicrosoftGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -CloudEnvironment $CloudEnvironment

    # Get Conditional Access policies
    $policies = Get-ConditionalAccessPoliciesData

    # Export results
    if ($policies -and $policies.Count -gt 0) {
        $outputPath = Resolve-DiscoveryOutputDir -OutputDir $OutputDir

        $outputFile = Join-Path $outputPath "ConditionalAccess_Policies.csv"
        $policies | Export-Csv -Path $outputFile -NoTypeInformation

        Write-Host "`n=== Conditional Access Policies Summary ===" -ForegroundColor Cyan
        Write-Host "Total policies: $($policies.Count)" -ForegroundColor Yellow

        $enabledPolicies = $policies | Where-Object { $_.State -eq "enabled" }
        $disabledPolicies = $policies | Where-Object { $_.State -eq "disabled" }
        $reportingPolicies = $policies | Where-Object { $_.State -eq "enabledForReportingButNotEnforced" }

        Write-Host "Enabled policies: $($enabledPolicies.Count)" -ForegroundColor Green
        Write-Host "Disabled policies: $($disabledPolicies.Count)" -ForegroundColor Red
        Write-Host "Report-only policies: $($reportingPolicies.Count)" -ForegroundColor Yellow

        Write-Host "Output file: $outputFile" -ForegroundColor Green
    }
    else {
        Write-Host "`nNo Conditional Access policies found or error occurred during enumeration." -ForegroundColor Yellow
    }

    $stopwatch.Stop()
    Write-Host "`nConditional Access policies enumeration completed in $([Math]::Round($stopwatch.Elapsed.TotalSeconds, 2)) seconds." -ForegroundColor Green
}
catch {
    Write-Error "Script execution failed: $_"
    exit 1
}
finally {
    # Always disconnect from Microsoft Graph
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-Host "Disconnected from Microsoft Graph" -ForegroundColor Green
    }
    catch {
        # Ignore disconnect errors
    }
}