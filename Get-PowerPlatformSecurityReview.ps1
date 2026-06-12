#Requires -Version 7.2
<#
.SYNOPSIS
    Reviews Power Platform security controls with a focus on DLP and Dataverse access.

.DESCRIPTION
    Connects interactively to the Power Platform admin APIs and exports:
    - Tenant and environment DLP policies
    - Connector grouping and blocked/business/non-business assignments
    - Environment role assignments exposed by the admin module

    This script is intended for security review and governance assessment work,
    not for tenant configuration changes.

.PARAMETER TenantId
    Optional Microsoft Entra tenant ID. When omitted, the value is resolved from
    the repo .env file if present.

.PARAMETER OutputDir
    Optional output directory. Defaults to a timestamped run folder under output/.

.PARAMETER UserPrincipalName
    Optional sign-in hint for interactive Power Platform authentication. When omitted,
    the script prompts for a value but does not force it into the login request.

.NOTES
    PowerShell Version: 7.2 minimum
    Authentication Method: Interactive user sign-in
    Required Modules: Microsoft.PowerApps.Administration.PowerShell
    Recommended Roles: Power Platform Administrator or Global Administrator
    Estimated Runtime: 2-15 minutes depending on environment count
#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]$TenantId,

    [ValidateSet('Commercial', 'GCCH')]
    [string]$CloudEnvironment,

    [Parameter()]
    [string]$OutputDir,

    [Parameter()]
    [string]$UserPrincipalName
)

. (Join-Path $PSScriptRoot 'Shared\DiscoveryConfig.ps1')

Use-DiscoveryDefaults -CliParameters @{
    TenantId = $TenantId
    CloudEnvironment = $CloudEnvironment
} -Defaults @{ CloudEnvironment = 'Commercial' } -AllowedValues @{ CloudEnvironment = @('Commercial', 'GCCH') }

if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) {
    $UserPrincipalName = Read-Host 'Enter Power Platform sign-in hint (press Enter to use the account picker)'
}

if (-not $OutputDir) {
    $OutputDir = Resolve-RunFolder
}

if (-not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$requiredModules = @(
    'Microsoft.PowerApps.Administration.PowerShell'
)

foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "Required module '$module' is not installed." -ForegroundColor Yellow
        $install = Read-Host "Would you like to install it now? (Y/N)"
        if ($install -match '^[Yy]$') {
            Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
        }
        else {
            throw "Required module '$module' is not installed."
        }
    }
}

Import-Module Microsoft.PowerApps.Administration.PowerShell -ErrorAction Stop

function Connect-PowerPlatformAdmin {
    param (
        [string]$TenantId,
        [string]$CloudEnvironment,
        [string]$UserPrincipalName
    )

    try {
        Write-Host 'Connecting to Power Platform admin APIs with interactive user authentication...' -ForegroundColor Cyan

        $addAccountParams = @{
            ErrorAction = 'Stop'
        }

        if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
            $addAccountParams['TenantID'] = $TenantId
        }

        $addAccountParams['Endpoint'] = if ($CloudEnvironment -eq 'GCCH') { 'usgovhigh' } else { 'prod' }

        Add-PowerAppsAccount @addAccountParams | Out-Null
        Write-Host 'Connected to Power Platform admin APIs.' -ForegroundColor Green
    }
    catch {
        throw "Failed to connect to Power Platform admin APIs: $($_.Exception.Message)"
    }
}

function ConvertTo-DelimitedString {
    param (
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    if ($Value -is [string]) {
        return $Value
    }

    if ($Value -is [System.Collections.IEnumerable]) {
        $items = foreach ($item in $Value) {
            if ($null -eq $item) { continue }
            if ($item -is [string]) {
                $item
                continue
            }

            if ($item.PSObject.Properties['displayName']) {
                $item.displayName
                continue
            }

            if ($item.PSObject.Properties['name']) {
                $item.name
                continue
            }

            if ($item.PSObject.Properties['id']) {
                $item.id
                continue
            }

            $item.ToString()
        }

        return ($items | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join '; '
    }

    return $Value.ToString()
}

function Get-ConnectorGroupName {
    param (
        [string]$Classification
    )

    switch ($Classification) {
        'General' { return 'Business' }
        'Confidential' { return 'NonBusiness' }
        'Blocked' { return 'Blocked' }
        default { return $Classification }
    }
}

function Get-DlpPolicyReviewData {
    Write-Host 'Retrieving Power Platform DLP policies...' -ForegroundColor Cyan

    $policies = @()
    try {
        $policies = @(Get-AdminDlpPolicy)
    }
    catch {
        throw "Failed to retrieve DLP policies: $($_.Exception.Message)"
    }

    $policyRows = @()
    $connectorRows = @()

    foreach ($policy in $policies) {
        $policyName = $policy.DisplayName
        if ([string]::IsNullOrWhiteSpace($policyName)) {
            $policyName = $policy.PolicyName
        }

        $environmentTargets = @()
        if ($policy.PSObject.Properties['Environments']) {
            $environmentTargets = @($policy.Environments)
        }
        elseif ($policy.PSObject.Properties['EnvironmentName']) {
            $environmentTargets = @($policy.EnvironmentName)
        }

        $policyRows += [PSCustomObject]@{
            PolicyName = $policyName
            PolicyId = $policy.PolicyName
            Scope = if ($environmentTargets.Count -gt 0) { 'Environment' } else { 'Tenant' }
            EnvironmentTargets = ConvertTo-DelimitedString -Value $environmentTargets
            CreatedTime = $policy.CreatedTime
            LastModifiedTime = $policy.LastModifiedTime
            ConnectorCount = @($policy.ConnectorConfigurations).Count
            BusinessConnectorCount = @($policy.ConnectorConfigurations | Where-Object { (Get-ConnectorGroupName $_.classification) -eq 'Business' }).Count
            NonBusinessConnectorCount = @($policy.ConnectorConfigurations | Where-Object { (Get-ConnectorGroupName $_.classification) -eq 'NonBusiness' }).Count
            BlockedConnectorCount = @($policy.ConnectorConfigurations | Where-Object { (Get-ConnectorGroupName $_.classification) -eq 'Blocked' }).Count
            RawPolicyType = $policy.Type
        }

        foreach ($connector in @($policy.ConnectorConfigurations)) {
            $connectorRows += [PSCustomObject]@{
                PolicyName = $policyName
                PolicyId = $policy.PolicyName
                Scope = if ($environmentTargets.Count -gt 0) { 'Environment' } else { 'Tenant' }
                EnvironmentTargets = ConvertTo-DelimitedString -Value $environmentTargets
                ConnectorName = $connector.connectorName
                ConnectorId = $connector.connectorId
                ConnectorType = $connector.connectorType
                ConnectorGroup = Get-ConnectorGroupName -Classification $connector.classification
                RawClassification = $connector.classification
                IsCustomConnector = $connector.connectorType -eq 'Custom'
            }
        }
    }

    return @{
        Policies = $policyRows
        Connectors = $connectorRows
    }
}

function Get-DataverseRoleReviewData {
    Write-Host 'Retrieving Power Platform environments...' -ForegroundColor Cyan

    try {
        $environments = @(Get-AdminPowerAppEnvironment)
    }
    catch {
        throw "Failed to retrieve Power Platform environments: $($_.Exception.Message)"
    }

    $environmentRows = @()
    $roleRows = @()
    foreach ($environment in $environments) {
        $environmentName = $environment.DisplayName
        if ([string]::IsNullOrWhiteSpace($environmentName)) {
            $environmentName = $environment.EnvironmentName
        }

        $hasDataverse = $false
        if ($environment.PSObject.Properties['CommonDataServiceDatabaseType']) {
            $hasDataverse = -not [string]::IsNullOrWhiteSpace([string]$environment.CommonDataServiceDatabaseType)
        }
        elseif ($environment.PSObject.Properties['DatabaseType']) {
            $hasDataverse = -not [string]::IsNullOrWhiteSpace([string]$environment.DatabaseType)
        }

        $environmentRows += [PSCustomObject]@{
            EnvironmentName = $environmentName
            EnvironmentId = $environment.EnvironmentName
            Location = $environment.Location
            EnvironmentType = $environment.EnvironmentType
            DataverseProvisioned = $hasDataverse
            DataverseType = if ($environment.PSObject.Properties['CommonDataServiceDatabaseType']) { $environment.CommonDataServiceDatabaseType } else { $environment.DatabaseType }
            CreatedTime = $environment.CreatedTime
        }

        if (-not $hasDataverse) {
            continue
        }

        Write-Host "Reviewing environment role assignments in $environmentName..." -ForegroundColor Yellow

        try {
            $roles = @(Get-AdminPowerAppEnvironmentRoleAssignment -EnvironmentName $environment.EnvironmentName)
        }
        catch {
            Write-Warning "Failed to retrieve environment role assignments for ${environmentName}: $($_.Exception.Message)"
            continue
        }

        foreach ($role in $roles) {
            $principalDisplayName = $null
            foreach ($candidateProperty in @('PrincipalDisplayName', 'DisplayName', 'UserDisplayName', 'RoleMemberName')) {
                if ($role.PSObject.Properties[$candidateProperty] -and -not [string]::IsNullOrWhiteSpace([string]$role.$candidateProperty)) {
                    $principalDisplayName = $role.$candidateProperty
                    break
                }
            }

            $principalType = $null
            foreach ($candidateProperty in @('PrincipalType', 'UserType', 'RoleMemberType')) {
                if ($role.PSObject.Properties[$candidateProperty] -and -not [string]::IsNullOrWhiteSpace([string]$role.$candidateProperty)) {
                    $principalType = $role.$candidateProperty
                    break
                }
            }

            $roleName = $null
            foreach ($candidateProperty in @('RoleName', 'DisplayName', 'SecurityRoleName')) {
                if ($role.PSObject.Properties[$candidateProperty] -and -not [string]::IsNullOrWhiteSpace([string]$role.$candidateProperty)) {
                    $roleName = $role.$candidateProperty
                    break
                }
            }

            $roleRows += [PSCustomObject]@{
                EnvironmentName = $environmentName
                EnvironmentId = $environment.EnvironmentName
                RoleName = $roleName
                RoleId = if ($role.PSObject.Properties['RoleId']) { $role.RoleId } else { $role.Id }
                PrincipalDisplayName = $principalDisplayName
                PrincipalId = if ($role.PSObject.Properties['PrincipalObjectId']) { $role.PrincipalObjectId } elseif ($role.PSObject.Properties['ObjectId']) { $role.ObjectId } else { $null }
                PrincipalType = $principalType
                BusinessUnit = if ($role.PSObject.Properties['BusinessUnitName']) { $role.BusinessUnitName } else { $null }
                RawAssignment = ($role | ConvertTo-Json -Depth 8 -Compress)
            }
        }

    }

    return @{
        Environments = $environmentRows
        RoleAssignments = $roleRows
        RolePrivileges = @()
    }
}

try {
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    Connect-PowerPlatformAdmin -TenantId $TenantId -CloudEnvironment $CloudEnvironment -UserPrincipalName $UserPrincipalName

    $dlpData = Get-DlpPolicyReviewData
    $dataverseData = Get-DataverseRoleReviewData

    $dlpPoliciesPath = Join-Path $OutputDir 'PowerPlatform-DLPPolicies.csv'
    $dlpConnectorsPath = Join-Path $OutputDir 'PowerPlatform-DLPConnectors.csv'
    $environmentsPath = Join-Path $OutputDir 'PowerPlatform-Environments.csv'
    $roleAssignmentsPath = Join-Path $OutputDir 'Dataverse-RoleAssignments.csv'
    $rolePrivilegesPath = Join-Path $OutputDir 'Dataverse-RolePrivileges.csv'
    $summaryPath = Join-Path $OutputDir 'PowerPlatform-SecurityReview-Summary.json'

    $dlpData.Policies | Export-Csv -Path $dlpPoliciesPath -NoTypeInformation -Encoding UTF8
    $dlpData.Connectors | Export-Csv -Path $dlpConnectorsPath -NoTypeInformation -Encoding UTF8
    $dataverseData.Environments | Export-Csv -Path $environmentsPath -NoTypeInformation -Encoding UTF8
    $dataverseData.RoleAssignments | Export-Csv -Path $roleAssignmentsPath -NoTypeInformation -Encoding UTF8
    $dataverseData.RolePrivileges | Export-Csv -Path $rolePrivilegesPath -NoTypeInformation -Encoding UTF8

    $summary = [PSCustomObject]@{
        GeneratedAt = (Get-Date).ToString('o')
        TenantId = $TenantId
        OutputDirectory = $OutputDir
        DlpPolicyCount = @($dlpData.Policies).Count
        DlpConnectorRows = @($dlpData.Connectors).Count
        EnvironmentCount = @($dataverseData.Environments).Count
        DataverseEnvironmentCount = @($dataverseData.Environments | Where-Object { $_.DataverseProvisioned }).Count
        RoleAssignmentCount = @($dataverseData.RoleAssignments).Count
        RolePrivilegeCount = @($dataverseData.RolePrivileges).Count
        ReviewFocus = @(
            'Power Platform DLP policies and connector grouping'
            'Environment role assignments exposed by the Power Platform admin module'
        )
    }

    $summary | ConvertTo-Json -Depth 6 | Set-Content -Path $summaryPath -Encoding UTF8

    $stopwatch.Stop()

    Write-Host ''
    Write-Host 'Power Platform security review complete.' -ForegroundColor Green
    Write-Host "DLP policies exported: $(@($dlpData.Policies).Count)" -ForegroundColor Green
    Write-Host "DLP connector rows exported: $(@($dlpData.Connectors).Count)" -ForegroundColor Green
    Write-Host "Environments exported: $(@($dataverseData.Environments).Count)" -ForegroundColor Green
    Write-Host "Environment role assignments exported: $(@($dataverseData.RoleAssignments).Count)" -ForegroundColor Green
    Write-Host 'Dataverse role privileges exported: 0 (not exposed by the installed Power Platform admin module)' -ForegroundColor Yellow
    Write-Host "Output folder: $OutputDir" -ForegroundColor Cyan
    Write-Host "Elapsed time: $([Math]::Round($stopwatch.Elapsed.TotalMinutes, 2)) minutes" -ForegroundColor Cyan
}
catch {
    Write-Error $_
    exit 1
}
finally {
    try {
        if (Get-Command -Name Disconnect-PowerAppsAccount -ErrorAction SilentlyContinue) {
            Disconnect-PowerAppsAccount | Out-Null
        }
    }
    catch {
    }
}