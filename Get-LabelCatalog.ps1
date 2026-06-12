#Requires -Version 7.2
<#
.SYNOPSIS
    Exports the full sensitivity label taxonomy from Purview

.DESCRIPTION
    Retrieves every sensitivity label, its parent, protection settings (encryption,
    content marking, auto-labeling), priority ranking, and scope. Also exports
    label publishing policies via Get-LabelPolicy.

    For Classify: the label hierarchy is needed to compute the label_vs_content
    dimension — is a site under-labeled relative to its content? e.g., container
    label is "General" but contains "Confidential" content labels.

.PARAMETER AADTenantName
    The AAD/Entra tenant name (e.g., 'contoso' for contoso.onmicrosoft.com).

.PARAMETER CloudEnvironment
    The cloud environment to connect to. Valid values are 'Commercial' or 'GCCH'. Default is 'Commercial'.

.PARAMETER UserPrincipalName
    Optional UPN for interactive IPPS authentication. When omitted, the script
    prompts for a UPN and uses interactive user sign-in.

.NOTES
    PowerShell Version: 7.2 minimum
    Authentication Method: Interactive user sign-in
    Required Modules: ExchangeOnlineManagement
    Required Role: Compliance Administrator
    Cadence: Weekly
    Estimated Runtime: Under 2 minutes
#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]$AADTenantName,

    [ValidateSet('Commercial', 'GCCH')]
    [string]$CloudEnvironment,

    [Parameter()]
    [string]$OutputDir,

    [Parameter()]
    [string]$UserPrincipalName
)

. (Join-Path $PSScriptRoot 'Shared\DiscoveryConfig.ps1')

Use-DiscoveryDefaults -CliParameters @{
    AADTenantName        = $AADTenantName
    CloudEnvironment     = $CloudEnvironment
} -Required @('AADTenantName', 'CloudEnvironment') `
  -Defaults @{ CloudEnvironment = 'Commercial' } `
  -AllowedValues @{ CloudEnvironment = @('Commercial', 'GCCH') }

if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) {
    $UserPrincipalName = Read-Host 'Enter UPN for interactive IPPS sign-in'
    if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) {
        throw 'A UserPrincipalName is required for interactive label catalog export.'
    }
}

# Check for required modules
$requiredModules = @('ExchangeOnlineManagement')
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

Import-Module ExchangeOnlineManagement

# Connect to Security & Compliance PowerShell
function Connect-IPPSCompliance {
    param (
        [string]$CloudEnvironment,
        [string]$UserPrincipalName
    )

    try {
        $connectionParams = @{
            UserPrincipalName = $UserPrincipalName
        }

        if ($CloudEnvironment -eq 'GCCH') {
            $connectionParams['ConnectionUri'] = 'https://ps.compliance.protection.office365.us/powershell-liveid/'
            $connectionParams['AzureADAuthorizationEndpointUri'] = 'https://login.microsoftonline.us/organizations'
        }

        Write-Host "Connecting to Security & Compliance PowerShell ($CloudEnvironment) with interactive user authentication..." -ForegroundColor Cyan
        Connect-IPPSSession @connectionParams
        Write-Host "Successfully connected to IPPS" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to connect to Security & Compliance PowerShell: $_"
        exit 1
    }
}

function Test-IppsLabelCmdletAvailability {
    $getLabelCommand = Get-Command -Name 'Get-Label' -ErrorAction SilentlyContinue
    $getLabelPolicyCommand = Get-Command -Name 'Get-LabelPolicy' -ErrorAction SilentlyContinue

    return [PSCustomObject]@{
        HasGetLabel = $null -ne $getLabelCommand
        HasGetLabelPolicy = $null -ne $getLabelPolicyCommand
    }
}

# Main execution
try {
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    Write-Host "=== Label Catalog Export ===" -ForegroundColor Cyan
    Write-Host "Tenant (AAD): $AADTenantName" -ForegroundColor Gray
    Write-Host "Environment: $CloudEnvironment" -ForegroundColor Gray
    Write-Host ""

    # Connect to IPPS
    Connect-IPPSCompliance -CloudEnvironment $CloudEnvironment `
        -UserPrincipalName $UserPrincipalName

    $syncedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    $labelDetails = @()
    $policyAssignments = @()

    $labelResults = @()
    $policyResults = @()
    $ippsCmdlets = Test-IppsLabelCmdletAvailability

    # --- Export Labels ---
    if ($ippsCmdlets.HasGetLabel) {
        Write-Host "Retrieving sensitivity labels..." -ForegroundColor Cyan
        $labels = Get-Label

        if ($labels -and $labels.Count -gt 0) {
            Write-Host "Found $($labels.Count) sensitivity labels" -ForegroundColor Green

            foreach ($label in $labels) {
                $labelDetails += $label

                # Determine encryption settings
                $isEncrypted = $false
                $encryptionRights = $null
                if ($label.EncryptionEnabled) {
                    $isEncrypted = $true
                    if ($label.EncryptionRightsDefinitions) {
                        $encryptionRights = $label.EncryptionRightsDefinitions | ConvertTo-Json -Compress -Depth 5
                    }
                }

                # Content marking
                $contentMarkingEnabled = $false
                if ($label.HeaderEnabled -or $label.FooterEnabled -or $label.WatermarkEnabled) {
                    $contentMarkingEnabled = $true
                }

                # Auto-labeling config on the label itself
                $autoLabelingEnabled = [bool]$label.AutoLabelingEnabled

                # Label scope
                $scopes = @()
                if ($label.ContentType) {
                    $scopes = @($label.ContentType)
                }

                $labelResults += [PSCustomObject]@{
                    LabelName                = $label.DisplayName
                    LabelId                  = $label.Guid
                    ParentLabelName          = $label.ParentLabelDisplayName
                    ParentLabelId            = $label.ParentId
                    Priority                 = $label.Priority
                    IsEncrypted              = $isEncrypted
                    EncryptionRightsDefinitions = $encryptionRights
                    ContentMarkingEnabled    = $contentMarkingEnabled
                    AutoLabelingEnabled      = $autoLabelingEnabled
                    LabelScope              = ($scopes | ConvertTo-Json -Compress)
                    IsActive                 = $label.Disabled -ne $true
                    CreatedDateTime          = $null
                    LastModifiedDateTime     = $null
                    Source                   = 'IPPS'
                    SyncedAt                 = $syncedAt
                }
            }
        }
        else {
            throw 'Get-Label returned no results after interactive authentication.'
        }
    }
    else {
        throw 'Get-Label is not available in this interactive IPPS session.'
    }

    # --- Export Label Publishing Policies ---
    if (-not $policyResults -or $policyResults.Count -eq 0) {
        if (-not $ippsCmdlets.HasGetLabelPolicy) {
            Write-Warning "Get-LabelPolicy is not available in this IPPS session. Skipping IPPS policy retrieval."
        }
        else {
        Write-Host "Retrieving label publishing policies..." -ForegroundColor Cyan
        $labelPolicies = Get-LabelPolicy

        if ($labelPolicies -and $labelPolicies.Count -gt 0) {
            Write-Host "Found $($labelPolicies.Count) label publishing policies" -ForegroundColor Green

            foreach ($policy in $labelPolicies) {
                $policyResults += [PSCustomObject]@{
                    PolicyName            = $policy.Name
                    PolicyId              = $policy.Guid
                    IsEnabled             = $policy.Enabled
                    Labels                = ($policy.Labels -join ', ')
                    PublishedTo           = ($policy.ExchangeLocation -join ', ')
                    CreatedDateTime       = $null
                    LastModifiedDateTime  = $null
                    Source                = 'IPPS'
                    SyncedAt              = $syncedAt
                }
            }
        }
        else {
            Write-Host "No label publishing policies found" -ForegroundColor Yellow
        }
        }
    }

    # Export results
    if ($OutputDir) { $outputPath = $OutputDir } else { $outputPath = Resolve-RunFolder }
    if (-not (Test-Path $outputPath)) { New-Item -ItemType Directory -Path $outputPath -Force | Out-Null }

    if ($labelResults.Count -gt 0) {
        $labelsFile = Join-Path $outputPath "LabelCatalog.csv"
        $labelResults | Export-Csv -Path $labelsFile -NoTypeInformation

        $labelDetailsFile = Join-Path $outputPath "SensitivityLabelDetails.json"
        $labelDetails | ConvertTo-Json -Depth 10 | Out-File -FilePath $labelDetailsFile -Encoding utf8

        Write-Host "`n=== Label Catalog Summary ===" -ForegroundColor Cyan
        Write-Host "Total labels: $($labelResults.Count)" -ForegroundColor Yellow

        $parentLabels = $labelResults | Where-Object { -not $_.ParentLabelId }
        $childLabels = $labelResults | Where-Object { $_.ParentLabelId }
        Write-Host "Parent labels: $($parentLabels.Count)" -ForegroundColor Yellow
        Write-Host "Sub-labels: $($childLabels.Count)" -ForegroundColor Yellow

        $encryptedCount = ($labelResults | Where-Object { $_.IsEncrypted -eq $true }).Count
        Write-Host "Labels with encryption: $encryptedCount" -ForegroundColor Yellow

        Write-Host "Labels file: $labelsFile" -ForegroundColor Green
        Write-Host "Label details file: $labelDetailsFile" -ForegroundColor Green
    }
    else {
        Write-Host "`nNo labels to export." -ForegroundColor Yellow
    }

    if ($policyResults.Count -gt 0) {
        $policiesFile = Join-Path $outputPath "LabelPolicies.csv"
        $policyResults | Export-Csv -Path $policiesFile -NoTypeInformation
        Write-Host "Policies file: $policiesFile" -ForegroundColor Green
    }

    if ($policyAssignments.Count -gt 0) {
        $policyAssignmentsFile = Join-Path $outputPath "LabelPolicyAssignments.json"
        $policyAssignments | ConvertTo-Json -Depth 8 | Out-File -FilePath $policyAssignmentsFile -Encoding utf8
        Write-Host "Policy assignments file: $policyAssignmentsFile" -ForegroundColor Green
    }

    $stopwatch.Stop()
    Write-Host "`nLabel catalog export completed in $([Math]::Round($stopwatch.Elapsed.TotalSeconds, 2)) seconds." -ForegroundColor Green
}
catch {
    Write-Error "Script execution failed: $_"
    exit 1
}
finally {
    try {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "Disconnected from Security & Compliance PowerShell" -ForegroundColor Green
    }
    catch {
        # Ignore disconnect errors
    }
}
