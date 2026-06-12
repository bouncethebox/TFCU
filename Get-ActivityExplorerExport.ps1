#Requires -Version 7.2
<#
.SYNOPSIS
    Exports Activity Explorer labeling activity data from Purview

.DESCRIPTION
    Retrieves Activity Explorer data showing labeling activity across the tenant -
    labels applied, changed, removed, DLP rule matches - by user, workload, and site.

    For Classify: this feeds the Signal activity intelligence concept. A site with
    SIT matches and zero labeling activity in 30 days is a site nobody is managing.

    Uses certificate-based (app-only) authentication via Connect-IPPSSession.
    The service principal must have Content Explorer List Viewer role in Purview.

    For large tenants (20K+ sites), the script automatically reconnects the
    IPPS session every 40 minutes to prevent token expiry timeouts.

.PARAMETER ClientId
    The Azure AD App Registration (Service Principal) Application ID.

.PARAMETER TenantId
    The Azure AD Tenant ID.

.PARAMETER CertificateThumbprint
    The thumbprint of the certificate used for app-only authentication.

.PARAMETER TenantName
    The SharePoint tenant name (e.g., 'contoso').

.PARAMETER AADTenantName
    The AAD/Entra tenant name used for UPN hints (e.g., 'contoso' for contoso.onmicrosoft.com).

.PARAMETER CloudEnvironment
    The cloud environment to connect to. Valid values are 'Commercial' or 'GCCH'. Default is 'Commercial'.

.PARAMETER LookbackDays
    Number of days to look back from today. Default is 7. Maximum is 30.

.PARAMETER PageSize
    Number of records per page. Default is 5000.

.PARAMETER MaxRetries
    Maximum retry attempts per activity filter on transient failure. Default is 3.

.PARAMETER SessionTimeoutMinutes
    Minutes before forcing a session reconnect to avoid token expiry. Default is 40.

.NOTES
    PowerShell Version: 7.2 minimum
    Authentication Method: Certificate-based (app-only)
    Required Module: ExchangeOnlineManagement
    Required Purview Role: Content Explorer List Viewer (on service principal)
    Cadence: Weekly (7-day lookback) or daily (1-day lookback)
    Estimated Runtime: 15-60 minutes for 20K-site tenant with 7-day window
    Session Refresh: Auto-reconnects every 40 minutes (MFA claim cached by Entra)
#>

[CmdletBinding()]
param (
    [string]$AdminUPN,

    [Parameter()]
    [string]$TenantName,

    [Parameter()]
    [string]$AADTenantName,

    [ValidateSet('Commercial', 'GCCH')]
    [string]$CloudEnvironment,

    [ValidateRange(1, 30)]
    [int]$LookbackDays = 7,

    [ValidateRange(100, 5000)]
    [int]$PageSize = 5000,

    [ValidateRange(1, 10)]
    [int]$MaxRetries = 3,

    [ValidateRange(10, 55)]
    [int]$SessionTimeoutMinutes = 40,

    [Parameter()]
    [string]$OutputDir
)

. (Join-Path $PSScriptRoot 'Shared\DiscoveryConfig.ps1')

Use-DiscoveryDefaults -CliParameters @{
    TenantName            = $TenantName
    AADTenantName         = $AADTenantName
    ClientId              = $ClientId
    TenantId              = $TenantId
    CertificateThumbprint = $CertificateThumbprint
    CloudEnvironment      = $CloudEnvironment
} -Required @('TenantName', 'AADTenantName', 'ClientId', 'TenantId', 'CertificateThumbprint', 'CloudEnvironment') `
  -Defaults @{ CloudEnvironment = 'Commercial' } `
  -AllowedValues @{ CloudEnvironment = @('Commercial', 'GCCH') }

# Check for required module
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

# Session timer for token refresh tracking
$script:sessionStartTime = $null

function Assert-ComplianceExportCommand {
    param (
        [Parameter(Mandatory)]
        [string]$CommandName,

        [string]$Context
    )

    if (-not (Get-Command -Name $CommandName -ErrorAction SilentlyContinue)) {
        $contextLabel = if ($Context) { " during $Context" } else { '' }
        throw "Required Purview cmdlet '$CommandName' is not available$contextLabel. Verify the signed-in account has the required Purview permissions and that Connect-IPPSSession imported the compliance commands successfully."
    }
}

function Get-ActivityExplorerCommandMetadata {
    $command = Get-Command -Name 'Export-ActivityExplorerData' -ErrorAction SilentlyContinue
    if (-not $command) {
        return $null
    }

    $parameterNames = @($command.Parameters.Keys)
    [PSCustomObject]@{
        SupportsFilter1Value = $parameterNames -contains 'Filter1Value'
        SupportsFilter2      = $parameterNames -contains 'Filter2'
        SupportsFilter2Value = $parameterNames -contains 'Filter2Value'
        SupportsPageCookie   = $parameterNames -contains 'PageCookie'
        SupportsOutputFormat = $parameterNames -contains 'OutputFormat'
    }
}

# Connect (or reconnect) to Security & Compliance PowerShell with cert-based auth
function Connect-IPPSCompliance {
    param (
        [string]$AdminUPN,
        [string]$CloudEnvironment,
        [switch]$Reconnect
    )

    try {
        if ($Reconnect) {
            Write-Host "  Refreshing IPPS session to prevent token expiry..." -ForegroundColor Yellow
            try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch { }
        }

        $orgDomain = if ($CloudEnvironment -eq 'GCCH') { "$AADTenantName.onmicrosoft.us" } else { "$AADTenantName.onmicrosoft.com" }
        $connectionParams = @{}
        if ($AdminUPN) { $connectionParams['UserPrincipalName'] = $AdminUPN }

        if ($CloudEnvironment -eq 'GCCH') {
            $connectionParams['ConnectionUri'] = 'https://ps.compliance.protection.office365.us/powershell-liveid/'
            $connectionParams['AzureADAuthorizationEndpointUri'] = 'https://login.microsoftonline.us/common'
        }

        $action = if ($Reconnect) { "Reconnecting" } else { "Connecting" }
        Write-Host "$action to Security & Compliance PowerShell ($CloudEnvironment)..." -ForegroundColor Cyan
        Connect-IPPSSession @connectionParams
        Assert-ComplianceExportCommand -CommandName 'Export-ActivityExplorerData' -Context 'IPPS connection setup'
        $script:sessionStartTime = Get-Date
        Write-Host "Successfully connected to IPPS" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to connect to Security & Compliance PowerShell: $_"
        exit 1
    }
}

# Check if session needs refresh based on elapsed time
function Test-SessionNeedsRefresh {
    param ([int]$TimeoutMinutes)
    if (-not $script:sessionStartTime) { return $false }
    $elapsed = (Get-Date) - $script:sessionStartTime
    return $elapsed.TotalMinutes -ge $TimeoutMinutes
}

# Export activity data for a single activity type with pagination and retry
function Export-ActivityData {
    param (
        [string]$ActivityType,
        [datetime]$StartTime,
        [datetime]$EndTime,
        [int]$PageSize,
        [int]$MaxRetries
    )

    $allResults = @()
    $pageCookie = $null
    $pageNumber = 1
    $hasMore = $true

    while ($hasMore) {
        # Mid-pagination session refresh check
        if ($pageNumber -gt 1 -and (Test-SessionNeedsRefresh -TimeoutMinutes $script:sessionTimeoutMin)) {
            Write-Host "    Refreshing session mid-pagination (page $pageNumber)..." -ForegroundColor Yellow
            Connect-IPPSCompliance -AdminUPN $script:currentAdminUPN -CloudEnvironment $script:currentEnv -Reconnect
        }

        $attempt = 0
        $success = $false

        while (-not $success -and $attempt -lt $MaxRetries) {
            $attempt++
            try {
                $commandMetadata = Get-ActivityExplorerCommandMetadata
                if (-not $commandMetadata) {
                    throw 'Export-ActivityExplorerData is not available in the current session.'
                }

                $exportParams = @{
                    StartTime = $StartTime
                    EndTime   = $EndTime
                    PageSize  = $PageSize
                }

                if ($commandMetadata.SupportsOutputFormat) {
                    $exportParams['OutputFormat'] = 'JSON'
                }

                if ($commandMetadata.SupportsFilter1Value) {
                    $exportParams['Filter1'] = @('Activity', 'Workload')
                    $exportParams['Filter1Value'] = @($ActivityType, 'SharePoint')
                }
                elseif ($commandMetadata.SupportsFilter2 -and $commandMetadata.SupportsFilter2Value) {
                    $exportParams['Filter1'] = 'Activity'
                    $exportParams['Filter2'] = 'Workload'
                    $exportParams['Filter2Value'] = 'SharePoint'
                    Write-Host "    Activity Explorer cmdlet does not support Filter1Value in this session. Skipping filtered export for '$ActivityType'." -ForegroundColor Yellow
                    return @()
                }
                else {
                    Write-Host "    Activity Explorer cmdlet does not expose the expected filter parameters in this session. Skipping '$ActivityType'." -ForegroundColor Yellow
                    return @()
                }

                if ($pageCookie -and $commandMetadata.SupportsPageCookie) {
                    $exportParams['PageCookie'] = $pageCookie
                }

                Write-Host "    Page $pageNumber (attempt $attempt)..." -ForegroundColor Gray
                $result = Export-ActivityExplorerData @exportParams

                if ($result -and $result.ResultData) {
                    $parsed = $result.ResultData | ConvertFrom-Json
                    if ($parsed) {
                        $allResults += $parsed
                        Write-Host "    Page $pageNumber returned $($parsed.Count) records" -ForegroundColor Gray
                    }
                }

                # Check for more pages
                if ($result.LastPage -or -not $result.ResultData) {
                    $hasMore = $false
                }
                else {
                    $pageCookie = $result.WaterMark
                    $pageNumber++
                }

                $success = $true
            }
            catch {
                Write-Warning "    Attempt $attempt failed for '$ActivityType' page $pageNumber : $_"
                if ($attempt -lt $MaxRetries) {
                    $backoff = [Math]::Pow(2, $attempt) * 5
                    Write-Host "    Retrying in $backoff seconds..." -ForegroundColor Yellow
                    Start-Sleep -Seconds $backoff
                }
                else {
                    Write-Error "    All $MaxRetries attempts failed for '$ActivityType' page $pageNumber. Skipping."
                    $hasMore = $false
                }
            }
        }
    }

    return $allResults
}

# Main execution
try {
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    $endTime = Get-Date
    $startTime = $endTime.AddDays(-$LookbackDays)

    Write-Host "=== Activity Explorer Export ===" -ForegroundColor Cyan
    Write-Host "Tenant: $TenantName" -ForegroundColor Gray
    Write-Host "Environment: $CloudEnvironment" -ForegroundColor Gray
    Write-Host "Time window: $($startTime.ToString('yyyy-MM-dd')) to $($endTime.ToString('yyyy-MM-dd'))" -ForegroundColor Gray
    Write-Host ""

    # Connect to IPPS
    Write-Host "Session will auto-refresh every $SessionTimeoutMinutes minutes to prevent token expiry.`n" -ForegroundColor Yellow

    # Store for mid-pagination reconnection
    $script:currentAdminUPN = $AdminUPN
    $script:currentEnv = $CloudEnvironment
    $script:sessionTimeoutMin = $SessionTimeoutMinutes

    Connect-IPPSCompliance -AdminUPN $AdminUPN -CloudEnvironment $CloudEnvironment
    Assert-ComplianceExportCommand -CommandName 'Export-ActivityExplorerData' -Context 'Activity Explorer export startup'

    # Activity types to export
    $activityTypes = @(
        'LabelApplied'
        'LabelChanged'
        'LabelRemoved'
        'DLPRuleMatch'
    )

    $allActivities = @()

    foreach ($activityType in $activityTypes) {
        # Check if session needs refresh before starting next activity type
        if (Test-SessionNeedsRefresh -TimeoutMinutes $SessionTimeoutMinutes) {
            Write-Host "`n  Session approaching token expiry ($SessionTimeoutMinutes min). Reconnecting..." -ForegroundColor Yellow
            Connect-IPPSCompliance -AdminUPN $AdminUPN -CloudEnvironment $CloudEnvironment -Reconnect
        }

        Write-Host "`nExporting activity: $activityType" -ForegroundColor Yellow

        $records = Export-ActivityData -ActivityType $activityType `
            -StartTime $startTime -EndTime $endTime `
            -PageSize $PageSize -MaxRetries $MaxRetries

        if ($records -and $records.Count -gt 0) {
            Write-Host "  Found $($records.Count) records for '$activityType'" -ForegroundColor Green

            foreach ($record in $records) {
                $allActivities += [PSCustomObject]@{
                    Timestamp   = $record.Happened
                    Activity    = $activityType
                    User        = $record.User
                    Workload    = $record.Workload
                    SiteUrl     = $record.ObjectId
                    LabelName   = $record.SensitivityLabelName
                    SITName     = $record.SensitiveInfoTypeName
                    Application = $record.Application
                }
            }
        }
        else {
            Write-Host "  No records found for '$activityType'" -ForegroundColor Gray
        }
    }

    # Export results
    if ($OutputDir) { $outputPath = $OutputDir } else { $outputPath = Resolve-RunFolder }
    if (-not (Test-Path $outputPath)) { New-Item -ItemType Directory -Path $outputPath -Force | Out-Null }

    if ($allActivities.Count -gt 0) {
        $outputFile = Join-Path $outputPath "ActivityExplorer.csv"
        $allActivities | Export-Csv -Path $outputFile -NoTypeInformation

        Write-Host "`n=== Activity Explorer Summary ===" -ForegroundColor Cyan
        Write-Host "Total records: $($allActivities.Count)" -ForegroundColor Yellow

        $activitySummary = $allActivities | Group-Object Activity | Sort-Object Count -Descending
        foreach ($group in $activitySummary) {
            Write-Host "  $($group.Name): $($group.Count) records" -ForegroundColor White
        }

        $uniqueSites = ($allActivities | Select-Object -ExpandProperty SiteUrl -Unique).Count
        Write-Host "Unique sites with activity: $uniqueSites" -ForegroundColor Yellow

        Write-Host "Output file: $outputFile" -ForegroundColor Green
    }
    else {
        Write-Host "`nNo activity records found in the $LookbackDays-day window." -ForegroundColor Yellow
    }

    $stopwatch.Stop()
    Write-Host "`nActivity export completed in $([Math]::Round($stopwatch.Elapsed.TotalMinutes, 1)) minutes." -ForegroundColor Green
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
