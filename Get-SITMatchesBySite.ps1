#Requires -Version 7.2
<#
.SYNOPSIS
    Exports Content Explorer SIT matches per site from Microsoft Purview

.DESCRIPTION
    Uses Export-ContentExplorerData to retrieve Sensitive Information Type (SIT)
    match counts aggregated by site. Iterates over a target SIT list using
    Option A (per-SIT, tenant-wide with -Aggregate) for efficient data collection.

    This is the critical Classify data - it answers "does this site actually
    contain sensitive content?" with per-site SIT counts and confidence levels.

    Uses certificate-based (app-only) authentication via Connect-IPPSSession.
    The service principal must have Content Explorer List Viewer role in Purview.

    For large tenants (20K+ sites), the script automatically reconnects the
    IPPS session every 40 minutes to prevent token expiry timeouts.

.PARAMETER AdminUPN
    The UserPrincipalName of the administrator running the script (optional, pre-fills login prompt).

.PARAMETER TenantName
    The SharePoint tenant name (e.g., 'contoso').

.PARAMETER AADTenantName
    The AAD/Entra tenant name used for UPN hints (e.g., 'contoso' for contoso.onmicrosoft.com).

.PARAMETER CloudEnvironment
    The cloud environment to connect to. Valid values are 'Commercial' or 'GCCH'. Default is 'Commercial'.

.PARAMETER TargetSITs
    Optional array of SIT names to query. If not provided, uses a default DIB/GCCH-oriented list.

.PARAMETER Workload
    The workload to query. Default is 'SPO'. Also accepts 'ODB' for OneDrive.

.PARAMETER PageSize
    Number of records per page. Default is 5000 (max 10000).

.PARAMETER MaxRetries
    Maximum retry attempts per SIT export on transient failure. Default is 3.

.PARAMETER SessionTimeoutMinutes
    Minutes before forcing a session reconnect to avoid token expiry. Default is 40.

.NOTES
    PowerShell Version: 7.2 minimum
    Authentication Method: Certificate-based (app-only)
    Required Module: ExchangeOnlineManagement (provides Connect-IPPSSession)
    Required Purview Role: Content Explorer List Viewer (on service principal)
    Cadence: Weekly (weekend run)
    Estimated Runtime: 30-90 minutes for 20K-site tenant with 10-15 SITs
    Session Refresh: Auto-reconnects every 40 minutes (MFA claim cached by Entra)
#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]$AdminUPN,

    [Parameter()]
    [string]$TenantName,

    [Parameter()]
    [string]$AADTenantName,

    [ValidateSet('Commercial', 'GCCH')]
    [string]$CloudEnvironment,

    [Parameter()]
    [string[]]$TargetSITs,

    [ValidateSet('SPO', 'ODB')]
    [string]$Workload = 'SPO',

    [ValidateRange(100, 10000)]
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

# SIT selection is handled after IPPS connection (needs Get-DlpSensitiveInformationType)
# If -TargetSITs was passed on the command line, skip the interactive picker.

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
        Assert-ComplianceExportCommand -CommandName 'Export-ContentExplorerData' -Context 'IPPS connection setup'
        Assert-ComplianceExportCommand -CommandName 'Get-DlpSensitiveInformationType' -Context 'IPPS connection setup'
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

# Export SIT matches for a single SIT with pagination and retry
function Export-SITData {
    param (
        [string]$SITName,
        [string]$Workload,
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
                $exportParams = @{
                    TagType  = 'SensitiveInformationType'
                    TagName  = $SITName
                    Workload = $Workload
                    PageSize = $PageSize
                    Aggregate = $true
                }

                if ($pageCookie) {
                    $exportParams['PageCookie'] = $pageCookie
                }

                Write-Host "    Page $pageNumber (attempt $attempt)..." -ForegroundColor Gray
                $result = Export-ContentExplorerData @exportParams

                $rows = @($result | Where-Object { $_.Name })
                if ($rows.Count -gt 0) {
                    $allResults += $rows
                    Write-Host "    Page $pageNumber got $($rows.Count) rows" -ForegroundColor Gray
                }

                $morePages = $false
                $result | ForEach-Object {
                    if ($_.MorePagesAvailable -eq $true) { $morePages = $true; $pageCookie = $_.PageCookie }
                }
                if ($morePages) {
                    $pageNumber++
                }
                else {
                    $hasMore = $false
                }

                $success = $true
            }
            catch {
                Write-Warning "    Attempt $attempt failed for '$SITName' page $pageNumber : $_"
                if ($attempt -lt $MaxRetries) {
                    $backoff = [Math]::Pow(2, $attempt) * 5
                    Write-Host "    Retrying in $backoff seconds..." -ForegroundColor Yellow
                    Start-Sleep -Seconds $backoff
                }
                else {
                    Write-Error "    All $MaxRetries attempts failed for '$SITName' page $pageNumber. Skipping remaining pages."
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

    Write-Host "=== SIT Matches by Site Export ===" -ForegroundColor Cyan
    Write-Host "Tenant: $TenantName" -ForegroundColor Gray
    Write-Host "Environment: $CloudEnvironment" -ForegroundColor Gray
    Write-Host "Workload: $Workload" -ForegroundColor Gray
    Write-Host ""

    # Connect to IPPS with cert-based auth
    Write-Host "Session will auto-refresh every $SessionTimeoutMinutes minutes to prevent token expiry.`n" -ForegroundColor Yellow

    # Store for mid-pagination reconnection
    $script:currentAdminUPN = $AdminUPN
    $script:currentEnv = $CloudEnvironment
    $script:sessionTimeoutMin = $SessionTimeoutMinutes

    Connect-IPPSCompliance -AdminUPN $AdminUPN -CloudEnvironment $CloudEnvironment
    Assert-ComplianceExportCommand -CommandName 'Export-ContentExplorerData' -Context 'SIT export startup'
    Assert-ComplianceExportCommand -CommandName 'Get-DlpSensitiveInformationType' -Context 'SIT discovery startup'

    # --- Interactive SIT picker (if -TargetSITs not provided) ---
    if (-not $TargetSITs -or $TargetSITs.Count -eq 0) {
        Write-Host "`nDiscovering Sensitive Information Types from tenant..." -ForegroundColor Cyan
        $allSITDefs = Get-DlpSensitiveInformationType | Sort-Object Publisher, Name

        $customSITs = @($allSITDefs | Where-Object { $_.Publisher -ne 'Microsoft Corporation' })
        $builtInSITs = @($allSITDefs | Where-Object { $_.Publisher -eq 'Microsoft Corporation' })

        Write-Host "`nFound $($customSITs.Count) custom SIT(s) and $($builtInSITs.Count) built-in SIT(s)" -ForegroundColor Green

        # Build numbered display list: custom first, then built-in
        $displayList = @()
        $index = 1

        if ($customSITs.Count -gt 0) {
            Write-Host "`n--- Custom SITs ---" -ForegroundColor Yellow
            foreach ($s in $customSITs) {
                Write-Host "  [$index] $($s.Name)" -ForegroundColor White
                $displayList += @{ Index = $index; Name = $s.Name; Publisher = $s.Publisher }
                $index++
            }
        }

        Write-Host "`n--- Built-in SITs (showing common ones) ---" -ForegroundColor Yellow
        # Show a curated subset of commonly-used built-in SITs
        $commonBuiltIn = @(
            'U.S. Social Security Number (SSN)'
            'Credit Card Number'
            'U.S. Individual Taxpayer Identification Number (ITIN)'
            'U.S. Bank Account Number'
            'All Full Names'
            'U.S. Passport Number'
            'U.S. Driver''s License Number'
            'U.S./U.K. Passport Number'
            'International Banking Account Number (IBAN)'
            'U.S. Physical Address'
            'IP Address'
            'Azure Storage Account Key'
            'U.S. Individual Tax Identification Number (ITIN)'
        )
        $matchedBuiltIn = @($builtInSITs | Where-Object { $_.Name -in $commonBuiltIn })
        foreach ($s in $matchedBuiltIn) {
            Write-Host "  [$index] $($s.Name)" -ForegroundColor Gray
            $displayList += @{ Index = $index; Name = $s.Name; Publisher = $s.Publisher }
            $index++
        }

        Write-Host "`n  [A] Select ALL custom SITs ($($customSITs.Count))" -ForegroundColor Cyan
        Write-Host "  [B] Select ALL built-in common SITs ($($matchedBuiltIn.Count))" -ForegroundColor Cyan
        Write-Host "  [*] Select everything listed above ($($displayList.Count))" -ForegroundColor Cyan

        Write-Host ""
        $selection = Read-Host "Enter selections (comma-separated numbers, A, B, *, or mix like 'A,15,16')"

        $TargetSITs = @()
        $tokens = $selection -split ',' | ForEach-Object { $_.Trim().ToUpper() }

        foreach ($token in $tokens) {
            if ($token -eq 'A') {
                $TargetSITs += $customSITs | ForEach-Object { $_.Name }
            }
            elseif ($token -eq 'B') {
                $TargetSITs += $matchedBuiltIn | ForEach-Object { $_.Name }
            }
            elseif ($token -eq '*') {
                $TargetSITs += $displayList | ForEach-Object { $_.Name }
            }
            elseif ($token -match '^\d+$') {
                $num = [int]$token
                $match = $displayList | Where-Object { $_.Index -eq $num }
                if ($match) {
                    $TargetSITs += $match.Name
                }
                else {
                    Write-Warning "Invalid selection: $token (max is $($displayList.Count))"
                }
            }
            else {
                Write-Warning "Unrecognized input: $token"
            }
        }

        # Deduplicate
        $TargetSITs = @($TargetSITs | Select-Object -Unique)

        if ($TargetSITs.Count -eq 0) {
            Write-Error "No SITs selected. Exiting."
            exit 1
        }

        Write-Host "`nSelected $($TargetSITs.Count) SIT(s) to scan:" -ForegroundColor Green
        foreach ($s in $TargetSITs) {
            Write-Host "  - $s" -ForegroundColor White
        }
    }

    $scannedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $allSITMatches = @()
    $sitIndex = 0

    foreach ($sit in $TargetSITs) {
        $sitIndex++

        # Check if session needs refresh before starting next SIT
        if (Test-SessionNeedsRefresh -TimeoutMinutes $SessionTimeoutMinutes) {
            Write-Host "`n  Session approaching token expiry ($SessionTimeoutMinutes min). Reconnecting..." -ForegroundColor Yellow
            Connect-IPPSCompliance -AdminUPN $AdminUPN -CloudEnvironment $CloudEnvironment -Reconnect
        }

        Write-Host "`n[$sitIndex/$($TargetSITs.Count)] Exporting: $sit" -ForegroundColor Yellow

        $rows = Export-SITData -SITName $sit -Workload $Workload -PageSize $PageSize -MaxRetries $MaxRetries

        if ($rows -and $rows.Count -gt 0) {
            Write-Host "  Found $($rows.Count) site(s) with matches for '$sit'" -ForegroundColor Green

            foreach ($row in $rows) {
                $allSITMatches += [PSCustomObject]@{
                    SiteUrl    = $row.Name
                    SITName    = $sit
                    MatchCount = $row.Count
                    ScannedAt  = $scannedAt
                }
            }
        }
        else {
            Write-Host "  No matches found for '$sit'" -ForegroundColor Gray
        }
    }

    # Export results
    $outputPath = Resolve-DiscoveryOutputDir -OutputDir $OutputDir

    if ($allSITMatches.Count -gt 0) {
        $outputFile = Join-Path $outputPath "SITMatchesBySite.csv"
        $allSITMatches | Export-Csv -Path $outputFile -NoTypeInformation

        Write-Host "`n=== SIT Matches Summary ===" -ForegroundColor Cyan
        Write-Host "Total site-SIT combinations: $($allSITMatches.Count)" -ForegroundColor Yellow

        $siteSummary = $allSITMatches | Group-Object SITName | Sort-Object Count -Descending
        foreach ($group in $siteSummary) {
            $totalMatches = ($group.Group | Measure-Object -Property MatchCount -Sum).Sum
            Write-Host "  $($group.Name): $($group.Count) site(s), $totalMatches total matches" -ForegroundColor White
        }

        Write-Host "Output file: $outputFile" -ForegroundColor Green
    }
    else {
        Write-Host "`nNo SIT matches found across any target SITs." -ForegroundColor Yellow
    }

    $stopwatch.Stop()
    Write-Host "`nSIT export completed in $([Math]::Round($stopwatch.Elapsed.TotalMinutes, 1)) minutes." -ForegroundColor Green
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
