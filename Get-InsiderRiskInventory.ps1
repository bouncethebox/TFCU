#Requires -Version 7.2
<#
.SYNOPSIS
    Exports Purview Insider Risk Management policies and entity lists

.DESCRIPTION
    Retrieves Insider Risk Management policies and entity lists from Security &
    Compliance PowerShell and exports both CSV and JSON outputs for downstream
    analysis.

    This script follows the isolated IPPS pattern used elsewhere in the repo to
    avoid the known module/session conflict with PnP.PowerShell and Microsoft.Graph
    modules. Run it only in the dedicated IPPS runner or in a fresh PowerShell
    session.

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
    Required Module: ExchangeOnlineManagement
    Required Role: Compliance Administrator with Insider Risk access
    Cadence: Weekly
    Estimated Runtime: Under 5 minutes
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
    AADTenantName    = $AADTenantName
    CloudEnvironment = $CloudEnvironment
} -Required @('AADTenantName', 'CloudEnvironment') `
  -Defaults @{ CloudEnvironment = 'Commercial' } `
  -AllowedValues @{ CloudEnvironment = @('Commercial', 'GCCH') }

if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) {
    $UserPrincipalName = Read-Host 'Enter UPN for interactive IPPS sign-in'
    if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) {
        throw 'A UserPrincipalName is required for interactive Insider Risk export.'
    }
}

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

function Test-IppsInsiderRiskCmdletAvailability {
    $getPolicyCommand = Get-Command -Name 'Get-InsiderRiskPolicy' -ErrorAction SilentlyContinue
    $getEntityListCommand = Get-Command -Name 'Get-InsiderRiskEntityList' -ErrorAction SilentlyContinue

    return [PSCustomObject]@{
        HasGetInsiderRiskPolicy     = $null -ne $getPolicyCommand
        HasGetInsiderRiskEntityList = $null -ne $getEntityListCommand
    }
}

try {
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    Write-Host "=== Insider Risk Inventory ===" -ForegroundColor Cyan
    Write-Host "Tenant (AAD): $AADTenantName" -ForegroundColor Gray
    Write-Host "Environment: $CloudEnvironment" -ForegroundColor Gray
    Write-Host ""

    Connect-IPPSCompliance -CloudEnvironment $CloudEnvironment `
        -UserPrincipalName $UserPrincipalName

    $ippsCmdlets = Test-IppsInsiderRiskCmdletAvailability

    if (-not $ippsCmdlets.HasGetInsiderRiskPolicy) {
        throw 'Get-InsiderRiskPolicy is not available in this IPPS session. This tenant or role assignment does not expose Insider Risk policy cmdlets in the current connection.'
    }

    if (-not $ippsCmdlets.HasGetInsiderRiskEntityList) {
        throw 'Get-InsiderRiskEntityList is not available in this IPPS session. This tenant or role assignment does not expose Insider Risk entity list cmdlets in the current connection.'
    }

    Write-Host "Retrieving Insider Risk policies..." -ForegroundColor Cyan
    $policies = @(Get-InsiderRiskPolicy)

    Write-Host "Retrieving Insider Risk entity lists..." -ForegroundColor Cyan
    $entityLists = @(Get-InsiderRiskEntityList)

    if ($OutputDir) { $outputPath = $OutputDir } else { $outputPath = Resolve-RunFolder }
    if (-not (Test-Path $outputPath)) { New-Item -ItemType Directory -Path $outputPath -Force | Out-Null }

    if ($policies.Count -gt 0) {
        $policiesCsv = Join-Path $outputPath 'IRM-Policies.csv'
        $policiesJson = Join-Path $outputPath 'IRM-Policies.json'

        $policies | Export-Csv -Path $policiesCsv -NoTypeInformation
        $policies | ConvertTo-Json -Depth 10 | Out-File -FilePath $policiesJson -Encoding utf8

        Write-Host "Policies exported to: $policiesCsv" -ForegroundColor Green
        Write-Host "Policies JSON exported to: $policiesJson" -ForegroundColor Green
    }
    else {
        Write-Host "No Insider Risk policies found in tenant" -ForegroundColor Yellow
    }

    if ($entityLists.Count -gt 0) {
        $entityListsCsv = Join-Path $outputPath 'IRM-EntityLists.csv'
        $entityLists | Export-Csv -Path $entityListsCsv -NoTypeInformation
        Write-Host "Entity lists exported to: $entityListsCsv" -ForegroundColor Green
    }
    else {
        Write-Host "No Insider Risk entity lists found in tenant" -ForegroundColor Yellow
    }

    $stopwatch.Stop()
    Write-Host "`nInsider Risk inventory completed in $([Math]::Round($stopwatch.Elapsed.TotalSeconds, 2)) seconds." -ForegroundColor Green
}
catch {
    Write-Error "Script execution failed: $_"
    exit 1
}
finally {
    try {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    }
    catch {
    }
}