#Requires -Version 7.2
<#
.SYNOPSIS
    Enumerates container sensitivity labels applied to SharePoint Online sites
    
.DESCRIPTION
    This script retrieves SharePoint Online and OneDrive container sensitivity labels
    applied at the site level using PnP PowerShell with certificate-based service
    principal authentication. It does not enumerate document labels, email labels,
    or Purview label publishing configuration.
    
.PARAMETER TenantName
    The tenant name (e.g., 'contoso' for contoso.sharepoint.com). This parameter is required.

.PARAMETER ClientId
    The Client ID (Application ID) of the registered application. This parameter is required.
    
.PARAMETER TenantId
    The Microsoft Entra Tenant ID where the app is registered. This parameter is required.
    
.PARAMETER CertificateThumbprint
    The thumbprint of the certificate used for authentication. This parameter is required.

.PARAMETER CloudEnvironment
    The cloud environment to connect to. Valid values are 'Commercial' or 'GCCH'. Default is 'Commercial'.

.EXAMPLE
    .\Get-SensitivityLabels.ps1
    
.EXAMPLE
    .\Get-SensitivityLabels.ps1 -TenantName "contoso" -ClientId "12345678-1234-1234-1234-123456789012" -TenantId "87654321-4321-4321-4321-210987654321" -CertificateThumbprint "ABCDEF1234567890"
    
.NOTES
    PowerShell Version: 7.2 minimum
    Authentication Method: Service Principal (Certificate-based) (Script-AppReg)
    Required Modules: PnP.PowerShell 2.x or 3.x
    Required Permissions: Sites.Read.All (SharePoint)
    Certificate: Must be installed in CurrentUser\My certificate store
#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]$TenantName,
    
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
    TenantName = $TenantName
    ClientId = $ClientId
    TenantId = $TenantId
    CertificateThumbprint = $CertificateThumbprint
    CloudEnvironment = $CloudEnvironment
} -Required @('TenantName', 'ClientId', 'TenantId', 'CertificateThumbprint', 'CloudEnvironment') -Defaults @{ CloudEnvironment = 'Commercial' } -AllowedValues @{ CloudEnvironment = @('Commercial', 'GCCH') }

# Check for required modules
$requiredModules = @('PnP.PowerShell')
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
Import-Module PnP.PowerShell

# Function to get sensitivity labels for all sites
function Get-SiteSensitivityLabels {
    Write-Host "Retrieving all SharePoint sites..." -ForegroundColor Cyan

    try {
        # Get all sites excluding OneDrive personal sites
        $sites = Get-PnPTenantSite -Detailed | Where-Object { $_.Url -notlike '*-my.sharepoint.*' }
        Write-Host "Found $($sites.Count) sites to process" -ForegroundColor Green

        $labelReport = @()
        $siteCount = $sites.Count
        $i = 1

        foreach ($site in $sites) {
            Write-Host "Processing site $i of $siteCount - $($site.Url)" -ForegroundColor Yellow

            try {
                # Container labels require connecting to each site individually
                # Disconnect from current context first to avoid connection conflicts
                Disconnect-PnPOnline -ErrorAction SilentlyContinue

                # Connect to the specific site to retrieve container label
                if ($CloudEnvironment -eq 'GCCH') {
                    Connect-PnPOnline -Url $site.Url -ClientId $ClientId -Tenant $TenantId -Thumbprint $CertificateThumbprint -AzureEnvironment USGovernmentHigh -ErrorAction Stop
                } else {
                    Connect-PnPOnline -Url $site.Url -ClientId $ClientId -Tenant $TenantId -Thumbprint $CertificateThumbprint -ErrorAction Stop
                }

                # Retrieve the web object without optional includes that vary by PnP version
                $web = Get-PnPWeb -ErrorAction Stop
                $siteLabel = $web.SensitivityLabel
                $siteLabelId = $web.SensitivityLabelId

                $labelReport += [PSCustomObject]@{
                    Url = $site.Url
                    Title = $site.Title
                    SensitivityLabel = $siteLabel
                    SensitivityLabelId = $siteLabelId
                    Template = $site.Template
                    Owner = $site.Owner
                    StorageUsageMB = $site.StorageUsageCurrent
                    LastContentModifiedDate = $site.LastContentModifiedDate
                    Status = $site.Status
                    SharingCapability = $site.SharingCapability
                }
            }
            catch {
                Write-Warning "Error processing site $($site.Url): $_"

                # Add entry with error
                $labelReport += [PSCustomObject]@{
                    Url = $site.Url
                    Title = $site.Title
                    SensitivityLabel = $null
                    SensitivityLabelId = $null
                    Template = $site.Template
                    Owner = $site.Owner
                    StorageUsageMB = $site.StorageUsageCurrent
                    LastContentModifiedDate = $site.LastContentModifiedDate
                    Status = $site.Status
                    SharingCapability = $site.SharingCapability
                }
            }

            $i++
        }

        Write-Host "Container sensitivity label enumeration complete" -ForegroundColor Green
        return $labelReport
    }
    catch {
        Write-Error "Failed to retrieve site sensitivity labels: $_"
        return @()
    }
}

# Main execution
try {
    $stopwatch = [system.diagnostics.stopwatch]::StartNew()

    $adminUrl = if ($CloudEnvironment -eq 'GCCH') {
        "https://$TenantName-admin.sharepoint.us"
    } else {
        "https://$TenantName-admin.sharepoint.com"
    }

    Write-Host "Connecting to SharePoint Online admin center..." -ForegroundColor Cyan
    if ($CloudEnvironment -eq 'GCCH') {
        Connect-PnPOnline -Url $adminUrl -ClientId $ClientId -Tenant $TenantId -Thumbprint $CertificateThumbprint -AzureEnvironment USGovernmentHigh -ErrorAction Stop
    } else {
        Connect-PnPOnline -Url $adminUrl -ClientId $ClientId -Tenant $TenantId -Thumbprint $CertificateThumbprint -ErrorAction Stop
    }
    Write-Host "Successfully connected to SharePoint Online admin center" -ForegroundColor Green

    # Get sensitivity labels for all sites (each site gets its own connection)
    $sensitivityLabels = Get-SiteSensitivityLabels

    # Export results
    if ($sensitivityLabels -and $sensitivityLabels.Count -gt 0) {
        $outputPath = Resolve-DiscoveryOutputDir -OutputDir $OutputDir

        $outputFile = Join-Path $outputPath "SensitivityLabels.csv"
        $sensitivityLabels | Export-Csv -Path $outputFile -NoTypeInformation

        Write-Host "`n=== Container Sensitivity Labels Summary ===" -ForegroundColor Cyan
        Write-Host "Total sites processed: $($sensitivityLabels.Count)" -ForegroundColor Yellow

        $labeledSites = $sensitivityLabels | Where-Object { $_.SensitivityLabel -and $_.SensitivityLabel -ne "Error retrieving" }
        Write-Host "Sites with sensitivity labels: $($labeledSites.Count)" -ForegroundColor Yellow

        $unlabeledSites = $sensitivityLabels | Where-Object { -not $_.SensitivityLabel -or $_.SensitivityLabel -eq "" }
        Write-Host "Sites without sensitivity labels: $($unlabeledSites.Count)" -ForegroundColor Yellow

        if ($labeledSites.Count -gt 0) {
            $uniqueLabels = $labeledSites | Select-Object -ExpandProperty SensitivityLabel -Unique
            Write-Host "Unique sensitivity labels found: $($uniqueLabels.Count)" -ForegroundColor Yellow
        }

        Write-Host "Output file: $outputFile" -ForegroundColor Green
    }
    else {
        Write-Host "`nNo sites found or error occurred during enumeration." -ForegroundColor Yellow
    }

    $stopwatch.Stop()
    Write-Host "`nContainer sensitivity label enumeration completed in $([Math]::Round($stopwatch.Elapsed.TotalSeconds, 2)) seconds." -ForegroundColor Green
}
catch {
    Write-Error "Script execution failed: $_"
    exit 1
}
finally {
    # Always disconnect from PnP
    try {
        Disconnect-PnPOnline -ErrorAction SilentlyContinue
        Write-Host "Disconnected from SharePoint Online" -ForegroundColor Green
    }
    catch {
        # Ignore disconnect errors
    }
}

