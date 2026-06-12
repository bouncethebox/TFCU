#Requires -Version 7.2
<#
.SYNOPSIS
    Discovers labeled content shared externally across SharePoint and OneDrive sites
    
.DESCRIPTION
    This script enumerates all SharePoint and OneDrive sites to identify files with
    sensitivity labels that are shared externally. Uses Microsoft Graph API with
    certificate-based service principal authentication to discover labeled content
    and external sharing configurations.
    
.PARAMETER ClientId
    The Client ID (Application ID) of the registered application. This parameter is required.
    
.PARAMETER TenantId
    The Microsoft Entra Tenant ID where the app is registered. This parameter is required.
    
.PARAMETER CertificateThumbprint
    The thumbprint of the certificate used for authentication. This parameter is required.

.PARAMETER CloudEnvironment
    The cloud environment to connect to. Valid values are 'Commercial' or 'GCCH'. Default is 'Commercial'.

.EXAMPLE
    .\Get-LabeledContentSharing.ps1
    
.EXAMPLE
    .\Get-LabeledContentSharing.ps1 -ClientId "12345678-1234-1234-1234-123456789012" -TenantId "87654321-4321-4321-4321-210987654321" -CertificateThumbprint "ABCDEF1234567890"
    
.NOTES
    PowerShell Version: 7.2 minimum
    Authentication Method: Service Principal (Certificate-based) (Script-AppReg)
    Required Modules: Microsoft.Graph.Sites 2.x, Microsoft.Graph.Files 2.x, Microsoft.Graph.Authentication 2.x
    Required Permissions: Sites.Read.All, Files.Read.All, InformationProtectionPolicy.Read.All
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
$requiredModules = @('Microsoft.Graph.Sites', 'Microsoft.Graph.Files', 'Microsoft.Graph.Authentication')
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
Import-Module Microsoft.Graph.Sites
Import-Module Microsoft.Graph.Files

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

# Function to get labeled content shared externally
function Get-LabeledSharedContent {
    Write-Host "Enumerating sites and labeled content..." -ForegroundColor Cyan
    
    try {
        # Get all sites (SharePoint/OneDrive)
        $sites = Get-MgSite -All -Property Id,Name,WebUrl,DisplayName
        Write-Host "Found $($sites.Count) sites to process" -ForegroundColor Green
        
        $results = @()
        $siteCount = $sites.Count
        $i = 1

        foreach ($site in $sites) {
            Write-Host "Processing site $i of $siteCount - $($site.DisplayName)" -ForegroundColor Yellow

            try {
                # Get all drives (document libraries) for the site
                $drives = Get-MgSiteDrive -SiteId $site.Id -All -ErrorAction SilentlyContinue

                foreach ($drive in $drives) {
                    try {
                        # Get root items from the drive
                        $items = Get-MgDriveRootChild -DriveId $drive.Id -All -ErrorAction SilentlyContinue

                        foreach ($item in $items) {
                            # Check if item has a sensitivity label and is shared
                            if ($item.AdditionalProperties.ContainsKey('shared') -and $item.AdditionalProperties.ContainsKey('sensitivityLabel')) {
                                $results += [PSCustomObject]@{
                                    SiteName = $site.DisplayName
                                    SiteUrl = $site.WebUrl
                                    DriveName = $drive.Name
                                    FileName = $item.Name
                                    FileType = $item.AdditionalProperties['file'].'mimeType'
                                    SensitivityLabelId = $item.AdditionalProperties['sensitivityLabel'].'labelId'
                                    SharedScope = if ($item.AdditionalProperties['shared']) { $item.AdditionalProperties['shared'].'scope' } else { 'Unknown' }
                                    WebUrl = $item.WebUrl
                                    LastModified = $item.LastModifiedDateTime
                                    Size = $item.Size
                                }
                            }
                        }
                    }
                    catch {
                        Write-Warning "Error processing drive $($drive.Name) in site $($site.DisplayName): $_"
                    }
                }
            }
            catch {
                Write-Warning "Error processing site $($site.DisplayName): $_"
            }

            $i++
        }

        Write-Host "Found $($results.Count) labeled items that are shared" -ForegroundColor Green
        return $results
    }
    catch {
        Write-Error "Failed to enumerate labeled content: $_"
        return @()
    }
}

# Main execution
try {
    $stopwatch = [system.diagnostics.stopwatch]::StartNew()

    # Connect to Microsoft Graph
    Connect-GraphWithCertificate -ClientId $ClientId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint -CloudEnvironment $CloudEnvironment

    # Get labeled shared content
    $labeledContent = Get-LabeledSharedContent

    # Export results
    if ($labeledContent -and $labeledContent.Count -gt 0) {
        if ($OutputDir) { $outputPath = $OutputDir } else { $outputPath = Resolve-RunFolder }
        if (-not (Test-Path $outputPath)) { New-Item -ItemType Directory -Path $outputPath -Force | Out-Null }

        $outputFile = Join-Path $outputPath "LabeledContentSharing.csv"
        $labeledContent | Export-Csv -Path $outputFile -NoTypeInformation

        Write-Host "`n=== Labeled Content Sharing Summary ===" -ForegroundColor Cyan
        Write-Host "Total labeled items shared: $($labeledContent.Count)" -ForegroundColor Yellow
        Write-Host "Unique sites: $(($labeledContent | Select-Object -Unique SiteName).Count)" -ForegroundColor Yellow
        Write-Host "Output file: $outputFile" -ForegroundColor Green
    }
    else {
        Write-Host "`nNo labeled content with external sharing found." -ForegroundColor Yellow
    }

    $stopwatch.Stop()
    Write-Host "`nLabeled content sharing enumeration completed in $([Math]::Round($stopwatch.Elapsed.TotalSeconds, 2)) seconds." -ForegroundColor Green
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

