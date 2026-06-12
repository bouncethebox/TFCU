<#
.SYNOPSIS
    Creates and configures Azure AD app registrations for M365 discovery scripts
    
.DESCRIPTION
    This script automates the creation of app registrations with required API permissions
    for all discovery scripts. Supports both commercial (standard) and GCCH cloud environments.
    Creates app registration, generates certificate, uploads it, and creates service principal.
    
.PARAMETER AppDisplayName
    The display name for the app registration. Default: "M365 Discovery Scripts"
    
.PARAMETER TenantId
    The Azure AD Tenant ID. This parameter is required.
    
.PARAMETER CloudEnvironment
    The cloud environment for the app registration. Options: 'Commercial' or 'GCCH'. Default: 'Commercial'
    
.PARAMETER CertificateValidityMonths
    Number of months the certificate should be valid. Default: 24
    
.NOTES
    PowerShell Version: 5.1 or later
    Required Modules: Microsoft.Graph.Applications 2.x
    Required Permissions: Application.ReadWrite.All, Directory.ReadWrite.All

    This script must be run by a user with Global Administrator or Application Administrator role
    in the target Azure AD tenant.
#>

[CmdletBinding()]
param (
    [string]$AppDisplayName = "M365 Discovery Scripts",
    
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$SPTenantName,

    [Parameter(Mandatory = $true)]
    [string]$AADTenantName,

    [ValidateSet('Commercial', 'GCCH')]
    [string]$CloudEnvironment = 'Commercial',
    
    [int]$CertificateValidityMonths = 24,

    [SecureString]$PfxPassword
)

function Get-PlainTextFromSecureString {
    param([SecureString]$SecureString)
    if (-not $SecureString) { return $null }
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    }
    finally {
        if ($ptr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
        }
    }
}

function New-RandomPassword {
    param([int]$Length = 32)
    $charPool = (33..126) | Where-Object { $_ -ne 34 -and $_ -ne 39 }  # avoid quotes
    return -join ((1..$Length) | ForEach-Object { [char](Get-Random -InputObject $charPool) })
}

# Define required API permissions for discovery scripts
$exchangePermission = if ($CloudEnvironment -eq 'GCCH') {
    @{
        ResourceAppId = "00000007-0000-0ff1-ce00-000000000000"  # Microsoft 365 Security & Compliance (GCCH)
        ResourceAccess = @(
            @{ Id = "455e5cd2-84e8-4751-8344-5672145dfa17"; Type = "Role" }  # Exchange.ManageAsApp
        )
    }
} else {
    @{
        ResourceAppId = "00000002-0000-0ff1-ce00-000000000000"  # Office 365 Exchange Online
        ResourceAccess = @(
            @{ Id = "dc50a0fb-09a3-484d-be87-e023b12c6440"; Type = "Role" }  # Exchange.ManageAsApp
        )
    }
}

# Core Graph permissions (available in both Commercial and GCCH)
$graphCoreAccess = @(
    @{ Id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"; Type = "Role" }  # Directory.Read.All
    @{ Id = "df021288-bdef-4463-88db-98f22de89214"; Type = "Role" }  # User.Read.All (required by Resolve-DisplayNameToUPN -UseGraph)
    @{ Id = "5b567255-7703-4780-807c-7be8301ae99b"; Type = "Role" }  # Group.Read.All
    @{ Id = "98830695-27a2-44f7-8c18-0c3ebc9698f6"; Type = "Role" }  # GroupMember.Read.All
    @{ Id = "01d4889c-1287-42c6-ac1f-5d1e02578ef6"; Type = "Role" }  # Files.Read.All
    @{ Id = "19da66cb-0fb0-4390-b071-ebc76a349482"; Type = "Role" }  # InformationProtectionPolicy.Read.All
    @{ Id = "b0afded3-3588-46d8-8b3d-9842eff778da"; Type = "Role" }  # AuditLog.Read.All
    @{ Id = "a82116e5-55eb-4c41-a434-62fe8a61c773"; Type = "Role" }  # Sites.FullControl.All (Graph API)
    @{ Id = "3011c876-62b7-4ada-afa2-506cbbecc68c"; Type = "Role" }  # User.EnableDisableAccount.All
    @{ Id = "246dd0d5-5bd0-4def-940b-0421030a5b68"; Type = "Role" }  # Policy.Read.All
    @{ Id = "2f51be20-0bb4-4fed-bf7b-db946066c75e"; Type = "Role" }  # DeviceManagementManagedDevices.Read.All
    @{ Id = "dc377aa6-52d8-4e23-b271-2a7ae04cedf3"; Type = "Role" }  # DeviceManagementConfiguration.Read.All
)

# Teams/Channel permissions - GUIDs differ between Commercial and GCCH
if ($CloudEnvironment -eq 'GCCH') {
    $graphCoreAccess += @(
        @{ Id = "2280dda6-0bfd-44ee-a2f4-cb867cfc4c1e"; Type = "Role" }  # Team.ReadBasic.All (same GUID)
        @{ Id = "660b7406-55f1-41ca-a0ed-0b035e182f3e"; Type = "Role" }  # TeamMember.Read.All (GCCH)
        @{ Id = "59a6b24b-4225-4393-8165-ebaec5f55d7a"; Type = "Role" }  # Channel.ReadBasic.All (same GUID)
        @{ Id = "c97b873f-f59f-49aa-8a0e-52b32d762124"; Type = "Role" }  # ChannelSettings.Read.All (GCCH)
        @{ Id = "3b55498e-47ec-484f-8136-9013221c06a9"; Type = "Role" }  # ChannelMember.Read.All (GCCH)
    )
} else {
    $graphCoreAccess += @(
        @{ Id = "2280dda6-0bfd-44ee-a2f4-cb867cfc4c1e"; Type = "Role" }  # Team.ReadBasic.All
        @{ Id = "2497278c-d82d-46a2-b1ce-39d4cdde5570"; Type = "Role" }  # TeamMember.Read.All
        @{ Id = "59a6b24b-4225-4393-8165-ebaec5f55d7a"; Type = "Role" }  # Channel.ReadBasic.All
        @{ Id = "660b7406-55f1-41ca-a0ed-0b035e182f3e"; Type = "Role" }  # ChannelSettings.Read.All
        @{ Id = "4437522e-9a86-4a41-a7da-e380edd4a97d"; Type = "Role" }  # ChannelMember.Read.All
    )
}

$requiredPermissions = @(
    @{
        ResourceAppId = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph
        ResourceAccess = $graphCoreAccess
    }
    @{
        ResourceAppId = "00000003-0000-0ff1-ce00-000000000000"  # SharePoint
        ResourceAccess = @(
            @{ Id = "678536fe-1083-478a-9c59-b99265e6b0d3"; Type = "Role" }  # Sites.FullControl.All
        )
    }
    $exchangePermission
)

$rootPath = Split-Path -Parent $PSScriptRoot
$sslFolder = Join-Path $rootPath 'SSL'
if (-not (Test-Path $sslFolder)) {
    New-Item -ItemType Directory -Path $sslFolder | Out-Null
}

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$safeName = ($AppDisplayName -replace '[^A-Za-z0-9-]', '_')
$certificateBaseName = "${safeName}_${timestamp}"
$cerFilePath = Join-Path $sslFolder "$certificateBaseName.cer"
$pfxFilePath = Join-Path $sslFolder "$certificateBaseName.pfx"
$infoFilePath = Join-Path $sslFolder "$certificateBaseName.json"

$plainTextPfxPassword = $null
if ($PfxPassword) {
    $plainTextPfxPassword = Get-PlainTextFromSecureString -SecureString $PfxPassword
} else {
    $plainTextPfxPassword = New-RandomPassword -Length 40
    $PfxPassword = ConvertTo-SecureString -String $plainTextPfxPassword -AsPlainText -Force
}

# Main execution
try {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "M365 Discovery App Registration" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Environment: $CloudEnvironment" -ForegroundColor Yellow
    Write-Host ""
    
    # Check if Microsoft.Graph.Applications module is available
    Write-Host "[1/5] Checking prerequisites..." -ForegroundColor Yellow
    try {
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop | Out-Null
        # Disable WAM broker if the parameter exists (2.35+) to avoid GCCH redirect URI mismatch
        if ((Get-Command Set-MgGraphOption -ErrorAction SilentlyContinue) -and
            (Get-Command Set-MgGraphOption).Parameters.ContainsKey('DisableLoginByWAM')) {
            Set-MgGraphOption -DisableLoginByWAM $true
        }
        Import-Module Microsoft.Graph.Applications -ErrorAction Stop | Out-Null
        Write-Host "[OK] Microsoft.Graph modules loaded" -ForegroundColor Green
    }
    catch {
        throw "Microsoft.Graph modules not found. Install with: Install-Module Microsoft.Graph -Scope CurrentUser -Force"
    }
    
    # Connect to Microsoft Graph
    Write-Host "`n[2/5] Connecting to Microsoft Graph..." -ForegroundColor Yellow
    try {
        $context = Get-MgContext -ErrorAction SilentlyContinue
        
        if ($null -eq $context -or $context.TenantId -ne $TenantId) {
            $connectParams = @{
                TenantId = $TenantId
                Scopes = @("Application.ReadWrite.All", "Directory.ReadWrite.All")
            }
            
            if ($CloudEnvironment -eq 'GCCH') {
                $connectParams.Environment = 'USGov'
            }
            
            Connect-MgGraph @connectParams -NoWelcome | Out-Null
            $context = Get-MgContext
        }
        
        Write-Host "[OK] Connected to Microsoft Graph" -ForegroundColor Green
        Write-Host "  Tenant: $($context.TenantId)" -ForegroundColor Gray
        Write-Host "  Account: $($context.Account)" -ForegroundColor Gray
    }
    catch {
        throw "Failed to connect to Microsoft Graph: $_"
    }
    
    # Generate self-signed certificate
    Write-Host "`n[3/5] Generating self-signed certificate..." -ForegroundColor Yellow
    try {
        $cert = New-SelfSignedCertificate -CertStoreLocation "Cert:\CurrentUser\My" -Subject "CN=$AppDisplayName" -KeyAlgorithm RSA -KeyLength 2048 -NotAfter (Get-Date).AddMonths($CertificateValidityMonths) -KeySpec KeyExchange -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" -KeyExportPolicy Exportable
        
        $certificateThumbprint = $cert.Thumbprint
        $certificateExpiry = $cert.NotAfter
        
        Write-Host "[OK] Certificate created" -ForegroundColor Green
        Write-Host "  Thumbprint: $certificateThumbprint" -ForegroundColor Gray
        Write-Host "  Expiry: $($certificateExpiry.ToString('yyyy-MM-dd'))" -ForegroundColor Gray

        Write-Host "  Exporting certificate artifacts..." -ForegroundColor Gray
        Export-Certificate -Cert $cert -FilePath $cerFilePath -Force | Out-Null
        Export-PfxCertificate -Cert $cert -FilePath $pfxFilePath -Password $PfxPassword -Force | Out-Null
        Write-Host "  [OK] Saved CER: $cerFilePath" -ForegroundColor Green
        Write-Host "  [OK] Saved PFX: $pfxFilePath" -ForegroundColor Green
    }
    catch {
        throw "Failed to create certificate: $_"
    }
    
    # Create app registration
    Write-Host "`n[4/5] Creating app registration..." -ForegroundColor Yellow
    try {
        Write-Host "  [4a] Calling New-MgApplication..." -ForegroundColor Gray
        $appParams = @{
            DisplayName = $AppDisplayName
            SignInAudience = "AzureADMyOrg"
            RequiredResourceAccess = $requiredPermissions
        }
        $app = New-MgApplication @appParams -ErrorAction Stop
        $appId = $app.AppId
        Write-Host "  [4a] OK - App created. ID: $appId  ObjectId: $($app.Id)" -ForegroundColor Green

        # Add certificate credential to app
        Write-Host "  [4b] Adding certificate credential..." -ForegroundColor Gray
        $certStore = Get-Item "Cert:\CurrentUser\My\$certificateThumbprint"
        $keyCredential = @{
            Type = "AsymmetricX509Cert"
            Usage = "Verify"
            Key = $certStore.RawData
            DisplayName = "$AppDisplayName Certificate"
            StartDateTime = Get-Date
            EndDateTime = $certificateExpiry
        }
        Update-MgApplication -ApplicationId $app.Id -KeyCredentials @($keyCredential) -ErrorAction Stop | Out-Null
        Write-Host "  [4b] OK - Certificate credential added" -ForegroundColor Green

        # Create service principal
        Write-Host "  [4c] Creating service principal..." -ForegroundColor Gray
        $servicePrincipal = New-MgServicePrincipal -AppId $appId -ErrorAction Stop
        Write-Host "  [4c] OK - Service principal created" -ForegroundColor Green
    }
    catch {
        throw "Failed to create app registration: $_"
    }
    
    # Display summary
    Write-Host "`n[5/5] Setup complete!" -ForegroundColor Yellow
    
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "App Registration Created Successfully" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Application Name: " -NoNewline
    Write-Host $AppDisplayName -ForegroundColor Cyan
    Write-Host "Application ID (Client ID): " -NoNewline
    Write-Host $appId -ForegroundColor Cyan
    Write-Host "Tenant ID: " -NoNewline
    Write-Host $TenantId -ForegroundColor Cyan
    Write-Host "SP Tenant Name: " -NoNewline
    Write-Host $SPTenantName -ForegroundColor Cyan
    Write-Host "AAD Tenant Name: " -NoNewline
    Write-Host $AADTenantName -ForegroundColor Cyan
    Write-Host "Certificate Thumbprint: " -NoNewline
    Write-Host $certificateThumbprint -ForegroundColor Cyan
    Write-Host "Certificate Expiry: " -NoNewline
    Write-Host $certificateExpiry.ToString('yyyy-MM-dd') -ForegroundColor Cyan
    Write-Host "Cloud Environment: " -NoNewline
    Write-Host $CloudEnvironment -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "Next Steps:" -ForegroundColor Yellow
    Write-Host "1. Wait 30-60 seconds for Azure AD to process the app registration" -ForegroundColor White
    Write-Host "2. Grant admin consent for API permissions:" -ForegroundColor White
    Write-Host "   - Go to Azure Portal > App Registrations > $AppDisplayName" -ForegroundColor Gray
    Write-Host "   - Navigate to 'API Permissions'" -ForegroundColor Gray
    Write-Host "   - Click 'Grant admin consent for [Your Tenant]'" -ForegroundColor Gray
    Write-Host ""
    Write-Host "3. Use these credentials with discovery scripts:" -ForegroundColor White
    
    $exampleCommand = ".\Get-SubsitesEnumeration.ps1 -ClientId '$appId' -TenantId '$TenantId' -CertificateThumbprint '$certificateThumbprint' -TenantName '$SPTenantName' -CloudEnvironment '$CloudEnvironment'"
    
    Write-Host ""
    Write-Host $exampleCommand -ForegroundColor Gray
    Write-Host ""
    Write-Host "Certificate Location:" -ForegroundColor Yellow
    Write-Host "  Store: Cert:\CurrentUser\My\$certificateThumbprint" -ForegroundColor Gray
    Write-Host ""
    $appInfo = [PSCustomObject]@{
        DisplayName = $AppDisplayName
        ApplicationId = $appId
        TenantId = $TenantId
        SPTenantName = $SPTenantName
        AADTenantName = $AADTenantName
        CertificateThumbprint = $certificateThumbprint
        CertificateExpiry = $certificateExpiry
        CloudEnvironment = $CloudEnvironment
        CerPath = $cerFilePath
        PfxPath = $pfxFilePath
        PfxPassword = $plainTextPfxPassword
        InfoGeneratedAt = Get-Date
    }

    $appInfo | ConvertTo-Json -Depth 4 | Set-Content -Path $infoFilePath -Encoding UTF8
    Write-Host "App registration details saved to: $infoFilePath" -ForegroundColor Yellow
    Write-Host "Certificates stored in: $sslFolder" -ForegroundColor Yellow
    if (-not $PSBoundParameters.ContainsKey('PfxPassword')) {
        Write-Host "A random PFX password was generated; retrieve it from the JSON file above." -ForegroundColor Yellow
    }

    Write-Host "========================================" -ForegroundColor Green
    
    # Disconnect from Graph
    Disconnect-MgGraph | Out-Null
    
    # Return summary object
    return [PSCustomObject]@{
        DisplayName = $AppDisplayName
        ApplicationId = $appId
        TenantId = $TenantId
        SPTenantName = $SPTenantName
        AADTenantName = $AADTenantName
        CertificateThumbprint = $certificateThumbprint
        CertificateExpiry = $certificateExpiry
        CloudEnvironment = $CloudEnvironment
        CerPath = $cerFilePath
        PfxPath = $pfxFilePath
        InfoFilePath = $infoFilePath
        PfxPassword = $plainTextPfxPassword
        CreatedAt = Get-Date
    }
}
catch {
    Write-Host ""
    Write-Error "Failed to create app registration: $_"
    exit 1
}
