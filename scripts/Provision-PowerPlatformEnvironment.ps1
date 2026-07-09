param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$ClientId,

    [Parameter(Mandatory = $true)]
    [string]$ClientSecret,

    [Parameter(Mandatory = $true)]
    [string]$EnvironmentDisplayName,

    [Parameter(Mandatory = $true)]
    [string]$LocationName,

    [Parameter(Mandatory = $true)]
    [string]$EnvironmentSku,

    [Parameter(Mandatory = $true)]
    [string]$CurrencyName,

    [Parameter(Mandatory = $true)]
    [string]$LanguageName,

    [Parameter(Mandatory = $true)]
    [string]$EnvironmentGroupName,

    [Parameter(Mandatory = $true)]
    [string]$SecurityGroupId
)

$ErrorActionPreference = "Stop"

Write-Host "Starting Power Platform environment automation..."

# ------------------------------------------------------------
# Install and import required Power Platform module
# ------------------------------------------------------------

Write-Host "Installing required PowerShell modules..."

Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted

Get-Module Microsoft.PowerApps* | Remove-Module -Force -ErrorAction SilentlyContinue

Install-Module Microsoft.PowerApps.Administration.PowerShell `
    -Scope CurrentUser `
    -Force `
    -AllowClobber `
    -SkipPublisherCheck

Import-Module Microsoft.PowerApps.Administration.PowerShell -Force

# ------------------------------------------------------------
# Helper: Get access token
# ------------------------------------------------------------

function Get-AccessToken {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Resource
    )

    $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

    $body = @{
        client_id     = $ClientId
        scope         = "$Resource/.default"
        client_secret = $ClientSecret
        grant_type    = "client_credentials"
    }

    $response = Invoke-RestMethod `
        -Method Post `
        -Uri $tokenUri `
        -Body $body `
        -ContentType "application/x-www-form-urlencoded"

    return $response.access_token
}

# ------------------------------------------------------------
# Helper: Enable Managed Environment
# ------------------------------------------------------------

function Enable-ManagedEnvironment {
    param(
        [Parameter(Mandatory = $true)]
        [string]$EnvironmentId
    )

    Write-Host "Enabling Managed Environment for: $EnvironmentId"

    $governanceConfiguration = [pscustomobject]@{
        protectionLevel = "Standard"
        settings = [pscustomobject]@{
            extendedSettings = @{}
        }
    }

    Set-AdminPowerAppEnvironmentGovernanceConfiguration `
        -EnvironmentName $EnvironmentId `
        -UpdatedGovernanceConfiguration $governanceConfiguration | Out-Null

    Write-Host "Managed Environment enabled."
}

# ------------------------------------------------------------
# Helper: Connector object for DLP policy
# ------------------------------------------------------------

function Get-ConnectorObject {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConnectorName
    )

    return [pscustomobject]@{
        id   = "/providers/Microsoft.PowerApps/apis/$ConnectorName"
        name = $ConnectorName
        type = "Microsoft.PowerApps/apis"
    }
}

# ------------------------------------------------------------
# Helper: Create or update environment-specific DLP policy
# ------------------------------------------------------------

function New-EnvironmentDlpPolicy {
    param(
        [Parameter(Mandatory = $true)]
        [string]$EnvironmentId,

        [Parameter(Mandatory = $true)]
        [string]$PolicyDisplayName
    )

    Write-Host "Creating or updating DLP policy: $PolicyDisplayName"

    # Business connectors = Confidential in DLP API
    $businessConnectors = @(
        "shared_sharepointonline",
        "shared_office365",
        "shared_office365users",
        "shared_commondataserviceforapps",
        "shared_teams"
    )

    # Non-Business connectors = General in DLP API
    $nonBusinessConnectors = @(
        "shared_msnweather",
        "shared_bingmaps"
    )

    # Blocked connectors
    $blockedConnectors = @(
        "shared_twitter",
        "shared_facebook",
        "shared_gmail",
        "shared_dropbox",
        "shared_box",
        "shared_http",
        "shared_httprequest"
    )

    $businessGroup = [pscustomobject]@{
        classification = "Confidential"
        connectors     = @(
            $businessConnectors | ForEach-Object {
                Get-ConnectorObject -ConnectorName $_
            }
        )
    }

    $nonBusinessGroup = [pscustomobject]@{
        classification = "General"
        connectors     = @(
            $nonBusinessConnectors | ForEach-Object {
                Get-ConnectorObject -ConnectorName $_
            }
        )
    }

    $blockedGroup = [pscustomobject]@{
        classification = "Blocked"
        connectors     = @(
            $blockedConnectors | ForEach-Object {
                Get-ConnectorObject -ConnectorName $_
            }
        )
    }

    $environmentReference = [pscustomobject]@{
        id   = "/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/$EnvironmentId"
        name = $EnvironmentId
        type = "Microsoft.BusinessAppPlatform/scopes/environments"
    }

    $newPolicy = [pscustomobject]@{
        displayName                     = $PolicyDisplayName
        defaultConnectorsClassification = "Blocked"
        connectorGroups                 = @(
            $nonBusinessGroup,
            $businessGroup,
            $blockedGroup
        )
        environmentType                 = "OnlyEnvironments"
        environments                    = @($environmentReference)
        etag                            = $null
    }

    $existingPolicies = Get-DlpPolicy

    $existingPolicy = $null

    if ($null -ne $existingPolicies.value) {
        $existingPolicy = $existingPolicies.value | Where-Object {
            $_.displayName -eq $PolicyDisplayName
        } | Select-Object -First 1
    }
    else {
        $existingPolicy = $existingPolicies | Where-Object {
            $_.displayName -eq $PolicyDisplayName
        } | Select-Object -First 1
    }

    if ($null -ne $existingPolicy) {
        Write-Host "DLP policy already exists. Updating existing policy."

        $newPolicy | Add-Member `
            -MemberType NoteProperty `
            -Name name `
            -Value $existingPolicy.name `
            -Force

        Set-DlpPolicy `
            -PolicyName $existingPolicy.name `
            -UpdatedPolicy $newPolicy | Out-Null
    }
    else {
        Write-Host "DLP policy does not exist. Creating new policy."

        New-DlpPolicy `
            -NewPolicy $newPolicy | Out-Null
    }

    Write-Host "DLP policy created or updated successfully."
}

# ------------------------------------------------------------
# Helper: Create or get Environment Group
# ------------------------------------------------------------

function New-OrGet-EnvironmentGroup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupDisplayName
    )

    Write-Host "Creating or retrieving Environment Group: $GroupDisplayName"

    $token = Get-AccessToken -Resource "https://api.powerplatform.com"

    $headers = @{
        Authorization  = "Bearer $token"
        "Content-Type" = "application/json"
    }

    $groupsUri = "https://api.powerplatform.com/environmentmanagement/environmentGroups?api-version=2024-10-01"

    $groups = Invoke-RestMethod `
        -Method Get `
        -Uri $groupsUri `
        -Headers $headers

    $existing = $null

    if ($null -ne $groups.value) {
        $existing = $groups.value | Where-Object {
            $_.displayName -eq $GroupDisplayName
        } | Select-Object -First 1
    }

    if ($null -ne $existing) {
        Write-Host "Environment Group already exists with ID: $($existing.id)"
        return $existing.id
    }

    $body = @{
        displayName = $GroupDisplayName
        description = "Created by GitHub Actions Power Platform automation"
    } | ConvertTo-Json -Depth 10

    $created = Invoke-RestMethod `
        -Method Post `
        -Uri $groupsUri `
        -Headers $headers `
        -Body $body

    Write-Host "Created Environment Group with ID: $($created.id)"

    return $created.id
}

# ------------------------------------------------------------
# Helper: Add environment to Environment Group
# ------------------------------------------------------------

function Add-EnvironmentToEnvironmentGroup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId,

        [Parameter(Mandatory = $true)]
        [string]$EnvironmentId
    )

    Write-Host "Adding environment $EnvironmentId to Environment Group $GroupId"

    $token = Get-AccessToken -Resource "https://api.powerplatform.com"

    $headers = @{
        Authorization  = "Bearer $token"
        "Content-Type" = "application/json"
    }

    $uri = "https://api.powerplatform.com/environmentmanagement/environmentGroups/$GroupId/addEnvironment/$EnvironmentId`?api-version=2024-10-01"

    try {
        Invoke-RestMethod `
            -Method Post `
            -Uri $uri `
            -Headers $headers | Out-Null

        Write-Host "Environment added to Environment Group."
    }
    catch {
        $statusCode = $null

        if ($_.Exception.Response -ne $null) {
            $statusCode = $_.Exception.Response.StatusCode.value__
        }

        if ($statusCode -eq 204 -or $statusCode -eq 409) {
            Write-Host "Environment is already added to the Environment Group."
        }
        else {
            throw
        }
    }
}

# ------------------------------------------------------------
# Validate existing security group ID
# ------------------------------------------------------------

Write-Host "Using existing security group ID: $SecurityGroupId"

if ([System.String]::IsNullOrWhiteSpace($SecurityGroupId)) {
    throw "SecurityGroupId is empty. Please provide an existing Entra security group Object ID."
}

# ------------------------------------------------------------
# Authenticate to Power Platform
# ------------------------------------------------------------

Write-Host "Authenticating to Power Platform using service principal..."

Add-PowerAppsAccount `
    -Endpoint prod `
    -TenantID $TenantId `
    -ApplicationId $ClientId `
    -ClientSecret $ClientSecret | Out-Null

Write-Host "Authenticated."

# ------------------------------------------------------------
# Create or retrieve Power Platform environment
# ------------------------------------------------------------

Write-Host "Checking if environment already exists: $EnvironmentDisplayName"

$existingEnvironments = Get-AdminPowerAppEnvironment

$existingEnvironment = $existingEnvironments | Where-Object {
    $_.DisplayName -eq $EnvironmentDisplayName
} | Select-Object -First 1

if ($null -ne $existingEnvironment) {
    Write-Host "Environment already exists."
    $environmentId = $existingEnvironment.EnvironmentName
}
else {
    Write-Host "Creating Power Platform environment: $EnvironmentDisplayName"

    $environment = New-AdminPowerAppEnvironment `
        -DisplayName $EnvironmentDisplayName `
        -LocationName $LocationName `
        -EnvironmentSku $EnvironmentSku `
        -ProvisionDatabase `
        -CurrencyName $CurrencyName `
        -LanguageName $LanguageName `
        -SecurityGroupId $SecurityGroupId `
        -WaitUntilFinished $true `
        -TimeoutInMinutes 120

    $environmentId = $environment.EnvironmentName
}

if ([System.String]::IsNullOrWhiteSpace($environmentId)) {
    throw "Environment creation failed. EnvironmentName is empty."
}

Write-Host "Environment ID: $environmentId"

# ------------------------------------------------------------
# Enable managed environment
# ------------------------------------------------------------

Enable-ManagedEnvironment `
    -EnvironmentId $environmentId

# ------------------------------------------------------------
# Create environment-specific DLP policy
# ------------------------------------------------------------

$dlpSafeEnvironmentName = $EnvironmentDisplayName -replace '[^a-zA-Z0-9\-]', '-'
$dlpPolicyName = "DLP-$dlpSafeEnvironmentName"

New-EnvironmentDlpPolicy `
    -EnvironmentId $environmentId `
    -PolicyDisplayName $dlpPolicyName

# ------------------------------------------------------------
# Create or retrieve Environment Group
# ------------------------------------------------------------

$environmentGroupId = New-OrGet-EnvironmentGroup `
    -GroupDisplayName $EnvironmentGroupName

if ([System.String]::IsNullOrWhiteSpace($environmentGroupId)) {
    throw "Environment Group ID is empty. Cannot continue."
}

# ------------------------------------------------------------
# Add environment to Environment Group
# ------------------------------------------------------------

Add-EnvironmentToEnvironmentGroup `
    -GroupId $environmentGroupId `
    -EnvironmentId $environmentId

# ------------------------------------------------------------
# Done
# ------------------------------------------------------------

Write-Host "Power Platform automation completed successfully."
Write-Host "Environment Display Name: $EnvironmentDisplayName"
Write-Host "Environment ID: $environmentId"
Write-Host "Security Group ID: $SecurityGroupId"
Write-Host "DLP Policy Name: $dlpPolicyName"
Write-Host "Environment Group Name: $EnvironmentGroupName"
Write-Host "Environment Group ID: $environmentGroupId"
