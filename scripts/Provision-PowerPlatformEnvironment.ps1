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
    [string]$EnvironmentGroupName
)

$ErrorActionPreference = "Stop"

Write-Host "Installing required PowerShell modules..."

Install-Module Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser -Force -AllowClobber
Install-Module Microsoft.PowerApps.PowerShell -Scope CurrentUser -Force -AllowClobber

Import-Module Microsoft.PowerApps.Administration.PowerShell
Import-Module Microsoft.PowerApps.PowerShell

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

    $response = Invoke-RestMethod -Method Post -Uri $tokenUri -Body $body -ContentType "application/x-www-form-urlencoded"
    return $response.access_token
}

function New-OrGet-EntraSecurityGroup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupDisplayName
    )

    Write-Host "Creating or retrieving Entra security group: $GroupDisplayName"

    $graphToken = Get-AccessToken -Resource "https://graph.microsoft.com"
    $headers = @{
        Authorization = "Bearer $graphToken"
        "Content-Type" = "application/json"
    }

    $mailNickname = ($GroupDisplayName -replace '[^a-zA-Z0-9]', '').ToLower()
    if (:IsNullOrWhiteSpace($mailNickname)) {
        $mailNickname = "ppenvgroup"
    }

    $encodedFilter = [System.Web.HttpUtility]::UrlEncode("displayName eq '$GroupDisplayName'")
    $existing = Invoke-RestMethod `
        -Method Get `
        -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=$encodedFilter" `
        -Headers $headers

    if ($existing.value.Count -gt 0) {
        Write-Host "Security group already exists."
        return $existing.value[0].id
    }

    $body = @{
        displayName     = $GroupDisplayName
        mailEnabled     = $false
        mailNickname    = $mailNickname
        securityEnabled = $true
    } | ConvertTo-Json -Depth 10

    $created = Invoke-RestMethod `
        -Method Post `
        -Uri "https://graph.microsoft.com/v1.0/groups" `
        -Headers $headers `
        -Body $body

    Write-Host "Created security group with ID: $($created.id)"
    return $created.id
}

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

function New-EnvironmentDlpPolicy {
    param(
        [Parameter(Mandatory = $true)]
        [string]$EnvironmentId,

        [Parameter(Mandatory = $true)]
        [string]$PolicyDisplayName
    )

    Write-Host "Creating DLP policy: $PolicyDisplayName"

    # Business = Confidential in Power Platform DLP API
    $businessConnectors = @(
        "shared_sharepointonline",
        "shared_office365",
        "shared_office365users",
        "shared_commondataserviceforapps",
        "shared_teams"
    )

    # Non-Business = General in Power Platform DLP API
    $nonBusinessConnectors = @(
        "shared_msnweather",
        "shared_bingmaps"
    )

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
        connectors     = @($businessConnectors | ForEach-Object { Get-ConnectorObject -ConnectorName $_ })
    }

    $nonBusinessGroup = [pscustomobject]@{
        classification = "General"
        connectors     = @($nonBusinessConnectors | ForEach-Object { Get-ConnectorObject -ConnectorName $_ })
    }

    $blockedGroup = [pscustomobject]@{
        classification = "Blocked"
        connectors     = @($blockedConnectors | ForEach-Object { Get-ConnectorObject -ConnectorName $_ })
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
    $existingPolicy = $existingPolicies.value | Where-Object { $_.displayName -eq $PolicyDisplayName }

    if ($null -ne $existingPolicy) {
        Write-Host "DLP policy already exists. Updating existing policy."
        $newPolicy.name = $existingPolicy.name
        Set-DlpPolicy -PolicyName $existingPolicy.name -UpdatedPolicy $newPolicy | Out-Null
    }
    else {
        New-DlpPolicy -NewPolicy $newPolicy | Out-Null
    }

    Write-Host "DLP policy created or updated."
}

function New-OrGet-EnvironmentGroup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupDisplayName
    )

    Write-Host "Creating or retrieving Environment Group: $GroupDisplayName"

    $token = Get-AccessToken -Resource "https://api.powerplatform.com"
    $headers = @{
        Authorization = "Bearer $token"
        "Content-Type" = "application/json"
    }

    $groupsUri = "https://api.powerplatform.com/environmentmanagement/environmentGroups?api-version=2024-10-01"

    $groups = Invoke-RestMethod -Method Get -Uri $groupsUri -Headers $headers
    $existing = $groups.value | Where-Object { $_.displayName -eq $GroupDisplayName }

    if ($null -ne $existing) {
        Write-Host "Environment Group already exists with ID: $($existing.id)"
        return $existing.id
    }

    $body = @{
        displayName = $GroupDisplayName
        description = "Created by GitHub Actions automation"
    } | ConvertTo-Json -Depth 10

    $created = Invoke-RestMethod -Method Post -Uri $groupsUri -Headers $headers -Body $body

    Write-Host "Created Environment Group with ID: $($created.id)"
    return $created.id
}

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
        Authorization = "Bearer $token"
        "Content-Type" = "application/json"
    }

    $uri = "https://api.powerplatform.com/environmentmanagement/environmentGroups/$GroupId/addEnvironment/$EnvironmentId`?api-version=2024-10-01"

    try {
        Invoke-RestMethod -Method Post -Uri $uri -Headers $headers | Out-Null
        Write-Host "Environment added to group."
    }
    catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 204) {
            Write-Host "Environment is already associated or no content returned."
        }
        else {
            throw
        }
    }
}

Write-Host "Authenticating to Power Platform using service principal..."

Add-PowerAppsAccount `
    -Endpoint prod `
    -TenantID $TenantId `
    -ApplicationId $ClientId `
    -ClientSecret $ClientSecret | Out-Null

Write-Host "Authenticated."

$securityGroupDisplayName = "SG-PP-$EnvironmentDisplayName"
$securityGroupId = New-OrGet-EntraSecurityGroup -GroupDisplayName $securityGroupDisplayName

Write-Host "Creating Power Platform environment: $EnvironmentDisplayName"

$environment = New-AdminPowerAppEnvironment `
    -DisplayName $EnvironmentDisplayName `
    -LocationName $LocationName `
    -EnvironmentSku $EnvironmentSku `
    -ProvisionDatabase `
    -CurrencyName $CurrencyName `
    -LanguageName $LanguageName `
    -SecurityGroupId $securityGroupId `
    -WaitUntilFinished $true `
    -TimeoutInMinutes 120

$environmentId = $environment.EnvironmentName

if (:IsNullOrWhiteSpace($environmentId)) {
    throw "Environment creation failed. EnvironmentName is empty."
}

Write-Host "Environment created: $environmentId"

Enable-ManagedEnvironment -EnvironmentId $environmentId

$dlpPolicyName = "DLP-$EnvironmentDisplayName"
New-EnvironmentDlpPolicy `
    -EnvironmentId $environmentId `
    -PolicyDisplayName $dlpPolicyName

$environmentGroupId = New-OrGet-EnvironmentGroup -GroupDisplayName $EnvironmentGroupName

Add-EnvironmentToEnvironmentGroup `
    -GroupId $environmentGroupId `
    -EnvironmentId $environmentId

Write-Host "Automation completed successfully."
Write-Host "Environment Name: $EnvironmentDisplayName"
Write-Host "Environment ID: $environmentId"
Write-Host "Security Group ID: $securityGroupId"
Write-Host "DLP Policy Name: $dlpPolicyName"
Write-Host "Environment Group ID: $environmentGroupId"
