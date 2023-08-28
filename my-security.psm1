
<#

#>
function Get-Token {
    [CmdletBinding()]
    param(
        $resourceAppIdUri = '',
        $oAuthUri = 'https://login.microsoftonline.com/{0}/oauth2/token',
        $tenantId, # Use the my-security.json file to set this to a singular value easily
        $appId, # Use the my-security.json file to set this to a singular value easily
        $appSecret # Use the my-security.json file to set this to a singular value easily
    )

    $oAuthUri = $oAuthUri -f $tenantId
    Write-Debug ("oAuthUri:" + $oauthUri)

    $authBody = [Ordered] @{
        resource = $resourceAppIdUri
        client_id = $appId
        client_secret = $appSecret
        grant_type = 'client_credentials'
    }
    
    $jsonBody = ConvertTo-Json $authBody
    Write-Debug ("BODY:" + $jsonBody)

    $response = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
    Write-Debug ("respose:" + $response)

    $response.access_token
}

function Get-GraphToken {
    [CmdletBinding()]
    param(
        $scope = 'https://graph.microsoft.com/.default',
        $oAuthUri = 'https://login.microsoftonline.com/{0}/oauth2/v2.0/token',
        $tenantId, # Use the my-security.json file to set this to a singular value easily
        $appId, # Use the my-security.json file to set this to a singular value easily
        $appSecret # Use the my-security.json file to set this to a singular value easily
    )

    $oAuthUri = $oAuthUri -f $tenantId
    Write-Debug ("oAuthUri:" + $oauthUri)

    $authBody = [Ordered] @{
        scope = $scope
        client_id = $appId
        client_secret = $appSecret
        grant_type = 'client_credentials'
    }

    $jsonBody = ConvertTo-Json $authBody
    Write-Debug ("BODY:" + $jsonBody)

    $response = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
    Write-Debug ("respose:" + $response)

    $response.access_token
}

function Get-MdeApiToken {
    [CmdletBinding()]
    param()

    $resourceAppIdUri = 'https://api.securitycenter.microsoft.com'
    Get-Token -resourceAppIdUri $resourceAppIdUri
}

function Get-DefenderApiToken {
    [CmdletBinding()]
    param()

    $resourceAppIdUri = 'https://api.security.microsoft.com'
    Get-Token -resourceAppIdUri $resourceAppIdUri
}

function Get-Alerts {
    [CmdletBinding()]
    param(
        $AccessToken
    )

    $api = "https://api.securitycenter.microsoft.com/api/alerts"

    $responseObject = Invoke-ApiCall -Uri $api -Bearer $AccessToken
    $responseObject.value
}

function Update-Alert {
    [CmdletBinding()]
    param(
        $AccessToken,
        $AlertId,
        $FieldName,
        $FieldValue
    )

    $body = '{"' + $FieldName + '":"' + $FieldValue + '"}'
    $api = "https://api.securitycenter.microsoft.com/api/alerts/$AlertId"
    $method = "PATCH"

    Invoke-ApiCall -Uri $api -Bearer $AccessToken -Method $method -Body $body
}

function Update-Alerts {
    [CmdletBinding()]
    param(
        $AccessToken,
        [string[]] $AlertIds,
        [string] $IncidentId,
        [string] $Comment
    )

    #$uri = "https://wdatpprd-cus3.securitycenter.windows.com/api/ine/alertsapiservice/alerts/incidentLinks?newApi=true"
    #$uri = "https://api.securitycenter.microsoft.com/api/ine/alertsapiservice/alerts/incidentLinks?newApi=true"
    $uri = "https://api.securitycenter.microsoft.com/api/alerts/incidentLinks?newApi=true"
    Write-Debug ("URI: " + $uri)

    $body = @{
        AlertIds = $AlertIds
        IncidentId = $IncidentId
        Comment = $Comment
    }
    $bodyArray = @()
    $bodyArray += $body

    $bodyValues = @{
        values = $bodyArray
    }

    $jsonBody = ConvertTo-Json $bodyValues
    Write-Debug ("Body: " + $jsonBody)

    $method = "PATCH"
    #$method = "POST"
    Write-Debug ("Method: " + $method)

    Invoke-ApiCall -Uri $uri -Method $method -Bearer $AccessToken -Body $jsonBody
}


function Invoke-ApiCall {
    [CmdletBinding()]
    param(
        $Uri = "",
        $Method = "GET",
        $Bearer = "",
        $Body = ""
    )

    $headers = @{ 
        'Content-Type' = 'application/json'
        Accept = 'application/json'
        Authorization = "Bearer $Bearer" 
    }

    $headerJson = ConvertTo-Json $headers
    Write-Debug ("Headers: " + $headerJson)

    Write-Debug "Uri: $Uri"
    Write-Debug "Method: $Method"
    Write-Debug "Body: $Body"

    $webResponse = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $headers -Body $Body -ErrorAction Stop
    Write-Debug "webResponse: $webResponse"
    $webResponse | ConvertFrom-Json
}

function Get-MdiLoginToken {
    param (
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential] $Credential
    )

    $params = @{
        'Body'        = @{
            'username'     = ($Credential).UserName
            'password'     = ($Credential).GetNetworkCredential().Password
            'grant_type'   = 'password'
            'redirect_uri' = 'urn:ietf:wg:oauth:2.0:oob' # PowerShell redirect Uri
            #'client_id'    = '1950a258-227b-4e31-a9cf-717495945fc2' # PowerShell client Id
            'client_id'    = '29d9ed98-a469-4536-ade2-f981bc1d605e' # Microsoft Authentication Broker
            'resource'     = '7b7531ad-5926-4f2d-8a1d-38495ad33e17' # Azure Advanced Threat Protection 1st party applicationId
        }
        'Method'      = 'Post'
        'ContentType' = 'application/x-www-form-urlencoded'
        'Uri'         = 'https://login.microsoftonline.com/common/oauth2/token'
    }
    $accessToken = Invoke-RestMethod @params | Select-Object -ExpandProperty access_token
    $accessToken

}

$mPath = (Get-Module -ListAvailable my-security).path
$jPath = $mPath.Replace("my-security.psm1", "my-security.json")
$json = (Get-Content $jPath -raw -ErrorAction SilentlyContinue) | ConvertFrom-Json

$counter = 0
$json.defaultParameters | ForEach-Object {
    $key = $_.function + ":" + $_.variable
    $PSDefaultParameterValues[$key] = $_.value
    $counter = $counter +1
}

Write-Host "My-Security Loaded $counter items into Default Parameters"