Import-Module AzureADPreview
Import-Module ADAL.PS

$appId='$appId'
$appSecret='appSecret'
$tenantId='tenantId'

# Get MS graph API connection
$authString = "https://login.microsoftonline.com/$tenantId" 
$authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext"-ArgumentList $authString
$creds = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential" -ArgumentList $AppId, $AppSecret
$context = $authContext.AcquireTokenAsync("https://graph.microsoft.com/", $creds).Result
$AccessToken = $context.AccessToken

$Resource = "deviceManagement/deviceCompliancePolicies"
$uri = "https://graph.microsoft.com/Beta/$($Resource)"

try {
    Invoke-RestMethod -Uri $uri -Headers @{"Authorization" = "Bearer $AccessToken"} -Method Post -Body $JSON_Windows10 -ContentType "application/json"

}catch {
    Write-Host
    $ex = $_.Exception
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break
}

$JSON_Windows10 = @"
    {
    "@odata.type": "#microsoft.graph.windows10CompliancePolicy",
    "description": "Default | W10 | Compliance Rule",
    "displayName": "Default | W10 | Compliance Rule",
    "scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":""}]}],
    "passwordRequired": true,
    "passwordBlockSimple": true,
    "securityPreventInstallAppsFromUnknownSources":  true,
    "passwordRequiredToUnlockFromIdle": false,
    "passwordMinutesOfInactivityBeforeLock": 30,
    "passwordExpirationDays": null,
    "passwordMinimumLength": 18,
    "passwordMinimumCharacterSetCount": 4,
    "passwordRequiredType": "alphanumeric",
    "passwordPreviousPasswordBlockCount": 24,
    "osMinimumVersion": "10.0.18363.657",
    "earlyLaunchAntiMalwareDriverEnabled": false,
    "bitLockerEnabled": false,
    "secureBootEnabled": true,
    "codeIntegrityEnabled": false,
    "storageRequireEncryption": true,
    "activeFirewallRequired": true,
    "defenderEnabled": true,
    "signatureOutOfDate": true,
    "rtpEnabled": true,
    "antivirusRequired": true,
    "antiSpywareRequired": true,
    "deviceThreatProtectionEnabled": false,
    "configurationManagerComplianceRequired": false,
    "tpmRequired": false
    }
"@


try {
    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/a2de9bda-ffed-4527-96d7-d6f3ac10da8c"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method Patch -Body $JSON_Windows10_Upd -ContentType "application/json"
}catch {
    Write-Host
    $ex = $_.Exception
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break
}

$JSON_Windows10_Upd = @"
    {
    "@odata.type": "#microsoft.graph.windows10CompliancePolicy",
    "description": "Default | W10 | Compliance Rule - create test4",
    "displayName": "Default | W10 | Compliance Rule - create test4",
    "passwordMinimumLength": 12,
    "passwordMinimumCharacterSetCount": 8,
    "osMinimumVersion": "10.0.18362.657"
    }
"@