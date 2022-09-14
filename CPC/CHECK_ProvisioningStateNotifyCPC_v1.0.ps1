<#PSScriptInfo
.VERSION 1.0
.AUTHOR Ivo Uenk
.RELEASENOTES

#>
<#
.SYNOPSIS
Check privisioning state, set extension attribute for CPC devices, notify owner.
.DESCRIPTION
Check privisioning state, set extension attribute for CPC devices, notify owner.
.NOTES
  Version:        1.0
  Author:         Ivo Uenk
  Creation Date:  2022-09-14
  Purpose/Change: Testing Pre-prod
#>

. .\GEN_Send_Mail.ps1

# Variables
$ExtensionAttributeKey = "extensionAttribute3"
$ExtensionAttributeValue = "CPCWelcomeMailHaveBeenSent"
$MailSender = Get-AutomationVariable "MailSender"

$TenantID = Get-AutomationVariable "TenantId"
$AppId = Get-AutomationVariable "cpcappId"
$AppSecret = Get-AutomationVariable "cpcappSecret"

# Credentials
$intuneAutomationCredential = Get-AutomationPSCredential -Name "AutomationCreds"
$userName = $intuneAutomationCredential.UserName  
$securePassword = $intuneAutomationCredential.Password
$psCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $userName, $securePassword 

# Connect to Microsoft services
Connect-AzureAD -Credential $psCredential

# Get MS graph API connection
$authString = "https://login.microsoftonline.com/$tenantId" 
$authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext"-ArgumentList $authString
$creds = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential" -ArgumentList $AppId, $AppSecret
$context = $authContext.AcquireTokenAsync("https://graph.microsoft.com/", $creds).Result
$AccessToken = $context.AccessToken

function Get-CPCUser {

[cmdletbinding()]

param
(
    $userPrincipalName
)

    try {
        $Resource = "users/$userPrincipalName"
        $UserUri = "https://graph.microsoft.com/v1.0/$($Resource)" 
        (Invoke-RestMethod -Uri $UserUri -Headers @{"Authorization" = "Bearer $AccessToken"} -Method Get)

    } catch {
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Output "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        throw "Get-CPCUser error"
    }
}

function Update-AADDevice {

[cmdletbinding()]

param
(
    $Id,
    $ExtensionAttributeKey,
    $ExtensionAttributeValue
)

    try {
        $Resource = "devices/$Id"
        $DeviceUri = "https://graph.microsoft.com/v1.0/$($Resource)" 

        $json = @"
{
    "extensionAttributes": {
        "$ExtensionAttributeKey": "$ExtensionAttributeValue"
    }
}
"@
        (Invoke-RestMethod -Uri $DeviceUri -Headers @{"Authorization" = "Bearer $AccessToken"} -Method Patch -Body $json -ContentType "application/json")

    } catch {
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Output "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        throw "Update-AADDevice error"
    }
}

#Get all Azure AD Devices starting with CPC
$AllAADDevices = @()
$AADDevicesUri = "https://graph.microsoft.com/v1.0/devices?`$filter=startsWith(Displayname,'CPC-')"

$AllAADDevicesResponse = (Invoke-RestMethod -Uri $AADDevicesUri -Headers @{"Authorization" = "Bearer $AccessToken"} -Method Get)
$AllAADDevices = $AllAADDevicesResponse.value | Select-Object id, DisplayName, accountEnabled, enrollmentProfileName, extensionAttributes
$AllAADDevicesNextLink = $AllAADDevicesResponse."@odata.nextLink"
while ($null -ne $AllAADDevicesNextLink) {
    $AllAADDevicesResponse = (Invoke-RestMethod -Uri $AllAADDevicesNextLink -Headers @{"Authorization" = "Bearer $AccessToken"} -Method Get)
    $AllAADDevicesNextLink = $AllAADDevicesResponse."@odata.nextLink"
    $AllAADDevices += $AllAADDevicesResponse.value | Select-Object id, DisplayName, accountEnabled, enrollmentProfileName, extensionAttributes
}

#Get all Cloud PCDevice
$AllCPCDevices = @()
$AllCPCDeviceUri = "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/cloudPCs"

$AllCPCDevicesResponse = (Invoke-RestMethod -Uri $AllCPCDeviceUri -Headers @{"Authorization" = "Bearer $AccessToken"} -Method Get)
$AllCPCDevices = $AllCPCDevicesResponse.value | Select-Object id, managedDeviceName, provisioningPolicyName, status, userPrincipalName, servicePlanName
$AllCPCDevicesNextLink = $AllCPCDevicesResponse."@odata.nextLink"
while ($null -ne $AllCPCDevicesNextLink) {
    $AllCPCDevicesResponse = (Invoke-RestMethod -Uri $AllCPCDevicesNextLink -Headers @{"Authorization" = "Bearer $AccessToken"} -Method Get)
    $AllCPCDevicesNextLink = $AllCPCDevicesResponse."@odata.nextLink"
    $AllCPCDevices += $AllCPCDevicesResponse.value | Select-Object id, managedDeviceName, provisioningPolicyName, status, userPrincipalName, servicePlanName
} 

# Mail message template
$mailTemplate = @"
  <html>
  <body>
    <h1>Attention: Your new Windows 365 Cloud PC is ready!</h1>
    <br>
    Please make sure to sign-in today, so the machine will receive updates immediately. For issues inform servicedesk and use information below.
    <br>
    <br>
    <b>Cloud PC Name:</b> CPC_NAME
    <br>
    <b>Owner Name:</b> CPC_OWNER
    <br>
    <br>
    <b>Sign in via URL to start your Cloud PC:</b> https://windows365.microsoft.com
    <br>
    <br/>
  </body>
</html>
"@

Foreach ($AADDeviceInfo in $AllAADDevices){
    #Check if Cloud PC is actived
    if ($AADDeviceInfo.AccountEnabled -eq $true){

        #Check For if Welcome mail has been sent before
        $Attributecheck = $AADDeviceInfo.ExtensionAttributes.$ExtensionAttributeKey
        if (!($Attributecheck -eq $ExtensionAttributeValue)){        
            #Check if Cloud PC is done provisioning
            try {
                $CPCDevice = $AllCPCDevices | Where-Object {$_.ManagedDeviceName -eq $AADDeviceInfo.DisplayName}
                if ($CPCDevice.Status -eq "provisioned") {
                    write-host ""
                    write-host "Cloud PC: '$($AADDeviceInfo.DisplayName)' has been provisioned correct and is ready to be logged into."
            
                    #Gathering user information
                    write-host "Gathering User information"
                    try {
                        write-host "Cloud PC: '$($AADDeviceInfo.DisplayName)' Primary user is: '$($CPCDevice.userPrincipalName)'"
                        write-host "Finding Email Address for user: '$($CPCDevice.userPrincipalName)'"
                            
                        $UserInfo = Get-CPCUser -userPrincipalName $CPCDevice.userPrincipalName
                        write-host "Primary SMTP for user $($UserInfo.UserPrincipalName) is: $($UserInfo.mail)"
                    }
                    catch {
                        write-output "Unable to get user information" | out-host
                        write-output $_.Exception.Message | out-host
                        break
                    }

                    #Send email
                    $bodyTemplate = $mailTemplate
                    $bodyTemplate = $bodyTemplate.Replace('CPC_NAME', $AADDeviceInfo.DisplayName)
                    $bodyTemplate = $bodyTemplate.Replace('CPC_OWNER', $CPCDevice.userPrincipalName)                 
  
                    # Send mail here
                    $Subject = "Windows 365 Cloud PC '$($AADDeviceInfo.DisplayName)' for '$($CPCDevice.userPrincipalName)' is ready!"
                    Send-Mail -Recipient $CPCDevice.userPrincipalName -Subject $Subject -Body $bodyTemplate -MailSender $MailSender
                                
                    try{  
                        #Set Attribute on Azure AD Device
                        Write-Host "Setting Attribute on AzureAD Device:'$($AADDeviceInfo.DisplayName)'"
                        Write-Host ""

                        Update-AADDevice -Id $AADDeviceInfo.Id -ExtensionAttributeKey $ExtensionAttributeKey -ExtensionAttributeValue $ExtensionAttributeValue                                    
                    }                           
                    catch{ 
                    write-output "Unable to set Attribute on AzureAD Device:'$AADDeviceInfo.DisplayName'" | out-host
                    write-output $_.Exception.Message | out-host
                    break
                    }
                } 
            }
            catch {
                write-output "Unable to get Cloud PC Device status in Endpoint Manager" | out-host
                write-output $_.Exception.Message | out-host
                break
            }
        }
    }
} 