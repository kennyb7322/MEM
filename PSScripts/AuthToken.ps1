function Get-AuthToken {

<#
.SYNOPSIS
This function is used to authenticate with the Graph API REST interface
.DESCRIPTION
The function authenticate with the Graph API Interface with the tenant name
.EXAMPLE
Get-AuthToken
Authenticates you with the Graph API interface
.NOTES
NAME: Get-AuthToken
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    $User
)

$userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User
$tenant = $userUpn.Host

# Getting path to ActiveDirectory Assemblies
# If the module count is greater than 1 find the latest version

$clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
$redirectUri = "urn:ietf:wg:oauth:2.0:oob"
$resourceAppIdURI = "https://graph.microsoft.com"
$authority = "https://login.microsoftonline.com/$Tenant"

    try {

    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

    # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
    # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

    $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"

    $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")

    $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result

        # If the accesstoken is valid then create the authentication header

        if($authResult.AccessToken){

        # Creating header for Authorization token

        $authHeader = @{
            'Content-Type'='application/json'
            'Authorization'="Bearer " + $authResult.AccessToken
            'ExpiresOn'=$authResult.ExpiresOn
            }

        return $authHeader

        }

        else {

        Write-Host
        Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
        Write-Host
        break

        }

    }

    catch {

    write-host $_.Exception.Message -f Red
    write-host $_.Exception.ItemName -f Red
    write-host
    break

    }

}


####################################################
$user = read-host "Input UPN: "

Connect-AzureAD
#Connect-MSGraph

$global:authToken = Get-AuthToken -User $user

####################################################

    #    $uri = read-host "Input URI:`nExamples are:`n
     #   All devices: https://graph.microsoft.com/beta/deviceManagement/managedDevices?
      #  Specific device: https://graph.microsoft.com/beta/deviceManagement/managedDevices/{managedDeviceId}`n
       # Output gets stored in '$output' and displayed."

       # $uri = 'https://graph.microsoft.com/beta/deviceManagement/manageddevices/$select=id,deviceName,hardwareinformation'

       $uri = 'https://graph.microsoft.com/beta/deviceManagement/managedDevices/6e076deb-be50-48ed-adf0-e0ae220a5fb9/'
       $uri2 = 'https://graph.microsoft.com/beta/users/1313aa43-192f-46a2-a7bb-4ed057609c25'
       #$uri = 'https://graph.microsoft.com/v1.0/applications/06e4c700-2791-4c2f-9d2f-1361e81c8d88'

        $output = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get

        $output2 = Invoke-RestMethod -Uri $uri2 -Headers $authToken -Method Get