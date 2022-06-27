 #Requires -Module Microsoft.Graph.Intune

<#PSScriptInfo
.VERSION 1.0
.AUTHOR Ivo Uenk
.RELEASENOTES

#>
<#
.SYNOPSIS
  Start VMs as part of an Update Management deployment
.DESCRIPTION
  .EXTERNALMODULEDEPENDENCIES  Microsoft.Graph.Intune
This script monitors apple token expiration in MEMCM (Intune) and checks if DEP, VPP, and APNS tokens, certificates are valided after the number of specified days.
.NOTES
  Version:        1.0
  Author:         Ivo Uenk
  Creation Date:  2021-10-11
  Purpose/Change: Initial script development
#>


Param()

# treshold days before expiration notification is fired
$notificationTreshold = (get-date).AddDays(30)

# Get the credential from Automation  
$credential = Get-AutomationPSCredential -Name 'AutomationCreds'  
$userName = $credential.UserName  
$securePassword = $credential.Password
$psCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $userName, $securePassword

Connect-MSGraph -Credential $psCredential

# Get initial domain name to display as tenant name on teams card
$organization =  Invoke-MSGraphRequest -HttpMethod GET -Url "organization"
$orgDomain = $organization.value.verifiedDomains | Where-Object {$_.isInitial} | Select-Object -ExpandProperty name

# optional mail configuration
$mailConfig = @{
    SMTPServer = "smtp.office365.com"
    SMTPPort = "587"
    Sender = "automation@ucorp.nl"
    Recipients = @("mail@udirection.com")
    Header = "Apple token expiration in MEMCM for tenant: $orgDomain"
}

# JSON template for teams card message
$bodyTemplate = @"
    {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": "Apple token expiration in MEMCM",
        "themeColor": "D778D7",
        "title": "Apple token expiration in MEMCM",
         "sections": [
            {
                "facts": [
                    {
                        "name": "Token Type:",
                        "value": "TOKEN_TYPE"
                    },
                    {
                        "name": "Token Name:",
                        "value": "TOKEN_NAME"
                    },
                    {
                        "name": "Expiration datetime:",
                        "value": "TOKEN_EXPIRATION_DATETIME"
                    },
                    {
                        "name": "Help URL:",
                        "value": "[Microsoft Docs: Renew iOS certificate and tokens](https://docs.microsoft.com/en-us/intune-education/renew-ios-certificate-token)"
                    }
                ],
                "text": "The following Apple token in your Intune Tenant: _$($orgDomain)_ is about to expire:"
            }
        ]
    }
"@

# Mail message template
$mailTemplate = @"
  <html>
  <body>
    <h1>Attention: Apple token expiration in MEMCM!</h1>
    <br>
    Please make sure to renew your expired apple token in MEMCM!
    <br>
    <br>
    <b>Token type:</b> TOKEN_TYPE 
    <br>
    <b>Token Name:</b> TOKEN_NAME 
    <br>
    <b>Expiration Datetime:</b> TOKEN_EXPIRATION_DATETIME <br>
    <b>Help URL: <a href="https://docs.microsoft.com/en-us/intune-education/renew-ios-certificate-token">Microsoft Docs</a><br>
    <br>
    <br/>
  </body>
</html>
"@

# Process Apple push notification certificate and check for expiration
$applePushNotificationCertificate = Get-DeviceManagement_ApplePushNotificationCertificate

if ($applePushNotificationCertificate.expirationDateTime -le $notificationTreshold){

    Write-Output "Apple Push Certificate: $($applePushNotificationCertificate.appleIdentifier) will expire soon!"

    # if mailconfig is enabled use mail template instead of teams card
    if ($mailConfig){

        $bodyTemplate = $mailTemplate
    }

    $bodyTemplate = $bodyTemplate.Replace("TOKEN_TYPE", "Apple Push Notification Certificate")
    $bodyTemplate = $bodyTemplate.Replace("TOKEN_NAME", $applePushNotificationCertificate.appleIdentifier)
    $bodyTemplate = $bodyTemplate.Replace("TOKEN_EXPIRATION_DATETIME", $applePushNotificationCertificate.expirationDateTime)

    if (-not $mailConfig){

        $request = Invoke-WebRequest -Method Post -Uri $webHookUri -Body $bodyTemplate -UseBasicParsing

    }else{

        Send-MailMessage -UseSsl -From $mailConfig.Sender -To $mailConfig.Recipients -SmtpServer $mailConfig.SMTPServer -Port $mailConfig.SMTPPort -Subject $mailConfig.Header -Body $bodyTemplate -Credential $psCredential -BodyAsHtml
    }
}else{

    Write-Output "Apple Push Certificate: $($applePushNotificationCertificate.appleIdentifier) still valid!"
}

# Process all Apple vpp tokens and check if they will expire soon
$appleVppTokens = Get-DeviceAppManagement_VppTokens

$appleVppTokens | ForEach-Object {

    $appleVppToken = $PSItem

    if ($appleVppToken.expirationDateTime -le $notificationTreshold){

        Write-Output "Apple VPP Token: $($appleVppToken.appleId) will expire soon!"

        # if mailconfig is enabled use mail template instead of teams card
        if ($mailConfig){

            $bodyTemplate = $mailTemplate
        }

        $bodyTemplate = $bodyTemplate.Replace("TOKEN_TYPE", "Apple VPP Token")
        $bodyTemplate = $bodyTemplate.Replace("TOKEN_NAME", "$($appleVppToken.organizationName): $($appleVppToken.appleId)")
        $bodyTemplate = $bodyTemplate.Replace("TOKEN_EXPIRATION_DATETIME", $appleVppToken.expirationDateTime)

        if (-not $mailConfig){

            $request = Invoke-WebRequest -Method Post -Uri $webHookUri -Body $bodyTemplate -UseBasicParsing
    
        }else{

            Send-MailMessage -UseSsl -From $mailConfig.Sender -To $mailConfig.Recipients -SmtpServer $mailConfig.SMTPServer -Port $mailConfig.SMTPPort -Subject $mailConfig.Header -Body $mailTemplate -Credential $psCredential 
        }
    }else{

        Write-Output "Apple VPP Token: $($appleVppToken.appleId) still valid!"
    }
}

# Process all Apple DEP Tokens (we have to switch to the beta endpoint)
Update-MSGraphEnvironment -SchemaVersion "Beta" -Quiet

$appleDepTokens = (Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/depOnboardingSettings").value

$appleDepTokens | ForEach-Object {

    $appleDepToken = $PSItem

    if ($appleDepToken.tokenExpirationDateTime -le $notificationTreshold){

        Write-Output "Apple Dep Token: $($appleDepToken.appleIdentifier) will expire soon!"

        # if mailconfig is enabled use mail template instead of teams card
        if ($mailConfig){

            $bodyTemplate = $mailTemplate
        }

        $bodyTemplate = $bodyTemplate.Replace("TOKEN_TYPE", "Apple DEP Token")
        $bodyTemplate = $bodyTemplate.Replace("TOKEN_NAME", "$($appleDepToken.tokenName): $($appleDepToken.appleIdentifier)")
        $bodyTemplate = $bodyTemplate.Replace("TOKEN_EXPIRATION_DATETIME", $appleDepToken.tokenExpirationDateTime)

        if (-not $mailConfig){

            $request = Invoke-WebRequest -Method Post -Uri $webHookUri -Body $bodyTemplate -UseBasicParsing
    
        }else{
    
            Send-MailMessage -UseSsl -From $mailConfig.Sender -To $mailConfig.Recipients -SmtpServer $mailConfig.SMTPServer -Port $mailConfig.SMTPPort -Subject $mailConfig.Header -Body $mailTemplate -Credential $psCredential 
        }

    }else{

        Write-Output "Apple Dep Token: $($appleDepToken.appleIdentifier) still valid!"
    }
}