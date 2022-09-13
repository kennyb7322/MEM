Function Send-Mail{

    param(
	    [Parameter(Mandatory=$true)]$Recipient,
	    [Parameter(Mandatory=$true)]$MailSender,
        [Parameter(Mandatory=$false)]$RecipientCC,
        [Parameter(Mandatory=$true)][string]$Subject,
        [Parameter(Mandatory=$true)][string]$Body
    )
    
    $clientID = Get-AutomationVariable -Name "mailappId"
    $ClientSecret = Get-AutomationVariable -Name "mailappSecret"
    $tenantID = Get-AutomationVariable -Name "TenantId"
 
    #Connect to GRAPH API
    $tokenBody = @{
        Grant_Type    = "client_credentials"
        Scope         = "https://graph.microsoft.com/.default"
        Client_Id     = $clientId
        Client_Secret = $clientSecret
    }
    $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantID/oauth2/v2.0/token" -Method POST -Body $tokenBody
    $headers = @{
        "Authorization" = "Bearer $($tokenResponse.access_token)"
        "Content-type"  = "application/json"
    }
 
#Send Mail    
$URLsend = "https://graph.microsoft.com/v1.0/users/$MailSender/sendMail"
$BodyJsonsend = @"
                    {
                        "message": {
                          "subject": "$Subject",
                          "body": {
                            "contentType": "HTML",
                            "content": "$Body"
                          },
                          "toRecipients": [
                            {
                              "emailAddress": {
                                "address": "$Recipient"
                              }
                            }
                          ]
                        },
                        "saveToSentItems": "false"
                      }
"@
 
    Invoke-RestMethod -Method POST -Uri $URLsend -Headers $headers -Body $BodyJsonsend
}