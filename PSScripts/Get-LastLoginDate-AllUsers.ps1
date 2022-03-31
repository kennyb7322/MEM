## Export Last login date for all Microsoft 365 Users

#Provide your Office 365 Tenant Id or Tenant Domain Name
$TenantId = "ucorponline.onmicrosoft.com"
  
#Provide Azure AD Application (client) Id of your app.
#You should have granted Admin consent for this app to use the application permissions "AuditLog.Read.All and User.Read.All" in your tenant.
$AppClientId="<Client ID>"
  
#Provide Application client secret key
$ClientSecret ="<Secret value>"
  
$RequestBody = @{client_id=$AppClientId;client_secret=$ClientSecret;grant_type="client_credentials";scope="https://graph.microsoft.com/.default";}
$OAuthResponse = Invoke-RestMethod -Method Post -Uri https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token -Body $RequestBody
$AccessToken = $OAuthResponse.access_token

#Form request headers with the acquired $AccessToken
$headers = @{'Content-Type'="application\json";'Authorization'="Bearer $AccessToken"}
 
#This request get users list with signInActivity.
$ApiUrl = "https://graph.microsoft.com/beta/users?`$select=displayName,userPrincipalName,signInActivity,userType,assignedLicenses&`$top=999"
 
$Result = @()
While ($ApiUrl -ne $Null) #Perform pagination if next page link (odata.nextlink) returned.
{
$Response = Invoke-WebRequest -Method GET -Uri $ApiUrl -ContentType "application\json" -Headers $headers | ConvertFrom-Json
if($Response.value)
{
$Users = $Response.value
ForEach($User in $Users)
{
 
$Result += New-Object PSObject -property $([ordered]@{ 
DisplayName = $User.displayName
UserPrincipalName = $User.userPrincipalName
LastSignInDateTime = if($User.signInActivity.lastSignInDateTime) { [DateTime]$User.signInActivity.lastSignInDateTime } Else {$null}
IsLicensed  = if ($User.assignedLicenses.Count -ne 0) { $true } else { $false }
IsGuestUser  = if ($User.userType -eq 'Guest') { $true } else { $false }
})
}
 
}
$ApiUrl=$Response.'@odata.nextlink'
}
$Result | Export-CSV C:\Users\Ivo\Desktop\LastLoginDateReport.CSV -NoTypeInformation -Encoding UTF8