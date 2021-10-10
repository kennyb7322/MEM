$Report = @()
$i = 0
$Accounts = (Get-MsolUser -All | ? {$_.StrongAuthenticationMethods -ne $Null} | Sort DisplayName)
ForEach ($Account in $Accounts) {
   Write-Host "Processing" $Account.DisplayName
   $i++
   $Methods = $Account | Select -ExpandProperty StrongAuthenticationMethods
   $MFA = $Account | Select -ExpandProperty StrongAuthenticationUserDetails
   $State = $Account | Select -ExpandProperty StrongAuthenticationRequirements
   $Methods | ForEach { If ($_.IsDefault -eq $True) {$Method = $_.MethodType}}
   If ($State.State -ne $Null) {$MFAStatus = $State.State}
      Else {$MFAStatus = "Disabled"}
   $ReportLine = [PSCustomObject]@{
       User      = $Account.DisplayName
       UPN       = $Account.UserPrincipalName
       MFAMethod = $Method
       MFAPhone  = $MFA.PhoneNumber
       MFAEmail  = $MFA.Email
       MFAStatus = $MFAStatus  }
   $Report += $ReportLine      }
Write-Host $i "accounts are MFA-enabled"

$Report | Export-CSV -NoTypeInformation c:\temp\MFAUsers.CSV