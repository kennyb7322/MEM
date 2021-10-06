#enter treshold days 
$deletionTresholdDays= 60
$path = "C:\Ucorp\AzureAD-Cleanup"

# Set Configs
$TenantId = "<TenantId>"
$AzureUser = "automation@ucorp.nl" 
$AzurePass = ConvertTo-SecureString "Password" -AsPlainText -Force

# Connect to Azure AD
$AzureCred = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $AzureUser, $AzurePass
Connect-AzureAD -TenantId $TenantId -Credential $AzureCred -ErrorAction Stop

$deletionTreshold= (Get-Date).AddDays(-$deletionTresholdDays)

$allDevices = Get-AzureADDevice -All:$true | Where-Object {$_.ApproximateLastLogonTimeStamp -le $deletionTreshold -and $_.IsCompliant -ne $true}

$Results = Foreach ($Device in $allDevices){
    $RegisteredOwner = Get-AzureADDeviceRegisteredOwner -ObjectId $Device.ObjectId

    New-Object -TypeName psobject -Property @{
    DeviceId = $Device.DeviceId
    ObjectId = $Device.ObjectId
    DeviceName = $Device.DisplayName
    UserPrincipalName = $RegisteredOwner.UserPrincipalName
    DeviceOSType = $Device.DeviceOSType
    LastLogonTime = $Device.ApproximateLastLogonTimeStamp
    IsCompliant = $Device.IsCompliant
    IsManaged = $Device.IsManaged
    }
}

$exportPath=$(Join-Path $path "UcorpAzureADDeviceExport.csv")

$Results | Sort-Object -Property LastLogonTime -Descending | Select-Object -Property DeviceName, ObjectId, DeviceID, UserPrincipalName, LastLogonTime, DeviceOSType, IsCompliant, IsManaged `
| Export-Csv -Path $exportPath -UseCulture -NoTypeInformation

Write-Output "Find report with all devices under: $exportPath"

$allDevices | ForEach-Object {
Write-Output "Removing device $($PSItem.ObjectId)"
Remove-AzureADDevice -ObjectId $PSItem.ObjectId
}