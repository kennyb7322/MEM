#Connect to Azure AD
Connect-AzureAD

$functionApp = New-AzFunctionApp -name "ucorpimportdevice" -Location "westeurope" `
-resourceGroupName "Ucorp-MEM-RG" `
-StorageAccountName "ucorpstorage" `
-OSType "Windows" `
-Runtime "powershell" `
-RuntimeVersion 7.0 `
-FunctionsVersion 3

#Get graph App
$graphApp = Get-AzureADServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'"

#get Role to read group objects
$groupReadPermission = $graphApp.AppRoles | where-Object {$_.Value -eq "DeviceManagementServiceConfig.ReadWrite.All"}
#DeviceManagementManagedDevices.ReadWrite.All
#DeviceManagementConfiguration.ReadWrite.All
#DeviceManagementManagedDevices.PrivilegedOperations.All
#DeviceManagementServiceConfig.ReadWrite.All

#use the MSI from the Function App Creation
$msi = Get-AzureADServicePrincipal -ObjectId "<ObjectId>"

New-AzureADServiceAppRoleAssignment -Id $groupReadPermission.Id -ObjectId $msi.ObjectId -PrincipalId $msi.ObjectId -ResourceId $graphApp.ObjectId