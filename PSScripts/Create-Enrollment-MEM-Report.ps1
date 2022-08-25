. .\GEN_Run_Env.ps1
. .\GEN_GraphAPI_RO.ps1

# Get devices
Write-Output -InputObject "Attempting to retrieve devices"

#Configure Mail/SPO Properties
$Path = "$env:TEMP"
$FileSuffix = Get-Date -format "yyyyMMdd-HHmmss"
$IntuneReport = "$Path\Intune_Enrollment_Report_$FileSuffix.csv"

$SiteURL = Get-AutomationVariable -Name SPOGlobalPlanningSiteUrl
$SiteURL2 = Get-AutomationVariable -Name SPPowerBISiteURL
$DestinationPath = Get-AutomationVariable -Name SPOGlobalPlanningDestinationPathTMP3
$DestinationPath2 = Get-AutomationVariable -Name SPPowerBIEnrollmentDestinationPathTMP

function Get-ManagedDevice {

[cmdletbinding()]

param
(
    $managedDeviceId
)

    try {
        $Resource = "deviceManagement/managedDevices/$managedDeviceId"
        $uri = "https://graph.microsoft.com/beta/$($Resource)" 
        (Invoke-RestMethod -Uri $uri -Headers authToken -Method Get)

    } catch {
        Write-Output "No managed device found or insufficient permissions"
    }
}

# Get all Autopilot devices
$APDevices = @()
$uri = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities"

$APDevicesResponse = (Invoke-RestMethod -Uri $uri -Headers authToken -Method Get)
$APDevices = $APDevicesResponse.value | Select-Object Select-Object serialNumber,groupTag,model,enrollmentState,managedDeviceId
$APDevicesNextLink = $APDevicesResponse."@odata.nextLink"
while ($null -ne $APDevicesNextLink) {
    $APDevicesResponse = (Invoke-RestMethod -Uri $APDevicesNextLink -Headers authToken -Method Get)
    $APDevicesNextLink = $APDevicesResponse."@odata.nextLink"
    $APDevices += $APDevicesResponse.value | Select-Object serialNumber,groupTag,model,enrollmentState,managedDeviceId
}

Set-Content -Path $IntuneReport -Value "Serial;Model;GroupTag;enrollmentState;Devicename;userPrincipalName;userDisplayName;Enrollment_Date;Time;Enrolled;OSVersion"

# Check if Autopilot device is enrolled and get info
Write-Output "Creating the list..." -ForegroundColor yellow

$DeviceCount = $null
Foreach ($APDevice in $APDevices){
    if ($apdevice.managedDeviceId -ne "00000000-0000-0000-0000-000000000000"){

        $Device = Get-ManagedDevice -managedDeviceId $apdevice.managedDeviceId | Select-Object deviceName,userPrincipalName,osVersion,managedDeviceName,enrolledDateTime
        $DeviceCount += +1

        Try {
            $EnrollmentDate = ((($device.managedDeviceName -split "_").Item(2)) -split "/").item(1) + "-" + ((($device.managedDeviceName -split "_").Item(2)) -split "/").item(0)+ "-" + ((($device.managedDeviceName -split "_").Item(2)) -split "/").item(2)
            $Time = ($device.managedDeviceName -split "_").Item(3)
        }
        Catch{
            $EnrollmentDate = ((($device.managedDeviceName -split "_").Item(3)) -split "/").item(1) + "-" + ((($device.managedDeviceName -split "_").Item(3)) -split "/").item(0)+ "-" + ((($device.managedDeviceName -split "_").Item(3)) -split "/").item(2)
            $Time = ($device.managedDeviceName -split "_").Item(4)
        }
        $lastSyncDate = ((($device.lastSyncDateTime-split "T").Item(0)) -split "-").item(2) + "-" + ((($device.lastSyncDateTime-split "T").Item(0)) -split "-").item(1) + "-" + ((($device.lastSyncDateTime-split "T").Item(0)) -split "-").item(0)
        "{0};{1};{2};{3};{4};{5};{6};{7};{8};{9};{10}" -f $APdevice.serialNumber,$APDevice.model,$APDevice.groupTag,$APDevice.enrollmentState,$device.deviceName,$device.userPrincipalName,$device.userDisplayName,$EnrollmentDate,$Time,$device.enrolledDateTime,$device.osVersion | Add-Content -Path $IntuneReport

    }
    Else {
        "{0};{1};{2};{3};{4};{5};{6};{7};{8};{9};{10}" -f $APdevice.serialNumber,$APDevice.model,$APDevice.groupTag,$APDevice.enrollmentState,"","","","","","","" | Add-Content -Path $IntuneReport
        }
}

$APDevcount = @($APdevices).Count

Write-Output "There are" $DeviceCount "out of" $APDevcount "devices enrolled..." -ForegroundColor green

.\GEN_Upload_to_SPO.ps1 -filename $Filename -siteurl $SiteURL -destinationpath $DestinationPath
.\GEN_Upload_to_SPP.ps1 -filename $Filename -siteurl $SiteURL2 -destinationpath $DestinationPath2