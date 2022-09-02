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
        (Invoke-RestMethod -Uri $uri -Headers $authHeader -Method Get)

    } catch {}
}

# Get all Autopilot devices
$APDevices = @()
$uri = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities"

$APDevicesResponse = (Invoke-RestMethod -Uri $uri -Headers $authHeader -Method Get)
$APDevices = $APDevicesResponse.value | Select-Object serialNumber,groupTag,model,enrollmentState,managedDeviceId
$APDevicesNextLink = $APDevicesResponse."@odata.nextLink"
while ($null -ne $APDevicesNextLink) {
    $APDevicesResponse = (Invoke-RestMethod -Uri $APDevicesNextLink -Headers $authHeader -Method Get)
    $APDevicesNextLink = $APDevicesResponse."@odata.nextLink"
    $APDevices += $APDevicesResponse.value | Select-Object serialNumber,groupTag,model,enrollmentState,managedDeviceId
}

# Create CSV file where data will be written to
Set-Content -Path $IntuneReport -Value "Serial;Model;GroupTag;enrollmentState;Devicename;userPrincipalName;userDisplayName;Enrollment_Date;Time;Enrolled;OSVersion"

# Check if Autopilot device is enrolled and get info
Write-Output "Creating the list..." -ForegroundColor yellow

Foreach ($APDevice in $APDevices){
    # managedDeviceId 00000000-0000-0000-0000-000000000000 is in 99% of the cases not managed in MEM will increase speed
    if ($apdevice.managedDeviceId -ne "00000000-0000-0000-0000-000000000000"){
        
        $Device = Get-ManagedDevice -managedDeviceId $apdevice.managedDeviceId | Select-Object deviceName,userPrincipalName,userDisplayName,osVersion,managedDeviceName,enrolledDateTime
        $DeviceCount += +1

        # Reset EnrollmentDate and Time for devices that are not in MEM but have managedDeviceId
        $EnrollmentDate = $null
        $Time = $null

        Try {
            $EnrollmentDate = ((($device.managedDeviceName -split "_").Item(2)) -split "/").item(1) + "-" + ((($device.managedDeviceName -split "_").Item(2)) -split "/").item(0) + "-" + ((($device.managedDeviceName -split "_").Item(2)) -split "/").item(2)
            $Time = ($device.managedDeviceName -split "_").Item(3)

            Try {
                $EnrollmentDate = ((($device.managedDeviceName -split "_").Item(3)) -split "/").item(1) + "-" + ((($device.managedDeviceName -split "_").Item(3)) -split "/").item(0) + "-" + ((($device.managedDeviceName -split "_").Item(3)) -split "/").item(2)
                $Time = ($device.managedDeviceName -split "_").Item(4)
            }
            # Only use catch for catching error messages don't do actions here
            Catch [System.Management.Automation.GetValueInvocationException]{
            }
        }
        Catch [System.Management.Automation.GetValueInvocationException]{
        }

        # Otherwise userDisplayName will be insterted into two columns
        $userDisplayName = ($device.userDisplayName -replace (',', '.'))

        "{0};{1};{2};{3};{4};{5};{6};{7};{8};{9};{10}" -f $APdevice.serialNumber,$APDevice.model,$APDevice.groupTag,$APDevice.enrollmentState,$device.deviceName,$device.userPrincipalName,$userDisplayName,$EnrollmentDate,$Time,$device.enrolledDateTime,$device.osVersion | Add-Content -Path $IntuneReport

    }
    Else {
        "{0};{1};{2};{3};{4};{5};{6};{7};{8};{9};{10}" -f $APdevice.serialNumber,$APDevice.model,$APDevice.groupTag,$APDevice.enrollmentState,"","","","","","","" | Add-Content -Path $IntuneReport
        }
}

$APDevcount = @($APdevices).Count

Write-Output "There are" $DeviceCount "out of" $APDevcount "devices enrolled..." -ForegroundColor green

.\GEN_Upload_to_SPO.ps1 -filename $IntuneReport -siteurl $SiteURL -destinationpath $DestinationPath
.\GEN_Upload_to_SPP.ps1 -filename $IntuneReport -siteurl $SiteURL2 -destinationpath $DestinationPath2

# Cleanup files used for process
Try {
    Remove-item $IntuneReport
} Catch {
    #Item already removed or cannot be found
}