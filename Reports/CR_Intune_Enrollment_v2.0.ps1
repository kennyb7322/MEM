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

$uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?"

        $DevicesResponse = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get)
        $Devices = $DevicesResponse.value | Select-Object deviceName,Id,userPrincipalName,userDisplayName,osVersion,managedDeviceName,enrolledDateTime
        $DevicesNextLink = $DevicesResponse."@odata.nextLink"

        while ($null -ne $DevicesNextLink){
            $DevicesResponse = (Invoke-RestMethod -Uri $DevicesNextLink -Headers $authToken -Method Get)
            $DevicesNextLink = $DevicesResponse."@odata.nextLink"
            $Devices += $DevicesResponse.value | Select-Object deviceName,Id,userPrincipalName,userDisplayName,osVersion,managedDeviceName,enrolledDateTime
        }

$uri2 = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities"

        $APDevicesResponse = (Invoke-RestMethod -Uri $uri2 -Headers $authToken -Method Get)
        $APDevices = $APDevicesResponse.value | Select-Object serialNumber,groupTag,model,enrollmentState,managedDeviceId
        $APDevicesNextLink = $APDevicesResponse."@odata.nextLink"
        while ($null -ne $APDevicesNextLink) {
            $APDevicesResponse = (Invoke-RestMethod -Uri $APDevicesNextLink -Headers $authToken -Method Get)
            $APDevicesNextLink = $APDevicesResponse."@odata.nextLink"
            $APDevices += $APDevicesResponse.value | Select-Object serialNumber,groupTag,model,enrollmentState,managedDeviceId
            }

$DeviceCount = @($Devices).count
$APDevcount = @($APdevices).Count

# Check if Autopilot device is enrolled and get info
Write-Output "There are" $DeviceCount "out of" $APDevcount "devices enrolled..." -ForegroundColor green
Write-Output "Creating the list..." -ForegroundColor yellow

# Create CSV file where data will be written to
Set-Content -Path $IntuneReport -Value "Serial;Model;GroupTag;enrollmentState;Devicename;userPrincipalName;userDisplayName;Enrollement_Date;Time;Enrolled;OSVersion"

Foreach ($APDevice in $APDevices){
    if ($apdevice.managedDeviceId -ne "00000000-0000-0000-0000-000000000000"){

        $Device = $Devices | Where-Object Id -eq $apdevice.managedDeviceId | Select-Object deviceName,userPrincipalName,userDisplayName,osVersion,managedDeviceName,enrolledDateTime

        $EnrollmentDate = $null
        $Time = $null

        Try {
	        $EnrollmentDate = ((($device.managedDeviceName -split "_").Item(2)) -split "/").item(1) + "-" + ((($device.managedDeviceName -split "_").Item(2)) -split "/").item(0) + "-" + ((($device.managedDeviceName -split "_").Item(2)) -split "/").item(2)
	        $Time = ($device.managedDeviceName -split "_").Item(3)
		
        } Catch [System.Management.Automation.GetValueInvocationException]{

	        Try {
		        $EnrollmentDate = ((($device.managedDeviceName -split "_").Item(3)) -split "/").item(1) + "-" + ((($device.managedDeviceName -split "_").Item(3)) -split "/").item(0) + "-" + ((($device.managedDeviceName -split "_").Item(3)) -split "/").item(2)
		        $Time = ($device.managedDeviceName -split "_").Item(4)
			
            } Catch [System.Management.Automation.GetValueInvocationException] {}
        }

        # Otherwise userDisplayName will be insterted into two columns
        $userDisplayName = ($device.userDisplayName -replace (',', '.'))

        "{0};{1};{2};{3};{4};{5};{6};{7};{8};{9};{10}" -f $APdevice.serialNumber,$APDevice.model,$APDevice.groupTag,$APDevice.enrollmentState,$device.deviceName,$device.userPrincipalName,$userDisplayName,$EnrollmentDate,$Time,$device.enrolledDateTime,$device.osVersion | Add-Content -Path $IntuneReport
    }
    
    Else {
        "{0};{1};{2};{3};{4};{5};{6};{7};{8};{9};{10}" -f $APdevice.serialNumber,$APDevice.model,$APDevice.groupTag,$APDevice.enrollmentState,"","","","","","","" | Add-Content -Path $IntuneReport
    }
}

.\GEN_Upload_to_SPO.ps1 -filename $IntuneReport -siteurl $SiteURL -destinationpath $DestinationPath
.\GEN_Upload_to_SPP.ps1 -filename $IntuneReport -siteurl $SiteURL2 -destinationpath $DestinationPath2

# Cleanup files used for process
Try {
    Remove-item $IntuneReport
} Catch {
    #Item already removed or cannot be found
}