. .\GEN_Run_Env.ps1
. .\GEN_GraphAPI_RO.ps1

# Get devices
Write-Output -InputObject "Attempting to retrieve devices"

#Configure Mail/SPO Properties
$Path = "$env:TEMP"
$FileSuffix = Get-Date -format "yyyyMMdd-HHmmss"
$FullReport = "$Path\Enrollment_Full_Report.csv"
$FullReportDate = "$Path\Enrollment_Full_Report_$FileSuffix.csv"

$SiteURL = Get-AutomationVariable -Name SPOEnrollmentSiteUrl
$DestinationPath = Get-AutomationVariable -Name SPOEnrollmentDestinationPath

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

    } catch {
        Write-Output "No managed device found or insufficient permissions"
    }
}

# Get all Autopilot devices
$APDevices = @()
$uri = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities"

$APDevicesResponse = (Invoke-RestMethod -Uri $uri -Headers $authHeader -Method Get)
$APDevices = $APDevicesResponse.value | Select-Object serialNumber,managedDeviceId,azureAdDeviceId,groupTag,model,enrollmentState,deploymentProfileAssignedDateTime,deploymentProfileAssignmentStatus
$APDevicesNextLink = $APDevicesResponse."@odata.nextLink"
while ($null -ne $APDevicesNextLink) {
    $APDevicesResponse = (Invoke-RestMethod -Uri $APDevicesNextLink -Headers $authHeader -Method Get)
    $APDevicesNextLink = $APDevicesResponse."@odata.nextLink"
    $APDevices += $APDevicesResponse.value | Select-Object serialNumber,managedDeviceId,azureAdDeviceId,groupTag,model,enrollmentState,deploymentProfileAssignedDateTime,deploymentProfileAssignmentStatus
}

Set-Content -Path $FullReport -Value "Serial;Intune_ID;Azure_ID;Devicename;GroupTag;OSVersion;lastSyncDate;enrollmentState;userPrincipalName;Enrollement_Date;Time;Enrolled;Model;deploymentProfileAssignedDateTime;deploymentProfileAssignmentStatus;OwnerType;ManagementState;ManagementAgent;ComplianceState;JoinType"

# Check if Autopilot device is enrolled and get info
Write-Output "Creating the list..." -ForegroundColor yellow

$DeviceCount = $null
Foreach ($APDevice in $APDevices){
    if ($apdevice.managedDeviceId -ne "00000000-0000-0000-0000-000000000000"){

        $Device = Get-ManagedDevice -managedDeviceId $apdevice.managedDeviceId | Select-Object id,enrolledDateTime,deviceName,userPrincipalName,osVersion,ownerType,managementState,managementAgent,complianceState,lastSyncDateTime,managedDeviceName,joinType
        $DeviceCount += +1

        # Reset EnrollmentDate and Time for devices that are not in MEM but have managedDeviceId
        $EnrollmentDate = $null
        $Time = $null

		Try {
			$EnrollmentDate = ((($device.managedDeviceName -split "_").Item(2)) -split "/").item(1) + "-" + ((($device.managedDeviceName -split "_").Item(2)) -split "/").item(0) + "-" + ((($device.managedDeviceName -split "_").Item(2)) -split "/").item(2)
			$Time = ($device.managedDeviceName -split "_").Item(3)
			$lastSyncDate = ((($device.lastSyncDateTime-split "T").Item(0)) -split "-").item(2) + "-" + ((($device.lastSyncDateTime-split "T").Item(0)) -split "-").item(1) + "-" + ((($device.lastSyncDateTime-split "T").Item(0)) -split "-").item(0)	
		
        } Catch [System.Management.Automation.GetValueInvocationException]{

			Try {
				$EnrollmentDate = ((($device.managedDeviceName -split "_").Item(3)) -split "/").item(1) + "-" + ((($device.managedDeviceName -split "_").Item(3)) -split "/").item(0) + "-" + ((($device.managedDeviceName -split "_").Item(3)) -split "/").item(2)
				$Time = ($device.managedDeviceName -split "_").Item(4)
			
            } Catch [System.Management.Automation.GetValueInvocationException] {}
		}

        "{0};{1};{2};{3};{4};{5};{6};{7};{8};{9};{10};{11};{12};{13};{14};{15};{16};{17};{18};{19}" -f $APdevice.serialNumber,$Device.id,$APDevice.azureAdDeviceId,$device.deviceName,$APDevice.groupTag,$device.osVersion,$lastSyncDate,$APdevice.enrollmentState,$device.userPrincipalName,$EnrollmentDate,$Time,$device.enrolledDateTime,$APdevice.model,$APDevice.deploymentProfileAssignedDateTime,$APdevice.deploymentProfileAssignmentStatus,$device.ownerType,$device.managementState,$device.managementAgent,$device.complianceState,$device.joinType | Add-Content -Path $FullReport		
	}

    Else {
    	"{0};{1};{2};{3};{4};{5};{6};{7};{8};{9};{10};{11};{12};{13};{14};{15};{16};{17};{18};{19}" -f $APdevice.serialNumber,"",$APDevice.azureAdDeviceId,"",$APDevice.groupTag,"","",$APdevice.enrollmentState,"","","","",$APdevice.model,$APDevice.deploymentProfileAssignedDateTime,$APdevice.deploymentProfileAssignmentStatus,"","","","","" | Add-Content -Path $FullReport
    }
}

$APDevcount = @($APdevices).Count

Write-Output "There are" $DeviceCount "out of" $APDevcount "devices enrolled..." -ForegroundColor green

Copy-Item $FullReport $FullReportDate

.\GEN_Upload_to_SPO.ps1 -filename $FullReportDate -siteurl $SiteURL -destinationpath $DestinationPath
.\GEN_Upload_to_SPO.ps1 -filename $FullReport -siteurl $SiteURL -destinationpath $DestinationPath

# Cleanup files used for process
$ItemsToRemove = @($FullReportDate,$FullReport)
Foreach ($Item in $ItemsToRemove){
    Try {
        Remove-item $Item
    } Catch {
        #Item already removed or cannot be found
    }
}