<#
Version: 1.0
Author:  Oliver Kieselbach
Runbook: Import-AutoPilotInfo

Description:
Get AutoPilot device information from Azure Blob Storage and import device to Intune 
AutoPilot service via Intune API running from a Azure Automation runbook.
Cleanup Blob Storage and send import notification to a Microsoft Teams channel.

Release notes:
Version 1.0: Original published version.

The script is provided "AS IS" with no warranties.
#>

####################################################

# Based on PowerShell Gallery WindowsAutoPilotIntune 
# https://www.powershellgallery.com/packages/WindowsAutoPilotIntune
# modified to support unattended authentication within a runbook

# Get automation account credentials
$credential = Get-AutomationPSCredential -Name 'AutomationCreds' 
$userName = $credential.UserName  
$securePassword = $credential.Password
$psCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $userName, $securePassword

# Connect to Microsoft services
Connect-AzAccount -Credential $psCredential
Connect-AzureAD -Credential $psCredential

# Get MS graph API connection
$TenantID = Get-AutomationVariable -Name 'TenantId' 
$AppId = Get-AutomationVariable -Name 'AppId' 
$AppSecret = Get-AutomationVariable -Name 'AppSecret'

$authString = "https://login.microsoftonline.com/$TenantID" 
$authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext"-ArgumentList $authString
$creds = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential" -ArgumentList $AppId, $AppSecret
$context = $authContext.AcquireTokenAsync("https://graph.microsoft.com/", $creds).Result
$AccessToken = $context.AccessToken

# Get connection info for storage account
$StorageAccountName = Get-AutomationVariable -Name 'StorageAccountName'
$ContainerName = Get-AutomationVariable -Name 'ContainerName'
$StorageKey = Get-AutomationVariable -Name 'StorageKey'
$accountContext = New-AzureStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageKey

Function Get-AutoPilotDevice(){
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$false)] $id
    )
    
        # Defining Variables
        $graphApiVersion = "beta"
        $Resource = "deviceManagement/windowsAutopilotDeviceIdentities"
    
        if ($id) {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$id"
        }
        else {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        }
        try {
            $response = (Invoke-RestMethod -Uri $uri -Headers @{"Authorization" = "Bearer $AccessToken"} -Method Get).value
            if ($id) {
                $response
            }
            else {
                $response.Value
            }
        }
        catch {
    
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
    
            Write-Output "Response content:`n$responseBody"
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    
            break
        }
    
    }
    
Function Get-AutoPilotImportedDevice(){
[cmdletbinding()]
param
(
    [Parameter(Mandatory=$false)] $id
)

    # Defining Variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/importedWindowsAutopilotDeviceIdentities"

    if ($id) {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$id"
    }
    else {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    }
    try {
        $response = (Invoke-RestMethod -Uri $uri -Headers @{"Authorization" = "Bearer $AccessToken"} -Method Get).value
        if ($id) {
            $response
        }
        else {
            $response.Value
        }
    }
    catch {

        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();

        Write-Output "Response content:`n$responseBody"
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"

        #break
        # in case we cannot verify we exit the script to prevent cleanups and loosing of .csv files in the blob storage
        Exit
    }

}

Function Add-AutoPilotImportedDevice(){
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)] $serialNumber,
        [Parameter(Mandatory=$true)] $hardwareIdentifier,
        [Parameter(Mandatory=$false)] $orderIdentifier = ""
    )
    
        # Defining Variables
        $graphApiVersion = "beta"
        $Resource = "deviceManagement/importedWindowsAutopilotDeviceIdentities"
    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        $json = @"
{
    "@odata.type": "#microsoft.graph.importedWindowsAutopilotDeviceIdentity",
    "orderIdentifier": "$orderIdentifier",
    "serialNumber": "$serialNumber",
    "productKey": "",
    "hardwareIdentifier": "$hardwareIdentifier",
    "state": {
        "@odata.type": "microsoft.graph.importedWindowsAutopilotDeviceIdentityState",
        "deviceImportStatus": "pending",
        "deviceRegistrationId": "",
        "deviceErrorCode": 0,
        "deviceErrorName": ""
        }
}
"@

        try {
            (Invoke-RestMethod -Uri $uri -Headers -Body $json -ContentType "application/json" @{"Authorization" = "Bearer $AccessToken"} -Method Post).Value
        }
        catch {
    
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
    
            Write-Output "Response content:`n$responseBody"
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    
            break
        }
    
    }

Function Remove-AutoPilotImportedDevice(){
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)] $id
    )

        # Defining Variables
        $graphApiVersion = "beta"
        $Resource = "deviceManagement/importedWindowsAutopilotDeviceIdentities"    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$id"

        try {
            (Invoke-RestMethod -Uri $uri -Headers @{"Authorization" = "Bearer $AccessToken"} -Method Delete).Value | Out-Null
        }
        catch {
    
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
    
            Write-Output "Response content:`n$responseBody"
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    
            break
        }
        
}

Function Import-AutoPilotCSV(){
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory=$true)] $csvFile,
        [Parameter(Mandatory=$false)] $orderIdentifier = ""
    )

        $deviceStatusesInitial = Get-AutoPilotImportedDevice
        $deviceCountInitial = $deviceStatusesInitial.Length
        if ($deviceCountInitial -ge 175) {
            Write-Output "Previous cleanup didn't work, stopping any further actions to prevent filling up Autopilot imported device space!"
            Exit
        }

        # Read CSV and process each device
        $devices = Import-CSV $csvFile
        foreach ($device in $devices) {
            Add-AutoPilotImportedDevice -serialNumber $device.'Device Serial Number' -hardwareIdentifier $device.'Hardware Hash' -orderIdentifier $orderIdentifier
        }

        # While we could keep a list of all the IDs that we added and then check each one, it is 
        # easier to just loop through all of them
        $processingCount = 1
        while ($processingCount -gt 0)
        {
            $deviceStatuses = Get-AutoPilotImportedDevice
            $deviceCount = $deviceStatuses.Length

            # Check to see if any devices are still processing (enhanced by check for pending)
            $processingCount = 0
            foreach ($device in $deviceStatuses){
                if ($($device.state.deviceImportStatus).ToLower() -eq "unknown" -or $($device.state.deviceImportStatus).ToLower() -eq "pending") {
                    $processingCount = $processingCount + 1
                }
            }
            Write-Output "Waiting for $processingCount of $deviceCount"

            # Still processing?  Sleep before trying again.
            if ($processingCount -gt 0){
                Start-Sleep 15
            }
        }

        # Generate some statistics for reporting...
        $global:totalCount = $deviceStatuses.Count
        $global:successCount = 0
        $global:errorCount = 0
        $global:softErrorCount = 0
        $global:errorList = @{}

        ForEach ($deviceStatus in $deviceStatuses) {
            if ($($deviceStatus.state.deviceImportStatus).ToLower() -eq 'success' -or $($deviceStatus.state.deviceImportStatus).ToLower() -eq 'complete') {
                $global:successCount += 1
            } elseif ($($deviceStatus.state.deviceImportStatus).ToLower() -eq 'error') {
                $global:errorCount += 1
                # ZtdDeviceAlreadyAssigned will be counted as soft error, free to delete
                if ($($deviceStatus.state.deviceErrorCode) -eq 806) {
                    $global:softErrorCount += 1
                }
                $global:errorList.Add($deviceStatus.serialNumber, $deviceStatus.state)
            }
        }

        # Display the statuses
        $deviceStatuses | ForEach-Object {
            Write-Output "Serial number $($_.serialNumber): $($_.state.deviceImportStatus), $($_.state.deviceErrorCode), $($_.state.deviceErrorName)"
        }

        # Cleanup the imported device records
        $deviceStatuses | ForEach-Object {
            Remove-AutoPilotImportedDevice -id $_.id
        }
}

Function Invoke-AutopilotSync(){
[cmdletbinding()]
param
(
)
    # Defining Variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/windowsAutopilotSettings/sync"

    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    try {
        $response = (Invoke-RestMethod -Uri $uri -Headers @{"Authorization" = "Bearer $AccessToken"} -Method Post).Value
        $response.Value
    }
    catch {

        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();

        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"

        break
    }

}

$global:totalCount = 0

$CurrentJobId= $PSPrivateMetadata.JobId.Guid
Write-Output "Current Job ID: '$CurrentJobId'"

#Get Automation account and resource group names
$AutomationAccounts = Get-AzAutomationAccount
foreach ($item in $AutomationAccounts) {
    # Loop through each Automation account to find this job
    $Job = Get-AzAutomationJob -ResourceGroupName $item.ResourceGroupName -AutomationAccountName $item.AutomationAccountName -Id $CurrentJobId -ErrorAction SilentlyContinue
    if ($Job) {
        $AutomationAccountName = $item.AutomationAccountName
        $ResourceGroupName = $item.ResourceGroupName
        $RunbookName = $Job.RunbookName
        break
    }
}
Write-Output "Automation Account Name: '$AutomationAccountName'"
Write-Output "Resource Group Name: '$ResourceGroupName'"
Write-Output "Runbook Name: '$RunbookName'"

#Check if the runbook is already running
if ($RunbookName) {
    $CurrentRunningJobs = Get-AzAutomationJob -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -RunbookName $RunbookName | Where-object {($_.Status -imatch '\w+ing$' -or $_.Status -imatch 'queued') -and $_.JobId.tostring() -ine $CurrentJobId}
    If ($CurrentRunningJobs) {
        Write-output "Active runbook job detected."
        Foreach ($job in $CurrentRunningJobs) {
            Write-Output " - JobId: $($job.JobId), Status: '$($job.Status)'."
        }
        Write-output "The runbook job will stop now."
        Exit
    } else {
        Write-Output "No concurrent runbook jobs found. OK to continue."
    }
}
else {
    Write-output "Runbook not found will stop now."
    Exit
}

# Main logic
$PathCsvFiles = "$env:TEMP"
$CombinedOutput = "$pathCsvFiles\combined.csv"

$countOnline = $(Get-AzureStorageContainer -Container $ContainerName -Context $accountContext | Get-AzureStorageBlob | Measure-Object).Count
if ($countOnline -gt 0) {
    Get-AzureStorageContainer -Container $ContainerName -Context $accountContext | Get-AzureStorageBlob | Get-AzureStorageBlobContent -Force -Destination $PathCsvFiles | Out-Null

    # Intune has a limit for 175 rows as maximum allowed import currently! We select max 175 csv files to combine them
    $downloadFiles = Get-ChildItem -Path $PathCsvFiles -Filter "*.csv" | Select-Object -First 175

    # parse all .csv files and combine to single one for batch upload!
    Set-Content -Path $CombinedOutput -Value "Device Serial Number,Windows Product ID,Hardware Hash" -Encoding Unicode
    $downloadFiles | ForEach-Object { Get-Content $_.FullName | Select-Object -Index 1 } | Add-Content -Path $CombinedOutput -Encoding Unicode
}

if (Test-Path $CombinedOutput) {
    # measure import timespan
    $importStartTime = Get-Date

    # Add a batch of AutoPilot devices
    Import-AutoPilotCSV $CombinedOutput

    # calculate import timespan
    $importEndTime = Get-Date
    $importTotalTime = $importEndTime - $importStartTime
    $importTotalTime = "$($importTotalTime.Hours):$($importTotalTime.Minutes):$($importTotalTime.Seconds)s"

    # Online blob storage cleanup, leave error device .csv files there expect it's ZtdDeviceAlreadyAssigned error
    # in case of error someone needs to check manually but we inform via Teams message later in the runbook
    $downloadFilesSearchableByName = @{}
    $downloadFilesSearchableBySerialNumber = @{}

    ForEach ($downloadFile in $downloadFiles) {
        $serialNumber = $(Get-Content $downloadFile.FullName | Select -Index 1 ).Split(',')[0]

        $downloadFilesSearchableBySerialNumber.Add($serialNumber, $downloadFile.Name)
        $downloadFilesSearchableByName.Add($downloadFile.Name, $serialNumber)
    }
    $serialNumber = $null

    $csvBlobs = Get-AzStorageContainer -Container $ContainerName -Context $accountContext | Get-AzStorageBlob 
    ForEach ($csvBlob in $csvBlobs) {
        $serialNumber = $downloadFilesSearchableByName[$csvBlob.Name]

        $isErrorDevice = $false
        $isSafeToDelete = $false

        if ($serialNumber) {
            ForEach ($number in $global:errorList.Keys){
                if ($number -eq $serialNumber) {
                    $isErrorDevice = $true
                    if ($global:errorList[$number].deviceErrorCode -eq 806) {
                        $isSafeToDelete = $true
                    }
                }
            }
            
            if (-not $isErrorDevice -or $isSafeToDelete) {
                Remove-AzStorageBlob -Container $ContainerName -Blob $csvBlob.Name-Context $accountContext
            }
        }
    }

    # Sync new devices to Intune
    Write-output "Triggering Sync to Intune."
    Invoke-AutopilotSync
}
else {
    Write-Output ""
    Write-Output "Nothing to import."
}

Write-Output "Finish"