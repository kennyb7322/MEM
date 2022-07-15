#Requires -Module  AzAccount, AzureAD

<#PSScriptInfo
.VERSION 1.0
.AUTHOR Ivo Uenk
.RELEASENOTES

#>
<#
.SYNOPSIS
Get HardwareID's from Blob storage and import in MEM.
.DESCRIPTION
Get AutoPilot device information from Azure Blob Storage and import device in MEM.
AutoPilot service via Intune API running from a Azure Automation runbook and Cleanup Blob Storage.
.NOTES
  Version:        1.0
  Author:         Ivo Uenk
  Creation Date:  2022-07-09
  Purpose/Change: Initial script development
#>

$intuneAutomationCredential = Get-AutomationPSCredential -Name 'AutomationCreds'
$userName = $intuneAutomationCredential.UserName  
$securePassword = $intuneAutomationCredential.Password
$psCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $userName, $securePassword 
$intuneAutomationAppId = Get-AutomationVariable -Name Microsoft Graph PowerShell
$tenant = Get-AutomationVariable -Name TenantId

# Get connection info for storage account
$StorageAccountName = Get-AutomationVariable -Name 'StorageAccountName'
$ContainerName = Get-AutomationVariable -Name 'ContainerName'
$StorageKey = Get-AutomationVariable -Name 'StorageKey'

function Get-AuthToken {

    try {
        $AadModule = Import-Module -Name AzureAD -ErrorAction Stop -PassThru
    }
    catch {
        throw 'AzureAD PowerShell module is not installed!'
    }

    $intuneAutomationCredential = Get-AutomationPSCredential -Name automation
    $intuneAutomationAppId = Get-AutomationVariable -Name IntuneClientId
    $tenant = Get-AutomationVariable -Name Tenant

    $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
    $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    $resourceAppIdURI = "https://graph.microsoft.com" 
    $authority = "https://login.microsoftonline.com/$tenant"
        
    try {
        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority 
        $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"
        $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($intuneAutomationCredential.Username, "OptionalDisplayableId")   
        $userCredentials = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.UserPasswordCredential -ArgumentList $intuneAutomationCredential.Username, $intuneAutomationCredential.Password
        $authResult = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContextIntegratedAuthExtensions]::AcquireTokenAsync($authContext, $resourceAppIdURI, $intuneAutomationAppId, $userCredentials);

        if ($authResult.Result.AccessToken) {
            $authHeader = @{
                'Content-Type'  = 'application/json'
                'Authorization' = "Bearer " + $authResult.Result.AccessToken
                'ExpiresOn'     = $authResult.Result.ExpiresOn
            }
            return $authHeader
        }
        elseif ($authResult.Exception) {
            throw "An error occured getting access token: $($authResult.Exception.InnerException)"
        }
    }
    catch { 
        throw $_.Exception.Message 
    }
}


function Connect-AutoPilotIntune {

    if($global:authToken){
        $DateTime = (Get-Date).ToUniversalTime()
        $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

        if($TokenExpires -le 0){
            Write-Output "Authentication Token expired" $TokenExpires "minutes ago"
            $global:authToken = Get-AuthToken
        }
    }
    else {
        $global:authToken = Get-AuthToken
    }
}

# Connect to Microsoft services
Connect-AzAccount -Credential $psCredential

# Get connection info for storage account
$accountContext = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageKey

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
            $response = Invoke-RestMethod -Uri $uri -Headers @{"Authorization" = "Bearer $AccessToken"} -Method Get
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
        $response = Invoke-RestMethod -Uri $uri -Headers @{"Authorization" = "Bearer $AccessToken"} -Method Get
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
            Invoke-RestMethod -Uri $uri -Headers @{"Authorization" = "Bearer $AccessToken"} -Method Post -Body $json -ContentType "application/json"
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
            Invoke-RestMethod -Uri $uri -Headers @{"Authorization" = "Bearer $AccessToken"} -Method Delete | Out-Null
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
        $response = Invoke-RestMethod -Uri $uri -Headers @{"Authorization" = "Bearer $AccessToken"} -Method Post
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

$countOnline = $(Get-AzStorageContainer -Container $ContainerName -Context $accountContext | Get-AzStorageBlob | Measure-Object).Count
if ($countOnline -gt 0) {
    Get-AzStorageContainer -Container $ContainerName -Context $accountContext | Get-AzStorageBlob | Get-AzStorageBlobContent -Force -Destination $PathCsvFiles | Out-Null

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