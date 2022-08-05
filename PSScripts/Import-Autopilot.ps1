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
  Creation Date:  2022-07-28
  Purpose/Change: Initial script development
#>

# Pre logic

# Credentials
$intuneAutomationCredential = Get-AutomationPSCredential -Name "AutomationCreds"
$userName = $intuneAutomationCredential.UserName  
$securePassword = $intuneAutomationCredential.Password
$psCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $userName, $securePassword 

# Variables from automation
$StorageAccountName = Get-AutomationVariable -Name 'StorageAccountName'
$ContainerName = Get-AutomationVariable -Name 'ContainerName'
$StorageKey = Get-AutomationVariable -Name 'StorageKey'

# Connect to Microsoft services
Connect-AzureAD -Credential $psCredential

# SharePoint Import folder
$SiteURL = "https://ucorponline.sharepoint.com/sites/intune"
Connect-PnPOnline -Url $SiteURL -Credentials $psCredential

# End Pre logic

# Functions

function Get-AuthToken {

    try {
        $AadModule = Import-Module -Name AzureAD -ErrorAction Stop -PassThru
    }
    catch {
        throw 'AzureAD PowerShell module is not installed!'
    }

    $intuneAutomationCredential = Get-AutomationPSCredential -Name "AutomationCreds"
    $intuneAutomationAppId = Get-AutomationVariable -Name 'MicrosoftIntunePowershell'
    $tenant = Get-AutomationVariable -Name 'TenantId'

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
            $response = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
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
        $response = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
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

Function Get-AutoPilotDeviceIdentities(){
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
            $response = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
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
        [Parameter(Mandatory=$true)] $groupTag,
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
    "groupTag": "$groupTag",
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
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $json -ContentType "application/json"
        }
        catch {
            
            # If already exists Invoke-RestMethod update for example group tag
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
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Delete | Out-Null
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
        [Parameter(Mandatory=$true)] $LogFile,
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

        foreach ($device in $devices | Where-Object {$device.'Device Serial Number' -in $correctDevices}) {
        $Serial = $device.'Device Serial Number'
        Add-AutoPilotImportedDevice -serialNumber $Serial -hardwareIdentifier $device.'Hardware Hash' -orderIdentifier $orderIdentifier -groupTag $device.'Group Tag'
        Write-Log -LogOutput ("Importing device: $Serial") -Path $LogFile
        }

        # While we could keep a list of all the IDs that we added and then check each one, it is easier to just loop through all of them
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

        # Generate some statistics for reporting
        $global:totalCount = $deviceStatuses.Count
        $global:successCount = 0
        $global:errorCount = 0
        $global:softErrorCount = 0
        $global:errorList = @{}

        ForEach ($deviceStatus in $deviceStatuses) {
        $Device = $deviceStatus.serialNumber

        if (($($deviceStatus.state.deviceImportStatus).ToLower() -eq 'success' -or $($deviceStatus.state.deviceImportStatus).ToLower() -eq 'complete'))  {
            $global:successCount += 1
            Write-Log -LogOutput ("Import completed for device: $Device") -Path $LogFile

        } elseif ($($deviceStatus.state.deviceImportStatus).ToLower() -eq 'error') {
            $global:errorCount += 1
            # ZtdDeviceAlreadyAssigned will be counted as soft error, free to delete
            Write-Log -LogOutput ("Import failed for device $Device") -Path $LogFile

            if ($($deviceStatus.state.deviceErrorCode) -eq 806) {
                $global:softErrorCount += 1
                Write-Log -LogOutput ("Device already exist: $Device") -Path $LogFile
                }

            $global:errorList.Add($deviceStatus.serialNumber, $devicestatus.state)
            }
        }

        # Display the statuses
        $deviceStatuses | ForEach-Object {
            Write-Output "Serial number $($_.serialNumber): $($_.groupTag), $($_.state.deviceImportStatus), $($_.state.deviceErrorCode), $($_.state.deviceErrorName)"
        }

        # Cleanup the imported device records
        $deviceStatuses | ForEach-Object {
            Remove-AutoPilotImportedDevice -id $_.id
        }

		# Sync new devices to Intune
		Write-output "Triggering Sync to Intune."
        Write-Log -LogOutput ("Triggering sync to Intune after imports") -Path $LogFile
		Invoke-AutopilotSync

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
        $response = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post
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

Function Write-Log{
	param (
        [Parameter(Mandatory=$True)]
        [array]$LogOutput,
        [Parameter(Mandatory=$True)]
        [string]$Path
	)
	$currentDate = (Get-Date -UFormat "%d-%m-%Y")
	$currentTime = (Get-Date -UFormat "%T")
	$logOutput = $logOutput -join (" ")
	"[$currentDate $currentTime] $logOutput" | Out-File $Path -Append
}

Function Get-HardwareInfo(){
    [CmdletBinding(DefaultParameterSetName="OA3ToolPath",
                   SupportsShouldProcess=$true,
                   PositionalBinding=$true
                  )]
    Param(
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
                  
        $OA3ToolPath,
        [Parameter(Mandatory=$true)] $csvFile,
        [Parameter(Mandatory=$true)] $XMLFile,
        [Parameter(Mandatory=$true)] $LogFile
    )

        # Read CSV and process each device
        $devices = Import-CSV $csvFile
        $global:AutopilotImports = @()
        $global:badDevices = @()

        Foreach ($Device in $Devices){
        $Serial = $device.'Device Serial Number'
        
        Try {
            $Hash = $device.'Hardware Hash'
            Start-Process -FilePath $OA3ToolPath -ArgumentList "/DecodeHwHash=$Hash /LogTrace=$XMLFile" -Wait
            [xml]$xmldata = Get-Content -Path $XMLFile -raw
            $h = [xml]$xmldata
        
            $s = $h.HardwareReport.HardwareInventory.p | Where-Object {$_.n -eq "SmbiosSystemSerialNumber"}
            $m = $h.HardwareReport.HardwareInventory.p | Where-Object {$_.n -eq "SmbiosSystemProductName"}
            $t = $h.HardwareReport.HardwareInventory.p | Where-Object {$_.n -eq "TPMVersion"}

            $obj = new-object psobject -Property @{
                SerialNumber = $s.v
                Model = $m.v
                GroupTag = $device.'Group Tag'
                TPMVersion = $t.v
                Owner = $device.'Owner'
            }
            $global:AutopilotImports += $obj

            Write-Output "Hardware report ran successfully for device: $Serial"
            Write-Log -LogOutput ("Hardware report ran successfully for device: $Serial") -Path $LogFile
        }
        
        Catch {
            $obj = new-object psobject -Property @{
                SerialNumber = $s.v
                Model = $m.v
                groupTag = $Device.'Group Tag'
                TPMVersion = $t.v
                Owner = $device.'Owner'
                Error = "Bad hardware hash"
            }
            $global:badDevices += $obj
            
            Write-Output "Bad hardware hash for device: $Serial"
            Write-Log -LogOutput ("Bad hardware hash for device: $Serial") -Path $LogFile
        }
    }
}

# End Functions

# Main logic
$global:totalCount = 0
Connect-AutoPilotIntune

# Declare checklists
$mList = @('HP EliteBook','HP ProBook','HP ProDesk','HP Z4 G4','HP ZBook','Latitude') # Check Model
$lList = @('A-CDS-O-P-L','A-CDS-O-C-L','A-CDS-O-C-D') # Check first part of Group Tag
$cList = @('AE','AU','BE','BG','BR','CH','CZ','DE','ES','FR','CB','HK','HU','ID','IE','IT','JP','KR','LK','LU','NL','PH','PL','RO','RU','SG','SK','TW','UA','US','VN') # Check Country
$eList = @('00','01','91','92','93','94','95','96','97','98','99') # Check Entity

# Define file path
$PathCsvFiles = "$env:TEMP"
$checkedCombinedOutput = "$pathCsvFiles\checkedcombinedoutput.csv"
$badCombinedOutput = "$pathCsvFiles\badCombinedOutput.csv"
$importFolderName = "/Shared Documents/ImportAutopilotDevice"
$importedFolderName = "/Shared Documents/ImportAutopilotDevice/Import"
$folderItems = Get-PnPFolderItem -FolderSiteRelativeUrl $folderName -ItemType File
$OA3ToolPath = "$pathCsvFiles\oa3tool.exe"
$XMLFile = $pathCsvFiles + "\" + "Autopilot" + ".xml"
$LogFile = $PathCsvFiles + "\" + "Autopilot-Actions" + "-" + ((Get-Date).ToString("dd-MM-yyyy-HHmm")) + ".log"

### Start downloading files
$su = $SiteURL.split("/",4)[-1]
$CSVtoImport = @()

foreach($item in $folderItems){
    # Get filename and createdby
    $FileRelativeURL = ("/" + $su + $importFolderName + "/" + $item.Name)
    $File = Get-PnPFile -Url "$FileRelativeURL" -AsListItem

    $obj = new-object psobject -Property @{
        FileName = $File["FileLeafRef"]
        CreatedBy = $File["Created_x0020_By"].Split("|",3)[-1]
    }
    $CSVtoImport += $obj

    # download the file
    Get-PnPFile -Url $FileRelativeURL -Path $PathCsvFiles -FileName $item.Name -AsFile -Force
    Write-Output "File $item.Name downloaded to $PathCsvFiles"
    Write-Log -LogOutput ("File $item.Name downloaded to $PathCsvFiles") -Path $LogFile

    # move the file to imported items
    $result = Move-PnPFile -SourceUrl ($importFolderName + "/" + $item.Name) -TargetUrl $importedFolderName -NoWait
    $jobStatus = Receive-PnPCopyMoveJobStatus -Job $result
    
    if($jobStatus.JobState == 0){
    Write-Output "File $item.Name moved to imported items"
    Write-Log -LogOutput ("File $item.Name moved to imported items") -Path $LogFile
    }
}
### End downloading files

$gclist = @()
$gelist = @()

### First stage permission check
Set-Content -Path $CheckedCombinedOutput -Value "Device Serial Number,Windows Product ID,Hardware Hash,Group Tag" -Encoding Unicode
Set-Content -Path $badCombinedOutput -Value "Device Serial Number,Windows Product ID,Hardware Hash,Group Tag,Owner" -Encoding Unicode

Foreach ($CSV in $CSVtoImport) {
    $pathCSV = get-childitem ($pathCsvFiles + "\" + $CSV.FileName)
    $ownerCSV = $CSV.CreatedBy
    $Entries = Import-Csv -path $pathCSV 

    # Get owner GSAFO1-CMW-Intune-Device-Operator groups assignments
    $Groups = (Get-AzureADUser -ObjectId $ownerCSV | Get-AzureADUserMembership | Where-Object {$_.DisplayName -like "GSAFO1-CMW-Intune-Device-Operator*"}).DisplayName

    Foreach ($Group in $Groups){
        $g = "{0}-{1}-{2}-{3}-{4}-{5}-{6}" -f $Group.Split('-')
        $gc = $g.Split("-")[-2] # Get country group
        $ge = $g.Split("-")[-1] # Get entity group
        
        $gclist += $gc
        $gelist += $ge
        }

    Foreach ($Entry in $Entries){
        $es = $entry.'Device Serial Number'
        $et = $entry.'Group Tag'
        $e = "{0}-{1}-{2}-{3}-{4}" -f $et.Split('-')
        $tc = $e.Split("-")[-2] # Get country tag
        $te = $e.Split("-")[-1] # Get entity tag    

        # Correct entries will be added to the CheckedCombinedOutput list
        If (($tc -in $gclist) -and ($te -in $gelist)){
            "{0},{1},{2},{3},{4}" -f $es,$entry.'Windows Product ID',$Entry.'Hardware Hash',$et,$ownerCSV | Add-Content -Path $CheckedCombinedOutput -Encoding Unicode

            Write-Output "$ownerCSV has permission on $et add $es to import list"
            Write-Log -LogOutput ("$ownerCSV has permission on $et add $es to import list") -Path $LogFile
        }
        # Bad entries will be added to the CheckedCombinedOutput list   
        Else {
            "{0},{1},{2},{3},{4}" -f $es,$entry.'Windows Product ID',$Entry.'Hardware Hash',$et,$ownerCSV | Add-Content -Path $badCombinedOutput -Encoding Unicode

            Write-Output "$ownerCSV no permission on $et do not import $es"
            Write-Log -LogOutput ("$ownerCSV no permission on $et do not import $es") -Path $LogFile
            #Mail de owner $upn dat het niet goed is gegaan voor $checkedFile
        }     
    }
}

Write-Output "End first stage permission check"
Write-Log -LogOutput ("End first stage permission check") -Path $LogFile
### End first stage permission check

### Second stage get hardware info for CheckedCombinedOutput 
# CheckedCombinedOutput is emtpy remove it
$emptyCheck = Import-CSV $checkedCombinedOutput
If (!$emptyCheck) {Remove-item $checkedCombinedOutput -ErrorAction SilentlyContinue}

if (Test-Path $checkedCombinedOutput) {
    # Download oa3tool.exe
    $accountContext = New-AzureStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageKey
    Get-AzureStorageContainer -Container $ContainerName -Context $accountContext | Get-AzureStorageBlob | Where-Object {$_.Name -eq "oa3tool.exe"} | `
    Get-AzureStorageBlobContent -Force -Destination $PathCsvFiles | Out-Null

	Get-HardwareInfo -csvFile $CheckedCombinedOutput -OA3ToolPath $OA3ToolPath -LogFile $LogFile -XMLFile $XMLFile
    Write-Log -LogOutput ("Get HardwareInfo...") -Path $LogFile

    $correctDevices = @()

    foreach ($AutopilotImport in $global:AutopilotImports){
    $Serial = $AutopilotImport.SerialNumber
    # Check if Group Tag is set correctly
        Try {
        $at = $AutopilotImport.GroupTag
        $l = "{0}-{1}-{2}-{3}-{4}" -f $at.Split('-')
        $c = $at.Split("-")[-2] # Get country tag
        $e = $at.Split("-")[-1] # Get entity tag
            
            # Check if conditions are met
            if ((($l -in $lList) -and ($c -in $cList) -and ($e -in $eList)) `
            -and ($AutopilotImport.Model -in $mList) `
            -and ($AutopilotImport.SerialNumber -eq $Serial) `
            -and ($AutopilotImport.TPMVersion -like "*2.0*")){

            $obj = new-object psobject -Property @{
                SerialNumber = $Serial
                groupTag = $AutopilotImport.GroupTag
                model = $AutopilotImport.Model
                TPMVersion = $AutopilotImport.TPMVersion
                Owner = $AutopilotImport.Owner
            }
            # Conditions are met add device
            $correctDevices += $obj

            Write-Output "Device: $Serial added to import list"
            Write-Log -LogOutput ("Device: $Serial added to import list") -Path $LogFile
            }                            
       
            Else {
                $ErrorGroupTag = if(($l -in $lList) -and ($c -in $cList) -and ($e -in $eList)){"(Bad Grouptag)"}
                $ErrorModel = if($AutopilotImport.Model -notin $mList){"(Bad Model)"}
                $ErrorSerial = if($AutopilotImport.SerialNumber -ne $Serial){"(Bad SerialNumber)"}
                $ErrorTMP = if($AutopilotImport.TPMVersion -notlike "*2.0*"){"(Bad TPM)"}

                $obj = new-object psobject -Property @{
                    SerialNumber = $Serial
                    groupTag = $AutopilotImport.GroupTag
                    model = $AutopilotImport.Model
                    TPMVersion = $AutopilotImport.TPMVersion
                    Owner = $AutopilotImport.Owner
                    Error = $ErrorSerial+$ErrorModel+$ErrorGroupTag+$ErrorTMP
                }
                # Conditions are not met add device
                $global:badDevices += $obj

                Write-Output "Bad device: $Serial error $ErrorSerial$ErrorModel$ErrorGroupTag$ErrorTMP"
                Write-Log -LogOutput ("Bad device: $Serial error $ErrorSerial$ErrorModel$ErrorGroupTag$ErrorTMP") -Path $LogFile
            }
        }

        Catch {
            $ErrorCode = if(!$AutopilotImport.GroupTag){"(No Grouptag)"}
            $ErrorCode = if($AutopilotImport.GroupTag){"(Bad Grouptag)"}

            $obj = new-object psobject -Property @{
                SerialNumber = $Serial
                groupTag = $AutopilotImport.GroupTag
                model = $AutopilotImport.Model
                TPMVersion = $AutopilotImport.TPMVersion
                Error = $ErrorCode
            }

            # Add wrong group tag devices to list below
            $global:badDevices += $obj

            Write-Output "Bad device: $Serial error $ErrorCode"
            Write-Log -LogOutput ("Bad device: $Serial error $ErrorCode") -Path $LogFile    
        }
    }
}
       
else {
    Write-Output "Nothing to import due to bad permissions..."
    Write-Log -LogOutput ("Nothing to import due to bad permissions...") -Path $LogFile   
}

Write-Output "End second stage get hardware info"
Write-Log -LogOutput ("End second stage get hardware info") -Path $LogFile
### End second stage get hardware info

### Third stage importing devices in Autopilot
if(!$correctDevices){
    Write-Output "Nothing to import due to bad hardware info..."
    Write-Log -LogOutput ("Nothing to import due to bad hardware info...") -Path $LogFile
}

# $correctDevices staat nu de waarheid in over wat geimporteerd is
# $global:badDevices staat nu de waarheid in over wat niet gelukt is

Else {
    Import-AutoPilotCSV $CheckedCombinedOutput -LogFile $LogFile
    Write-Log -LogOutput ("Entries found start importing devices...") -Path $LogFile
}

Write-Output "End third stage importing devices in Autopilot"
Write-Log -LogOutput ("End third stage importing devices in Autopilot") -Path $LogFile
### End third stage importing devices in Autopilot

# Post logic

# Online blob storage cleanup
#$downloadFilesSearchableByName = @{}
#$downloadFilesSearchableBySerialNumber = @{}

#    ForEach ($CSV in $CSVtoImport) {
#    $serialNumber = $(Get-Content ($pathCsvFiles + "\" + $CSV.FileName) | Select-Object -Index 1 ).Split(',')[0]

#    $downloadFilesSearchableBySerialNumber.Add($serialNumber, $downloadFile.Name)
#    $downloadFilesSearchableByName.Add($downloadFile.Name, $serialNumber)
#}
#$serialNumber = $null

#$downloadedFiles = get-childitem $pathCsvFiles | Where-Object {$_.Name -like "*.csv"}
    
#ForEach ($file in $downloadedFiles) {

#    $ImportFile = $file.name
#    $serialNumber = $downloadFilesSearchableByName[$csvBlob.Name]

#    if ($serialNumber) {
#        ForEach ($number in $global:errorList.Keys){
#            if ($number -eq $serialNumber){
#                $Errorcode = "Error during import"
#                if ($global:errorList[$number].deviceErrorCode -eq 806) {
#                    $Errorcode = "Device already imported"
#                    }
#                }
#                             
#                $obj = new-object psobject -Property @{
#                SerialNumber = $number
#                Error = $ErrorCode
#                }
#                $badImports += $obj
#        }  
#           
#     }          
#     
#     Remove-AzStorageBlob -Container $ContainerName -Blob $csvBlob.Name -Context $accountContext
#     Write-Log -LogOutput ("Remove $ImportFile from container: $ContainerName.") -Path $LogFile         
#}

# Export Autopilot import errors and upload to Azure Storage
$ImportBadDevices = "Autopilot-Import-BadDevices" + "-" + ((Get-Date).ToString("dd-MM-yyyy-HHmm")) + ".csv"
$ImportErrors = "Autopilot-Import-Errors" + "-" + ((Get-Date).ToString("dd-MM-yyyy-HHmm")) + ".csv"
$ImportBadDevicesPath = Join-Path $PathCsvFiles -ChildPath $ImportBadDevices
$ImportErrorsPath = Join-Path $PathCsvFiles -ChildPath $ImportErrors

$LogFilename = "Autopilot-Actions" + "-" + ((Get-Date).ToString("dd-MM-yyyy-HHmm")) + ".log"
$checkedCombinedOutputName = "checkedcombinedoutput" + "-" + ((Get-Date).ToString("dd-MM-yyyy-HHmm")) + ".csv"
$badCombinedOutputName = "badCombinedOutput" + "-" + ((Get-Date).ToString("dd-MM-yyyy-HHmm")) + ".csv"

If(!$badDevices){Write-Log -LogOutput ("No bad devices found.") -Path $LogFile}

Else {
	$badDevices | Select-Object SerialNumber, Model, GroupTag, TPMVersion, Error  | Export-Csv -Path $ImportBadDevicesPath -Delimiter ";" -NoTypeInformation
    Set-AzureStorageBlobContent -Container $ContainerName -File $ErrorsFilePath -Blob $ErrorsFilename -Context $accountContext
    Write-Log -LogOutput ("Bad devices found creating log file.") -Path $LogFile
}

If(!$badImports){Write-Log -LogOutput ("No import errors found.") -Path $LogFile}

Else {
	$badImports | Select-Object SerialNumber, Error  | Export-Csv -Path $ImportErrorsPath -Delimiter ";" -NoTypeInformation
    Set-AzureStorageBlobContent -Container $ContainerName -File $ErrorsFilePath -Blob $ErrorsFilename -Context $accountContext
    Write-Log -LogOutput ("Bad devices found creating log file.") -Path $LogFile
}

Write-Output "Finished post logic."
Write-Log -LogOutput ("Finished post logic.") -Path $LogFile

# Upload log file
Set-AzureStorageBlobContent -Container $ContainerName -File $LogFile -Blob $LogFilename -Context $accountContext
Set-AzureStorageBlobContent -Container $ContainerName -File $checkedCombinedOutput -Blob $checkedCombinedOutputName -Context $accountContext
Set-AzureStorageBlobContent -Container $ContainerName -File $badCombinedOutput -Blob $badCombinedOutputName -Context $accountContext

$ItemsToRemove = @($CheckedCombinedOutput,$badCombinedOutput,$LogFile,$OA3ToolPath)
Foreach ($Item in $ItemsToRemove){Remove-item $Item -ErrorAction SilentlyContinue}
Foreach ($CSV in $CSVtoImport) {Remove-item ($pathCsvFiles + "\" + $CSV.FileName) -ErrorAction SilentlyContinue}

# End post logic