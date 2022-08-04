using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

# Write to the Azure Functions log stream.
Write-Host "PowerShell HTTP trigger function processed a request."

# Pre logic

# Storage account
$StorageAccountName = $env:StorageAccountName
$ContainerName = $env:ContainerName
$StorageKey = $env:StorageKey

$PathCsvFiles = "$env:TEMP"
$CombinedOutput = "$pathCsvFiles\combined.csv"
$LogFile = $PathCsvFiles + "\" + "Autopilot-Actions" + (Get-Date -UFormat "%d-%m-%Y") + ".log"

$accountContext = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageKey

# Interact with query parameters or the body of the request.
$Scope = $Request.Query.Scope
if (-not $Scope) {
    $Scope = $Request.Body.Scope
}
#If parameter "Scope" has not been provided, we assume that graph.microsoft.com is the target resource
If (!$Scope) {
    $Scope = "https://graph.microsoft.com/"
}

#Add .net core library
$authNdllPath = '.\bin\Debug\net6.0\publish\Microsoft.Azure.Services.AppAuthentication.dll'
add-type -Path $authNdllPath
$tokenProvider = New-Object Microsoft.Azure.Services.AppAuthentication.AzureServiceTokenProvider('')
$accessToken = ($tokenProvider.GetAccessTokenAsync("$Scope")).Result

$authHeader = @{
    'Content-Type'='application/json'
    'Authorization'='Bearer ' +  $accessToken
}

# End Pre logic

# Functions

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
            $response = Invoke-RestMethod -Uri $uri -Headers $authHeader -Method Get
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
        $response = Invoke-RestMethod -Uri $uri -Headers $authHeader -Method Get
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
            $response = Invoke-RestMethod -Uri $uri -Headers $authHeader -Method Get
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
            Invoke-RestMethod -Uri $uri -Headers $authHeader -Method Post -Body $json -ContentType "application/json"
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
            Invoke-RestMethod -Uri $uri -Headers $authHeader -Method Delete | Out-Null
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

        foreach ($device in $devices | Where-Object {$device.'Device Serial Number' -in $global:correctDevices}) {
        $Serial = $device.'Device Serial Number'
        Add-AutoPilotImportedDevice -serialNumber $Serial -hardwareIdentifier $device.'Hardware Hash' -orderIdentifier $orderIdentifier -groupTag $device.'Group Tag'
        Write-Log -LogOutput ("Importing device: $Serial") -Path $LogFile
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
        $response = Invoke-RestMethod -Uri $uri -Headers $authHeader -Method Post
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

            Write-Verbose "Hardware report ran successfully for device: $Serial"
            Write-Log -LogOutput ("Hardware report ran successfully for device: $Serial") -Path $LogFile

            $obj = new-object psobject -Property @{
                SerialNumber = $s.v
                Model = $m.v
                GroupTag = $device.'Group Tag'
                TPMVersion = $t.v
            }
            $global:AutopilotImports += $obj
        }
        Catch {
            Write-Verbose "Bad hardware hash for device: $Serial"
            Write-Log -LogOutput ("Bad hardware hash for device: $Serial") -Path $LogFile
            $obj = new-object psobject -Property @{
                SerialNumber = $Serial
                groupTag = $Device.'Group Tag'
                Error = "Bad hardware hash"
            }
            $global:badDevices += $obj           
        }
    }
}

# End Functions

# Main logic
$global:totalCount = 0

$PathCsvFiles = "$env:TEMP"
$OA3ToolPath = "$pathCsvFiles\oa3tool.exe"
$XMLFile = $pathCsvFiles + "\" + "Autopilot" + ".xml"
$LogFile = $PathCsvFiles + "\" + "Autopilot-Actions" + "-" + ((Get-Date).ToString("dd-MM-yyyy-HHmm")) + ".log"
$checkedCombinedOutput = "$pathCsvFiles\checkedcombinedoutput.csv"
$wrongCombinedOutput = "$pathCsvFiles\wrongcombinedoutput.csv"

# Check if parameters are correct
$mList = @('HP EliteBook','HP ProBook','HP ProDesk','HP Z4 G4','HP ZBook','Latitude') # Check modellist
$lList = @('A-CDS-O-P-L','A-CDS-O-C-L','A-CDS-O-C-D') # Check part of Group Tag
$cList = @('AE','AU','BE','BG','BR','CH','CZ','DE','ES','FR','CB','HK','HU','ID','IE','IT','JP','KR','LK','LU','NL','PH','PL','RO','RU','SG','SK','TW','UA','US','VN') # Check part of Group Tag
$eList = @('00','01','91','92','93','94','95','96','97','98','99') # Check part of Group Tag

$countOnline = $(Get-AzStorageContainer -Container $ContainerName -Context $accountContext | Get-AzStorageBlob | Where-Object {$_.Name -notlike "*BadDevices*"} | Measure-Object).Count
if ($countOnline -gt 0) {
    Get-AzStorageContainer -Container $ContainerName -Context $accountContext | Get-AzStorageBlob | Where-Object {$_.Name -notlike "*BadDevices*"} | Get-AzStorageBlobContent -Force -Destination $PathCsvFiles | Out-Null

    # Intune has a limit for 175 rows as maximum allowed import currently! We select max 175 csv files to combine them
    $downloadFiles = Get-ChildItem -Path $PathCsvFiles -Filter "*.csv" | Select-Object -First 175

    Set-Content -Path $CheckedCombinedOutput -Value "Device Serial Number,Windows Product ID,Hardware Hash,Group Tag" -Encoding Unicode
    Set-Content -Path $wrongCombinedOutput -Value "Device Serial Number,Windows Product ID,Hardware Hash,Group Tag" -Encoding Unicode

    $gclist = @()
    $gelist = @()

    Foreach ($downloadFile in $downloadFiles) {
        
        # Get real owner from file propIndex 10
        $f = get-childitem ($pathCsvFiles + "\" + $downloadFile.name)
        $o = (New-Object -ComObject Shell.Application).NameSpace((Split-Path $f))
        $Owner = $o.GetDetailsOf($o.ParseName((Split-Path -Leaf $f)),10)
        $Entries = Import-Csv -path $f 

        # Get owner GSAFO1-CMW-Intune-Device-Operator groups assignments
        $UPN = (Get-AzureADUser -Filter "mailNickname eq '$($Owner.Split('\')[1])'").UserPrincipalName
        $Groups = (Get-AzureADUser -ObjectId $UPN | Get-AzureADUserMembership | Where-Object {$_.DisplayName -like "GSAFO1-CMW-Intune-Device-Operator*"}).DisplayName

        Foreach ($Group in $Groups){

            $g = "{0}-{1}-{2}-{3}-{4}-{5}-{6}" -f $Group.Split('-')
            $gc = $g.Split("-")[-2] # NL
            $ge = $g.Split("-")[-1] # 00
        
            $gclist += $gc
            $gelist += $ge
            }

        Foreach ($Entry in $Entries){

            $ps = $entry.'Device Serial Number'

            $p = $entry.'Group Tag'
            $d = "{0}-{1}-{2}-{3}-{4}" -f $p.Split('-')
            $tc = $p.Split("-")[-2] # NL
            $te = $p.Split("-")[-1] # 00    

            If (($tc -in $gclist) -and ($te -in $gelist)){
                "{0},{1},{2},{3}" -f $ps,$entry.'Windows Product ID',$Entry.'Hardware Hash',$p | Add-Content -Path $CheckedCombinedOutput -Encoding Unicode

                Write-Output "$UPN has permission on $p add $ps to import list"
                Write-Log -LogOutput ("$UPN has permission on $p add $ps to import list") -Path $LogFile
            }
            
            Else {
                "{0},{1},{2},{3}" -f $ps,$entry.'Windows Product ID',$Entry.'Hardware Hash',$p | Add-Content -Path $wrongCombinedOutput -Encoding Unicode

                Write-Output "$UPN no permission on $p do not import $ps"
                Write-Log -LogOutput ("$UPN no permission on $p do not import $ps") -Path $LogFile

                #Mail de owner $upn dat het niet goed is gegaan voor $checkedFile
            }     
        }
    }
}

# Import combined CSV
if (Test-Path $checkedCombinedOutput) {
	Get-HardwareInfo -csvFile $checkedCombinedOutput -OA3ToolPath $OA3ToolPath -LogFile $LogFile -XMLFile $XMLFile
    Write-Verbose "Get HardwareInfo..."
    Write-Log -LogOutput ("Get HardwareInfo...") -Path $LogFile

    foreach ($AutopilotImport in $global:AutopilotImports){
    $Serial = $AutopilotImport.SerialNumber
    # Check if Group Tag is set correctly
        Try {
        $i = $AutopilotImport.GroupTag
        $d = "{0}-{1}-{2}-{3}-{4}" -f $i.Split('-')
        $c = $i.Split("-")[-2] # NL
        $e = $i.Split("-")[-1] # 00
            
            # Check conditions
            if (($d -in $lList) -and ($c -in $cList) -and ($e -in $eList) `
            -and ($AutopilotImport.Model -in $mList) `
            -and ($AutopilotImport.SerialNumber -eq $Serial) `
            -and ($AutopilotImport.TPMVersion -like "*2.0*")){
            
            # Conditions are met add device
            $correctDevices += $AutopilotImport.SerialNumber
            Write-Verbose "Device: $Serial added to import list"
            Write-Log -LogOutput ("Device: $Serial added to import list") -Path $LogFile
            }                            
       
            Else {

                $ErrorGroupTag = "(Bad Grouptag)"
                $ErrorModel = if($AutopilotImport.Model -notin $mList){"(Bad Model)"}
                $ErrorSerial = if($AutopilotImport.SerialNumber -ne $Serial){"(Bad SerialNumber)"}
                $ErrorTMP = if($AutopilotImport.TPMVersion -notlike "*2.0*"){"(Bad TPM)"}

                $obj = new-object psobject -Property @{
                    SerialNumber = $Serial
                    groupTag = $AutopilotImport.GroupTag
                    model = $AutopilotImport.Model
                    TPMVersion = $AutopilotImport.TPMVersion
                    Error = $ErrorSerial+$ErrorModel+$ErrorGroupTag+$ErrorTMP
                }

                $global:badDevices += $obj
                Write-Verbose "Bad device: $Serial error $ErrorSerial$ErrorModel$ErrorGroupTag$ErrorTMP"
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
            Write-Verbose "Bad device: $Serial error $ErrorCode"
            Write-Log -LogOutput ("Bad device: $Serial error $ErrorCode") -Path $LogFile    
            }
     }
}
       
else {
    Write-Verbose "Nothing to import."
}


# Add a batch of AutoPilot devices
if(!$correctDevices){
    Write-Verbose "Nothing to import."
    Write-Log -LogOutput ("Nothing to import.") -Path $LogFile
}

Else {
    Import-AutoPilotCSV $CombinedOutput -LogFile $LogFile
    Write-Verbose "Entries found start importing devices..."
    Write-Log -LogOutput ("Entries found start importing devices...") -Path $LogFile
}

Write-Verbose "Finished main logic."
Write-Log -LogOutput ("Finished main logic.") -Path $LogFile
# End main logic

# Post logic

# Online blob storage cleanup
$downloadFilesSearchableByName = @{}
$downloadFilesSearchableBySerialNumber = @{}

    ForEach ($downloadFile in $downloadFiles) {
    $serialNumber = $(Get-Content $downloadFile.FullName | Select-Object -Index 1 ).Split(',')[0]

    $downloadFilesSearchableBySerialNumber.Add($serialNumber, $downloadFile.Name)
    $downloadFilesSearchableByName.Add($downloadFile.Name, $serialNumber)
}
$serialNumber = $null

$csvBlobs = Get-AzStorageContainer -Container $ContainerName -Context $accountContext | Get-AzStorageBlob | Where-Object {$_.Name -notlike "*BadDevices*"} | Where-Object {$_.Name -like "*.csv"}
    
ForEach ($csvBlob in $csvBlobs) {

    $ImportFile = $csvBlob.Name
    $serialNumber = $downloadFilesSearchableByName[$csvBlob.Name]

    if ($serialNumber) {
        ForEach ($number in $global:errorList.Keys){
            if ($number -eq $serialNumber){
                $Errorcode = "Error during import"
                if ($global:errorList[$number].deviceErrorCode -eq 806) {
                    $Errorcode = "Device already imported"
                    }
                }
                             
                $obj = new-object psobject -Property @{
                SerialNumber = $number
                Error = $ErrorCode
                }

                $badImports += $obj
        }  
           
     }          
     
     Remove-AzStorageBlob -Container $ContainerName -Blob $csvBlob.Name -Context $accountContext
     Write-Verbose "Remove $ImportFile from container: $ContainerName."
     Write-Log -LogOutput ("Remove $ImportFile from container: $ContainerName.") -Path $LogFile         
}


# Export Autopilot import errors and upload to Azure Storage
$ErrorsFilename = "Autopilot-Import-BadDevices" + "-" + ((Get-Date).ToString("dd-MM-yyyy-HHmm")) + ".csv"
$ErrorsFilePath = Join-Path $PathCsvFiles -ChildPath $ErrorsFilename
$LogFilename = "Autopilot-Actions" + "-" + ((Get-Date).ToString("dd-MM-yyyy-HHmm")) + ".log"

If(!$badDevices){
    Write-Verbose "No bad devices found."
    Write-Log -LogOutput ("No bad devices found.") -Path $LogFile
}

Else {
	$badDevices | Select-Object SerialNumber, Model, GroupTag, TPMVersion, Error  | Export-Csv -Path $ErrorsFilePath -Delimiter ";" -NoTypeInformation
    Set-AzStorageBlobContent -Container $ContainerName -File $ErrorsFilePath -Blob $ErrorsFilename -Context $accountContext
    Write-Verbose "Bad devices found creating log file."
    Write-Log -LogOutput ("Bad devices found creating log file.") -Path $LogFile
}

Write-Verbose "Finished post logic."
Write-Log -LogOutput ("Finished post logic.") -Path $LogFile

Set-AzStorageBlobContent -Container $ContainerName -File $LogFile -Blob $LogFilename -Context $accountContext

# End post logic

