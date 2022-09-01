#Requires -Module  PnP.PowerShell, AzureAD

<#PSScriptInfo
.VERSION 1.0
.AUTHOR Ivo Uenk
.RELEASENOTES

#>
<#
.SYNOPSIS
Get Autopilot CSV's from SharePoint and import in Autopilot with permission, condition and error check.
.DESCRIPTION
Get Autopilot CSV's from SharePoint and import in Autopilot with permission, condition and error check.
.NOTES
  Version:        1.1
  Author:         Ivo Uenk
  Creation Date:  2022-08-30
  Purpose/Change: Testing Pre-prod
#>

# Variables
$PathCsvFiles = "$env:TEMP"
$checkedCombinedOutput = "$pathCsvFiles\checkedcombinedoutput.csv"
$importFolderName = "/Shared Documents/ImportAutopilotDevice"
$sourcesFolderName = "/sites/intune/Shared Documents/ImportAutopilotDevice/Sources"
$importedFolderName = "/sites/intune/Shared Documents/ImportAutopilotDevice/Imported"
$errorsFolderName = "/sites/intune/Shared Documents/ImportAutopilotDevice/Errors"
$resourceFolderName = "/sites/intune/Shared Documents/ImportAutopilotDevice/Resources"
$LogFolderName = "/sites/intune/Shared Documents/ImportAutopilotDevice/Logging"
$oa3toolRelativeURL = $resourceFolderName + "/" + "oa3tool.exe"
$OA3ToolPath = "$pathCsvFiles\oa3tool.exe"
$XMLFile = $pathCsvFiles + "\" + "Autopilot" + ".xml"
$LogFile = $PathCsvFiles + "\" + "Autopilot-Actions" + "-" + ((Get-Date).ToString("dd-MM-yyyy-HHmm")) + ".log"
$MailSender = Get-AutomationVariable -Name "MailSender"

# Declare checklist
$Model = Get-AutomationVariable -Name "cModel"
$cModel = $Model.Split(",")
$Label = Get-AutomationVariable -Name "cLabel"
$cLabel = $Label.Split(",")
$Country = Get-AutomationVariable -Name "cCountry"
$cCountry = $Country.Split(",")
$Entity = Get-AutomationVariable -Name "cEntity"
$cEntity = $Entity.Split(",")

# Credentials
$intuneAutomationCredential = Get-AutomationPSCredential -Name "AutomationCreds"
$userName = $intuneAutomationCredential.UserName  
$securePassword = $intuneAutomationCredential.Password
$psCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $userName, $securePassword 

# Connect to Microsoft services
Connect-AzureAD -Credential $psCredential

$SiteURL = "https://ucorponline.sharepoint.com/sites/intune"
Connect-PnPOnline -Url $SiteURL -Credentials $psCredential
$folderItems = Get-PnPFolderItem -FolderSiteRelativeUrl $importFolderName -ItemType File

# Functions

function Get-AuthToken {

    try {
        $AadModule = Import-Module -Name AzureAD -ErrorAction Stop -PassThru
    }
    catch {
        throw 'AzureAD PowerShell module is not installed!'
    }

    $intuneAutomationCredential = Get-AutomationPSCredential -Name "AutomationCreds"
    $intuneAutomationAppId = Get-AutomationVariable -Name "MicrosoftIntunePowershell"
    $tenant = Get-AutomationVariable -Name "TenantId"

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
            Write-Log -LogOutput ("Previous cleanup didn't work, stopping any further actions to prevent filling up Autopilot imported device space!") -Path $LogFile
            Exit
        }
 
        # Read CSV and process each device
        $devices = Import-CSV $csvFile

        foreach ($device in $devices) {
        $Serial = $device.'Device Serial Number'
        Add-AutoPilotImportedDevice -serialNumber $Serial -hardwareIdentifier $device.'Hardware Hash' -orderIdentifier $orderIdentifier -groupTag $device.'Group Tag'
        Write-Log -LogOutput ("Importing device: $Serial.") -Path $LogFile
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
        $global:succesDevice = @()
        $global:successCount = 0
        $global:errorCount = 0
        $global:errorDevice = @()
        $global:softErrorCount = 0
        $global:softErrorDeviceAlreadyAssigned = @()
        $global:softErrorDeviceAssignedOtherTenant = @()
        $global:errorList = @{}

        ForEach ($deviceStatus in $deviceStatuses) {
        $Device = $deviceStatus.serialNumber

            if (($($deviceStatus.state.deviceImportStatus).ToLower() -eq 'success' -or $($deviceStatus.state.deviceImportStatus).ToLower() -eq 'complete'))  {
                $global:successCount += 1
                $global:successDevice += $device
                Write-Log -LogOutput ("Import completed for device: $Device.") -Path $LogFile

            } elseif ($($deviceStatus.state.deviceImportStatus).ToLower() -eq 'error') {
                $global:errorCount += 1
                $global:errorDevice += $Device
                # Device is already registered to the same Tenant
                Write-Log -LogOutput ("Import failed for device $Device.") -Path $LogFile

                if ($($deviceStatus.state.deviceErrorCode) -eq 806) {
                    $global:softErrorCount += 1
                    $global:softErrorDeviceAlreadyAssigned += $Device
                    Write-Log -LogOutput ("Device already exist in same tenant: $Device.") -Path $LogFile
                
                } elseif ($($deviceStatus.state.deviceErrorCode) -eq 808) {
                    $global:softErrorCount += 1
                    $global:softErrorDeviceAssignedOtherTenant += $Device
                    Write-Log -LogOutput ("Device is assigned to another tenant: $Device.") -Path $LogFile
                }
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
        Write-Log -LogOutput ("Triggering sync to Intune after imports.") -Path $LogFile
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
                WindowsProductID = $device.'Windows Product ID'
                Hash = $device.'Hardware Hash'
                Model = $m.v
                GroupTag = $device.'Group Tag'
                TPMVersion = $t.v
                Owner = $device.'Owner'
            }
            $global:AutopilotImports += $obj
            Write-Log -LogOutput ("Hardware report ran successfully for device: $Serial.") -Path $LogFile
        }
        
        Catch {
            $obj = new-object psobject -Property @{
                SerialNumber = $s.v
                WindowsProductID = $device.'Windows Product ID'
                Hash = $device.'Hardware Hash'
                Model = $m.v
                groupTag = $Device.'Group Tag'
                TPMVersion = $t.v
                Owner = $device.'Owner'
                Error = "Bad hardware hash"
            }
            $global:badDevices += $obj
            Write-Log -LogOutput ("Bad hardware hash for device: $Serial.") -Path $LogFile
        }
    }
}

Function Send-Mail{

    param(
	    [Parameter(Mandatory=$true)]$Recipient,
	    [Parameter(Mandatory=$true)]$MailSender,
        [Parameter(Mandatory=$false)]$RecipientCC,
        [Parameter(Mandatory=$true)][string]$Subject,
        [Parameter(Mandatory=$true)][string]$Body
    )


    $clientID = Get-AutomationVariable -Name "clientId"
    $ClientSecret = Get-AutomationVariable -Name "clientSecret"
    $tenantID = Get-AutomationVariable -Name "TenantId"
 
    #Connect to GRAPH API
    $tokenBody = @{
        Grant_Type    = "client_credentials"
        Scope         = "https://graph.microsoft.com/.default"
        Client_Id     = $clientId
        Client_Secret = $clientSecret
    }
    $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantID/oauth2/v2.0/token" -Method POST -Body $tokenBody
    $headers = @{
        "Authorization" = "Bearer $($tokenResponse.access_token)"
        "Content-type"  = "application/json"
    }
 
#Send Mail    
$URLsend = "https://graph.microsoft.com/v1.0/users/$MailSender/sendMail"
$BodyJsonsend = @"
                    {
                        "message": {
                          "subject": "$Subject",
                          "body": {
                            "contentType": "HTML",
                            "content": "$Body"
                          },
                          "toRecipients": [
                            {
                              "emailAddress": {
                                "address": "$Recipient"
                              }
                            }
                          ]
                        },
                        "saveToSentItems": "false"
                      }
"@
 
    Invoke-RestMethod -Method POST -Uri $URLsend -Headers $headers -Body $BodyJsonsend
}

# End Functions

### first stage: download and prepare files
# Start downloading files from SharePoint
$su = $SiteURL.split("/",4)[-1]
$CSVtoImport = @()

# Download oa3tool.exe
Get-PnPFile -Url $oa3toolRelativeURL -Path $PathCsvFiles -FileName "oa3tool.exe" -AsFile -Force

# Download CSV files from SharePoint
foreach($item in $folderItems){
    # Get filename and createdby
    $FileName = $item.Name
    $FileRelativeURL = ("/" + $su + $importFolderName + "/" + $FileName)
    $File = Get-PnPFile -Url "$FileRelativeURL" -AsListItem

    $obj = new-object psobject -Property @{
        FileName = $File["FileLeafRef"]
        CreatedBy = $File["Created_x0020_By"].Split("|",3)[-1]
    }
    $CSVtoImport += $obj

    Get-PnPFile -Url $FileRelativeURL -Path $PathCsvFiles -FileName $FileName -AsFile -Force
    Write-Log -LogOutput ("File $FileName downloaded to $PathCsvFiles.") -Path $LogFile
	
	# remove the file the downloaded file from SharePoint
	#Remove-PnPFile -ServerRelativeUrl $FileRelativeURL -Force
    $targetLibraryUrl = $sourcesFolderName + '/' + $FileName
    Move-PnPFile -SourceUrl $item.ServerRelativeUrl -TargetUrl $targetLibraryUrl -AllowSchemaMismatch -Force -Overwrite -AllowSmallerVersionLimitOnDestination  
}

Write-Log -LogOutput ("End first stage: download and prepare files.") -Path $LogFile
### End first stage: download and prepare files

### Second stage: permission check
$gcCountry = @()
$gcEntity = @()
$global:badDevices = @()

Set-Content -Path $CheckedCombinedOutput -Value "Device Serial Number,Windows Product ID,Hardware Hash,Group Tag,Owner" -Encoding Unicode

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
        
        $gcCountry += $gc
        $gcEntity += $ge
        }

    Foreach ($Entry in $Entries){

        if(!$entry.'Group Tag'){
            $es = $entry.'Device Serial Number'

            $obj = new-object psobject -Property @{
                SerialNumber = $es
                WindowsProductID = $entry.'Windows Product ID'
                Hash = $Entry.'Hardware Hash'
                groupTag = ""
                model = "Model not checked"
                TPMVersion = "TPM not checked"
                Owner = $ownerCSV
                Error = "(No grouptag)"
            }
            # Conditions are not met add device
            $global:badDevices += $obj
            Write-Log -LogOutput ("$ownerCSV no grouptag found do not import $es.") -Path $LogFile
        }
        Else {
            $es = $entry.'Device Serial Number'
            $et = $entry.'Group Tag'
            $e = "{0}-{1}-{2}-{3}-{4}" -f $et.Split('-')
            $tc = $et.Split("-")[-2] # Get country tag
            $te = $et.Split("-")[-1] # Get entity tag    

            # Correct entries will be added to the CheckedCombinedOutput list
            If (($tc -in $gcCountry) -and ($te -in $gcEntity)){
                "{0},{1},{2},{3},{4}" -f $es,$entry.'Windows Product ID',$Entry.'Hardware Hash',$et,$ownerCSV | Add-Content -Path $CheckedCombinedOutput -Encoding Unicode
                Write-Log -LogOutput ("$ownerCSV has permission on $et add $es to import list.") -Path $LogFile
            }
            # Bad entries will be added to the $global:badDevices variable 
            Else {
                $obj = new-object psobject -Property @{
                    SerialNumber = $es
                    WindowsProductID = $entry.'Windows Product ID'
                    Hash = $Entry.'Hardware Hash'
                    groupTag = $et
                    model = "Model not checked"
                    TPMVersion = "TPM not checked"
                    Owner = $ownerCSV
                    Error = "(No permissions)"
                }
                # Conditions are not met add device
                $global:badDevices += $obj
                Write-Log -LogOutput ("$ownerCSV no permission on $et do not import $es.") -Path $LogFile
            }
        }     
    }
}

Write-Log -LogOutput ("End second stage: permission check.") -Path $LogFile
### End second stage: permission check

### Third stage: get hardware info and check if conditions are met
$emptyCheck = Import-CSV $checkedCombinedOutput

If (!$emptyCheck){
    Remove-item $checkedCombinedOutput -ErrorAction SilentlyContinue
}
Else {
    if (Test-Path $checkedCombinedOutput) {
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
                if ((($l -in $cLabel) -and ($c -in $cCountry) -and ($e -in $cEntity)) `
                -and ($AutopilotImport.Model -in $cModel) `
                -and ($AutopilotImport.SerialNumber -eq $Serial) `
                -and ($AutopilotImport.TPMVersion -like "*2.0*")){

                $obj = new-object psobject -Property @{
                    SerialNumber = $Serial
                    WindowsProductID = $AutopilotImport.WindowsProductID
                    Hash = $AutopilotImport.Hash
                    groupTag = $AutopilotImport.GroupTag
                    model = $AutopilotImport.Model
                    TPMVersion = $AutopilotImport.TPMVersion
                    Owner = $AutopilotImport.Owner
                }
                # Conditions are met add device
                $correctDevices += $obj

                Write-Log -LogOutput ("Device: $Serial conditions are met remain on import list.") -Path $LogFile
                }                            
       
                Else {
                    $ErrorGroupTag = if(!($l -in $cLabel) -and ($c -in $cCountry) -and ($e -in $cEntity)){"(Bad Grouptag)"}
                    $ErrorModel = if($AutopilotImport.Model -notin $cModel){"(Bad Model)"}
                    $ErrorSerial = if($AutopilotImport.SerialNumber -ne $Serial){"(Bad SerialNumber)"}
                    $ErrorTMP = if($AutopilotImport.TPMVersion -notlike "*2.0*"){"(Bad TPM)"}

                    $obj = new-object psobject -Property @{
                        SerialNumber = $Serial
                        WindowsProductID = $AutopilotImport.WindowsProductID
                        Hash = $AutopilotImport.Hash
                        groupTag = $AutopilotImport.GroupTag
                        model = $AutopilotImport.Model
                        TPMVersion = $AutopilotImport.TPMVersion
                        Owner = $AutopilotImport.Owner
                        Error = $ErrorSerial+$ErrorModel+$ErrorGroupTag+$ErrorTMP
                    }
                    # Conditions are not met add device
                    $global:badDevices += $obj                
                    # Remove $Serial from $checkedCombinedOutput
                    (Get-Content $checkedCombinedOutput) | Where-Object {$_ -notmatch $Serial} | Set-Content $checkedCombinedOutput -Encoding Unicode
                    Write-Log -LogOutput ("Bad device: $Serial error $ErrorSerial$ErrorModel$ErrorGroupTag$ErrorTMP removed from import list.") -Path $LogFile
                }
            }

            Catch {
                $ErrorCode = if($AutopilotImport.GroupTag){
                "(Bad Grouptag)"}
                Else {"(No Grouptag)"}

                $obj = new-object psobject -Property @{
                    SerialNumber = $Serial
                    WindowsProductID = $AutopilotImport.WindowsProductID
                    Hash = $AutopilotImport.Hash
                    groupTag = $AutopilotImport.GroupTag
                    model = $AutopilotImport.Model
                    TPMVersion = $AutopilotImport.TPMVersion
                    Owner = $AutopilotImport.Owner
                    Error = $ErrorCode
                }

                # Add wrong group tag devices to list below
                $global:badDevices += $obj

                # Remove $Serial from $checkedCombinedOutput
                (Get-Content $checkedCombinedOutput) | Where-Object {$_ -notmatch $Serial} | Set-Content $checkedCombinedOutput -Encoding Unicode
                Write-Log -LogOutput ("Bad device: $Serial error $ErrorCode removed from import list.") -Path $LogFile    
            }
        }
    }
       
    else {Write-Log -LogOutput ("Nothing to import due to bad permissions...") -Path $LogFile}

    Write-Log -LogOutput ("End third stage: get hardware info and check if conditions are met.") -Path $LogFile
    ### End third stage: get hardware info and check if conditions are met

    ### Fourth stage: importing checked devices in Autopilot
    if(!$correctDevices){
        Write-Log -LogOutput ("Nothing to import due to bad hardware info...") -Path $LogFile
    }

    Else {
        $global:totalCount = 0
    
        Connect-AutoPilotIntune
        Import-AutoPilotCSV $CheckedCombinedOutput -LogFile $LogFile

        ForEach ($AutopilotImport in $global:AutopilotImports){
        $Device = $AutopilotImport.SerialNumber

            if ($Device -in $global:successDevice) {
                # Do nothing device is imported successfully

            } elseif (($Device -in $global:errorDevice) -or ($Device -in $global:softErrorDeviceAlreadyAssigned) -or ($Device -in $global:softErrorDeviceAssignedOtherTenant)){
                $FatalError = if($Device -in $global:ErrorCode){"(Fatal error during import)"}
                $ZtdDeviceAlreadyAssigned = if($Device -in $global:softErrorDeviceAlreadyAssigned){"(Device already assigned in Autopilot)"}
                $ZtdDeviceAssignedToOtherTenant = if($Device -in $global:softErrorDeviceAssignedOtherTenant){"(Device is assigned to another tenant)"}

                $obj = new-object psobject -Property @{
                    SerialNumber = $Device
                    WindowsProductID = $AutopilotImport.WindowsProductID
                    Hash = $AutopilotImport.Hash
                    groupTag = $AutopilotImport.GroupTag
                    model = $AutopilotImport.Model
                    TPMVersion = $AutopilotImport.TPMVersion
                    Owner = $AutopilotImport.Owner
                    Error = $FatalError+$ZtdDeviceAlreadyAssigned+$ZtdDeviceAssignedToOtherTenant
                }
                $global:badDevices += $obj

                # Remove $Serial from $checkedCombinedOutput
                (Get-Content $checkedCombinedOutput) | Where-Object {$_ -notmatch $Device} | Set-Content $checkedCombinedOutput -Encoding Unicode
                Write-Log -LogOutput ("Bad device: $Device error $FatalError$ZtdDeviceAlreadyAssigned$ZtdDeviceAssignedToOtherTenant removed from import list.") -Path $LogFile    
            }
        }
    }

    Write-Log -LogOutput ("End fourth stage: importing checked devices in Autopilot.") -Path $LogFile
    ### End fourth stage: importing checked devices in Autopilot

    ### Fifth stage: uploading and cleaning files
    # Export Autopilot imports and upload to SharePoint
    $CheckDevicesImported = Import-CSV $checkedCombinedOutput

    If($CheckDevicesImported){
    $DevicesImported = "Autopilot-Import" + "-" + ((Get-Date).ToString("dd-MM-yyyy-HHmm")) + ".csv"
    $DevicesImportedPath = Join-Path $PathCsvFiles -ChildPath $DevicesImported

    $CheckDevicesImported | Select-Object 'Device Serial Number', 'Windows Product ID', 'Hardware Hash', 'Group Tag'  | Export-Csv -Path $DevicesImportedPath -Delimiter "," -NoTypeInformation
    Add-PnPFile -Path $DevicesImportedPath -Folder $importedFolderName 
    Write-Log -LogOutput ("Device imports found creating log file and upload to SharePoint.") -Path $LogFile
    }

    Else {Write-Log -LogOutput ("No devices are imported due to errors check Autopilot-Import-Errors.csv.") -Path $LogFile}
}

# Export Autopilot import errors, upload to SharePoint and send mail to user
If($global:badDevices){

# Set the style for the email
$CSS = @"
<caption>Error(s) from Autopilot import process</caption>
<style>
table, th, td {
  border: 1px solid black;
  border-collapse: collapse;
}
th, td {
  padding: 5px;
}
th {
  text-align: left;
}
</style>
"@

    $u = ($global:badDevices | Select-Object Owner -Unique)
    $Users = $u.Owner
    
    Foreach ($User in $Users){
        $UserDevices = $global:badDevices | Where-Object {$_.Owner -eq $User}
        $Body = @() 

        Foreach ($UserDevice in $UserDevices){
            
            $obj = new-object psobject -Property @{
            SerialNumber = $UserDevice.SerialNumber
            Model = $UserDevice.model
            TPMVersion = $UserDevice.TPMVersion.Split('-')[1]
            GroupTag = $UserDevice.groupTag
            Owner = $UserDevice.Owner
            Error = $UserDevice.Error
            }

            $Body += $obj | Select-Object SerialNumber, Model, TPMVersion, GroupTag, Owner, Error
        }
        
        # Format content to be able to use it as body for send-mail
        $Content = $Body | ConvertTo-Html | Out-String
        $Content = $Content.Trim('<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">')
        $Content = $Content.Replace('<html xmlns="http://www.w3.org/1999/xhtml">', '<html>')
        $Content = $content.Replace("<title>HTML TABLE</title>", $CSS)
            
        $Subject = "Error occured during Autopilot import for $User"
        Send-Mail -Recipient $User -Subject $Subject -Body $Content -MailSender $MailSender
    }

	$ImportErrors = "Autopilot-Import-Errors" + "-" + ((Get-Date).ToString("dd-MM-yyyy-HHmm")) + ".csv"
	$ImportErrorsPath = Join-Path $PathCsvFiles -ChildPath $ImportErrors

	$global:badDevices | Select-Object SerialNumber, WindowsProductID, Hash, Model, GroupTag, TPMVersion, Owner, Error  | Export-Csv -Path $ImportErrorsPath -Delimiter "," -NoTypeInformation   
	Add-PnPFile -Path $ImportErrorsPath -Folder $errorsFolderName
	Write-Log -LogOutput ("Import errors found creating log file and upload to SharePoint.") -Path $LogFile
}

Else {Write-Log -LogOutput ("No bad devices found.") -Path $LogFile}

Write-Log -LogOutput ("End fifth stage: uploading and removing files.") -Path $LogFile
### End fifth stage: uploading and cleaning files

# Upload log file
Add-PnPFile -Path $LogFile -Folder $LogFolderName

# Clean remaining files from hybrid worker temp folder
$ItemsToRemove = @($CheckedCombinedOutput,$DevicesImportedPath,$ImportErrorsPath,$LogFile,$OA3ToolPath,$XMLFile)
Foreach ($Item in $ItemsToRemove){
    Try {
        Remove-item $Item -ErrorAction SilentlyContinue
    } Catch {
        #Item already removed or cannot be found
    }
}

Foreach ($CSV in $CSVtoImport) {Remove-item ($pathCsvFiles + "\" + $CSV.FileName) -ErrorAction SilentlyContinue}