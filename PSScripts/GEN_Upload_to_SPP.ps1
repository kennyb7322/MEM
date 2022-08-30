param(
	  [Parameter(Mandatory=$true)]$Filename,
	  [Parameter(Mandatory=$true)]$SiteURL,
	  [Parameter(Mandatory=$true)]$DestinationPath
)

#File to Upload to SharePoint
$SourceFilePath = $Filename
  
#Get Credentials to connect
$Cred = Get-AutomationPSCredential -Name ReadOnlyAccount

# This Powershell script is to uplaod the files to a sharepoint document library REMOTELY with user Credentails
function UploadDocuments($destination, $File){
	try {
	$webclient = New-Object System.Net.WebClient
	$webclient.Credentials = $cred
	$webclient.UploadFile($destination + "/" + $File.Name, "PUT", $File.FullName)
	
	} catch {
	Write-Host "Error:: $($_.Exception.Message)" -foregroundcolor red -BackgroundColor Yellow
	}
	}

# Set the variables
$Destination = $SiteURL + $DestinationPath
$file = get-item $sourcefilepath
		
UploadDocuments -destination $destination -File $file