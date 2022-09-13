param(
	  [Parameter(Mandatory=$true)]$Filename,
	  [Parameter(Mandatory=$true)]$SiteURL,
	  [Parameter(Mandatory=$true)]$DestinationPath
)

#Import PnP
Import-Module PnP.Powershell
#Import-Module SharepointPnPPowershellOnline

#File to Upload to SharePoint
$SourceFilePath = $Filename
  
#Get Credentials to connect
$Cred = Get-AutomationPSCredential -Name ReadOnlyAccount
  
#Connect to PnP Online
Connect-PnPOnline -Url $SiteURL -Credentials $Cred -WarningAction Ignore
      
#powershell pnp to upload file to sharepoint online
Add-PnPFile -Path $SourceFilePath -Folder $DestinationPath | Out-Null