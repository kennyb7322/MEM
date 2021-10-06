$DownloadFolder = "C:\Install\Adobe_Acrobat_Reader_DC_MUI\"
$FTPFolderUrl = "ftp://ftp.adobe.com/pub/adobe/reader/win/AcrobatDC/"

mkdir $DownloadFolder
$LogFile = $DownloadFolder + "\" + "Updating-AcrobatProDC-" + (Get-Date -UFormat "%d-%m-%Y") + ".log"

Function Write-Log
{
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

#connect to ftp, and get directory listing
$FTPRequest = [System.Net.FtpWebRequest]::Create("$FTPFolderUrl") 
$FTPRequest.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectory
$FTPResponse = $FTPRequest.GetResponse()
$ResponseStream = $FTPResponse.GetResponseStream()
$FTPReader = New-Object System.IO.Streamreader -ArgumentList $ResponseStream
$DirList = $FTPReader.ReadToEnd()

#from Directory Listing get last entry in list, but skip one to avoid the 'misc' dir
$LatestUpdate = $DirList -split '[\r\n]' | Where {$_} | Select -Last 1 -Skip 1

#build file name
$LatestFile = "AcroRdrDCUpd" + $LatestUpdate + "_MUI.msp"

#build download url for latest file
$DownloadURL = "$FTPFolderUrl$LatestUpdate/$LatestFile"

#download file
(New-Object System.Net.WebClient).DownloadFile($DownloadURL, ($DownloadFolder + $LatestFile))

Write-Log -LogOutput ("Installing update $LatestFile") -Path $LogFile

Invoke-Expression -Command '$DownloadFolder /p AdbeRdrUpd11011.msp /p /qn'

$Installer = ($DownloadFolder + $LatestFile)

$arguments = "/p `"$Installer`" /qn"
Start-Process msiexec.exe -ArgumentList $arguments -Wait