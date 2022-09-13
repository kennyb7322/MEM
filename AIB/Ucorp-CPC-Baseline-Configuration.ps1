<#
.Synopsis
    Customization script for Azure Image Builder
.DESCRIPTION
    Customization script for Azure Image Builder - Baseline Personal Configuration
.NOTES
    Author: Ivo Uenk
    Version: 1.0
#>

# Creating logoutput and filenames
$path = "c:\AIB"
$LogFile = $path + "\" + "CPC-Baseline-Configuration-" + (Get-Date -UFormat "%d-%m-%Y") + ".log"

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

# Disable Store auto update
Schtasks /Change /Tn "\Microsoft\Windows\WindowsUpdate\Scheduled Start" /Disable

# region Time Zone Redirection
$Name = "fEnableTimeZoneRedirection"
$value = "1"

try {
    New-ItemProperty -ErrorAction Stop -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name $name -Value $value -PropertyType DWORD -Force
    if ((Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services").PSObject.Properties.Name -contains $name) {
        Write-Log -LogOutput ("Added time zone redirection registry key") -Path $LogFile
    }
    else {
        Write-Log -LogOutput ("Error locating the Teams registry key") -Path $LogFile
    }
}
catch {
    $ErrorMessage = $_.Exception.message
    Write-Log -LogOutput ("Error adding teams registry KEY: $ErrorMessage") -Path $LogFile
}

Invoke-Expression ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))

choco install adobereader -params '"/NoUpdates"' -y
choco install Firefox --params "/l:nl-NL /NoDesktopShortcut /NoMaintenanceService /RemoveDistributionDir" -y
