$RegCheck = 'DefaultApps'
$version = 1
$RegRoot= "HKLM"
if (Test-Path "$RegRoot`:\Software\Ucorp") {
    try{
        $regexist = Get-ItemProperty "$RegRoot`:\Software\Ucorp" -Name $RegCheck -ErrorAction Stop
    }catch{
        $regexist = $false
    }
} 
else {
    New-Item "$RegRoot`:\Software\Ucorp"
}    
if ((!($regexist)) -or ($regexist.$RegCheck -lt $Version)) {
    try{
        Set-ExecutionPolicy Bypass -Scope Process -Force
        Invoke-Expression ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))
    
        choco install chocolateygui -y
        chocolateyguicli feature enable --name="'AllowNonAdminAccessToSettings'" --global
	    choco install adobereader -params '"/NoUpdates"' -y
        choco install googlechrome -y
	    choco install Firefox --params "/l:nl-NL /NoDesktopShortcut /NoMaintenanceService /RemoveDistributionDir" -y

        $location = "C:\Users\Public\Desktop\"
        if(Test-Path $location){
            #Remove-Item "$location\*"
        }
        else{
            Write-Output "Directory does not exist"
        }
    }catch{
        write-error 'unable to install default choco apps'
        break 
    }

    if(!($regexist)){
        New-ItemProperty "$RegRoot`:\Software\Ucorp" -Name $RegCheck -Value $Version -PropertyType string
    }else{
        Set-ItemProperty "$RegRoot`:\Software\Ucorp" -Name $RegCheck -Value $version
    }
}