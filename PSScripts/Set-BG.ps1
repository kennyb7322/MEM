$RegCheck = 'Background'
$version = 1
$RegRoot= "HKCU"

$Background = 'C:\Windows\Web\Wallpaper\Theme1\ucorp-background.jpg'

if (Test-Path "$RegRoot`:\Software\Ucorp") {
    try{
        $regexist = Get-ItemProperty "$RegRoot`:\Software\Ucorp" -Name $RegCheck -ErrorAction Stop
    }catch{
        $regexist = $false
    }
} 
else {
    New-Item HKCU:\Software\Ucorp
}    
if ((!($regexist)) -or ($regexist.$RegCheck -lt $Version)) {
    if(Test-Path $Background){
        try{
            Set-ItemProperty 'HKCU:\Control Panel\Desktop' -Name 'WallPaper' -Value "$background"
        }catch{
            Write-Error 'Failed to set background'
            break
        }    
    }else{
       Write-Error "$Background nog niet gevonden"
       break
    }
    
    if(!($regexist)){
        New-ItemProperty "$RegRoot`:\Software\Ucorp" -Name $RegCheck -Value $Version -PropertyType string
    }else{
        Set-ItemProperty "$RegRoot`:\Software\Ucorp" -Name $RegCheck -Value $version
    }
}