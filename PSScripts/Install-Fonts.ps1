$path = "C:\Packages"
mkdir $path -ErrorAction SilentlyContinue

$fontsUri = 'https://ucorpavdstd.blob.core.windows.net/ucorpavdrepo/Fonts.zip?sp=r&st=2021-09-27T21:07:48Z&se=2024-09-28T05:07:48Z&spr=https&sv=2020-08-04&sr=b&sig=SNXRogZ0%2Bz5aaT25GgD2BYRMkxWbX9miBNEwlhA2qGc%3D'
$FontsFile = "Fonts.zip"
if(Test-Path "$path\$fontsfile"){
    Remove-Item "$path\$fontsfile"
}

if (Test-Path HKLM:\Software\Ucorp) {
    $regexist = Get-ItemProperty "HKLM:\Software\Ucorp" -Name 'Fonts' -ErrorAction SilentlyContinue
}
else {
    New-Item HKLM:\Software\Ucorp -ErrorAction SilentlyContinue
} 

if ((!($regexist)) -or ($regexist.Fonts -lt 2) ) {

    try{
        Invoke-WebRequest -Uri $fontsUri -OutFile "$path\$fontsfile"
        Expand-Archive "$path\$fontsfile" -DestinationPath $path

        Set-Location "$path\Fonts"
        $fonts = Get-ChildItem *.ttf
        $fonts.ForEach({.\add-font.ps1 $_.name})
    
    }catch{
        Write-Error 'Failed to install custom Fonts'
    }
    
    Remove-Item "$path\fonts" -Recurse -ErrorAction SilentlyContinue
    Remove-Item "$path\$fontsfile" -ErrorAction SilentlyContinue

    try{
        if(!($regexist)){
            New-ItemProperty HKLM:\Software\Ucorp -Name 'Fonts' -Value 1 -PropertyType string -ErrorAction Stop
        }else{
            Set-ItemProperty HKLM:\Software\Ucorp -Name 'Fonts' -Value 2 -ErrorAction Stop
        }
    }catch{
        Write-Error 'failed to set Registy value'
    }
}
