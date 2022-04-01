$RegCheck = 'OptimalizationPack'
$version = 1
$RegRoot= "HKLM"

$path ="C:\Packages\"
$ErrorActionPreference = 'SilentlyContinue'

if (Test-Path "$RegRoot`:\Software\Ucorp") 
{
    try
    {
        $regexist = Get-ItemProperty "$RegRoot`:\Software\Ucorp" -Name $RegCheck -ErrorAction Stop

    }catch{
        $regexist = $false
    }

} else {
    New-Item "$RegRoot`:\Software\Ucorp"
}

if ((!($regexist)) -or ($regexist.$RegCheck -lt $Version)) 
{
    try
    {    
        $OptimalizationToolURL="https://github.com/iuenk/AVD/blob/main/Resources/Virtual-Desktop-Optimization-Tool-custom-20h2.zip?raw=true"
        $installerFile="Virtual-Desktop-Optimization-Tool-custom-20h2.zip"

        mkdir $path -ErrorAction SilentlyContinue
        Invoke-WebRequest $OptimalizationToolURL -OutFile $path\$installerFile
        Expand-Archive $path\$installerFile -DestinationPath $path
        Set-Location $path\Virtual-Desktop-Optimization-Tool-master
        .\Win10_VirtualDesktop_Optimize.ps1 -WindowsVersion 2009 -Verbose

    } catch {
    Write-Error "Unable to run the Virtual Desktop Optimalization Tool"
    break
    }

    if(!($regexist))
    {
        New-ItemProperty "$RegRoot`:\Software\Ucorp" -Name $RegCheck -Value $Version -PropertyType string

    }else{
        Set-ItemProperty "$RegRoot`:\Software\Ucorp" -Name $RegCheck -Value $version
    }
}