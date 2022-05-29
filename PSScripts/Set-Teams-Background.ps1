if(Test-Path HKCU:\Software\Ucorp){
    [string]$valueexist= Get-ItemProperty "HKCU:\Software\Ucorp" -Name 'Teamsbackground'
}else{
    New-Item HKCU:\Software\Ucorp
}

if ((!($valueexist)) -or ($valueexist.Teamsbackground -lt 2) ) {

    if (!(Test-Path "$env:appdata\Microsoft\Teams\Backgrounds")) {
     New-Item "$env:appdata\Microsoft\Teams\Backgrounds" -ItemType Directory | Out-Null
    }
    if (!(Test-Path "$env:appdata\Microsoft\Teams\Backgrounds\Uploads")) {
    New-Item "$env:appdata\Microsoft\Teams\Backgrounds\Uploads" -ItemType Directory | Out-Null
    }

    if (!(Test-Path "$env:temp\Teamsbackground")) {
        New-Item "$env:temp\Teamsbackground" -ItemType Directory | Out-Null
       }

    $background1 = 'https://ucorpstorage.blob.core.windows.net/m365filerepo/Microsoft-nostalgia-Teams-background-1.jpg?sp=r&st=2022-05-29T19:50:55Z&se=2026-05-30T03:50:55Z&spr=https&sv=2020-08-04&sr=b&sig=4AHXEAYX2SqExfEmWxfyvdevInxTwDWRYZ6L3EFLPbE%3D'
    $background2 = 'https://ucorpstorage.blob.core.windows.net/m365filerepo/Microsoft-nostalgia-Teams-background-2.jpg?sp=r&st=2022-05-29T19:51:25Z&se=2026-05-30T03:51:25Z&spr=https&sv=2020-08-04&sr=b&sig=818cNbbd8R%2BoGv7DOZnsj2c4y5wPWNv0wgnhVibdmgU%3D'

    $Destination1 = "$env:appdata\Microsoft\Teams\Backgrounds\Uploads\Background1.png"
    $Destination2 = "$env:appdata\Microsoft\Teams\Backgrounds\Uploads\Background2.png"
    Invoke-WebRequest -Uri $background1 -OutFile "$Destination1"
    Invoke-WebRequest -Uri $background2 -OutFile "$Destination2"

    if(!($valueexist)){
    New-ItemProperty HKCU:\Software\Ucorp -Name 'Teamsbackground' -Value 1 -PropertyType string
    }else{
    Set-ItemProperty HKCU:\Software\Ucorp -Name 'Teamsbackground' -Value 2
    }
}