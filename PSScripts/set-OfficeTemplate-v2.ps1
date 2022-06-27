$urlTemplate = 'https://ucorpstorage.blob.core.windows.net/m365filerepo/OfficeTemplates-190524.exe?sp=r&st=2022-06-02T09:46:41Z&se=2026-06-02T17:46:41Z&spr=https&sv=2020-08-04&sr=b&sig=2PevngRDKghn5qDltdv4GhLYEGIgNAi9zecuhDUyBGg%3D'


$TemplateLoc = 'UcorpOfficeTemplates'
if (Test-Path "$env:TMP\template.exe") {
    Remove-Item "$env:TMP\template.exe"
}
if (Test-Path HKCU:\Software\Ucorp) {
    $regexist = Get-ItemProperty "HKCU:\Software\Ucorp" -Name 'Templates'
}
else {
    New-Item HKCU:\Software\Ucorp
}    
if ((!($regexist)) -or ($regexist.templates -lt 4) ) {
    Invoke-WebRequest -Uri $urlTemplate -OutFile "$env:TMP\template.exe"

    Start-Sleep -Seconds 20

    #if (!(Test-Path "$env:USERPROFILE\documents\$TemplateLoc")) {
    #    New-Item "$env:USERPROFILE\documents\$TemplateLoc" -ItemType Directory | Out-Null
    #}

    if (!(Test-Path "$env:appdata\Microsoft")) {
        New-Item "$env:appdata\Microsoft" -ItemType Directory | Out-Null
    }

    if (!(Test-Path "$env:appdata\Microsoft\Signatures")) {
        New-Item "$env:appdata\Microsoft\Signatures" -ItemType Directory | Out-Null
    }

    if (!(Test-Path "$env:appdata\Microsoft\Templates")) {
        New-Item "$env:appdata\Microsoft\Templates" -ItemType Directory | Out-Null
    }

    if (!(Test-Path "$env:appdata\Microsoft\Templates\UcorpOfficeTemplates")) {
    }
    else
    {
    Remove-Item -Path "$env:appdata\Microsoft\Templates\UcorpOfficeTemplates" -Recurse | Out-Null
    }

    Invoke-Expression "$env:TMP\template.exe /s" 
    #Invoke-Expression "$env:TMP\signature.exe /s"
    
    if (!(Test-Path HKCU:\Software\Microsoft\Office)) {
        New-Item -Path HKCU:\Software\Microsoft\Office | Out-Null
    }    
    if (!(Test-Path HKCU:\Software\Microsoft\Office\16.0)) {
        New-Item -Path HKCU:\Software\Microsoft\Office\16.0 | Out-Null
    }    
    if (!(Test-Path HKCU:\Software\Microsoft\Office\16.0\PowerPoint)) {
        New-Item -Path HKCU:\Software\Microsoft\Office\16.0\PowerPoint | Out-Null
    } 
    if (!(Test-Path HKCU:\Software\Microsoft\Office\16.0\PowerPoint\Options)) {
        New-Item -Path HKCU:\Software\Microsoft\Office\16.0\PowerPoint\Options | Out-Null
    }     
    if (!(Test-Path HKCU:\Software\Microsoft\Office\16.0\Word)) {
        New-Item -Path HKCU:\Software\Microsoft\Office\16.0\Word | Out-Null
    } 
    if (!(Test-Path HKCU:\Software\Microsoft\Office\16.0\Word\Options)) {
        New-Item -Path HKCU:\Software\Microsoft\Office\16.0\Word\Options | Out-Null
    }

    $Wordexist = Get-ItemProperty "HKCU:\Software\Microsoft\Office\16.0\Word\Options" -Name 'PersonalTemplates'
    $PowerPointexist = Get-ItemProperty "HKCU:\Software\Microsoft\Office\16.0\PowerPoint\Options" -Name 'PersonalTemplates'

    if (!($Wordexist)) {
        New-ItemProperty 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' -Name 'PersonalTemplates' -Value "$env:appdata\Microsoft\Templates\$TemplateLoc" -PropertyType string
    }
    else {
        Set-ItemProperty 'HKCU:\Software\Microsoft\Office\16.0\Word\Options' -Name 'PersonalTemplates' -Value "$env:appdata\Microsoft\Templates\$TemplateLoc"
    }
    if (!($PowerPointexist)) {
        New-ItemProperty 'HKCU:\Software\Microsoft\Office\16.0\PowerPoint\Options' -Name 'PersonalTemplates' -Value "$env:appdata\Microsoft\Templates\$TemplateLoc" -PropertyType string
    }
    else {
        Set-ItemProperty 'HKCU:\Software\Microsoft\Office\16.0\PowerPoint\Options' -Name 'PersonalTemplates' -Value "$env:appdata\Microsoft\Templates\$TemplateLoc"
    }

    if (Test-Path "$env:TMP\template.exe") {
        Remove-Item "$env:TMP\template.exe"
    }

    if(!($regexist)){
        New-ItemProperty HKCU:\Software\Ucorp -Name 'Templates' -Value 1 -PropertyType string
    }else{
        Set-ItemProperty HKCU:\Software\Ucorp -Name 'Templates' -Value 4
    }
}