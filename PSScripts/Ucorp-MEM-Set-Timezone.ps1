if (Test-Path HKCU:\Software\Ucorp) {
    [string]$regexist = Get-ItemProperty "HKCU:\Software\Ucorp" -Name 'TimeZone'
}
else {
    New-Item HKCU:\Software\Ucorp
}    
if (!($regexist)) {
    try{
        set-timezone -Id 'W. Europe Standard Time' -ErrorAction Stop
        New-ItemProperty HKCU:\Software\Ucorp -Name 'TimeZone' -Value 1 -PropertyType string
    }catch{
        #'DO Nothing'
    }
}