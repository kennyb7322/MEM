$TaskPath = 'C:\Windows\system32\Tasks'
$TaskFolder = 'Ucorp'
$TaskName = 'StartChrome'
$RegCheck = 'StartChrome'
$version = 1
$RegRoot= "HKCU"

if (Test-Path HKCU:\Software\Ucorp) {
    $regexist = Get-ItemProperty "$RegRoot`:\Software\Ucorp" -Name $RegCheck -ErrorAction SilentlyContinue
}
else {
    if(!(Test-Path "$RegRoot`:\Software\Ucorp")){
        New-Item HKCU:\Software\Ucorp
    }
}    
if ((!($regexist)) -or ($regexist.$RegCheck -lt $Version)) {
    try{
        if(Test-Path $TaskPath){
            $RemoveTrigger = "schtasks /Delete /TN '$TaskFolder\$TaskName' /F"
            Invoke-Expression $RemoveTrigger
        }
        try{
            $Delay = new-timespan -minutes 1
            $A = New-ScheduledTaskAction -Execute "C:\Program Files\Google\Chrome\Application\chrome.exe"
            $T = New-ScheduledTaskTrigger -AtLogOn -RandomDelay $Delay
            $T.Delay = 'PT1M'
            $P = New-ScheduledTaskPrincipal -UserId (Get-CimInstance –ClassName Win32_ComputerSystem | Select-Object -expand UserName)
            $S = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopIfGoingOnBatteries -AllowStartIfOnBatteries
            $D = New-ScheduledTask -Action $A -Principal $P -Trigger $T -Settings $S
            Register-ScheduledTask  -TaskName "$TaskFolder\$TaskName" -InputObject $D -ErrorAction Stop

        }catch{
            write-error 'failed to create auto start Chrome task'
            break
        }
        if($regexist.$RegCheck){
            set-ItemProperty HKCU:\Software\Ucorp -Name $RegCheck -Value $version -ErrorAction Stop -Force
        }else{
            new-ItemProperty HKCU:\Software\Ucorp -Name $RegCheck -Value $version -PropertyType string -ErrorAction Stop -Force
        }
    }catch{
        write-error 'failed to create auto start Chrome task'
        break
    }
}