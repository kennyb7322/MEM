$TaskPath = 'C:\Windows\system32\Tasks'
$TaskFolder = 'Ucorp'
$TaskName = 'UpdateAppxPackages'
$RegCheck = 'AppxUpdate'
$version = 1
$RegRoot= "HKLM"

if (Test-Path HKLM:\Software\Ucorp) {
    $regexist = Get-ItemProperty "$RegRoot`:\Software\Ucorp" -Name $RegCheck -ErrorAction SilentlyContinue
}
else {
    if(!(Test-Path "$RegRoot`:\Software\Ucorp")){
        New-Item HKLM:\Software\Ucorp
    }
}    
if ((!($regexist)) -or ($regexist.$RegCheck -lt $Version)) {
    try{
        if(Test-Path $TaskPath){
            $RemoveTrigger = "schtasks /Delete /TN '$TaskFolder\$TaskName' /F"
            Invoke-Expression $RemoveTrigger
        }
        try{
            $A = New-ScheduledTaskAction -Execute "Powershell" -Argument "-command & {Get-CimInstance -Namespace Root\cimv2\mdm\dmmap -ClassName MDM_EnterpriseModernAppManagement_AppManagement01 | Invoke-CimMethod -MethodName UpdateScanMethod}"
            $T = New-ScheduledTaskTrigger -AtStartup
            $P = New-ScheduledTaskPrincipal -UserId 'system'
            $S = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopIfGoingOnBatteries -AllowStartIfOnBatteries
            $D = New-ScheduledTask -Action $A -Principal $P -Trigger $T -Settings $S
            Register-ScheduledTask  -TaskName "$TaskFolder\$TaskName" -InputObject $D -ErrorAction Stop
        }catch{
            write-error 'failed to create scheduledtask'
            break
        }
        if($regexist.$RegCheck){
            set-ItemProperty HKLM:\Software\Ucorp -Name $RegCheck -Value $version -ErrorAction Stop -Force
        }else{
            new-ItemProperty HKLM:\Software\Ucorp -Name $RegCheck -Value $version -PropertyType string -ErrorAction Stop -Force
        }
    }catch{
        write-error 'failed to schedule daily Appx packages update'
        break
    }
}