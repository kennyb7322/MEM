Stop-Process -Name chrome
Start-Sleep -s 2

if (Test-Path HKCU:\Software\Ucorp) {
    [string]$regexist = Get-ItemProperty "HKCU:\Software\Ucorp" -Name 'Chrome'
}else{
    New-Item HKCU:\Software\Ucorp
}    

if (Get-Process | Where-Object {$_.name -like 'chrome'}){
    Write-Error 'chrome is active' -ErrorAction Stop
    break
}

if ((!($regexist)) -or ($regexist.templates -lt 2) ) {
    $neededFileExt = "rdp"
    $path = $env:LOCALAPPDATA + "\Google\Chrome\User Data\Default\Preferences"

    if(Test-Path $path){
        $prefContent = Get-Content $path -Encoding utf8
        $prefs = ConvertFrom-Json $prefContent
        If(($prefs | Get-Member).name -contains "download") #if the download node exists
        {
            If(($prefs.download | Get-Member).name -contains "extensions_to_open") #sometimes the download node doesn't have the extensions_to_open child
            {
                If($prefs.download.extensions_to_open) #if it has value, grab the contents
                {
                    [string[]]$existingFileExt = $prefs.download.extensions_to_open.tostring().split(":")
                }Else{
                    [string[]]$existingFileExt = $null
                }
            }Else{ #if extensions_to_open doesn't exist, create it
                $prefs.download | Add-Member -MemberType NoteProperty -Name extensions_to_open -Value ""
                [string[]]$existingFileExt = $null
            }
            Foreach($ext in $neededFileExt)
            {
                If($existingFileExt -notcontains $ext) #only add the necessary extension if it isn't already there
                {
                    [string[]]$existingFileExt += $ext
                }
            }
            $prefs.download.extensions_to_open = $existingFileExt -join ":" #the extensions are in the format: ext:ext:ext
            ConvertTo-Json $prefs -Compress -depth 100 | Out-File $path -Encoding utf8 #write it back
        }
        if(!($regexist)){
            New-ItemProperty HKCU:\Software\Ucorp -Name 'Chrome' -Value 2 -PropertyType string
        }else{
            Set-ItemProperty HKCU:\Software\Ucorp -Name 'Chrome' -Value 2
        }
        
    }else{
        exit 12345
    }
}