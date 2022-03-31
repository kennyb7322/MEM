try{
    $update = "c:\windows\system32\usoclient.exe ScanInstallWait"
    Invoke-Expression $update
}catch{
    Write-Error 'failed to trigger windows update'
}