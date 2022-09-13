#Section with checks and proxy when running in Azure or on Hybrid worker
if($(Test-Path HKLM:\SOFTWARE\ING)) {
    try {
        $AadModule = Import-Module -Name AzureADPreview -ErrorAction Stop -PassThru
    }
    catch {
        throw 'AzureAD PowerShell module is not installed!'
    }
    # Set default proxy (Only used when running on IPC)
    [system.net.webrequest]::defaultwebproxy = new-object system.net.webproxy('http://.<proxyaddress>.net:8090')
    [system.net.webrequest]::defaultwebproxy.credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    [system.net.webrequest]::defaultwebproxy.BypassProxyOnLocal = $true
    $_ = [system.net.webrequest]::defaultwebproxy.BypassArrayList.Add('.*.<domain>.net')
    $_ = [system.net.webrequest]::defaultwebproxy.BypassArrayList.Add('localhost')

    # Log on which machine the runbook was started
    $myFQDN=(Get-WmiObject win32_computersystem).DNSHostName+"."+(Get-WmiObject win32_computersystem).Domain
    Write-Output "Runbook started on $myFQDN"

} else {
    try {
        $AadModule = Import-Module -Name AzureAD -ErrorAction Stop -PassThru
    }
    catch {
        throw 'AzureAD PowerShell module is not installed!'
    }
    Write-Output "Runbook started on Azure"
}
