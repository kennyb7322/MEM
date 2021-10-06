$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey |foreach {
    try{
        Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name 'NetbiosOptions' -Value 2 -ErrorAction Stop
    }catch{
        Write-Error 'unable to set NetbiosOptions(NBT-NS)'
    }
}

try{
    Get-ItemProperty  "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient" -ErrorAction Stop
}catch{
    New-Item "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient" -Force
}

try{
    Get-ItemProperty "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient" -Name 'EnableMulticast' -ErrorAction Stop
    set-ItemProperty "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient" -Name 'EnableMulticast' -Value 2
}catch{
    try{
    new-ItemProperty "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient" -Name 'EnableMulticast' -Value 2 -PropertyType dword    
    }catch{
        Write-Error 'failed to set EnableMulticast (LLMNR)'
    }
}

try{
    Get-ItemProperty "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient" -Name 'EnableMulticast' -ErrorAction Stop
    set-ItemProperty "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient" -Name 'EnableMulticast' -Value 2
}catch{
    try{
    new-ItemProperty "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient" -Name 'EnableMulticast' -Value 2 -PropertyType dword    
    }catch{
        Write-Error 'failed to set EnableMulticast (LLMNR)'
    }
}

$TLSKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\client'
try{
    Get-ItemProperty $TLSKey  -ErrorAction Stop
}catch{
    New-Item $TLSKey -Force
}

try{
    Get-ItemProperty $TLSKey -Name 'Enabled' -ErrorAction Stop
    set-ItemProperty $TLSKey -Name 'Enabled' -Value 1
}catch{
    try{
    new-ItemProperty "$TLSKey" -Name 'Enabled' -Value 1 -PropertyType dword    
    }catch{
        Write-Error "failed to create $TLSKey -name Enabled"
    }
}

try{
    Get-ItemProperty $TLSKey -Name 'DisabledByDefault' -ErrorAction Stop
    set-ItemProperty $TLSKey -Name 'DisabledByDefault' -Value 0
}catch{
    try{
    new-ItemProperty "$TLSKey" -Name 'DisabledByDefault' -Value 0 -PropertyType dword    
    }catch{
        Write-Error "failed to create $TLSKey -name DisabledByDefault"
    }
}

try{
    Get-ItemProperty "HKLM:\software\microsoft\.NETFramework\v4.0.30319" -Name 'schusestrongcrypto' -ErrorAction Stop
    set-ItemProperty "HKLM:\software\microsoft\.NETFramework\v4.0.30319" -Name 'schusestrongcrypto' -Value 1
}catch{
    try{
    new-ItemProperty "HKLM:\software\microsoft\.NETFramework\v4.0.30319" -Name 'schusestrongcrypto' -Value 1 -PropertyType dword    
    }catch{
        Write-Error "failed to create HKLM:\software\microsoft\.NETFramework\v4.0.30319 -name schusestrongcrypto"
    }
}

try{
    Get-ItemProperty "HKLM:\software\wow6432node\microsoft\.NETFramework\v4.0.30319" -Name 'schusestrongcrypto' -ErrorAction Stop
    set-ItemProperty "HKLM:\software\wow6432node\microsoft\.NETFramework\v4.0.30319" -Name 'schusestrongcrypto' -Value 1
}catch{
    try{
    new-ItemProperty "HKLM:\software\wow6432node\microsoft\.NETFramework\v4.0.30319" -Name 'schusestrongcrypto' -Value 1 -PropertyType dword    
    }catch{
        Write-Error "failed to create HKLM:\software\wow6432node\microsoft\.NETFramework\v4.0.30319 -name schusestrongcrypto"
    }
}

#ADV200005 | Microsoft Guidance for Disabling SMBv3 Compression
try{
    get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -name 'DisableCompression' -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -name 'DisableCompression' -Value 1 -Force -ErrorAction Stop
}catch{
    try{
        new-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -name 'DisableCompression' -Type DWORD -Value 1 -Force -ErrorAction Stop
    }catch{
        Write-Error "failed to create HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -name DisableCompression"
    }
}


#Acrobat Reader: Flash is an unsecure technology with many known vulnerabilities, it is recommended to avoid using it.
try{
    Get-ItemProperty -path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name 'bEnableFlash' -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -name 'bEnableFlash' -Value 0 -ErrorAction Stop
}catch{
    try{
        new-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -name 'bEnableFlash' -Type DWORD -Value 1 -Force -ErrorAction Stop
    }catch{
        Write-Error "failed to create HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown -name 'bEnableFlash'"
    }
}

#Acrobat Reader:JavaScript could potentially be used by attackers to manipulate users or to execute undesired code locally.
try{
    Get-ItemProperty -path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name 'bDisableJavaScript' -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -name 'bDisableJavaScript' -Value 1 -ErrorAction Stop
}catch{
    try{
        new-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -name 'bDisableJavaScript' -Type DWORD -Value 1 -Force -ErrorAction Stop
    }catch{
        Write-Error "failed to create HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown -name 'bDisableJavaScript"
    }
}

#If LSA isn't running as a protected process, attackers could easily abuse the low process integrity for attacks (such as Pass-the-Hash).
try{
    Get-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name 'RunAsPPL' -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -name 'RunAsPPL' -Value 1 -ErrorAction Stop
}catch{
    try{
        new-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -name 'RunAsPPL' -Type DWORD -Value 1 -Force -ErrorAction Stop
    }catch{
        Write-Error "failed to create HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -name 'RunAsPPL"
    }
}

#Denying elevation requests from standard user accounts requires tasks that need elevation to be initiated by accounts with administrative privileges. This prevents privileged account credentials from being cached with standard user profile information to help mitigate credential theft.
try{
    Get-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name 'consentPromptBehaviorUser' -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -name 'consentPromptBehaviorUser' -Value 0 -ErrorAction Stop
}catch{
    try{
        new-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -name 'consentPromptBehaviorUser' -Type DWORD -Value 0 -Force -ErrorAction Stop
    }catch{
        Write-Error "failed to create HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -name 'consentPromptBehaviorUser"
    }
}

#A Network Bridge can connect two or more network segments, allowing unauthorized access or exposure of sensitive data in another network segment.
try{
    Get-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name 'NC_AllowNetBridge_NLA' -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -name 'NC_AllowNetBridge_NLA' -Value 0 -ErrorAction Stop
}catch{
    try{
        new-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -name 'NC_AllowNetBridge_NLA' -Type DWORD -Value 0 -Force -ErrorAction Stop
    }catch{
        Write-Error "failed to create HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections -name 'NC_AllowNetBridge_NLA"
    }
}

#Selecting an incorrect network location may allow greater exposure of a system.
try{
    Get-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name 'NC_StdDomainUserSetLocation' -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -name 'NC_StdDomainUserSetLocation' -Value 1 -ErrorAction Stop
}catch{
    try{
        new-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -name 'NC_StdDomainUserSetLocation' -Type DWORD -Value 1 -Force -ErrorAction Stop
    }catch{
        Write-Error "failed to create HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections -name 'NC_StdDomainUserSetLocation'"
    }
}

#This exposes the system sharing the connection to others with potentially malicious purpose.
try{
    Get-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name 'NC_ShowSharedAccessUI' -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -name 'NC_ShowSharedAccessUI' -Value 0 -ErrorAction Stop
}catch{
    try{
        new-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -name 'NC_ShowSharedAccessUI' -Type DWORD -Value 0 -Force -ErrorAction Stop
    }catch{
        Write-Error "failed to create HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections -name 'NC_ShowSharedAccessUI'"
    }
}

#Standard user accounts must not be granted elevated privileges. Enabling Windows Installer to elevate privileges when installing applications can allow malicious persons and applications to gain full control of a system.
try{
    Get-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name 'AlwaysInstallElevated' -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -name 'AlwaysInstallElevated' -Value 0 -ErrorAction Stop
}catch{
    try{
        new-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -name 'AlwaysInstallElevated' -Type DWORD -Value 0 -Force -ErrorAction Stop
    }catch{
        Write-Error "failed to create HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer -name 'AlwaysInstallElevated'"
    }
}

#Using older/weaker authentication levels (LM & NTLM) make it potentially possible for attackers to sniff that traffic to more easily reproduce the user's password.
try{
    Get-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name 'LmCompatibilityLevel' -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -name 'LmCompatibilityLevel' -Value 5 -ErrorAction Stop
}catch{
    try{
        new-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -name 'LmCompatibilityLevel' -Type DWORD -Value 5 -Force -ErrorAction Stop
    }catch{
        Write-Error "failed to create HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -name 'LmCompatibilityLevel'"
    }
}

#Due to the difficulty in managing local Administrator passwords, many organizations choose to use the same password on all endpoints during deployment. This poses a serious attack surface security risk because if an attacker manages to compromise one system and learn the password to its local Administrator account, then they can leverage that account to instantly gain access to all other computers that also use that password for their local Administrator account.
try{
    Get-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name 'AdmPwdEnabled' -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -name 'AdmPwdEnabled' -Value 1 -ErrorAction Stop
}catch{
    try{
        new-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -name 'AdmPwdEnabled' -Type DWORD -Value 1 -Force -ErrorAction Stop
    }catch{
        Write-Error "failed to create HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd -name 'AdmPwdEnabled'"
    }
}

#Locally cached passwords or credentials can be accessed by malicious code or unauthorized users.
try{
    Get-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name 'DisableDomainCreds' -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -name 'DisableDomainCreds' -Value 1 -ErrorAction Stop
}catch{
    try{
        new-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -name 'DisableDomainCreds' -Type DWORD -Value 1 -Force -ErrorAction Stop
    }catch{
        Write-Error "failed to create HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -name 'DisableDomainCreds"
    }
}

#Allowing autorun commands to execute may introduce malicious code to a system without user intervention or awareness. Configuring this setting prevents autorun commands from executing.
try{
    Get-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoAutorun' -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -name 'NoAutorun' -Value 1 -ErrorAction Stop
}catch{
    try{
        new-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -name 'NoAutorun' -Type DWORD -Value 1 -Force -ErrorAction Stop
    }catch{
        Write-Error "failed to create HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -name 'NoAutorun'"
    }
}

#BitLocker requires the use of the function keys [F1-F10] for PIN entry since the PIN is entered in the pre-OS environment before localization support is available. This limits each PIN digit to one of ten possibilities. The TPM has an anti-hammering feature that includes a mechanism to exponentially increase the delay for PIN retry attempts; however, using a PIN that is short in length improves an attacker's chances of guessing the correct PIN.
try{
    Get-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name 'MinimumPIN' -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -name 'MinimumPIN' -Value 6 -ErrorAction Stop
}catch{
    try{
        new-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -name 'MinimumPIN' -Type DWORD -Value 6 -Force -ErrorAction Stop
    }catch{
        Write-Error "failed to create HKLM:\SOFTWARE\Policies\Microsoft\FVE -name 'MinimumPIN'"
    }
}

#If disabled, malicious attackers could potentially gain access to user credentials stored in memory and expose the machine to various types of attacks, such as pass-the-hash.
try{
    Get-ItemProperty -path "HKLM:\System\CurrentControlSet\Control\DeviceGuard" -Name 'EnableVirtualizationBasedSecurity' -ErrorAction Stop
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\DeviceGuard" -name 'EnableVirtualizationBasedSecurity' -Value 1 -ErrorAction Stop
}catch{
    try{
        new-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\DeviceGuard" -name 'EnableVirtualizationBasedSecurity' -Type DWORD -Value 1 -Force -ErrorAction Stop
    }catch{
        Write-Error "failed to create HKLM:\System\CurrentControlSet\Control\DeviceGuard -name 'EnableVirtualizationBasedSecurity'"
    }
}

