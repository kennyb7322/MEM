$HKLMregistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive'##Path to HKLM keys
$DiskSizeregistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive\DiskSpaceCheckThresholdMB'##Path to max disk size key
$KFMSilentOptIn = 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive'
$TenantGUID = 'a2de9bda-ffed-4527-96d7-d6f3ac10da8c'

IF(!(Test-Path $HKLMregistryPath))
{New-Item -Path $HKLMregistryPath -Force}
IF(!(Test-Path $DiskSizeregistryPath))
{New-Item -Path $DiskSizeregistryPath -Force}
New-ItemProperty -Path $HKLMregistryPath -Name 'SilentAccountConfig' -Value '1' -PropertyType DWORD -Force | Out-Null ##Enable silent account configuration
New-ItemProperty -Path $DiskSizeregistryPath -Name $TenantGUID -Value '102400' -PropertyType DWORD -Force | Out-Null ##Set max OneDrive threshold before prompting
New-ItemProperty -Path $KFMSilentOptIn -Name 'KFMSilentOptIn' -Value $TenantGUID -Force | Out-Null ##Silent redirect known folders to Onedrive
