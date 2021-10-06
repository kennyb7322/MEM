# Script to define regional settings on Azure Virtual Machines deployed from the market place
# Blogpost: https://mscloud.be/configure-regional-settings-and-windows-locales-on-azure-virtual-machines/
######################################

#variables
$regionalsettingsURL = 'https://ucorpwvdstorage.blob.core.windows.net/wvdfilerepo/NLRegion.xml?sp=r&st=2020-08-07T12:07:06Z&se=2022-08-07T20:07:06Z&spr=https&sv=2019-12-12&sr=b&sig=C1tZv9fmqgx125WUmQKbaFTA3LZ2dH%2Bf5M3MGibxhxE%3D'
$RegionalSettings = "D:\NLRegion.xml"

#download regional settings file
$webclient = New-Object System.Net.WebClient
$webclient.DownloadFile($regionalsettingsURL,$RegionalSettings)

# Set Locale, language etc. 
& $env:SystemRoot\System32\control.exe "intl.cpl,,/f:`"$RegionalSettings`""

# Set languages/culture. Not needed perse.
Set-WinSystemLocale nl-NL
Set-WinUserLanguageList -LanguageList nl-NL -Force
Set-Culture -CultureInfo nl-NL
Set-WinHomeLocation -GeoId 176
Set-TimeZone -Name "W. Europe Standard Time"

# restart virtual machine to apply regional settings to current user. You could also do a logoff and login.
Start-sleep -Seconds 40
Restart-Computer