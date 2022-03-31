# Set TimeZone and system settings
$systemlocale = "nl-NL"

Set-Culture -CultureInfo $systemlocale
Set-WinSystemLocale -SystemLocale $systemlocale
Set-WinHomeLocation -GeoId 176
Set-WinUserLanguageList $systemlocale -Force

Set-TimeZone -Id "W. Europe Standard Time"