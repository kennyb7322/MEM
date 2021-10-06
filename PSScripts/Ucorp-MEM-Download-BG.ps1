$url = 'https://ucorpstorage.blob.core.windows.net/m365filerepo/Bsodwindows10.jpg?sp=r&st=2021-04-11T09:08:40Z&se=2024-04-11T17:08:40Z&spr=https&sv=2020-02-10&sr=b&sig=T5b3eY3xq6no60jJdLgRtbdCYVVA4JSKj5zbliVA1xo%3D'
$Destination = 'C:\Windows\Web\Wallpaper\Theme1\ucorp-background.jpg'

Invoke-WebRequest -Uri $url -OutFile $Destination