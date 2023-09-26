$Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer'
Set-ItemProperty -Path $Path -Name 'ShowFrequent' -Value 0

$Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
Set-ItemProperty -Path $Path -Name 'NavPaneExpandToCurrentFolder' -Value 1
Set-ItemProperty -Path $Path -Name 'HideFileExt' -Value 0
Set-ItemProperty -Path $Path -Name 'LaunchTo' -Value 1 # 1 This PC - 2 Quick Access
Set-ItemProperty -Path $Path -Name 'ShowRecent' -Value 0
Set-ItemProperty -Path $Path -Name 'Start_TrackDocs' -Value 0

$Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState'
$values = Get-ItemPropertyValue -Path $Path -Name 'Settings'

$values[4] = 10 # in the same window
# $values[4] = 42 # in its own window
Set-ItemProperty -Path $Path -Name 'Settings' -Value $values
