#Uninstalls Wave Browser
echo "_________________________"
echo "Uninstalling Wave Browser"
echo "_________________________"

$BadApp = Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq "WaveBrowser"}

$BadApp.Uninstall


#Kills background tasks
echo "____________________________"
echo "Stopping background services"
echo "____________________________"


Stop-Process -name wavebrowser -Force -Verbose

Stop-Process -name SWUpdaterCrashHandler64 -Force -Verbose

Stop-Process -name SWUpdaterCrashHandler -Force -Verbose

Stop-Process -name SWUpdater -Force -Verbose


#Remove scheduled tasks
echo "________________________"
echo "Deleting scheduled tasks"
echo "________________________"


Unregister-ScheduledTask -TaskName *Wavesor* -Confirm:$false -Verbose

Unregister-ScheduledTask -TaskName WaveBrowser-StartAtLogin -Confirm:$false -Verbose


#Removes Tasks folder
echo "_______________________"
echo "Removing task locations"
echo "_______________________"

Remove-Item -Path "C:\Windows\System32\Tasks\Wavesor*" -Force -Recurse -Verbose

#Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Wavesor*" #This won't work for some reason


#Removes directories
echo "____________________________"
echo "Removing install directories"
echo "____________________________"

Remove-Item "c:\Users\*\Wavesor Software” -Force -Recurse -Verbose


#Removes Registry keys
echo "______________________"
echo "Deleting registry keys"
echo "______________________"

<#
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | out-null 
Get-ChildItem -Path c:\Users | ? Name -notMatch 'Public|Administrator' | ForEach {
    $TempName    = $_.Name
    $TempHive    = Join-Path HKU $_.Name
    $ProfilePath = Join-Path $_.FullName NTUSER.DAT
    reg load       $TempHive $ProfilePath
    Remove-Item    "HKU:\$TempName\SOFTWARE\WaveBrowser" -Recurse -Force -Verbose
    reg unload     $TempHive
}
#>

Remove-Item "HKCU:\Software\WaveBrowser" -Force -Recurse -Verbose

Remove-Item "HKCU:\Software\Wavesor" -Force -Recurse -Verbose


#Removes shortcut on desktop
echo "_________________________"
echo "Deleting desktop shortcut"
echo "_________________________"

Remove-Item "C:\Users\*\Desktop\WaveBrowser.lnk" -Force -Recurse -Verbose


#Removes Start Menu shortcut
echo "____________________________"
echo "Removing start menu shortcut"
echo "____________________________"

Remove-Item "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Wavebrowser.*" -Force -Recurse -Verbose


#Reset Default apps
#Remove pinned taskbar 
