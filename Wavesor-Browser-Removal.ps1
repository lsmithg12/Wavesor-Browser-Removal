Function Set-Owner {
    <#
        .SYNOPSIS
            Changes owner of a file or folder to another user or group.
        .DESCRIPTION
            Changes owner of a file or folder to another user or group.
        .PARAMETER Path
            The folder or file that will have the owner changed.
        .PARAMETER Account
            Optional parameter to change owner of a file or folder to specified account.
            Default value is 'Builtin\Administrators'
        .PARAMETER Recurse
            Recursively set ownership on subfolders and files beneath given folder.
        .NOTES
            Name: Set-Owner
            Author: Boe Prox
            Version History:
                 1.0 - Boe Prox
                    - Initial Version
        .EXAMPLE
            Set-Owner -Path C:\temp\test.txt
            Description
            -----------
            Changes the owner of test.txt to Builtin\Administrators
        .EXAMPLE
            Set-Owner -Path C:\temp\test.txt -Account 'Domain\bprox
            Description
            -----------
            Changes the owner of test.txt to Domain\bprox
        .EXAMPLE
            Set-Owner -Path C:\temp -Recurse 
            Description
            -----------
            Changes the owner of all files and folders under C:\Temp to Builtin\Administrators
        .EXAMPLE
            Get-ChildItem C:\Temp | Set-Owner -Recurse -Account 'Domain\bprox'
            Description
            -----------
            Changes the owner of all files and folders under C:\Temp to Domain\bprox
    #>
    [cmdletbinding(
        SupportsShouldProcess = $True
    )]
    Param (
        [parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [Alias('FullName')]
        [string[]]$Path,
        [parameter()]
        [string]$Account = 'Builtin\Administrators',
        [parameter()]
        [switch]$Recurse
    )
    Begin {
        #Prevent Confirmation on each Write-Debug command when using -Debug
        If ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }
        Try {
            [void][TokenAdjuster]
        } Catch {
            $AdjustTokenPrivileges = @"
            using System;
            using System.Runtime.InteropServices;
             public class TokenAdjuster
             {
              [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
              internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
              ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
              [DllImport("kernel32.dll", ExactSpelling = true)]
              internal static extern IntPtr GetCurrentProcess();
              [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
              internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr
              phtok);
              [DllImport("advapi32.dll", SetLastError = true)]
              internal static extern bool LookupPrivilegeValue(string host, string name,
              ref long pluid);
              [StructLayout(LayoutKind.Sequential, Pack = 1)]
              internal struct TokPriv1Luid
              {
               public int Count;
               public long Luid;
               public int Attr;
              }
              internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
              internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
              internal const int TOKEN_QUERY = 0x00000008;
              internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
              public static bool AddPrivilege(string privilege)
              {
               try
               {
                bool retVal;
                TokPriv1Luid tp;
                IntPtr hproc = GetCurrentProcess();
                IntPtr htok = IntPtr.Zero;
                retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
                tp.Count = 1;
                tp.Luid = 0;
                tp.Attr = SE_PRIVILEGE_ENABLED;
                retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
                retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                return retVal;
               }
               catch (Exception ex)
               {
                throw ex;
               }
              }
              public static bool RemovePrivilege(string privilege)
              {
               try
               {
                bool retVal;
                TokPriv1Luid tp;
                IntPtr hproc = GetCurrentProcess();
                IntPtr htok = IntPtr.Zero;
                retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
                tp.Count = 1;
                tp.Luid = 0;
                tp.Attr = SE_PRIVILEGE_DISABLED;
                retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
                retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                return retVal;
               }
               catch (Exception ex)
               {
                throw ex;
               }
              }
             }
"@
            Add-Type $AdjustTokenPrivileges
        }

        #Activate necessary admin privileges to make changes without NTFS perms
        [void][TokenAdjuster]::AddPrivilege("SeRestorePrivilege") #Necessary to set Owner Permissions
        [void][TokenAdjuster]::AddPrivilege("SeBackupPrivilege") #Necessary to bypass Traverse Checking
        [void][TokenAdjuster]::AddPrivilege("SeTakeOwnershipPrivilege") #Necessary to override FilePermissions
    }
    Process {
        ForEach ($Item in $Path) {
            Write-Verbose "FullName: $Item"
            #The ACL objects do not like being used more than once, so re-create them on the Process block
            $DirOwner = New-Object System.Security.AccessControl.DirectorySecurity
            $DirOwner.SetOwner([System.Security.Principal.NTAccount]$Account)
            $FileOwner = New-Object System.Security.AccessControl.FileSecurity
            $FileOwner.SetOwner([System.Security.Principal.NTAccount]$Account)
            $DirAdminAcl = New-Object System.Security.AccessControl.DirectorySecurity
            $FileAdminAcl = New-Object System.Security.AccessControl.DirectorySecurity
            $AdminACL = New-Object System.Security.AccessControl.FileSystemAccessRule('Builtin\Administrators','FullControl','ContainerInherit,ObjectInherit','InheritOnly','Allow')
            $FileAdminAcl.AddAccessRule($AdminACL)
            $DirAdminAcl.AddAccessRule($AdminACL)
            Try {
                $Item = Get-Item -LiteralPath $Item -Force -ErrorAction Stop
                If (-NOT $Item.PSIsContainer) {
                    If ($PSCmdlet.ShouldProcess($Item, 'Set File Owner')) {
                        Try {
                            $Item.SetAccessControl($FileOwner)
                        } Catch {
                            Write-Warning "Couldn't take ownership of $($Item.FullName)! Taking FullControl of $($Item.Directory.FullName)"
                            $Item.Directory.SetAccessControl($FileAdminAcl)
                            $Item.SetAccessControl($FileOwner)
                        }
                    }
                } Else {
                    If ($PSCmdlet.ShouldProcess($Item, 'Set Directory Owner')) {                        
                        Try {
                            $Item.SetAccessControl($DirOwner)
                        } Catch {
                            Write-Warning "Couldn't take ownership of $($Item.FullName)! Taking FullControl of $($Item.Parent.FullName)"
                            $Item.Parent.SetAccessControl($DirAdminAcl) 
                            $Item.SetAccessControl($DirOwner)
                        }
                    }
                    If ($Recurse) {
                        [void]$PSBoundParameters.Remove('Path')
                        Get-ChildItem $Item -Force | Set-Owner @PSBoundParameters
                    }
                }
            } Catch {
                Write-Warning "$($Item): $($_.Exception.Message)"
            }
        }
    }
    End {  
        #Remove priviledges that had been granted
        [void][TokenAdjuster]::RemovePrivilege("SeRestorePrivilege") 
        [void][TokenAdjuster]::RemovePrivilege("SeBackupPrivilege") 
        [void][TokenAdjuster]::RemovePrivilege("SeTakeOwnershipPrivilege")     
    }
}

Set-Variable -Name ErrorActionPreference -Value SilentlyContinue

#Uninstalls Wave Browser
echo "_________________________"
echo "Uninstalling Wave Browser"
echo "_________________________"

<# $UninstallWaveBrowser = (Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\| Get-ItemProperty | Where {$_.DisplayName 
-like "WaveBrowser"}).UninstallString.Replace("MsiExec.exe /I","") #>

<# if ($UninstallWaveBrowser) {
    $UninstallArg = '/x '+$UninstallWaveBrowser+' /qn /norestart'
    Start-Process -FilePath msiexec.exe -ArgumentList $UninstallArg -wait
} #>

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

#Remove-Item "c:\Users\*\Wavesor Software” -Force -Recurse -Verbose

(Get-ChildItem -Path "c:\Users\*\Wavesor Software\"  -Depth 200  -Force -Recurse).Fullname |
ForEach-Object {


echo "Setting permissions to SYSTEM for $_"
Set-Owner -Recurse -Account '.\SYSTEM' -Verbose

echo "Removing...  $_"
Remove-Item "$_" -Force -Recurse
Remove-Item "$_" -Force -Recurse


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
