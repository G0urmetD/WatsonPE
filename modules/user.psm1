# - Scheduled task, the user can modify (from PowerUp)
# - Default writable Folders
# - AlwaysInstallElevated
# - CustomActions
# - From local administrator to NT SYSTEM
# - Impersonation Privileges
#     - SeBackup (Read sensitive files: SAM/SYSTEM/MEMORY.DMP)
#     - SeAssignPrimaryToken (Allows a user to impersonate tokens and privesc to NT SYSTEM using tools as potato.exe/rottenpotato.exe/juicyportato.exe)
#     - SeCreateToken (Create arbitrary token including local admin rights with "NtCreateToken")
#     - SeDebug (Duplicate the "lsass.exe" token [https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1])
#     - SeLoadDriver (Can be used to load buggy drivers as szkg64.sys [CVE-2018-15732])
#     - SeRestore (Launch ISE.exe with SeRestore privileges, enabled "Enable-SeRestorePrivilege", Rename utilman.exe to utilman.old, Rename cmd.exe to utilman.exe, lock and press Win+U)
#     - SeTakeOwnership ('takeown.exe /f "%windir%\system32"' , 'icalcs.exe "%windir%\system32" /grant "%username%":F' , Rename cmd.exe to utilman.exe, lock and press Win+U )
#     - SeTcb (Manipulate tokens to have local admin rights included. May require SeImpersonate to be verified.)
#     - SeRelable (Allows you to own resources that have an integrity level even higher than your own [https://github.com/decoder-it/RelabelAbuse])
#     - SeImpersonate (allows to impersonate any token, given that a handle to it can be obtained. Exploited with: juicy-potato/RogueWinRM/SweetPotato/PrintSpoofer)
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
