# Windows Privilege Escalation
## Summary

### Computer
- [x] Kernel Exploitation
- [x] HotFixID & HotFixHistory
- [x] Incorrect permissions in Services (Find-PathDLLHijack)
- [x] Unquoted Service Paths
- [x] Insecure GUI Apps
- [x] Evaluating Vulnerable Drivers
- [x] PrintNightmare
- [x] Runas [https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/#eop-runas]
- [x] Abusing Shadow Copies [https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/#eop-abusing-shadow-copies]
- [x] LSA Protection

### Current User
- Default writable Folders
- AlwaysInstallElevated
- CustomActions
- From local administrator to NT SYSTEM
- Impersonation Privileges
    - SeBackup (Read sensitive files: SAM/SYSTEM/MEMORY.DMP)
    - SeAssignPrimaryToken (Allows a user to impersonate tokens and privesc to NT SYSTEM using tools as potato.exe/rottenpotato.exe/juicyportato.exe)
    - SeCreateToken (Create arbitrary token including local admin rights with "NtCreateToken")
    - SeDebug (Duplicate the "lsass.exe" token [https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1])
    - SeLoadDriver (Can be used to load buggy drivers as szkg64.sys [CVE-2018-15732])
    - SeRestore (Launch ISE.exe with SeRestore privileges, enabled "Enable-SeRestorePrivilege", Rename utilman.exe to utilman.old, Rename cmd.exe to utilman.exe, lock and press Win+U)
    - SeTakeOwnership ('takeown.exe /f "%windir%\system32"' , 'icalcs.exe "%windir%\system32" /grant "%username%":F' , Rename cmd.exe to utilman.exe, lock and press Win+U )
    - SeTcb (Manipulate tokens to have local admin rights included. May require SeImpersonate to be verified.)
    - SeRelable (Allows you to own resources that have an integrity level even higher than your own [https://github.com/decoder-it/RelabelAbuse])
    - SeImpersonate (allows to impersonate any token, given that a handle to it can be obtained. Exploited with: juicy-potato/RogueWinRM/SweetPotato/PrintSpoofer)
- Privileged File Write (usable only before 1903)
    - WerTrigger (Exploit Privileged File Writes bugs with Windows Problem Reporting)
        - Clone https://github.com/sailay1996/WerTrigger
        - Copy phoneinfo.dll to C:\Windows\System32\
        - Place Report.wer file and WerTrigger.exe in a same directory.
        - Then, run WerTrigger.exe
        - Enjoy a shell as NT AUTHORITY\SYSTEM
    - WerMgr (Exploit Privileged Directory Creation Bugs with Windows Error Reporting)
        - Clone https://github.com/binderlabs/DirCreate2System
        - Create directory C:\Windows\System32\wermgr.exe.local\
        - Grant access to it: cacls C:\Windows\System32\wermgr.exe.local /e /g everyone:f
        - Place spawn.dll file and dircreate2system.exe in a same directory and run .\dircreate2system.exe
        - Enjoy a shell as NT AUTHORITY\SYSTEM
- Privileged File Delete
    - During an MSI installation, the Windows Installer service maintains a record of every changes in case it needs to be rolled back, to do that it will create:
        - a folder at C:\Config.msi containing
            - a rollback script (.rbs)
            - a rollback file (.rbf)
    - [https://github.com/thezdi/PoC/tree/master/FilesystemEoPs/FolderOrFileDeleteToSystem]
        - The exploit contains a .msi file with 2 actions, the first produces a delay and the second throws and error to make it rollback. The rollback will "restore" a malicious HID.dll in `C:\Program Files\Microsoft Shared\ink\HID.dll`
        - Then switch to the secure desktop using: `[CTRL]+[ALT]+[DELETE]` and open the On-Screen Keyboard (osk.exe).
        - osk.exe process first looks for the `C:\Program Files\Common Files\Microsoft\shared\ink\HID.dll` library instead of `C:\Windows\System32\HID.dll`

### Credentials
- Looting for Passwords/Credentials
    - SAM & SYSTEM files
    - HiveNightmare
    - LAPS Settings
    - Search for file contents
    - Search for file with certain filename
    - Search the registry for key names and passwords
    - Passwords in unattend.xml
    - Wifi Passwords
    - Sticky Notes Passwords
    - Passwords stored in Services
    - Passwords stored in Key Manager
    - PowerShell History
    - PowerShell Transcript
    - Password in Alternate Data Stream
    - Windows Credential Manager
    - Windows Vault
    - DPAPI Masterkeys
    - DPAPI Credential files

### Enumeration Module
- User Enumeration
- Network Enumeration
- Antivirus Enumeration
- Process Enumeration & Tasks

### Common Vulnerabilities
- MS10-015 (KiTrap0D) - Microsoft Windows NT/2000/2003/2008/XP/Vista/7
- MS11-080 (afd.sys) - Microsoft Windows XP/2003
- MS15-051 (Client Copy Image) - Microsoft Windows 2003/2008/7/8/2012
- MS16-032 - Microsoft Windows 7 < 10 / 2008 < 2012 R2 (x86/x64)
- MS17-010 (Eternal Blue)
- CVE-2019-1388
- CVE-2024-30080 (Microsoft Message Queuing (MSMQ) Remote Code Execution Vulnerability)
```PowerShell
$msmqService = Get-Service -Name MSMQ -ErrorAction SilentlyContinue
if ($msmqService.Status -eq 'Running') {
    Write-Output "[!] MSMQ service is running."
} else {
    Write-Output "[+] MSMQ service is not running."
}
```
