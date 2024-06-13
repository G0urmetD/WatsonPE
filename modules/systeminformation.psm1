function KernelInformation {

    $osVersion = [System.Environment]::OSVersion.Version
    $osCaption = (Get-WmiObject -class Win32_OperatingSystem).Caption
    
    $osInfo = @{
        OS       = $osCaption
        Major    = $osVersion.Major
        Minor    = $osVersion.Minor
        Build    = $osVersion.Build
        Revision = $osVersion.Revision
    }

    $osInfo.GetEnumerator() | ForEach-Object { Write-Output "$($_.Key): $($_.Value)" }
}

function Test-DomainJoinStatus {
    # Check if the computer is domain joined
    $isDomainJoined = (Get-WmiObject Win32_ComputerSystem).PartOfDomain

    if ($isDomainJoined) {
        Write-Host -ForegroundColor Cyan "[INFO]" -NoNewline
        Write-Host " current computer is domain joined."

        # Fetch domain information
        $domainName = (Get-WmiObject Win32_ComputerSystem).Domain
        $domain = (Get-WmiObject Win32_NTDomain -Filter "DomainName='$domainName'")
        $forestName = $domain.DnsForestName
        $primaryDC = $domain.DomainControllerName
        $logonServer = $env:LOGONSERVER.TrimStart("\\")
        $domainSid = (Get-WmiObject Win32_ComputerSystem).DomainSid
        $domainRole = switch((Get-WmiObject Win32_ComputerSystem).DomainRole) {
            0 { "Standalone Workstation" }
            1 { "Member Workstation" }
            2 { "Standalone Server" }
            3 { "Member Server" }
            4 { "Backup Domain Controller" }
            5 { "Primary Domain Controller" }
        }

        # Get all domain controllers
        $domainControllers = (Get-WmiObject Win32_NTDomain -Filter "DomainName='$domainName'").DomainControllerName -join ", "

        # Trust Relationships
        $trusts = (Get-WmiObject -Namespace "Root\MicrosoftActiveDirectory" -Class "MSAD_TrustedDomain").Name -join ", "

        # PDC Emulator
        $pdcEmulator = (Get-ADDomainController -Discover -Service "PrimaryDC").Name

        # Functional Levels
        $domainFL = (Get-ADDomain).DomainMode
        $forestFL = (Get-ADForest).ForestMode

        # Output domain information
        Write-Output "DomainName: $domainName"
        Write-Output "ForestName: $forestName"
        Write-Output "PrimaryDC: $primaryDC"
        Write-Output "LogonServer: $logonServer"
        Write-Output "Domain SID: $domainSid"
        Write-Output "Domain Role: $domainRole"
        Write-Output "Domain Controllers: $domainControllers"
        Write-Output "Trust Relationships: $trusts"
        Write-Output "PDC Emulator: $pdcEmulator"
        Write-Output "Domain Functional Level: $domainFL"
        Write-Output "Forest Functional Level: $forestFL"
    } else {
        Write-Host -ForegroundColor Cyan "[INFO]" -NoNewline
        Write-Host " current computer is NOT domain joined."
    }
}

function AntiVirusDetection {
    WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName
    Get-ChildItem 'registry::HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions' -ErrorAction SilentlyContinue
}

function returnHotFixID {
    <#
    .NOTES
        Thanks to winPEAS creator.
    #>
    
    param(
      [string]$title
    )
    # Match on KB or if patch does not have a KB, return end result
    if (($title | Select-String -AllMatches -Pattern 'KB(\d{4,6})').Matches.Value) {
      return (($title | Select-String -AllMatches -Pattern 'KB(\d{4,6})').Matches.Value)
    }
    elseif (($title | Select-String -NotMatch -Pattern 'KB(\d{4,6})').Matches.Value) {
      return (($title | Select-String -NotMatch -Pattern 'KB(\d{4,6})').Matches.Value)
    }
}

function WindowsHotfixes {
    $Hotfix = Get-HotFix | Sort-Object -Descending -Property InstalledOn -ErrorAction SilentlyContinue | Select-Object HotfixID, Description, InstalledBy, InstalledOn
    $Hotfix | Format-Table -AutoSize
}

function WindowsHotfixHistory {
    <#
    .NOTES
        Thanks to winPEAS creator.
    #>
    
    $session = (New-Object -ComObject 'Microsoft.Update.Session')
    # Query the latest 50 updates starting with the first record
    $history = $session.QueryHistory("", 0, 1000) | Select-Object ResultCode, Date, Title

    #create an array for unique HotFixes
    $HotfixUnique = @()
    #$HotfixUnique += ($history[0].title | Select-String -AllMatches -Pattern 'KB(\d{4,6})').Matches.Value

    $HotFixReturnNum = @()
    #$HotFixReturnNum += 0 

    for ($i = 0; $i -lt $history.Count; $i++) {
    $check = returnHotFixID -title $history[$i].Title
    if ($HotfixUnique -like $check) {
        #Do Nothing
    }
    else {
        $HotfixUnique += $check
        $HotFixReturnNum += $i
    }
    }
    $FinalHotfixList = @()

    $hotfixreturnNum | ForEach-Object {
    $HotFixItem = $history[$_]
    $Result = $HotFixItem.ResultCode
    # https://learn.microsoft.com/en-us/windows/win32/api/wuapi/ne-wuapi-operationresultcode?redirectedfrom=MSDN
    switch ($Result) {
        1 {
        $Result = "Missing/Superseded"
        }
        2 {
        $Result = "Succeeded"
        }
        3 {
        $Result = "Succeeded With Errors"
        }
        4 {
        $Result = "Failed"
        }
        5 {
        $Result = "Canceled"
        }
    }
    $FinalHotfixList += [PSCustomObject]@{
        Result = $Result
        Date   = $HotFixItem.Date
        Title  = $HotFixItem.Title
    }    
    }
    $FinalHotfixList | Format-Table -AutoSize
}

function PSAuditWEFLAPS {
    <#
    .DESCRIPTION
        This function checks for PS, Audit, WEF and LAPS settings.
    #>

    # Audit log settings
    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Checking for audit log settings in registry ..."
    if ((Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\).Property) {
        Get-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\
    } else {
        Write-Host -ForegroundColor CYAN "[INFO]" -NoNewline
        Write-Host " No Audit Log settings, no registry entry found."
    }

    Write-Host ""

    # Windows Event Forward (WEF)
    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Checking for Windows Event Forward (WEF) settings in registry ..."
    if (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager) {
        Get-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
    } else {
        Write-Host -ForegroundColor CYAN "[INFO]" -NoNewline
        Write-Host " Logs are not being fowarded, no registry entry found."
    }

    Write-Host ""

    # LAPS settings
    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Checking for LAPS (Windows Local Administrator Password Solution) settings in registry ..."
    if (Test-Path 'C:\Program Files\LAPS\CSE\Admpwd.dll') { 
        Write-Host -ForegroundColor CYAN "[INFO]" -NoNewline
        Write-Host " LAPS dll found on this machine at C:\Program Files\LAPS\CSE\"
    } elseif (Test-Path 'C:\Program Files (x86)\LAPS\CSE\Admpwd.dll' ) { 
        Write-Host -ForegroundColor CYAN "[INFO]" -NoNewline
        Write-Host " LAPS dll found on this machine at C:\Program Files (x86)\LAPS\CSE\"
    } else { 
        Write-Host -ForegroundColor CYAN "[INFO]" -NoNewline
        Write-Host " LAPS dlls not found on this machine."
    }
    if ((Get-ItemProperty HKLM:\Software\Policies\Microsoft Services\AdmPwd -ErrorAction SilentlyContinue).AdmPwdEnabled -eq 1) { 
        Write-Host -ForegroundColor CYAN "[INFO]" -NoNewline
        Write-Host " LAPS registry key found on this machine."
    }
}

function LSAProtection {
    <#
    .DESCRIPTION
        The LSA (Local Security Authority) is a protected subsystem of Windows. Its task is not to grant access to resources without a user, service or system being correctly authenticated.
    #>
    
    $RunAsPPL = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\LSA).RunAsPPL
    $RunAsPPLBoot = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\LSA).RunAsPPLBoot
    switch ($RunAsPPL) {
    2 { 
        Write-Host -ForegroundColor CYAN "[INFO]" -NoNewline
        Write-Host " RunAsPPL: 2. Enabled without UEFI Lock"
    }
    1 { 
        Write-Host -ForegroundColor CYAN "[INFO]" -NoNewline
        Write-Host " RunAsPPL: 1. Enabled with UEFI Lock" 
    }
    0 { 
        Write-Host -ForegroundColor GREEN "[YES]" -NoNewline
        Write-Host " RunAsPPL: 0. LSA Protection Disabled. Try mimikatz."
    }
    Default { 
        Write-Host -ForegroundColor CYAN "[INFO]" -NoNewline
        Write-Host " The system was unable to find the specified registry value: RunAsPPL / RunAsPPLBoot" 
    }
    }
    if ($RunAsPPLBoot) { 
        Write-Host -ForegroundColor CYAN "[INFO]" -NoNewline
        Write-Host " RunAsPPLBoot = $($RunAsPPLBoot)" 
    }
}

function CredentialGuard {
    <#
    .DESCRIPTION
        When Credential Guard is enabled, Kerberos does not allow unrestricted Kerberos delegation or DES encryption, not only for logged-in credentials, but also for prompted or stored credentials.
    #>

    $LsaCfgFlags = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\LSA).LsaCfgFlags
    switch ($LsaCfgFlags) {
    2 { 
        Write-Host -ForegroundColor CYAN "[INFO]" -NoNewline
        Write-Host " LsaCfgFlags 2. Enabled without UEFI Lock"
    }
    1 { 
        Write-Host -ForegroundColor CYAN "[INFO]" -NoNewline
        Write-Host " LsaCfgFlags 1. Enabled with UEFI Lock"
    }
    0 { 
        Write-Host -ForegroundColor GREEN "[YES]" -NoNewline
        Write-Host " LsaCfgFlags 0. LsaCfgFlags Disabled."
    }
    Default { 
        Write-Host -ForegroundColor Cyan "[INFO]" -NoNewline
        Write-Host " The system was unable to find the specified registry value: LsaCfgFlags"
    }
    }
}

function WDigest {
    <#
    .DESCRIPTION
        WDigest authentication is a challenge/response protocol that was primarily used for LDAP and web-based authentication for Windows Server 2003. 
        The feature was first introduced with Windows XP and was enabled by default on Windows systems. WDigest enables clients to transmit logon 
        information in plain text to HTTP applications (HTTP: Hypertext Transfer Protocol) and SASL applications (SASL: Simple Authentication Security Layer).

        Microsoft stored the plain text credentials in Windows RAM when users logged on to their workstations to make the authentication process more convenient for end users. 
        The workstations used these cached credentials to authenticate to HTTP and SASL services without requiring users to re-enter their credentials over and over again. 
        The plain text credentials are used for authentication via HTTP and SASL exchange.
    #>

    $WDigest = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest).UseLogonCredential
    switch ($WDigest) {
    0 { 
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " Value 0 found. Plain-text Passwords are not stored in LSASS"
    }
    1 { 
        Write-Host -ForegroundColor GREEN "[YES]" -NoNewline
        Write-Host " Value 1 found. Plain-text Passwords may be stored in LSASS"
    }
    Default { 
        Write-Host -ForegroundColor CYAN "[INFO]" -NoNewline
        Write-Host " The system was unable to find the specified registry value: UesLogonCredential" 
    }
    }
}

function CachedWinlogonCredentials {
    <#
    .DESCRIPTION
        Mscash is a Microsoft hashing algorithm that is used for storing cached domain credentials locally on a system after a successful logon. 
        It's worth noting that cached credentials do not expire. Domain credentials are cached on a local system so that domain members can logon to the machine even if the DC is down. 
        It's worth noting that mscash hash is not passable - i.e PTH attacks will not work

    .NOTES
        https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-and-cracking-mscash-cached-domain-credentials
    #>
    
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon") {
        $number = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CACHEDLOGONSCOUNT").CACHEDLOGONSCOUNT
        Write-Host -ForegroundColor Cyan "[INFO]" -NoNewline
        Write-Host " Number of cached winlogon credentials = $number"

        Write-Host -ForegroundColor CYAN "[INFO]" -NoNewline
        Write-Host " However, only the SYSTEM user can view the credentials here: HKEY_LOCAL_MACHINE\SECURITY\Cache"

        Write-Host -ForegroundColor GREEN "[YES]" -NoNewline
        Write-Host " Seems we have a local privilege escalation factor."
        Write-Host ""
        Write-Host -ForegroundColor DarkGreen "[HINT]" -NoNewline
        Write-Host " Using Mimikatz = lsadump::cache"
    }

    # additional Winlogon checks
    (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").DefaultDomainName
    (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").DefaultUserName
    (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").DefaultPassword
    (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").AltDefaultDomainName
    (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").AltDefaultUserName
    (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").AltDefaultPassword
}

function EnvironmentVariables {
    Write-Host -ForegroundColor CYAN "[INFO]" -NoNewline
    Write-Host " Maybe you can take advantage of modifying/creating a binary in some of the following locations"

    Write-Host -ForegroundColor CYAN "[INFO]" -NoNewline
    Write-Host " PATH variable entries permissions - place binary or DLL to execute instead of legitimate"

    Write-Host -ForegroundColor DarkGreen "[HINT]" -NoNewline
    Write-Host " https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#dll-hijacking"

    Get-ChildItem env: | Format-Table -Wrap
}

function UACSettings {
    <#
    .DESCRIPTION
        This function checks the status of User Account Control (UAC) on a Windows system. It examines various settings in the registry key "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" to determine if UAC is enabled and what configurations are present.
    #>
    # Check if the registry key exists
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") {
        $systemPolicy = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        
        # Check if EnableLUA = 1
        if ($systemPolicy.EnableLUA -eq 1) {
            # Check if LocalAccountTokenFilterPolicy exists and is equal to 1
            if ($systemPolicy.PSObject.Properties.Name -contains "LocalAccountTokenFilterPolicy" -and $systemPolicy.LocalAccountTokenFilterPolicy -eq 1) {
                Write-Host -ForegroundColor GREEN "[YES]" -NoNewline
                Write-Host " EnableLUA = 1 and LocalAccountTokenFilterPolicy = 1. NO UAC FOR ANYONE."

                Write-Host "
                    0 = UAC won't prompt (like disabled)
                    1 = admin is asked for username and password to execute the binary with high rights (on Secure Desktop)
                    2 = UAC will always ask for confirmation to the administrator when he tries to execute something with high privileges
                    3 = like 1 but not necessary on Secure Desktop
                    4 = like 2 but not necessary on Secure Desktop
                    5 = [default] it will ask the administrator to confirm to run non Windows binaries with high privileges
                "

                Write-Host -ForegroundColor DarkGreen "[HINT]" -NoNewline
                Write-Host " https://book.hacktricks.xyz/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control"
            }
            # Check if FilterAdministratorToken exists and is equal to 0
            elseif ($systemPolicy.PSObject.Properties.Name -contains "FilterAdministratorToken" -and $systemPolicy.FilterAdministratorToken -eq 0) {
                Write-Host -ForegroundColor GREEN "[YES]" -NoNewline
                Write-Host " EnableLUA = 1 and LocalAccountTokenFilterPolicy = 0 and FilterAdministratorToken = 0. NO UAC FOR RID 500 (BUILT-IN Administrators)."

                Write-Host "
                    0 = UAC won't prompt (like disabled)
                    1 = admin is asked for username and password to execute the binary with high rights (on Secure Desktop)
                    2 = UAC will always ask for confirmation to the administrator when he tries to execute something with high privileges
                    3 = like 1 but not necessary on Secure Desktop
                    4 = like 2 but not necessary on Secure Desktop
                    5 = [default] it will ask the administrator to confirm to run non Windows binaries with high privileges
                "

                Write-Host -ForegroundColor DarkGreen "[HINT]" -NoNewline
                Write-Host " https://book.hacktricks.xyz/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control"
            }
            # Check if FilterAdministratorToken exists and is equal to 1
            elseif ($systemPolicy.PSObject.Properties.Name -contains "FilterAdministratorToken" -and $systemPolicy.FilterAdministratorToken -eq 1) {
                Write-Host -ForegroundColor RED "[NO]" -NoNewline
                Write-Host " EnableLUA = 1 and LocalAccountTokenFilterPolicy = 0 and FilterAdministratorToken = 1. UAC FOR EVERYONE."

                Write-Host "
                    0 = UAC won't prompt (like disabled)
                    1 = admin is asked for username and password to execute the binary with high rights (on Secure Desktop)
                    2 = UAC will always ask for confirmation to the administrator when he tries to execute something with high privileges
                    3 = like 1 but not necessary on Secure Desktop
                    4 = like 2 but not necessary on Secure Desktop
                    5 = [default] it will ask the administrator to confirm to run non Windows binaries with high privileges
                "

                Write-Host -ForegroundColor DarkGreen "[HINT]" -NoNewline
                Write-Host " https://book.hacktricks.xyz/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control"
            }
        }
        # Check if EnableLUA = 0
        elseif ($systemPolicy.EnableLUA -eq 0) {
            Write-Host -ForegroundColor GREEN "[YES]" -NoNewline
            Write-Host " EnableLUA = 0. NO UAC FOR ANYONE."
        }
    }
}

function Spooler {
    <#
    .DESCRIPTION
        A running spooler service leads possibly to RCE or LPE.

    .NOTES
        https://www.hackingarticles.in/windows-privilege-escalation-printnightmare/
    #>

    if((Get-Service -Name Spooler).Status -eq "Running") {
        $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"

        Write-Host -ForegroundColor GREEN "[YES]" -NoNewline
        Write-Host " Spooler service is running, good luck."

        Write-Host -ForegroundColor DarkGreen "[HINT]" -NoNewline
        Write-Host " https://www.hackingarticles.in/windows-privilege-escalation-printnightmare/"
        
        if(Test-Path $registryPath) {
            $permissions = Get-Acl -Path $registryPath | Select-Object -ExpandProperty Access
            $canInstallPrinterDrivers = $permissions | Where-Object { $_.IdentityReference -match "BUILTIN\\Administrators" -and $_.FileSystemRights -match "FullControl" }

            if ($canInstallPrinterDrivers) {
                Write-Host -ForegroundColor GREEN "[YES]" -NoNewline
                Write-Host " The user has authorizations to install printer drivers."
            } else {
                Write-Host -ForegroundColor GREEN "[YES]" -NoNewline
                Write-Host " The user has no authorizations to install printer drivers."
            }
        }
    } else {
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " Spooler service is not running."
    }
}

function WeakRegistryKeyPermissions {
    <#
    .DESCRIPTION
        Weak registry permissions represent a vulnerability within the Windows registry resulting from misconfigured access controls. 
        This issue involves specific registry keys or entries having permissions that permit unauthorized users to manipulate or access crucial system configurations. 
        This vulnerability can be exploited by attackers who inject malicious code into registry keys, thus obtaining unauthorized privileged access.
    #>
    # Define the path to search
    $path = 'HKLM:\System\CurrentControlSet\services\*'

    # Get all registry keys
    $keys = Get-ChildItem -Path $path

    # Store results in a variable
    $results = @()

    foreach ($key in $keys) {
        try {
            $acl = Get-Acl -Path $key.PSPath
            $permissions = $acl.Access

            foreach ($permission in $permissions) {
                if ($permission.IdentityReference -eq "Everyone" -and $permission.FileSystemRights -eq "FullControl") {
                    $results += [PSCustomObject]@{
                        RegistryKey = $key.PSPath
                        IdentityReference = $permission.IdentityReference
                        FileSystemRights = $permission.FileSystemRights
                        AccessControlType = $permission.AccessControlType
                    }
                }
            }
        } catch {
            Write-Host "Error accessing ACL for $($key.PSPath): $_"
        }
    }

    # Output the results in table format
    $results | Format-Table -AutoSize
}

function UnattendedFiles {
    <#
    .DESCRIPTION
        Function to check for unattended files and search for specific strings within them.
    #>

    # array with file paths
    $files = @(
        'C:\Windows\Panther\unattend.xml',
        'C:\Windows\Panther\Unattend\unattend.xml',
        'C:\Windows\System32\Sysprep\unattend.xml',
        'C:\Windows\System32\Sysprep\sysprep.xml',
        'C:\Windows\System32\Sysprep\Panther\unattend.xml',
        'C:\Windows\sysprep.inf',
        'C:\Windows\unattend.xml',
        'C:\unattend.xml',
        'C:\sysprep.inf'
    )

    # define strings to search in files
    $searchStrings = @("Username", "username", "Value", "value", "Benutzername", "benutzername", "Wert", "wert")

    Write-Host;foreach ($file in $files) {
        if (Test-Path $file) {
            Write-Host -ForegroundColor CYAN "[+]" -NoNewline
            Write-Host " $file"
            
            # search through file to find strings
            $content = Get-Content $file
            foreach ($searchString in $searchStrings) {
                $searchResults = Select-String -InputObject $content -Pattern $searchString

                foreach ($result in $searchResults) {
                    Write-Host "    Found '$($result.Matches.Value)' for '$searchString' at line $($result.LineNumber): $($result.Line)"
                }
            }
        }
    }
}

function Check-DirectoryPermissions {
    <#
    .DESCRIPTION
        This function checks the directory permissions of running processes to identify potential vulnerabilities 
        for DLL injection. It lists the executable paths of all processes, excluding those in "system32", and 
        checks if the directory permissions allow modifications by certain user groups such as Everyone, 
        Authenticated Users, or the current user. If such permissions are found, it outputs the directory 
        path and the associated permissions.
    #>
    
    # Get the list of processes and their paths
    $processes = Get-WmiObject -Query "SELECT ExecutablePath FROM Win32_Process WHERE ExecutablePath IS NOT NULL"

    # Filter out the processes whose path contains "system32"
    $filteredProcesses = $processes | Where-Object { $_.ExecutablePath -notmatch "system32" -and $_.ExecutablePath -match ":" }

    # Loop through the filtered processes
    foreach ($process in $filteredProcesses) {
        $path = [System.IO.Path]::GetDirectoryName($process.ExecutablePath)

        # Execute icacls and filter the output
        $icaclsOutput = icacls $path 2>$null
        $match = $icaclsOutput | Select-String -Pattern "\((F|M|W)\) .*:\\"

        # Filter further by specific users and groups
        $userMatches = $match -match "everyone|authenticated users|todos|$env:username"
        if ($userMatches) {
            Write-Host -ForegroundColor GREEN "[YES]" -NoNewline
            Write-Host " Potentially vulnerable directory permissions found in: $path"

            Write-Output $icaclsOutput
            Write-Output ""
        }
    }
}
