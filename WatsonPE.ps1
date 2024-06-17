<#
.DESCRIPTION
    WatsonPE is a small Local Privilege Escalation scan tool, to automate the LPE search on Windows workstations, servers or dc's.
    The tool can be used on Windows 10/11 and Windows Server 2016/2019/2022/2025.

.PARAMETER all
    The all parameter is used for every check in the repository.

.PARAMETER light
    The light parameter is default and used for quick wins and juicy stuff.

.PARAMETER help
    The help parameter is used to show the help function and get an idea of the full functionality of the tool.
#>

param(
    [Parameter(HelpMessage = "Switch parameter to run all local priv checks.")]
    [Alias('a')]
    [switch]$all,

    [Parameter(HelpMessage = "Switch parameter run quick wins.")]
    [Alias('l')]
    [switch]$light,

    [Parameter(HelpMessage = "Show some help.")]
    [Alias('h')]
    [switch]$help
)

function Show-Banner {
    <#
    .DESCRIPTION
        Tool Banner.
    .PARAMETER version
        Defines the version.
    #>

    param(
        [string]$version = "1.1"
    )

    Write-Host "
     _    _       _                  ______ _____ 
    | |  | |     | |                 | ___ \  ___|
    | |  | | __ _| |_ ___  ___  _ __ | |_/ / |__  
    | |/\| |/ _` | __/ __|/ _  \| '_ \|  __/|  __| 
    \  /\  / (_| | |_\__ \ (_) | | | | |   | |___ 
     \/  \/ \__,_|\__|___/\___/|_| |_\_|   \____/ 
                                               
    " -ForegroundColor DarkMagenta
    Write-Output "
    Author = G0urmetD
    version = $version
    "
}

# display the tool banner
Show-Banner

if($help) {
    Write-Host "==================== { Description } ===================="
    Write-Output "WatsonPE is a small Local Privilege Escalation scan tool, to automate the LPE search on Windows workstations, servers or dc's."
    Write-Host "==================== { Parameters } ===================="
    Write-Output "
        -h, -help               Show help function.
        -a, -all                Run all checks.
        -l, -light              Run light checks (quick wins).
    "
    Write-Host "==================== { Colors } ===================="
    Write-Host -ForegroundColor YELLOW "        [YELLOW]" -NoNewline
    Write-Host "         ====> running action"
    Write-Host -ForegroundColor DarkMagenta "        [DarkMagenta]" -NoNewline
    Write-Host "    ====> script information output"
    Write-Host -ForegroundColor CYAN "        [CYAN]" -NoNewline
    Write-Host "           ====> action information"
    Write-Host -ForegroundColor BLUE "        [BLUE]" -NoNewline
    Write-Host "           ====> LPE function information banner"
    Write-Host ""
    Write-Host -ForegroundColor GREEN "        [GREEN]" -NoNewline
    Write-Host "          ====> possible Local Privilege Escalation"
    Write-Host -ForegroundColor RED "        [RED]" -NoNewline
    Write-Host "            ====> NO possible Local Privilege Escalation"

    exit
}

function CheckSystemInfo {
    <#
    .DESCRIPTION
        Fetch system information to get difference between running on a workstation or server.
    #>

    # import of modules
    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Importing the modules ..."
    $modulePath = ".\modules"
    Get-ChildItem -Path $modulePath -Filter *.psm1 | ForEach-Object { Import-Module -Name $_.FullName -Force }

    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " checking on which system we are running (workstation/domain controller/server)."
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem

    if ($osInfo.ProductType -eq 1) {
        # workstation OS
        Write-Host -ForegroundColor DarkMagenta "[WORKSTATION]" -NoNewline
        Write-Host " found a workstation OS = $($osInfo.Version)"
        Write-Host ""
        if ($all) {
            Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
            Write-Host " -all parameter was provided, starting scan ..."
            
            Invoke-WorkstationChecks -All
        } elseif ($light) {
            Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
            Write-Host " -light parameter was provided, starting scan ..."

            Invoke-WorkstationChecks -Light
        } else {
            Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
            Write-Host " No parameter was provided, running -light scan as default."
            
            Invoke-WorkstationChecks
        }
    } elseif ($osInfo.ProductType -eq 2) {
        # domain controller
        Write-Host -ForegroundColor DarkMagenta "[DOMAIN CONTROLLER]" -NoNewline
        Write-Host " found a domain controller OS = $($osInfo.Version)"
        Write-Host ""
        if ($all) {
            Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
            Write-Host " -all parameter was provided, starting scan ..."
            
            Invoke-DomainControllerChecks -All
        } elseif ($light) {
            Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
            Write-Host " -light parameter was provided, starting scan ..."
            
            Invoke-DomainControllerChecks -Light
        } else {
            Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
            Write-Host " No parameter was provided, running -light scan as default."
            
            Invoke-DomainControllerChecks
        }
    } elseif ($osInfo.ProductType -eq 3) {
        # server
        Write-Host -ForegroundColor DarkMagenta "[SERVER]" -NoNewline
        Write-Host " found a server OS = $($osInfo.Version)"
        Write-Host ""
        if ($all) {
            Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
            Write-Host " -all parameter was provided, starting scan ..."
            
            Invoke-ServerChecks -All
        } elseif ($light) {
            Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
            Write-Host " -light parameter was provided, starting scan ..."
            
            Invoke-ServerChecks -Light
        } else {
            Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
            Write-Host " No parameter was provided, running -light scan as default."
            
            Invoke-ServerChecks
        }
    } else {
        Write-Host -ForegroundColor Red "[ERROR]" -NoNewline
        Write-Host " Was not possible to identify the system = $($osInfo.Version)"
        Write-Host ""
    }
}

function Invoke-WorkstationChecks {
    
    param(
        [Parameter(HelpMessage = "Switch parameter to run all local priv checks.")]
        [Alias('a')]
        [switch]$all,

        [Parameter(HelpMessage = "Switch parameter run quick wins.")]
        [Alias('l')]
        [switch]$light
    )

    if($all) {
        Write-Host "==================== { Computer Information } ====================" -ForegroundColor Blue
        Write-Host "==============================================================" -ForegroundColor Blue
        Write-Host "==================== { KernelInformation" -ForegroundColor Blue
        KernelInformation

        Write-Host ""
        Write-Host "==================== { Domain joined test & domain information" -ForegroundColor Blue
        Test-DomainJoinStatus

        Write-Host ""
        Write-Host "==================== { Domain joined test & domain information" -ForegroundColor Blue
        AntiVirusDetection

        Write-Host ""
        Write-Host "==================== { Windows Installed Hotfixes" -ForegroundColor Blue
        WindowsHotfixes

        Write-Host ""
        Write-Host "==================== { Windows Hotfix History" -ForegroundColor Blue
        WindowsHotfixHistory

        Write-Host ""
        Write-Host "==================== { Audit, WEF and LAPS" -ForegroundColor Blue
        PSAuditWEFLAPS

        Write-Host ""
        Write-Host "==================== { LSA Protection check" -ForegroundColor Blue
        LSAProtection

        Write-Host ""
        Write-Host "==================== { Credential Guard check" -ForegroundColor Blue
        CredentialGuard

        Write-Host ""
        Write-Host "==================== { WDigest" -ForegroundColor Blue
        WDigest

        Write-Host ""
        Write-Host "==================== { Cached Winlogon Credentials" -ForegroundColor Blue
        CachedWinlogonCredentials

        Write-Host ""
        Write-Host "==================== { Environment Variables" -ForegroundColor Blue
        EnvironmentVariables

        Write-Host ""
        Write-Host "==================== { UAC Settings/Bypass" -ForegroundColor Blue
        UACSettings

        Write-Host ""
        Write-Host "==================== { Spooler/PrintNightmare" -ForegroundColor Blue
        Spooler

        Write-Host ""
        Write-Host "==================== { Weak registry settings" -ForegroundColor Blue
        WeakRegistryKeyPermissions

        Write-Host ""
        Write-Host "==================== { Unattended Files" -ForegroundColor Blue
        UnattendedFiles

        Write-Host ""
        Write-Host "==================== { Check Directory Permissions" -ForegroundColor Blue
        CheckDirectoryPermissions

        Write-Host ""
        Write-Host "==================== { User Information } ====================" -ForegroundColor Blue
        Write-Host "==============================================================" -ForegroundColor Blue
        Write-Host "==================== { Local Groups and directory access" -ForegroundColor Blue
        UserInformation

        Write-Host ""
        Write-Host "==================== { Net accounts Information" -ForegroundColor Blue
        NetAccountsInfo

        Write-Host ""
        Write-Host "==================== { Remote Sessions" -ForegroundColor Blue
        RemoteSessions

        Write-Host ""
        Write-Host "==================== { Current Sessions" -ForegroundColor Blue
        CurrentSessions

        Write-Host ""
        Write-Host "==================== { AlwaysInstallElevated" -ForegroundColor Blue
        AlwaysInstallElevated

        Write-Host ""
        Write-Host "==================== { SeBackUpPrivilege" -ForegroundColor Blue
        SeBackUpPrivilege

        Write-Host ""
        Write-Host "==================== { SeImpersonatePrivilege" -ForegroundColor Blue
        SeImpersonatePrivilege

        Write-Host ""
        Write-Host "==================== { UnquotedServicePath" -ForegroundColor Blue
        UnquotedServicePath

        Write-Host ""
        Write-Host "==================== { HiveNightmare" -ForegroundColor Blue
        HiveNightmare

        Write-Host ""
        Write-Host "==================== { Credentials } ====================" -ForegroundColor Blue
        Write-Host "==============================================================" -ForegroundColor Blue
        Write-Host "==================== { Remote Desktop Credential Manager" -ForegroundColor Blue
        RemoteDesktopCredentialManager

        Write-Host ""
        Write-Host "==================== { Cloud Credentials" -ForegroundColor Blue
        CloudCredentials

        Write-Host ""
        Write-Host "==================== { OpenVPN Credentials" -ForegroundColor Blue
        OpenVPNCredentials

        Write-Host ""
        Write-Host "==================== { Wifi Credentials" -ForegroundColor Blue
        WifiCredentials

        Write-Host ""
        Write-Host "==================== { OpenSSH Keys" -ForegroundColor Blue
        OpenSSHKeys

        Write-Host ""
        Write-Host "==================== { WinVNC Passwords" -ForegroundColor Blue
        WinVNCPasswords

        Write-Host ""
        Write-Host "==================== { SNMP Passwords" -ForegroundColor Blue
        SNMPPasswords

        Write-Host ""
        Write-Host "==================== { TightVNC Passwords" -ForegroundColor Blue
        TightVNCPasswords

        Write-Host ""
        Write-Host "==================== { Group Policy Passwords" -ForegroundColor Blue
        GroupPolicyPasswords

        Write-Host ""
        Write-Host "==================== { SAM SYSTEM Backup" -ForegroundColor Blue
        SAMSYSTEMBackup

        Write-Host ""
        Write-Host "==================== { Kerberos Tickets" -ForegroundColor Blue
        KerberosTickets

        Write-Host ""
        Write-Host "==================== { DPAPI Master Keys" -ForegroundColor Blue
        DPAPIMasterKeys

        Write-Host ""
        Write-Host "==================== { DPAPI RPC Master Keys" -ForegroundColor Blue
        DPAPIRPCMasterKeys

        Write-Host ""
        Write-Host "==================== { Cached Windows Vault Credentials" -ForegroundColor Blue
        CachedWindowsVaultCredentials

        Write-Host ""
        Write-Host "==================== { GPP Passwords in files" -ForegroundColor Blue
        Find-GPHistoryFiles

        Write-Host ""
        Write-Host "==================== { PuTTY } ====================" -ForegroundColor Blue
        Write-Host "==============================================================" -ForegroundColor Blue

        Write-Host ""
        Write-Host "==================== { PuTTY Credentials" -ForegroundColor Blue
        PuTTYCredentials

        Write-Host ""
        Write-Host "==================== { PuTTY Keys" -ForegroundColor Blue
        PuTTYKeys

        Write-Host ""
        Write-Host "==================== { PuTTY SSH known Hosts" -ForegroundColor Blue
        PuTTYSSHKnownHosts
    } elseif($light) {
        Write-Host "==================== { Computer Information } ====================" -ForegroundColor Blue
        Write-Host "==============================================================" -ForegroundColor Blue
        Write-Host "==================== { KernelInformation" -ForegroundColor Blue
        KernelInformation

        Write-Host ""
        Write-Host "==================== { Domain joined test & domain information" -ForegroundColor Blue
        Test-DomainJoinStatus

        Write-Host ""
        Write-Host "==================== { Credential Guard check" -ForegroundColor Blue
        CredentialGuard

        Write-Host ""
        Write-Host "==================== { Cached Winlogon Credentials" -ForegroundColor Blue
        CachedWinlogonCredentials

        Write-Host ""
        Write-Host "==================== { Spooler/PrintNightmare" -ForegroundColor Blue
        Spooler

        Write-Host ""
        Write-Host "==================== { User Information } ====================" -ForegroundColor Blue
        Write-Host "==============================================================" -ForegroundColor Blue
        Write-Host "==================== { Local Groups and directory access" -ForegroundColor Blue
        UserInformation

        Write-Host ""
        Write-Host "==================== { AlwaysInstallElevated" -ForegroundColor Blue
        AlwaysInstallElevated

        Write-Host ""
        Write-Host "==================== { SeBackUpPrivilege" -ForegroundColor Blue
        SeBackUpPrivilege

        Write-Host ""
        Write-Host "==================== { SeImpersonatePrivilege" -ForegroundColor Blue
        SeImpersonatePrivilege

        Write-Host ""
        Write-Host "==================== { UnquotedServicePath" -ForegroundColor Blue
        UnquotedServicePath

        Write-Host ""
        Write-Host "==================== { HiveNightmare" -ForegroundColor Blue
        HiveNightmare

        Write-Host ""
        Write-Host "==================== { Group Policy Passwords" -ForegroundColor Blue
        GroupPolicyPasswords

        Write-Host ""
        Write-Host "==================== { SAM SYSTEM Backup" -ForegroundColor Blue
        SAMSYSTEMBackup
    } else {
        Write-Host "==================== { Computer Information } ====================" -ForegroundColor Blue
        Write-Host "==============================================================" -ForegroundColor Blue
        Write-Host "==================== { KernelInformation" -ForegroundColor Blue
        KernelInformation

        Write-Host ""
        Write-Host "==================== { Domain joined test & domain information" -ForegroundColor Blue
        Test-DomainJoinStatus

        Write-Host ""
        Write-Host "==================== { Credential Guard check" -ForegroundColor Blue
        CredentialGuard

        Write-Host ""
        Write-Host "==================== { Cached Winlogon Credentials" -ForegroundColor Blue
        CachedWinlogonCredentials

        Write-Host ""
        Write-Host "==================== { Spooler/PrintNightmare" -ForegroundColor Blue
        Spooler
        Write-Host ""
        Write-Host "==================== { User Information } ====================" -ForegroundColor Blue
        Write-Host "==============================================================" -ForegroundColor Blue
        Write-Host "==================== { Local Groups and directory access" -ForegroundColor Blue
        UserInformation

        Write-Host ""
        Write-Host "==================== { AlwaysInstallElevated" -ForegroundColor Blue
        AlwaysInstallElevated

        Write-Host ""
        Write-Host "==================== { SeBackUpPrivilege" -ForegroundColor Blue
        SeBackUpPrivilege

        Write-Host ""
        Write-Host "==================== { SeImpersonatePrivilege" -ForegroundColor Blue
        SeImpersonatePrivilege

        Write-Host ""
        Write-Host "==================== { UnquotedServicePath" -ForegroundColor Blue
        UnquotedServicePath

        Write-Host ""
        Write-Host "==================== { HiveNightmare" -ForegroundColor Blue
        HiveNightmare

        Write-Host ""
        Write-Host "==================== { Group Policy Passwords" -ForegroundColor Blue
        GroupPolicyPasswords

        Write-Host ""
        Write-Host "==================== { SAM SYSTEM Backup" -ForegroundColor Blue
        SAMSYSTEMBackup
    }
}

function Invoke-ServerChecks {
    Write-Host "==================== { Computer Information } ====================" -ForegroundColor Blue
    Write-Host "==============================================================" -ForegroundColor Blue
    Write-Host "==================== { KernelInformation" -ForegroundColor Blue
    KernelInformation

    Write-Host ""
    Write-Host "==================== { Domain joined test & domain information" -ForegroundColor Blue
    Test-DomainJoinStatus

    Write-Host ""
    Write-Host "==================== { Domain joined test & domain information" -ForegroundColor Blue
    AntiVirusDetection

    Write-Host ""
    Write-Host "==================== { Windows Installed Hotfixes" -ForegroundColor Blue
    WindowsHotfixes

    Write-Host ""
    Write-Host "==================== { Windows Hotfix History" -ForegroundColor Blue
    WindowsHotfixHistory

    Write-Host ""
    Write-Host "==================== { Audit, WEF and LAPS" -ForegroundColor Blue
    PSAuditWEFLAPS

    Write-Host ""
    Write-Host "==================== { LSA Protection check" -ForegroundColor Blue
    LSAProtection

    Write-Host ""
    Write-Host "==================== { Credential Guard check" -ForegroundColor Blue
    CredentialGuard

    Write-Host ""
    Write-Host "==================== { WDigest" -ForegroundColor Blue
    WDigest

    Write-Host ""
    Write-Host "==================== { Cached Winlogon Credentials" -ForegroundColor Blue
    CachedWinlogonCredentials

    Write-Host ""
    Write-Host "==================== { Environment Variables" -ForegroundColor Blue
    EnvironmentVariables

    Write-Host ""
    Write-Host "==================== { UAC Settings/Bypass" -ForegroundColor Blue
    UACSettings

    Write-Host ""
    Write-Host "==================== { Spooler/PrintNightmare" -ForegroundColor Blue
    Spooler

    Write-Host ""
    Write-Host "==================== { Weak registry settings" -ForegroundColor Blue
    WeakRegistryKeyPermissions

    Write-Host ""
    Write-Host "==================== { Unattended Files" -ForegroundColor Blue
    UnattendedFiles

    Write-Host ""
    Write-Host "==================== { Unattended Files" -ForegroundColor Blue
    CheckDirectoryPermissions

    Write-Host ""
    Write-Host "==================== { User Information } ====================" -ForegroundColor Blue
    Write-Host "==============================================================" -ForegroundColor Blue
    
    Write-Host ""
    Write-Host "==================== { Whoami" -ForegroundColor Blue
    Whoami
    
    Write-Host ""
    Write-Host "==================== { Local Groups and directory access" -ForegroundColor Blue
    UserInformation

    Write-Host ""
    Write-Host "==================== { Net accounts Information" -ForegroundColor Blue
    NetAccountsInfo

    Write-Host ""
    Write-Host "==================== { Remote Sessions" -ForegroundColor Blue
    RemoteSessions

    Write-Host ""
    Write-Host "==================== { Current Sessions" -ForegroundColor Blue
    CurrentSessions

    Write-Host ""
    Write-Host "==================== { AlwaysInstallElevated" -ForegroundColor Blue
    AlwaysInstallElevated

    Write-Host ""
    Write-Host "==================== { SeBackUpPrivilege" -ForegroundColor Blue
    SeBackUpPrivilege

    Write-Host ""
    Write-Host "==================== { SeImpersonatePrivilege" -ForegroundColor Blue
    SeImpersonatePrivilege

    Write-Host ""
    Write-Host "==================== { UnquotedServicePath" -ForegroundColor Blue
    UnquotedServicePath

    Write-Host ""
    Write-Host "==================== { Credentials } ====================" -ForegroundColor Blue
    Write-Host "==============================================================" -ForegroundColor Blue

    Write-Host ""
    Write-Host "==================== { Remote Desktop Credential Manager" -ForegroundColor Blue
    RemoteDesktopCredentialManager

    Write-Host ""
    Write-Host "==================== { Cloud Credentials" -ForegroundColor Blue
    CloudCredentials

    Write-Host ""
    Write-Host "==================== { OpenVPN Credentials" -ForegroundColor Blue
    OpenVPNCredentials

    Write-Host ""
    Write-Host "==================== { Wifi Credentials" -ForegroundColor Blue
    WifiCredentials

    Write-Host ""
    Write-Host "==================== { OpenSSH Keys" -ForegroundColor Blue
    OpenSSHKeys

    Write-Host ""
    Write-Host "==================== { WinVNC Passwords" -ForegroundColor Blue
    WinVNCPasswords

    Write-Host ""
    Write-Host "==================== { SNMP Passwords" -ForegroundColor Blue
    SNMPPasswords

    Write-Host ""
    Write-Host "==================== { TightVNC Passwords" -ForegroundColor Blue
    TightVNCPasswords

    Write-Host ""
    Write-Host "==================== { Group Policy Passwords" -ForegroundColor Blue
    GroupPolicyPasswords

    Write-Host ""
    Write-Host "==================== { SAM SYSTEM Backup" -ForegroundColor Blue
    SAMSYSTEMBackup

    Write-Host ""
    Write-Host "==================== { Kerberos Tickets" -ForegroundColor Blue
    KerberosTickets

    Write-Host ""
    Write-Host "==================== { DPAPI Master Keys" -ForegroundColor Blue
    DPAPIMasterKeys

    Write-Host ""
    Write-Host "==================== { DPAPI RPC Master Keys" -ForegroundColor Blue
    DPAPIRPCMasterKeys

    Write-Host ""
    Write-Host "==================== { Cached Windows Vault Credentials" -ForegroundColor Blue
    CachedWindowsVaultCredentials

    Write-Host ""
    Write-Host "==================== { GPP Passwords in files" -ForegroundColor Blue
    Find-GPHistoryFiles

    Write-Host ""
    Write-Host "==================== { PuTTY } ====================" -ForegroundColor Blue
    Write-Host "==============================================================" -ForegroundColor Blue

    Write-Host ""
    Write-Host "==================== { PuTTY Credentials" -ForegroundColor Blue
    PuTTYCredentials

    Write-Host ""
    Write-Host "==================== { PuTTY Keys" -ForegroundColor Blue
    PuTTYKeys

    Write-Host ""
    Write-Host "==================== { PuTTY SSH known Hosts" -ForegroundColor Blue
    PuTTYSSHKnownHosts
}

function Invoke-DomainControllerChecks {
    Write-Host "==================== { Computer Information } ====================" -ForegroundColor Blue
    Write-Host "==============================================================" -ForegroundColor Blue
    Write-Host "==================== { KernelInformation" -ForegroundColor Blue
    KernelInformation

    Write-Host ""
    Write-Host "==================== { Domain joined test & domain information" -ForegroundColor Blue
    Test-DomainJoinStatus

    Write-Host ""
    Write-Host "==================== { Domain joined test & domain information" -ForegroundColor Blue
    AntiVirusDetection

    Write-Host ""
    Write-Host "==================== { Windows Installed Hotfixes" -ForegroundColor Blue
    WindowsHotfixes

    Write-Host ""
    Write-Host "==================== { Windows Hotfix History" -ForegroundColor Blue
    WindowsHotfixHistory

    Write-Host ""
    Write-Host "==================== { Audit, WEF and LAPS" -ForegroundColor Blue
    PSAuditWEFLAPS

    Write-Host ""
    Write-Host "==================== { LSA Protection check" -ForegroundColor Blue
    LSAProtection

    Write-Host ""
    Write-Host "==================== { Credential Guard check" -ForegroundColor Blue
    CredentialGuard

    Write-Host ""
    Write-Host "==================== { WDigest" -ForegroundColor Blue
    WDigest

    Write-Host ""
    Write-Host "==================== { Cached Winlogon Credentials" -ForegroundColor Blue
    CachedWinlogonCredentials

    Write-Host ""
    Write-Host "==================== { Environment Variables" -ForegroundColor Blue
    EnvironmentVariables

    Write-Host ""
    Write-Host "==================== { UAC Settings/Bypass" -ForegroundColor Blue
    UACSettings

    Write-Host ""
    Write-Host "==================== { Spooler/PrintNightmare" -ForegroundColor Blue
    Spooler

    Write-Host ""
    Write-Host "==================== { Weak registry settings" -ForegroundColor Blue
    WeakRegistryKeyPermissions

    Write-Host ""
    Write-Host "==================== { Unattended Files" -ForegroundColor Blue
    UnattendedFiles

    Write-Host ""
    Write-Host "==================== { Unattended Files" -ForegroundColor Blue
    CheckDirectoryPermissions

    Write-Host ""
    Write-Host "==================== { User Information } ====================" -ForegroundColor Blue
    Write-Host "==============================================================" -ForegroundColor Blue
    
    Write-Host ""
    Write-Host "==================== { Whoami" -ForegroundColor Blue
    Whoami
    
    Write-Host ""
    Write-Host "==================== { Local Groups and directory access" -ForegroundColor Blue
    UserInformation

    Write-Host ""
    Write-Host "==================== { Net accounts Information" -ForegroundColor Blue
    NetAccountsInfo

    Write-Host ""
    Write-Host "==================== { Remote Sessions" -ForegroundColor Blue
    RemoteSessions

    Write-Host ""
    Write-Host "==================== { Current Sessions" -ForegroundColor Blue
    CurrentSessions

    Write-Host ""
    Write-Host "==================== { AlwaysInstallElevated" -ForegroundColor Blue
    AlwaysInstallElevated

    Write-Host ""
    Write-Host "==================== { SeBackUpPrivilege" -ForegroundColor Blue
    SeBackUpPrivilege

    Write-Host ""
    Write-Host "==================== { SeImpersonatePrivilege" -ForegroundColor Blue
    SeImpersonatePrivilege

    Write-Host ""
    Write-Host "==================== { UnquotedServicePath" -ForegroundColor Blue
    UnquotedServicePath

    Write-Host ""
    Write-Host "==================== { Credentials } ====================" -ForegroundColor Blue
    Write-Host "==============================================================" -ForegroundColor Blue

    Write-Host ""
    Write-Host "==================== { Remote Desktop Credential Manager" -ForegroundColor Blue
    RemoteDesktopCredentialManager

    Write-Host ""
    Write-Host "==================== { Cloud Credentials" -ForegroundColor Blue
    CloudCredentials

    Write-Host ""
    Write-Host "==================== { OpenVPN Credentials" -ForegroundColor Blue
    OpenVPNCredentials

    Write-Host ""
    Write-Host "==================== { Wifi Credentials" -ForegroundColor Blue
    WifiCredentials

    Write-Host ""
    Write-Host "==================== { OpenSSH Keys" -ForegroundColor Blue
    OpenSSHKeys

    Write-Host ""
    Write-Host "==================== { WinVNC Passwords" -ForegroundColor Blue
    WinVNCPasswords

    Write-Host ""
    Write-Host "==================== { SNMP Passwords" -ForegroundColor Blue
    SNMPPasswords

    Write-Host ""
    Write-Host "==================== { TightVNC Passwords" -ForegroundColor Blue
    TightVNCPasswords

    Write-Host ""
    Write-Host "==================== { Group Policy Passwords" -ForegroundColor Blue
    GroupPolicyPasswords

    Write-Host ""
    Write-Host "==================== { SAM SYSTEM Backup" -ForegroundColor Blue
    SAMSYSTEMBackup

    Write-Host ""
    Write-Host "==================== { Kerberos Tickets" -ForegroundColor Blue
    KerberosTickets

    Write-Host ""
    Write-Host "==================== { DPAPI Master Keys" -ForegroundColor Blue
    DPAPIMasterKeys

    Write-Host ""
    Write-Host "==================== { DPAPI RPC Master Keys" -ForegroundColor Blue
    DPAPIRPCMasterKeys

    Write-Host ""
    Write-Host "==================== { Cached Windows Vault Credentials" -ForegroundColor Blue
    CachedWindowsVaultCredentials

    Write-Host ""
    Write-Host "==================== { GPP Passwords in files" -ForegroundColor Blue
    Find-GPHistoryFiles

    Write-Host ""
    Write-Host "==================== { PuTTY } ====================" -ForegroundColor Blue
    Write-Host "==============================================================" -ForegroundColor Blue

    Write-Host ""
    Write-Host "==================== { PuTTY Credentials" -ForegroundColor Blue
    PuTTYCredentials

    Write-Host ""
    Write-Host "==================== { PuTTY Keys" -ForegroundColor Blue
    PuTTYKeys

    Write-Host ""
    Write-Host "==================== { PuTTY SSH known Hosts" -ForegroundColor Blue
    PuTTYSSHKnownHosts
}

# Call the CheckSystemInfo function
CheckSystemInfo
