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
    [Parameter(HelpMessage = "Starts scan with all checks.")]
    [Alias('a')]
    [switch]$all,

    [Parameter(HelpMessage = "Starts scan with light checks.")]
    [Alias('l')]
    [switch]$light,

    [Parameter(HelpMessage = "Start enumeration module.")]
    [Alias('e')]
    [switch]$enum,

    [Parameter(HelpMessage = "Starts credential enumeration.")]
    [Alias('c')]
    [switch]$creds,

    [Parameter(HelpMessage = "Send some help for young padawans.")]
    [Alias('h')]
    [switch]$help
)

function ShowBanner {
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

    Author: G0urmetD
    Version: $version
    " -ForegroundColor Magenta
}
function SendHelp {
    ShowBanner
    Write-Host "
        -a, -all           Starts scan with all checks.
        -l, -light         Starts scan with light checks.
        -e, -enum          Starts the enumeration module.
        -c, -creds         Starts credential enumeration.
        
        -h, -help          Send some help for young padawans.
    "
}

if($all) {

    # show the banner
    ShowBanner

    # import necessary modules
    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Importing the modules ..."
    $modulePath = ".\modules"
    Get-ChildItem -Path $modulePath -Filter *.psm1 | ForEach-Object { Import-Module -Name $_.FullName -Force }

    Write-Host "=====================================================================================================" -ForegroundColor Blue
    Write-Host "=================================== Computer Information=============================================" -ForegroundColor Blue
    Write-Host "=====================================================================================================" -ForegroundColor Blue
    Write-Host ""

    Write-Host "================================= { OS Information } ================================================" -ForegroundColor Blue
    Write-Host "=====================================================================================================" -ForegroundColor Blue
    KernelInformation | Format-Table

    Write-Host ""
    Write-Host "================================= { Windows Hotfixes } ==============================================" -ForegroundColor Blue
    Write-Host "=====================================================================================================" -ForegroundColor Blue
    WindowsHotfixes
    WindowsHotfixHistory

    Write-Host ""
    Write-Host "================================= { LSAProtection } =================================================" -ForegroundColor Blue
    Write-Host "=====================================================================================================" -ForegroundColor Blue
    LSAProtection

    Write-Host ""
    Write-Host "================================= { Unquoted Service Path } =========================================" -ForegroundColor Blue
    Write-Host "=====================================================================================================" -ForegroundColor Blue
    UnquotedServicePath

    Write-Host ""
    Write-Host "================================= { Spooler / PrintNightmare } ======================================" -ForegroundColor Blue
    Write-Host "=====================================================================================================" -ForegroundColor Blue
    Spooler

    Write-Host ""
    Write-Host "================================= { Insecure GUI Apps } =============================================" -ForegroundColor Blue
    Write-Host "=====================================================================================================" -ForegroundColor Blue
    InsecureGUIApps

    Write-Host ""
    Write-Host "================================= { Cached Windows Vault Credentials } ==============================" -ForegroundColor Blue
    Write-Host "=====================================================================================================" -ForegroundColor Blue
    CachedWindowsVaultCredentials

    Write-Host ""
    Write-Host "================================= { Shadow Copies } =================================================" -ForegroundColor Blue
    Write-Host "=====================================================================================================" -ForegroundColor Blue
    ShadowCopies

    Write-Host ""
    Write-Host "================================= { Search for vulnerable drivers } =================================" -ForegroundColor Blue
    Write-Host "=====================================================================================================" -ForegroundColor Blue
    $vulnerableDrivers = Get-VulnerableDrivers
    if ($vulnerableDrivers.Count -gt 0) {
        Write-Host -ForegroundColor GREEN "[YES]" -NoNewline
        Write-Host " No vulnerable drivers found."

        $vulnerableDrivers | Format-Table -AutoSize
    }
    else {
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " No vulnerable drivers found."
    }

    Write-Host ""
    Write-Host "================================= { Incorrect permissions in Services } =============================" -ForegroundColor Blue
    Write-Host "=====================================================================================================" -ForegroundColor Blue
    Find-PathDLLHijack

    Start-Sleep -Seconds 2

    Write-Host "=====================================================================================================" -ForegroundColor Blue
    Write-Host "=================================== User Information ================================================" -ForegroundColor Blue
    Write-Host "=====================================================================================================" -ForegroundColor Blue
    Write-Host ""

    Write-Host "================================= { From Local administrator to NT SYSTEM } =========================" -ForegroundColor Blue
    Write-Host "=====================================================================================================" -ForegroundColor Blue
    if (Test-IsAdmin) {
        Write-Host -ForegroundColor GREEN "[YES]" -NoNewline
        Write-Host " You have already local admin rights. Your account is part of the Administrators group."
        Write-Host -ForegroundColor DarkGreen "[HINT]" -NoNewline
        Write-Host " Try: PsExec.exe -i -s cmd.exe"
    } else {
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " You have NO local admin rights."
    }

    Write-Host "=====================================================================================================" -ForegroundColor Blue
    Write-Host "=================================== Credential Enumeration ==========================================" -ForegroundColor Blue
    Write-Host "=====================================================================================================" -ForegroundColor Blue
    Write-Host ""

    Write-Host "================================= { SAM & SYSTEM files } ============================================" -ForegroundColor Blue
    Write-Host "=====================================================================================================" -ForegroundColor Blue
    SAMSYSTEMBackup

    Write-Host "================================= { HiveNightmare } =================================================" -ForegroundColor Blue
    Write-Host "=====================================================================================================" -ForegroundColor Blue
    HiveNightmare

    Write-Host "================================= { Passwords in unattend.xml } =====================================" -ForegroundColor Blue
    Write-Host "=====================================================================================================" -ForegroundColor Blue
    Get-UnattendedInstallFile

    Write-Host "================================= { WiFi credentials } ==============================================" -ForegroundColor Blue
    Write-Host "=====================================================================================================" -ForegroundColor Blue
    WifiCredentials

    Write-Host "================================= { Windows Credential Manager } ====================================" -ForegroundColor Blue
    Write-Host "=====================================================================================================" -ForegroundColor Blue
    CachedWindowsVaultCredentials

    Write-Host "================================= { Windows Vault } ================================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    Get-VaultCredential

    Write-Host "================================= { DPAPI Masterkeys } =============================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    DPAPIMasterKeys

    Write-Host "================================= { DPAPI RPC Masterkeys } =========================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    DPAPIRPCMasterKeys

    Write-Host "================================= { Remote Desktop Credential Manager } ============================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    RemoteDesktopCredentialManager

    Write-Host "================================= { Cloud Credentials } ============================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    CloudCredentials

    Write-Host "================================= { OpenVPN Credentiasl } ==========================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    OpenVPNCredentials

    Write-Host "================================= { OpenSSH Keys } =================================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    OpenSSHKeys

    Write-Host "================================= { WinVNC Passwords } =============================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    WinVNCPasswords

    Write-Host "================================= { SNMP Passwords } ===============================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    SNMPPasswords

    Write-Host "================================= { TightVNC Passwords } ===========================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    TightVNCPasswords

    Write-Host "================================= { Group Policy Passwords } =======================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    GroupPolicyPasswords

    Write-Host "================================= { Kerberos Tickets } =============================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    KerberosTickets

    Write-Host "================================= { Group Policy History Files } ===================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    Find-GPHistoryFiles

    Write-Host "================================= { PuTTY Credentials } ============================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    PuTTYCredentials

    Write-Host "================================= { PuTTY Keys } ===================================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    PuTTYKeys

    Write-Host "================================= { PuTTY SSH Known Hosts } ========================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    PuTTYSSHKnownHosts
} elseif($light) {

} elseif ($enum) {
    
} elseif ($creds) {
    Write-Host "=====================================================================================================" -ForegroundColor Blue
    Write-Host "=================================== Credential Enumeration ==========================================" -ForegroundColor Blue
    Write-Host "=====================================================================================================" -ForegroundColor Blue
    Write-Host ""

    Write-Host "================================= { SAM & SYSTEM files } ============================================" -ForegroundColor Blue
    Write-Host "=====================================================================================================" -ForegroundColor Blue
    SAMSYSTEMBackup

    Write-Host "================================= { HiveNightmare } =================================================" -ForegroundColor Blue
    Write-Host "=====================================================================================================" -ForegroundColor Blue
    HiveNightmare

    Write-Host "================================= { Passwords in unattend.xml } =====================================" -ForegroundColor Blue
    Write-Host "=====================================================================================================" -ForegroundColor Blue
    Get-UnattendedInstallFile

    Write-Host "================================= { WiFi credentials } ==============================================" -ForegroundColor Blue
    Write-Host "=====================================================================================================" -ForegroundColor Blue
    WifiCredentials

    Write-Host "================================= { Windows Credential Manager } ====================================" -ForegroundColor Blue
    Write-Host "=====================================================================================================" -ForegroundColor Blue
    CachedWindowsVaultCredentials

    Write-Host "================================= { Windows Vault } ================================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    Get-VaultCredential

    Write-Host "================================= { DPAPI Masterkeys } =============================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    DPAPIMasterKeys

    Write-Host "================================= { DPAPI RPC Masterkeys } =========================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    DPAPIRPCMasterKeys

    Write-Host "================================= { Remote Desktop Credential Manager } ============================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    RemoteDesktopCredentialManager

    Write-Host "================================= { Cloud Credentials } ============================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    CloudCredentials

    Write-Host "================================= { OpenVPN Credentiasl } ==========================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    OpenVPNCredentials

    Write-Host "================================= { OpenSSH Keys } =================================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    OpenSSHKeys

    Write-Host "================================= { WinVNC Passwords } =============================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    WinVNCPasswords

    Write-Host "================================= { SNMP Passwords } ===============================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    SNMPPasswords

    Write-Host "================================= { TightVNC Passwords } ===========================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    TightVNCPasswords

    Write-Host "================================= { Group Policy Passwords } =======================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    GroupPolicyPasswords

    Write-Host "================================= { Kerberos Tickets } =============================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    KerberosTickets

    Write-Host "================================= { Group Policy History Files } ===================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    Find-GPHistoryFiles

    Write-Host "================================= { PuTTY Credentials } ============================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    PuTTYCredentials

    Write-Host "================================= { PuTTY Keys } ===================================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    PuTTYKeys

    Write-Host "================================= { PuTTY SSH Known Hosts } ========================================" -ForegroundColor Blue
    Write-Host "====================================================================================================" -ForegroundColor Blue
    PuTTYSSHKnownHosts
} else {
    SendHelp
    exit
}
