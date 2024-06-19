# - Antivirus Enumeration
# - Network Enumeration
# - User Enumeration
# - Process Enumeration & Tasks
# - ScheduledTaskEnumeration

function AntiVirusDetection {
    try {
        $antivirusProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object DisplayName, ProductState

        if ($antivirusProducts) {
            Write-Host -ForegroundColor CYAN "[INFO]" -NoNewline
            Write-Host " AntiVirus Software founded:"

            $antivirusProducts | Format-Table DisplayName, ProductState -AutoSize
        } else {
            Write-Output "Keine Antivirus-Software gefunden."
        }

        $defenderExclusions = Get-ChildItem 'registry::HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions' -ErrorAction SilentlyContinue

        if ($defenderExclusions) {
            Write-Output "Windows Defender Ausschlüsse:"
            $defenderExclusions | Format-Table PSChildName -AutoSize
        } else {
            Write-Host -ForegroundColor CYAN "[INFO]" -NoNewline
            Write-Host " No Windows Defender exclusions found."
        }
    }
    catch {
        Write-Host -ForegroundColor CYAN "[ERROR]" -NoNewline
        Write-Host " Error in identifying antivirus software or windows defender exclusions: $_"
    }
}

function NetworkEnumeration {
    <#
    .DESCRIPTION
        Function to enumerate saved WIFI's, open ports and saved Connections (RDP/PuTTY).
    #>

    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Searching for wifi's."
    netsh wlan show profiles

    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Searching for saved connections RDP/PuTTY."
    
}

function UserEnumeration {
    <#
    .DESCRIPTION
        Search for local users on the current computer and their group memberships. On top the function searches for user profiles and extract the usernames.
    #>
    
    Write-Output "=== Local users ==="
    $adsi = [ADSI]"WinNT://$env:COMPUTERNAME"
    $adsi.Children | Where-Object {$_.SchemaClassName -eq 'user'} | Foreach-Object {
        $groups = $_.Groups() | Foreach-Object {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)}
        $_ | Select-Object @{n='UserName';e={$_.Name}},@{n='Groups';e={$groups -join ';'}}
    }

    Write-Output ""
    Write-Output "=== user profiles ==="
    $userProfiles = Get-ChildItem -Path 'C:\Users' | Where-Object { $_.PSIsContainer -and $_.Name -ne 'Public' -and $_.Name -ne 'Default' -and $_.Name -ne 'Default User' } | Select-Object -ExpandProperty Name
    $userProfiles | Format-Table
}

function ProcessEnumeration {

}

function ScheduledTaskEnumeration {

}