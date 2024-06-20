# - [x] Antivirus Enumeration
# - Network Enumeration
# - [x] User Enumeration
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
    function Get-RDPSessions {
        <#
        .DESCRIPTION
            Function searches for RDP sessions in the registry and prints out information about hostname/ip address and username.
            As well as searching for Default.rdp file in the user profile.
        #>
        
        param (
            [string]$Path = "$env:USERPROFILE\Documents"
        )

        function Get-RegistryRDPEntries {
            $rdpEntries = @()
            
            $registryPaths = @(
                "HKCU:\Software\Microsoft\Terminal Server Client\Default",
                "HKCU:\Software\Microsoft\Terminal Server Client\Servers"
            )

            foreach ($regPath in $registryPaths) {
                if (Test-Path $regPath) {
                    $entries = Get-ItemProperty -Path $regPath
                    foreach ($entry in $entries.PSObject.Properties) {
                        # Extrahiere nur relevante Einträge
                        if ($entry.Name -match "MRU") {
                            $rdpEntries += [PSCustomObject]@{
                                Host = $entry.Value
                                RegistryPath = $regPath
                            }
                        }
                        if ($regPath -match "Servers" -and $entry.Name -eq "UsernameHint") {
                            $rdpEntries += [PSCustomObject]@{
                                Host = Split-Path -Leaf $regPath
                                Username = $entry.Value
                                RegistryPath = $regPath
                            }
                        }
                    }
                }
            }
            return $rdpEntries
        }

        function Get-DefaultRDPFile {
            $rdpFilePath = Join-Path -Path $Path -ChildPath "Default.rdp"
            if ([System.IO.File]::Exists($rdpFilePath)) {
                #$fileInfo = Get-Item -Path $rdpFilePath
                $fileContent = Get-Content -Path $rdpFilePath
                return [PSCustomObject]@{
                    Name = $fileInfo.Name
                    Path = $fileInfo.FullName
                    LastModified = $fileInfo.LastWriteTime
                    Content = $fileContent -join "`n"
                }
            } else {
                return $null
            }
        }

        $registryEntries = Get-RegistryRDPEntries
        $defaultRDPFile = Get-DefaultRDPFile

        if ($registryEntries.Count -eq 0) {
            Write-Host -ForegroundColor RED "[NO]" -NoNewline
            Write-Host " NO RDP entries found in the registry."
        } else {
            Write-Host -ForegroundColor CYAN "[RESULT]" -NoNewline
            Write-Host " Found RDP entries in the registry."
            $registryEntries | ForEach-Object {
                $output = "Host: $_.Host"
                if ($_.PSObject.Properties["Username"]) {
                    $output += ", Username: $_.Username"
                }
                Write-Output $output
            }
        }

        if ($null -eq $defaultRDPFile) {
            Write-Host ""
            Write-Host -ForegroundColor RED "[NO]" -NoNewline
            Write-Host " NO Default.rdp file found in directory: $Path"
        } else {
            Write-Host ""
            Write-Host -ForegroundColor CYAN "[RESULT]" -NoNewline
            Write-Host " Found RDP Default.rdp file in the user profile."
            Write-Output "Name: $($defaultRDPFile.Name), Path: $($defaultRDPFile.Path), Last change: $($defaultRDPFile.LastModified)"
            Write-Output "Content: `n$($defaultRDPFile.Content)"
        }
    }

    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Searching for wifi's."
    netsh wlan show profiles

    Write-Host -ForegroundColor YELLOW "[INFO]" -NoNewline
    Write-Host " Searching for saved connections RDP."
    Get-RDPSessions
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
