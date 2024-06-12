function PuTTYCredentials {
    if (Test-Path HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions) {
        Get-ChildItem HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions | ForEach-Object {
            $RegKeyName = Split-Path $_.Name -Leaf
            
            Write-Host -ForegroundColor GREEN "[YES]" -NoNewline
            Write-Host " Found some PuTTY credentials..."
            
            Write-Host "Key: $RegKeyName"
            @("HostName", "PortNumber", "UserName", "PublicKeyFile", "PortForwardings", "ConnectionSharing", "ProxyUsername", "ProxyPassword") | ForEach-Object {
            Write-Host "$_ :"
            Write-Host "$((Get-ItemProperty  HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions\$RegKeyName).$_)"
            }
        }
    } else { 
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " No putty credentials found in HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions"
    }
}

function PuTTYKeys {
    if (Test-Path HKCU:\Software\SimonTatham\PuTTY\SshHostKeys) { 
        Write-Host -ForegroundColor GREEN "[YES]" -NoNewline
        Write-Host " $((Get-Item -Path HKCU:\Software\SimonTatham\PuTTY\SshHostKeys).Property)"
    } else { 
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " No putty ssh keys found."
    }
}

function PuTTYSSHKnownHosts {
    $knownHostsFile = "$env:USERPROFILE\.ssh\known_hosts"

    if (Test-Path $knownHostsFile) {
        Get-Content $knownHostsFile
    } else {
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " No 'known_hosts file found.'"
    }
}