function MSMQVulnerability {
    <#
    .DESCRIPTION
        [CVE-2024-30080] Checks if the service msmq is running.
    #>

    $msmqService = Get-Service -Name MSMQ -ErrorAction SilentlyContinue
    if ($msmqService.Status -eq 'Running') {
        Write-Output "[!] MSMQ service is running."

        Write-Host -ForegroundColor GREEN "[YES]" -NoNewline
        Write-Host " MSMQ service is running. Search for an exploit."
    } else {
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " MSMQ service is NOT running."
    }
}

function MS17010 {
    <#
    .DESCRIPTION
        [CVE-2017] Checks for EternalBlue - SMBv1.

    .NOTES
        https://support.sophos.com/support/s/article/KB-000038107?language=en_US

        # File:             C:\Windows\System32\drivers\srv.sys
        # InternalName:     SRV.SYS
        # OriginalFileName: SRV.SYS.MUI
        # FileVersion:      10.0.14393.0 (rs1_release.160715-1616)
        # FileDescription:  Server driver
        # Product:          Microsoft Windows Operating System
        # ProductVersion:   10.0.14393.0
        # Debug:            False
        # Patched:          False
        # PreRelease:       False
        # PrivateBuild:     False
        # SpecialBuild:     False
        # Language:         English (United States)

        # Current OS: Microsoft Windows Server 2016 Datacenter (Build Number 14393)
        # Expected Version of srv.sys: 10.0.14393.953
        # Actual Version of srv.sys: 10.0.14.393.0
        # Message: [VULNERABLE] System is NOT patched against MS17-010
    #>

    [reflection.assembly]::LoadWithPartialName("System.Version")
    $os = Get-WmiObject -class Win32_OperatingSystem
    $osName = $os.Caption
    $s = "%systemroot%\system32\drivers\srv.sys"
    $v = [System.Environment]::ExpandEnvironmentVariables($s)
    If (Test-Path "$v") {
        Try {
            $versionInfo = (Get-Item $v).VersionInfo
            $versionString = "$($versionInfo.FileMajorPart).$($versionInfo.FileMinorPart).$($versionInfo.FileBuildPart).$($versionInfo.FilePrivatePart)"
            $fileVersion = New-Object System.Version($versionString)
        } Catch {
            Write-Host -ForegroundColor CYAN "[INFO]" -NoNewline
        Write-Host " Unable to retrieve file version info, please verify vulnerability state manually."
            Return
        }
    } Else {
        Write-Host "`n`n"
        Write-Host -ForegroundColor CYAN "[INFO]" -NoNewline
        Write-Host " Srv.sys does not exist, please verify vulnerability state manually."
        Return
    }

    if ($osName.Contains("Vista") -or ($osName.Contains("2008") -and -not $osName.Contains("R2"))) {
        if ($versionString.Split('.')[3][0] -eq "1") {
            $currentOS = "$osName GDR"
            $expectedVersion = New-Object System.Version("6.0.6002.19743")
        } elseif ($versionString.Split('.')[3][0] -eq "2") {
            $currentOS = "$osName LDR"
            $expectedVersion = New-Object System.Version("6.0.6002.24067")
        } else {
            $currentOS = "$osName"
            $expectedVersion = New-Object System.Version("9.9.9999.99999")
        }
    } elseif ($osName.Contains("Windows 7") -or ($osName.Contains("2008 R2"))) {
        $currentOS = "$osName LDR"
        $expectedVersion = New-Object System.Version("6.1.7601.23689")
    } elseif ($osName.Contains("Windows 8.1") -or $osName.Contains("2012 R2")) {
        $currentOS = "$osName LDR"
        $expectedVersion = New-Object System.Version("6.3.9600.18604")
    } elseif ($osName.Contains("Windows 8") -or $osName.Contains("2012")) {
        $currentOS = "$osName LDR"
        $expectedVersion = New-Object System.Version("6.2.9200.22099")
    } elseif ($osName.Contains("Windows 10")) {
        if ($os.BuildNumber -eq "10240") {
            $currentOS = "$osName TH1"
            $expectedVersion = New-Object System.Version("10.0.10240.17319")
        } elseif ($os.BuildNumber -eq "10586") {
            $currentOS = "$osName TH2"
            $expectedVersion = New-Object System.Version("10.0.10586.839")
        } elseif ($os.BuildNumber -eq "14393") {
            $currentOS = "$($osName) RS1"
            $expectedVersion = New-Object System.Version("10.0.14393.953")
        } elseif ($os.BuildNumber -eq "15063") {
            $currentOS = "$osName RS2"
            "No need to Patch. RS2 is released as patched. "
            return
        }
    } elseif ($osName.Contains("2016")) {
        $currentOS = "$osName"
        $expectedVersion = New-Object System.Version("10.0.14393.953")
    } elseif ($osName.Contains("Windows XP")) {
        $currentOS = "$osName"
        $expectedVersion = New-Object System.Version("5.1.2600.7208")
    } elseif ($osName.Contains("Server 2003")) {
        $currentOS = "$osName"
        $expectedVersion = New-Object System.Version("5.2.3790.6021")
    } else {
        Write-Host "Unable to determine OS applicability, please verify vulnerability state manually." -ForegroundColor Yellow
        $currentOS = "$osName"
        $expectedVersion = New-Object System.Version("9.9.9999.99999")
    }

    Write-Host "`n`nCurrent OS: $currentOS (Build Number $($os.BuildNumber))" -ForegroundColor Cyan

    Write-Host "`nExpected Version of srv.sys: $($expectedVersion.ToString())" -ForegroundColor Cyan

    Write-Host "`nActual Version of srv.sys: $($fileVersion.ToString())" -ForegroundColor Cyan

    If ($($fileVersion.CompareTo($expectedVersion)) -lt 0) {
        Write-Host "`n`n"
        Write-Host -ForegroundColor GREEN "[YES]" -NoNewline
        Write-Host " System is NOT patched."
    } Else {
        Write-Host "`n`n"
        Write-Host -ForegroundColor RED "[NO]" -NoNewline
        Write-Host " System is patched."
    }
}
