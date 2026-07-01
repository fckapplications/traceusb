$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $here
$scriptPath = Join-Path $repoRoot "TraceUSB.ps1"

function New-FakeEvent {
    param(
        [int]$Id,
        [datetime]$TimeCreated,
        [string]$Message = "",
        [hashtable]$Data = @{}
    )

    $dataXml = ""
    foreach ($key in $Data.Keys) {
        $escapedKey = [System.Security.SecurityElement]::Escape([string]$key)
        $escapedValue = [System.Security.SecurityElement]::Escape([string]$Data[$key])
        $dataXml += "<Data Name='$escapedKey'>$escapedValue</Data>"
    }

    $xml = "<Event><System><EventID>$Id</EventID></System><EventData>$dataXml</EventData></Event>"
    $event = [PSCustomObject]@{
        Id          = $Id
        TimeCreated = $TimeCreated
        Message     = $Message
        XmlText     = $xml
    }

    $event | Add-Member -MemberType ScriptMethod -Name ToXml -Value { $this.XmlText }
    return $event
}

function New-BamValue {
    param([datetime]$Time)

    return [BitConverter]::GetBytes($Time.ToUniversalTime().ToFileTimeUtc())
}

Describe "TraceUSB forensic analyzer" {
    It "parses cleanly" {
        $tokens = $null
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors) | Out-Null
        $errors.Count | Should Be 0
    }

    It "does not contain a real hardcoded Discord webhook URL" {
        $scriptText = Get-Content -Raw -LiteralPath $scriptPath
        $scriptText | Should Not Match 'discord\.com/api/webhooks/\d+/[A-Za-z0-9_-]{20,}'
    }

    It "can build Discord relay debug artifacts without sending HTTP" {
        $outputDir = Join-Path $TestDrive "relay-debug"
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

        & $scriptPath `
            -OutputDirectory $outputDir `
            -DiscordSelfTest `
            -DiscordDebug `
            -DiscordRelayUrl "https://relay.example.test/traceusb" `
            -DiscordRelayToken "test-token"

        $payloadFiles = [System.IO.Directory]::GetFiles($outputDir, "discord_payload_*.json")
        $manifestFiles = [System.IO.Directory]::GetFiles($outputDir, "discord_attachments_*.txt")
        $payloadFiles.Count | Should Be 1
        $manifestFiles.Count | Should Be 1

        $payload = Get-Content -Raw -LiteralPath $payloadFiles[0]
        $manifest = Get-Content -Raw -LiteralPath $manifestFiles[0]
        $payload | Should Match "TraceUSB webhook self-test"
        $manifest | Should Match "DeliveryKind: relay"
        $manifest | Should Match "HTTP send skipped"
    }

    It "keeps portable SQLite pinned and optional" {
        $scriptText = Get-Content -Raw -LiteralPath $scriptPath
        $scriptText | Should Match 'PortableSQLiteDownloadSha256'
        $scriptText | Should Match 'PortableSQLiteExeSha256'
        $scriptText | Should Match 'DisablePortableSQLiteDownload'
    }

    It "reconstructs SCUM and BattlEye start, close, and duration context" {
        $sessionDate = [datetime]"2026-07-01"
        $gameStart = $sessionDate.AddHours(14).AddMinutes(12)
        $gameEnd = $sessionDate.AddHours(15).AddMinutes(48).AddSeconds(21)
        $beStart = $sessionDate.AddHours(14).AddMinutes(10).AddSeconds(55)
        $beEnd = $sessionDate.AddHours(15).AddMinutes(49).AddSeconds(2)
        $outputDir = Join-Path $TestDrive "sessions-out"
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

        Mock Get-WinEvent {
            $ids = @($FilterHashtable.Id)

            if ($FilterHashtable.LogName -eq "Security" -and $ids -contains 4688) {
                return @(
                    (New-FakeEvent -Id 4688 -TimeCreated $gameStart -Data @{
                        NewProcessName = "C:\Program Files (x86)\Steam\steamapps\common\SCUM\SCUM\Binaries\Win64\SCUM.exe"
                        NewProcessId = "0x54a4"
                        ParentProcessName = "C:\Program Files (x86)\Steam\steam.exe"
                        SubjectUserSid = "S-1-5-21-test"
                    })
                )
            }

            if ($FilterHashtable.LogName -eq "Security" -and $ids -contains 4689) {
                return @(
                    (New-FakeEvent -Id 4689 -TimeCreated $gameEnd -Data @{
                        ProcessName = "C:\Program Files (x86)\Steam\steamapps\common\SCUM\SCUM\Binaries\Win64\SCUM.exe"
                        ProcessId = "0x54a4"
                        SubjectUserSid = "S-1-5-21-test"
                    })
                )
            }

            if ($FilterHashtable.LogName -eq "System" -and $ids -contains 7036) {
                return @(
                    (New-FakeEvent -Id 7036 -TimeCreated $beStart -Data @{
                        param1 = "BattlEye Service"
                        param2 = "running"
                    }),
                    (New-FakeEvent -Id 7036 -TimeCreated $beEnd -Data @{
                        param1 = "BattlEye Service"
                        param2 = "stopped"
                    })
                )
            }

            return @()
        }

        Mock Get-PnpDevice { return @() }
        Mock Get-PnpDeviceProperty { return @() }
        Mock Get-CimInstance { return @() }
        Mock Get-Process { return @() }
        Mock Get-ChildItem { return @() }
        Mock Get-ItemProperty { return $null }
        Mock Get-AuthenticodeSignature { return [PSCustomObject]@{ Status = "NotSigned"; SignerCertificate = $null } }
        Mock Start-Process { throw "Start-Process should not run with -NoOpen" }

        & $scriptPath `
            -OutputDirectory $outputDir `
            -NoOpen `
            -GameSessionDate $sessionDate `
            -DisableDiscordWebhook `
            -DisableBrowserHistoryScan `
            -DisableNetworkAnomalyScan `
            -DisableCaseBundle

        $gameSessionFiles = [System.IO.Directory]::GetFiles($outputDir, "game_sessions_*.txt")
        $gameSessionFiles.Count | Should Be 1

        $gameSessions = Get-Content -Raw -LiteralPath $gameSessionFiles[0]
        $gameSessions | Should Match "SCUM Game"
        $gameSessions | Should Match "BattlEye Service"
        $gameSessions | Should Match "Status: Closed"
        $gameSessions | Should Match "Exact start/end from Windows event logs"
        $gameSessions | Should Match "Duration:"

        $timeline = Get-Content -Raw -LiteralPath ([System.IO.Directory]::GetFiles($outputDir, "timeline_*.txt") | Select-Object -First 1)
        $timeline | Should Match "GameSession"
        $timeline | Should Match "SCUM Game ended"
    }

    It "correlates USB, 4688, Prefetch, BAM, Defender, and SCUM context" {
        $now = Get-Date
        $loaderTime = $now.AddMinutes(-10)
        $gameTime = $now.AddMinutes(-12)
        $outputDir = Join-Path $TestDrive "out"
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

        Mock Get-WinEvent {
            if ($FilterHashtable.LogName -eq "Security" -and $FilterHashtable.Id -contains 4688) {
                return @(
                    (New-FakeEvent -Id 4688 -TimeCreated $gameTime -Data @{
                        NewProcessName = "C:\Games\SCUM\SCUM-Win64-Shipping.exe"
                        ParentProcessName = "C:\Program Files (x86)\Steam\steam.exe"
                        SubjectUserSid = "S-1-5-21-test"
                    }),
                    (New-FakeEvent -Id 4688 -TimeCreated $loaderTime -Data @{
                        NewProcessName = "E:\LOADER.EXE"
                        ParentProcessName = "C:\Windows\explorer.exe"
                        SubjectUserSid = "S-1-5-21-test"
                    })
                )
            }

            if ($FilterHashtable.LogName -eq "Microsoft-Windows-Windows Defender/Operational") {
                return @(
                    (New-FakeEvent -Id 1116 -TimeCreated $loaderTime.AddMinutes(1) -Data @{
                        "Threat Name" = "SuspiciousTool"
                        Path = "E:\LOADER.EXE"
                    })
                )
            }

            if ($FilterHashtable.LogName -eq "System" -and $FilterHashtable.Id -eq 104) {
                return @(
                    (New-FakeEvent -Id 104 -TimeCreated $loaderTime.AddMinutes(2) -Message "The System log file was cleared")
                )
            }

            if ($FilterHashtable.LogName -eq "System" -and $FilterHashtable.Id -eq 7045) {
                return @()
            }

            if ($FilterHashtable.LogName -eq "Security" -and $FilterHashtable.Id -eq 1102) {
                return @()
            }

            return @()
        }

        Mock Get-PnpDevice {
            return @(
                [PSCustomObject]@{
                    FriendlyName = "USB Flash Disk"
                    InstanceId = "USB\VID_TEST"
                }
            )
        }

        Mock Get-PnpDeviceProperty {
            return @(
                [PSCustomObject]@{ KeyName = "DEVPKEY_Device_LastArrivalDate"; Data = $loaderTime.AddMinutes(-3) },
                [PSCustomObject]@{ KeyName = "DEVPKEY_Device_LastRemovalDate"; Data = $null }
            )
        }

        Mock Get-CimInstance {
            return @([PSCustomObject]@{ DeviceID = "E:"; DriveType = 2 })
        }

        Mock Get-Process {
            return @([PSCustomObject]@{ ProcessName = "nvcontainer" })
        }

        Mock Test-Path {
            return $true
        }

        Mock Get-AuthenticodeSignature {
            return [PSCustomObject]@{
                Status = "NotSigned"
                SignerCertificate = $null
            }
        }

        Mock Get-ChildItem {
            if ($LiteralPath -eq "C:\Windows\Prefetch") {
                return @([PSCustomObject]@{
                    BaseName = "LOADER.EXE-1234ABCD"
                    LastWriteTime = $loaderTime
                })
            }

            if ($Path -like "HKLM:*bam*") {
                return @([PSCustomObject]@{
                    PSPath = "HKLM:\System\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-test"
                    PSChildName = "S-1-5-21-test"
                })
            }

            return @()
        }

        Mock Get-ItemProperty {
            $obj = New-Object PSObject
            $obj | Add-Member -MemberType NoteProperty -Name "E:\LOADER.EXE" -Value (New-BamValue $loaderTime)
            return $obj
        }

        Mock Start-Process { throw "Start-Process should not run with -NoOpen" }
        Mock Invoke-RestMethod { throw "Invoke-RestMethod should not run unless -EnableDiscordWebhook is set" }

        $previewPath = Join-Path $outputDir "discord_preview.html"
        & $scriptPath -OutputDirectory $outputDir -NoOpen -LookbackHours 24 -DiscordPreviewPath $previewPath -DisableDiscordWebhook -DisableBrowserHistoryScan -DisableNetworkAnomalyScan -DisableCaseBundle

        [System.IO.Directory]::GetFiles($outputDir, "analise_*.txt").Count | Should Be 1
        [System.IO.Directory]::GetFiles($outputDir, "timeline_*.txt").Count | Should Be 1
        [System.IO.Directory]::GetFiles($outputDir, "evidence_*.jsonl").Count | Should Be 0
        [System.IO.Directory]::GetFiles($outputDir, "translations_*.txt").Count | Should Be 0
        [System.IO.Directory]::GetFiles($outputDir, "filtered_history_*.txt").Count | Should Be 0
        $previewFiles = [System.IO.Directory]::GetFiles($outputDir, "discord_preview_*.html")
        $previewFiles.Count | Should Be 1

        $previewHtml = Get-Content -Raw -LiteralPath $previewFiles[0]
        $previewHtml | Should Match "TraceUSB forensic summary"
        $previewHtml | Should Match "CorrelatedExecution"
        $previewHtml | Should Match "evidence_"
        $previewHtml | Should Match "translations_"
    }

    It "can save a Discord webhook secret without running collection" {
        $outputDir = Join-Path $TestDrive "secret-out"
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        $secretPath = Join-Path $outputDir "discord.secret"

        Mock Get-WinEvent { throw "Get-WinEvent should not run while saving webhook secret" }
        Mock Invoke-RestMethod { throw "Invoke-RestMethod should not run while saving webhook secret" }

        & $scriptPath `
            -OutputDirectory $outputDir `
            -SaveDiscordWebhookSecret `
            -DiscordWebhookUrl "https://discord.com/api/webhooks/test/token" `
            -DiscordWebhookSecretPath $secretPath

        [System.IO.File]::Exists($secretPath) | Should Be $true
        [System.IO.File]::Exists((Join-Path $outputDir "analise.txt")) | Should Be $false
        (Get-Content -Raw -LiteralPath $secretPath) | Should Not Match "discord.com"
    }
}
