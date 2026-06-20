[CmdletBinding()]
param(
    [ValidateRange(1, 720)]
    [int]$LookbackHours = 24,

    [string]$OutputDirectory = [Environment]::GetFolderPath("Desktop"),

    [switch]$NoOpen,

    [switch]$EnableAuditPolicy,

    [switch]$EnableScreenshotTrigger,

    [switch]$IncludeLowConfidence,

    [switch]$EnableDiscordWebhook = $true,

    [switch]$DisableDiscordWebhook,

    [string]$DiscordWebhookUrl,

    [string]$DiscordWebhookSecretPath,

    [string]$DiscordWebhookEnvVar = "https://discord.com/api/webhooks/1517354954388410419/SoBhKuy38K_9Rkke31dy_uXHKrfxpr8V5ygsDwBbWqkF4wYjh0bHGHqh-wzxni1KpSmL",

    [switch]$SaveDiscordWebhookSecret,

    [string]$DiscordPreviewPath,

    [string]$DiscordUsername = "TraceUSB",

    [string]$DiscordTitle = "TraceUSB forensic summary",

    [string]$DiscordSubtitle = "Forensic relevance report. This is not proof of cheating.",

    [ValidateRange(1, 20)]
    [int]$DiscordMaxItems = 8,

    [ValidateRange(5, 120)]
    [int]$DiscordTimeoutSeconds = 20,

    [ValidateRange(1024, 25000000)]
    [int]$DiscordMaxAttachmentBytes = 7000000,

    [switch]$DiscordSelfTest,

    [switch]$VerboseConsole,

    [string]$DiscordAlertColor = "D64545",

    [string]$DiscordNoticeColor = "E0A33A",

    [string]$DiscordInfoColor = "4E7DD9",

    [switch]$DiscordIncludeLowConfidence,

    [switch]$SaveDiscordAttachmentsLocal,

    [string]$SubjectLabel,

    [switch]$EnableBrowserHistoryScan = $true,

    [switch]$DisableBrowserHistoryScan,

    [string[]]$BrowserHistoryKeywords = @(
        "ciroscript",
        "project cheats",
        "byster",
        "crooked",
        "scum cheat",
        "scum hack",
        "scum esp",
        "scum aimbot",
        "scum script",
        "lag switch",
        "fake lag",
        "clumsy",
        "windivert",
        "battleye bypass",
        "wallhack",
        "aimbot",
        "trainer",
        "bypass",
        "macro",
        "cheats",
        "cheat",
        "hacks",
        "hack",
        "script",
        "scum",
        "esp"
    ),

    [ValidateRange(1, 365)]
    [int]$BrowserHistoryLookbackDays = 30,

    [ValidateRange(1, 500)]
    [int]$BrowserHistoryMaxHits = 100,

    [string]$SQLiteCliPath,

    [switch]$NoRedactUrls,

    [string[]]$GameProcessPatterns = @(
        "SCUM.exe",
        "SCUM-Win64-Shipping.exe",
        "SCUM_Launcher.exe",
        "BEService.exe",
        "BEService_x64.exe"
    )
)

$ErrorActionPreference = "SilentlyContinue"

if ($DisableDiscordWebhook) {
    $EnableDiscordWebhook = $false
}

if ($DisableBrowserHistoryScan) {
    $EnableBrowserHistoryScan = $false
}

$script:StartTime = (Get-Date).AddHours(-1 * $LookbackHours)
$script:OutputDirectory = $OutputDirectory
$script:RunStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$script:SafeSubjectLabel = ""
if ($SubjectLabel) {
    $script:SafeSubjectLabel = ($SubjectLabel -replace '[^\w\-.]+', '_').Trim('_')
}
$script:ArtifactSuffix = if ($script:SafeSubjectLabel) {
    "$($script:SafeSubjectLabel)_$($script:RunStamp)"
} else {
    $script:RunStamp
}
$script:ReportFileName = "analise_$($script:ArtifactSuffix).txt"
$script:TimelineFileName = "timeline_$($script:ArtifactSuffix).txt"
$script:EvidenceFileName = "evidence_$($script:ArtifactSuffix).jsonl"
$script:TranslationsFileName = "translations_$($script:ArtifactSuffix).txt"
$script:FilteredHistoryFileName = "filtered_history_$($script:ArtifactSuffix).txt"
$script:RunLogFileName = "traceusb_run_$($script:ArtifactSuffix).log"
$script:ReportPath = Join-Path $script:OutputDirectory $script:ReportFileName
$script:TimelinePath = Join-Path $script:OutputDirectory $script:TimelineFileName
$script:EvidencePath = Join-Path $script:OutputDirectory $script:EvidenceFileName
$script:TranslationsPath = Join-Path $script:OutputDirectory $script:TranslationsFileName
$script:FilteredHistoryPath = Join-Path $script:OutputDirectory $script:FilteredHistoryFileName
$script:RunLogPath = Join-Path $script:OutputDirectory $script:RunLogFileName

$script:Report = New-Object System.Collections.Generic.List[string]
$script:Timeline = New-Object System.Collections.Generic.List[object]
$script:Evidence = New-Object System.Collections.Generic.List[object]
$script:FilteredHistoryHits = New-Object System.Collections.Generic.List[object]
$script:DiscordAttachments = New-Object System.Collections.Generic.List[object]
$script:RunLog = New-Object System.Collections.Generic.List[string]
$script:DiscordStatus = if ($EnableDiscordWebhook) { "not_attempted" } else { "disabled" }
$script:DiscordAttachmentCount = 0
$script:Correlation = @{}
$script:GameSessionTimes = New-Object System.Collections.Generic.List[datetime]
$script:UsbTimes = New-Object System.Collections.Generic.List[datetime]
$script:AntiForensicTimes = New-Object System.Collections.Generic.List[datetime]

$script:KnownPublishers = @(
    "Microsoft",
    "Google",
    "Mozilla",
    "Valve",
    "Discord",
    "NVIDIA",
    "Advanced Micro Devices",
    "OBS",
    "Logitech",
    "Corsair",
    "RivaTuner",
    "SteelSeries",
    "BattlEye"
)

$script:KnownSafePaths = @(
    "C:\Windows",
    "C:\Program Files",
    "C:\Program Files (x86)"
)

$script:OverlayProcessPatterns = @{
    "NVIDIA"       = "nvidia|nvcontainer|nvsphelper|shadowplay|nvidia share"
    "AMD"          = "radeon|amdow|amdrsserv|relive|cncmd"
    "RTSS"         = "rtss|rtsshooksloader"
    "MSI"          = "msiafterburner|afterburner"
    "Steam"        = "gameoverlayui|steamwebhelper"
    "Discord"      = "discord"
    "Overwolf"     = "overwolf"
    "ReShade"      = "reshade"
}

function Ensure-OutputDirectory {
    if (-not (Test-Path -LiteralPath $script:OutputDirectory)) {
        New-Item -ItemType Directory -Path $script:OutputDirectory -Force | Out-Null
    }
}

function Write-RunLog {
    param([string]$Message)

    if (-not $Message) { return }

    $line = "{0:u} {1}" -f (Get-Date), $Message
    $script:RunLog.Add($line)

    if ($VerboseConsole) {
        Write-Host "[TraceUSB] $Message"
    }
}

function Write-RunLogFile {
    Ensure-OutputDirectory
    Set-Content -LiteralPath $script:RunLogPath -Value $script:RunLog -Encoding UTF8
}

function Write-ConsoleSummary {
    Write-Host ""
    Write-Host "TraceUSB concluido."
    if ([System.IO.File]::Exists($script:ReportPath)) {
        Write-Host "Analise: $script:ReportPath"
    }
    else {
        Write-Host "Analise: nao gerada neste modo"
    }
    if ([System.IO.File]::Exists($script:TimelinePath)) {
        Write-Host "Timeline: $script:TimelinePath"
    }
    else {
        Write-Host "Timeline: nao gerada neste modo"
    }
    Write-Host "Run log: $script:RunLogPath"
    Write-Host "Discord: $script:DiscordStatus"
}

function Write-Section {
    param([string]$Title)

    $script:Report.Add("")
    $script:Report.Add("==== $Title ====")
    $script:Report.Add("")
}

function Add-TimelineEvent {
    param(
        [AllowNull()]$Time,
        [string]$Category,
        [string]$Event,
        [string]$Details
    )

    if (-not $Time) { return }

    $script:Timeline.Add([PSCustomObject]@{
        Time     = $Time
        Category = $Category
        Event    = $Event
        Details  = $Details
    })
}

function Add-Evidence {
    param(
        [AllowNull()]$Time,
        [string]$Category,
        [string]$Source,
        [Nullable[int]]$EventId,
        [string]$ExeName,
        [string]$Path,
        [string]$ParentPath,
        [string]$UserSid,
        [string]$Device,
        [int]$Confidence,
        [string[]]$Reasons,
        [string]$Details
    )

    $boundedConfidence = [Math]::Max(0, [Math]::Min(100, $Confidence))
    $cleanReasons = @($Reasons | Where-Object { $_ } | Select-Object -Unique)

    $entry = [PSCustomObject]@{
        Time       = $Time
        Category   = $Category
        Source     = $Source
        EventId    = $EventId
        ExeName    = $ExeName
        Path       = $Path
        ParentPath = $ParentPath
        UserSid    = $UserSid
        Device     = $Device
        Confidence = $boundedConfidence
        Reasons    = $cleanReasons
        Details    = $Details
    }

    $script:Evidence.Add($entry)

    if ($Time) {
        $timelineDetails = $Details
        if (-not $timelineDetails) {
            $timelineDetails = @($ExeName, $Path, $Device) | Where-Object { $_ } | Select-Object -First 1
        }
        Add-TimelineEvent -Time $Time -Category $Category -Event $Source -Details $timelineDetails
    }

    return $entry
}

function Get-EventDataMap {
    param($Event)

    $map = @{}

    try {
        [xml]$xml = $Event.ToXml()
        foreach ($data in $xml.Event.EventData.Data) {
            $name = [string]$data.Name
            if ($name) {
                $map[$name] = [string]$data.'#text'
            }
        }
    }
    catch {}

    return $map
}

function Get-EventDataValue {
    param(
        [hashtable]$Map,
        [string[]]$Names
    )

    foreach ($name in $Names) {
        if ($Map.ContainsKey($name) -and $Map[$name]) {
            return $Map[$name]
        }
    }

    return $null
}

function Get-MessageValue {
    param(
        [string]$Message,
        [string[]]$Patterns
    )

    foreach ($pattern in $Patterns) {
        $match = [regex]::Match($Message, $pattern, "IgnoreCase")
        if ($match.Success) {
            return $match.Groups[1].Value.Trim()
        }
    }

    return $null
}

function Normalize-ExecutablePath {
    param([string]$Path)

    if (-not $Path) { return $null }

    $clean = $Path.Trim().Trim('"')
    $clean = $clean -replace '^\\\?\\', ''
    $clean = $clean -replace '^\\\\\?\\', ''

    if ($clean -eq "-" -or $clean -eq "N/A") { return $null }

    return $clean
}

function Get-ExeNameFromPath {
    param(
        [string]$Path,
        [string]$FallbackName
    )

    if ($Path) {
        try {
            $leaf = Split-Path $Path -Leaf
            if ($leaf) { return $leaf }
        }
        catch {}
    }

    return $FallbackName
}

function Test-NameMatchesAny {
    param(
        [string]$Name,
        [string[]]$Patterns
    )

    if (-not $Name) { return $false }

    foreach ($pattern in $Patterns) {
        if ($Name -like $pattern -or $Name -match [regex]::Escape($pattern)) {
            return $true
        }
    }

    return $false
}

function Get-UsbType {
    param([string]$Name)

    if ($Name -match "Mass Storage|Storage|Flash|Disk|USBSTOR") { return "Storage" }
    if ($Name -match "Audio|Headset|Microphone") { return "Audio" }
    if ($Name -match "Keyboard|Mouse|Input|HID") { return "Input" }
    if ($Name -match "Camera|Imaging") { return "Camera" }

    return "Unknown"
}

function Get-DurationText {
    param($Start, $End)

    if (-not $Start -or -not $End) { return $null }

    try {
        $span = New-TimeSpan -Start $Start -End $End
        return "{0:hh\:mm\:ss}" -f $span
    }
    catch {
        return $null
    }
}

function Test-RemovablePath {
    param([string]$Path)

    $clean = Normalize-ExecutablePath $Path
    if (-not $clean -or $clean -notmatch '^[A-Za-z]:\\') {
        return $false
    }

    $drive = $clean.Substring(0, 2)

    try {
        $disk = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $drive }
        if ($disk -and $disk.DriveType -eq 2) {
            return $true
        }
    }
    catch {}

    return $false
}

function Test-SafePath {
    param([string]$Path)

    $clean = Normalize-ExecutablePath $Path
    if (-not $clean) { return $false }

    foreach ($safePath in $script:KnownSafePaths) {
        if ($clean.StartsWith($safePath, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Test-SuspiciousName {
    param([string]$Name)

    if (-not $Name) { return $false }

    $upper = $Name.ToUpperInvariant()

    if ($upper -match '^[A-Z0-9]{10,}\.EXE$') { return $true }
    if ($upper -match '[^\u0000-\u007F]') { return $true }
    if ($upper -match 'TMP|TEMP|LOADER|INJECT|MAPPER|OVERLAY|CHEAT|HACK|AIM|ESP|_UNINS') { return $true }

    return $false
}

function Test-SuspiciousPath {
    param([string]$Path)

    $clean = Normalize-ExecutablePath $Path
    if (-not $clean) { return $false }

    if ($clean -match '\\AppData\\Local\\Temp\\|\\Temp\\|\\Downloads\\|\\Desktop\\|\\Public\\|\\ProgramData\\') {
        return $true
    }

    return $false
}

function Get-FileTrustInfo {
    param([string]$Path)

    $clean = Normalize-ExecutablePath $Path
    $trusted = $false
    $signed = $false
    $publisher = "UNKNOWN"
    $status = "Unavailable"

    try {
        if ($clean -and (Test-Path -LiteralPath $clean)) {
            $sig = Get-AuthenticodeSignature -LiteralPath $clean
            if ($sig) {
                $status = [string]$sig.Status
                if ($sig.Status -eq "Valid") {
                    $signed = $true
                }
                if ($sig.SignerCertificate) {
                    $publisher = [string]$sig.SignerCertificate.Subject
                    foreach ($known in $script:KnownPublishers) {
                        if ($publisher -match [regex]::Escape($known)) {
                            $trusted = $true
                            break
                        }
                    }
                }
            }
        }
    }
    catch {}

    return [PSCustomObject]@{
        Signed    = $signed
        Trusted   = $trusted
        Publisher = $publisher
        Status    = $status
    }
}

function Convert-BamTimestamp {
    param($Value)

    try {
        if ($Value -is [byte[]] -and $Value.Length -ge 8) {
            $fileTime = [BitConverter]::ToInt64($Value, 0)
            if ($fileTime -gt 0) {
                return [DateTime]::FromFileTimeUtc($fileTime).ToLocalTime()
            }
        }
    }
    catch {}

    return $null
}

function Add-UniqueString {
    param(
        [object]$Object,
        [string]$Property,
        [string]$Value
    )

    if (-not $Value) { return }

    $values = @($Object.$Property)
    if ($values -notcontains $Value) {
        $Object.$Property = @($values + $Value | Where-Object { $_ } | Select-Object -Unique)
    }
}

function Add-CorrelationSignal {
    param(
        [string]$Source,
        [AllowNull()]$Time,
        [string]$Name,
        [string]$Path,
        [string]$ParentPath,
        [string]$UserSid,
        [int]$Score,
        [string[]]$Reasons
    )

    $cleanPath = Normalize-ExecutablePath $Path
    $exeName = Get-ExeNameFromPath -Path $cleanPath -FallbackName $Name
    if (-not $exeName) { return }

    $key = $exeName.ToUpperInvariant()

    if (-not $script:Correlation.ContainsKey($key)) {
        $script:Correlation[$key] = [PSCustomObject]@{
            Name        = $exeName
            Sources     = @()
            Paths       = @()
            ParentPaths = @()
            UserSids    = @()
            FirstSeen   = $Time
            LastSeen    = $Time
            Score       = 0
            Reasons     = @()
        }
    }

    $entry = $script:Correlation[$key]
    Add-UniqueString -Object $entry -Property "Sources" -Value $Source
    Add-UniqueString -Object $entry -Property "Paths" -Value $cleanPath
    Add-UniqueString -Object $entry -Property "ParentPaths" -Value (Normalize-ExecutablePath $ParentPath)
    Add-UniqueString -Object $entry -Property "UserSids" -Value $UserSid

    if ($Time) {
        if (-not $entry.FirstSeen -or $Time -lt $entry.FirstSeen) { $entry.FirstSeen = $Time }
        if (-not $entry.LastSeen -or $Time -gt $entry.LastSeen) { $entry.LastSeen = $Time }
    }

    $entry.Score = [Math]::Min(100, $entry.Score + $Score)

    foreach ($reason in @($Reasons)) {
        Add-UniqueString -Object $entry -Property "Reasons" -Value $reason
    }
}

function Test-NearAnyTime {
    param(
        [AllowNull()]$Time,
        [System.Collections.Generic.List[datetime]]$Times,
        [int]$Minutes = 30
    )

    if (-not $Time -or -not $Times -or $Times.Count -eq 0) { return $false }

    foreach ($candidate in $Times) {
        if ([Math]::Abs(($Time - $candidate).TotalMinutes) -le $Minutes) {
            return $true
        }
    }

    return $false
}

function Get-ProcessCreationData {
    param($Event)

    $map = Get-EventDataMap $Event
    $message = [string]$Event.Message

    $path = Get-EventDataValue -Map $map -Names @("NewProcessName", "ProcessName")
    if (-not $path) {
        $path = Get-MessageValue -Message $message -Patterns @(
            'Novo Nome do Processo:\s+(.+)',
            'New Process Name:\s+(.+)'
        )
    }

    $parentPath = Get-EventDataValue -Map $map -Names @("ParentProcessName", "CreatorProcessName")
    if (-not $parentPath) {
        $parentPath = Get-MessageValue -Message $message -Patterns @(
            'Nome do Processo Criador:\s+(.+)',
            'Creator Process Name:\s+(.+)'
        )
    }

    $userSid = Get-EventDataValue -Map $map -Names @("SubjectUserSid", "TargetUserSid")

    $cleanPath = Normalize-ExecutablePath $path
    $cleanParent = Normalize-ExecutablePath $parentPath
    $exeName = Get-ExeNameFromPath -Path $cleanPath -FallbackName $null

    return [PSCustomObject]@{
        Path       = $cleanPath
        ParentPath = $cleanParent
        ExeName    = $exeName
        UserSid    = $userSid
    }
}

function Get-DefenderData {
    param($Event)

    $map = Get-EventDataMap $Event
    $message = [string]$Event.Message

    $threat = Get-EventDataValue -Map $map -Names @("Threat Name", "ThreatName", "Name")
    if (-not $threat) {
        $threat = Get-MessageValue -Message $message -Patterns @(
            'Nome da ameaca:\s*(.+)',
            'Nome da ameaça:\s*(.+)',
            'Threat Name:\s*(.+)'
        )
    }

    $path = Get-EventDataValue -Map $map -Names @("Path", "File Path", "Resources")
    if (-not $path) {
        $path = Get-MessageValue -Message $message -Patterns @(
            'Caminho:\s*(.+)',
            'Path:\s*(.+)'
        )
    }

    return [PSCustomObject]@{
        Threat = $threat
        Path   = Normalize-ExecutablePath $path
    }
}

function Collect-LogClearingEvents {
    Write-Section "LOG CLEARING AND ANTI-FORENSIC EVENTS"

    $events = @()
    $events += Get-WinEvent -FilterHashtable @{ LogName = "System"; Id = 104; StartTime = $script:StartTime }
    $events += Get-WinEvent -FilterHashtable @{ LogName = "Security"; Id = 1102; StartTime = $script:StartTime }

    foreach ($event in @($events | Sort-Object TimeCreated -Descending)) {
        $logName = "Unknown"
        $map = Get-EventDataMap $event

        $candidate = Get-EventDataValue -Map $map -Names @("LogFileCleared", "SubjectLogonId", "Channel")
        if ($candidate) { $logName = $candidate }

        if ($event.Id -eq 104) {
            $fromMessage = Get-MessageValue -Message ([string]$event.Message) -Patterns @(
                'log\s+(.+?)\s+foi',
                'The\s+(.+?)\s+log file was cleared'
            )
            if ($fromMessage) { $logName = $fromMessage }
        }

        $script:AntiForensicTimes.Add($event.TimeCreated)

        Add-Evidence -Time $event.TimeCreated -Category "AntiForensic" -Source "EventLog" -EventId $event.Id -Confidence 45 -Reasons @("Event log clearing observed") -Details "Log cleared: $logName" | Out-Null

        $script:Report.Add("Event ID: $($event.Id)")
        $script:Report.Add("Log: $logName")
        $script:Report.Add("Time: $($event.TimeCreated)")
        $script:Report.Add("")
    }
}

function Collect-UsbEvents {
    Write-Section "USB HISTORY"

    $usbHistory = @()

    $devices = Get-PnpDevice -Class USB -PresentOnly:$false
    foreach ($dev in @($devices)) {
        if (-not $dev.FriendlyName) { continue }
        if ($dev.FriendlyName -match "Hub|Host Controller|Root") { continue }

        $props = Get-PnpDeviceProperty -InstanceId $dev.InstanceId
        $arrival = ($props | Where-Object { $_.KeyName -like "*LastArrivalDate*" } | Select-Object -First 1).Data
        $removal = ($props | Where-Object { $_.KeyName -like "*LastRemovalDate*" } | Select-Object -First 1).Data
        $type = Get-UsbType $dev.FriendlyName

        if ($arrival -and $arrival -ge $script:StartTime) {
            $script:UsbTimes.Add($arrival)
            Add-Evidence -Time $arrival -Category "USB" -Source "PnP" -Device $dev.FriendlyName -Confidence 20 -Reasons @("USB arrival") -Details "$($dev.FriendlyName) ($type) connected" | Out-Null
        }

        if ($removal -and $removal -ge $script:StartTime) {
            $script:UsbTimes.Add($removal)
            Add-Evidence -Time $removal -Category "USB" -Source "PnP" -Device $dev.FriendlyName -Confidence 20 -Reasons @("USB removal") -Details "$($dev.FriendlyName) ($type) removed" | Out-Null
        }

        if ($arrival -or $removal) {
            $usbHistory += [PSCustomObject]@{
                Name    = $dev.FriendlyName
                Type    = $type
                Arrival = $arrival
                Removal = $removal
            }
        }
    }

    foreach ($item in @($usbHistory | Sort-Object Arrival -Descending)) {
        $script:Report.Add("Device: $($item.Name)")
        $script:Report.Add("Type: $($item.Type)")
        $script:Report.Add("Connected: $($item.Arrival)")
        $script:Report.Add("Removed: $($item.Removal)")
        $duration = Get-DurationText -Start $item.Arrival -End $item.Removal
        if ($duration) { $script:Report.Add("Duration: $duration") }
        $script:Report.Add("")
    }

    Write-Section "ACTIVE USB DEVICES"

    Get-PnpDevice -PresentOnly |
        Where-Object {
            $_.InstanceId -match "^USB" -and
            $_.FriendlyName -and
            $_.FriendlyName -notmatch "Hub|Host Controller|Root"
        } |
        Sort-Object FriendlyName |
        ForEach-Object {
            $script:Report.Add("Device: $($_.FriendlyName)")
            $script:Report.Add("Type: $(Get-UsbType $_.FriendlyName)")
            $script:Report.Add("")
        }
}

function Collect-DefenderEvents {
    Write-Section "WINDOWS DEFENDER"

    $events = Get-WinEvent -FilterHashtable @{
        LogName   = "Microsoft-Windows-Windows Defender/Operational"
        Id        = 1116, 1117, 5001, 5004, 5010
        StartTime = $script:StartTime
    }

    foreach ($event in @($events | Sort-Object TimeCreated -Descending)) {
        $data = Get-DefenderData $event
        $eventName = switch ($event.Id) {
            1116 { "Threat detected" }
            1117 { "Action taken" }
            5001 { "Defender disabled" }
            5004 { "Defender configuration changed" }
            5010 { "Defender engine failure" }
            default { "Defender event" }
        }

        $score = switch ($event.Id) {
            1116 { 55 }
            1117 { 45 }
            5001 { 45 }
            5004 { 35 }
            5010 { 35 }
            default { 25 }
        }

        $reasons = @($eventName)
        if ($data.Path) { $reasons += "File path present in Defender event" }

        Add-Evidence -Time $event.TimeCreated -Category "Defender" -Source "DefenderOperational" -EventId $event.Id -Path $data.Path -Confidence $score -Reasons $reasons -Details "$eventName $($data.Threat)" | Out-Null

        if ($data.Path) {
            Add-CorrelationSignal -Source "DEFENDER" -Time $event.TimeCreated -Path $data.Path -Score 35 -Reasons @("Defender referenced this path")
        }

        $script:Report.Add("Time: $($event.TimeCreated)")
        $script:Report.Add("Event: $eventName")
        if ($data.Threat) { $script:Report.Add("Threat: $($data.Threat)") }
        if ($data.Path) { $script:Report.Add("Path: $($data.Path)") }
        $script:Report.Add("")
    }
}

function Collect-ProcessEvents {
    Write-Section "PROCESS EXECUTION EVENTS"

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            Id        = 4688
            StartTime = $script:StartTime
        } -ErrorAction Stop
    }
    catch {
        $script:Report.Add("Could not access Event ID 4688. Run as Administrator or enable Security auditing.")
        $script:Report.Add("")
        return
    }

    foreach ($event in @($events | Sort-Object TimeCreated -Descending)) {
        $data = Get-ProcessCreationData $event
        if (-not $data.ExeName) { continue }

        $reasons = @("Process creation event")
        $score = 10

        $isGame = Test-NameMatchesAny -Name $data.ExeName -Patterns $GameProcessPatterns
        if ($isGame) {
            $script:GameSessionTimes.Add($event.TimeCreated)
            Add-Evidence -Time $event.TimeCreated -Category "GameContext" -Source "Security4688" -EventId 4688 -ExeName $data.ExeName -Path $data.Path -ParentPath $data.ParentPath -UserSid $data.UserSid -Confidence 20 -Reasons @("SCUM or BattlEye process observed") -Details $data.ExeName | Out-Null
        }

        if (Test-RemovablePath $data.Path) {
            $score += 35
            $reasons += "Executed from removable drive"
        }
        if (Test-SuspiciousName $data.ExeName) {
            $score += 20
            $reasons += "Suspicious executable name"
        }
        if (Test-SuspiciousPath $data.Path) {
            $score += 15
            $reasons += "Unusual execution path"
        }
        if ($data.ParentPath -and (Test-SuspiciousPath $data.ParentPath)) {
            $score += 10
            $reasons += "Unusual parent path"
        }

        Add-CorrelationSignal -Source "4688" -Time $event.TimeCreated -Name $data.ExeName -Path $data.Path -ParentPath $data.ParentPath -UserSid $data.UserSid -Score $score -Reasons $reasons

        if ($score -ge 40) {
            Add-Evidence -Time $event.TimeCreated -Category "Execution" -Source "Security4688" -EventId 4688 -ExeName $data.ExeName -Path $data.Path -ParentPath $data.ParentPath -UserSid $data.UserSid -Confidence $score -Reasons $reasons -Details $data.ExeName | Out-Null
        }
    }
}

function Collect-PrefetchEvents {
    $prefetchPath = "C:\Windows\Prefetch"
    if (-not (Test-Path -LiteralPath $prefetchPath)) { return }

    Get-ChildItem -LiteralPath $prefetchPath -Filter "*.pf" |
        Where-Object { $_.LastWriteTime -ge $script:StartTime } |
        ForEach-Object {
            $name = $_.BaseName
            if ($name -match '^(.*)-[A-F0-9]{8}$') {
                $name = $matches[1]
            }

            $score = 10
            $reasons = @("Prefetch execution artifact")

            if (Test-SuspiciousName $name) {
                $score += 20
                $reasons += "Suspicious executable name"
            }

            Add-CorrelationSignal -Source "PREFETCH" -Time $_.LastWriteTime -Name $name -Score $score -Reasons $reasons
        }
}

function Collect-BamEvents {
    $bamPath = "HKLM:\System\CurrentControlSet\Services\bam\State\UserSettings"
    if (-not (Test-Path $bamPath)) { return }

    Get-ChildItem $bamPath |
        ForEach-Object {
            $sid = Split-Path $_.PSChildName -Leaf
            $props = Get-ItemProperty $_.PSPath

            foreach ($property in $props.PSObject.Properties) {
                $name = [string]$property.Name
                if ($name -notmatch "\.exe") { continue }

                $time = Convert-BamTimestamp $property.Value
                if ($time -and $time -lt $script:StartTime) { continue }

                $path = Normalize-ExecutablePath $name
                $exe = Get-ExeNameFromPath -Path $path -FallbackName $null
                $score = 10
                $reasons = @("BAM execution artifact")

                if (Test-RemovablePath $path) {
                    $score += 35
                    $reasons += "BAM path appears removable"
                }
                if (Test-SuspiciousName $exe) {
                    $score += 20
                    $reasons += "Suspicious executable name"
                }
                if (Test-SuspiciousPath $path) {
                    $score += 15
                    $reasons += "Unusual execution path"
                }

                Add-CorrelationSignal -Source "BAM" -Time $time -Name $exe -Path $path -UserSid $sid -Score $score -Reasons $reasons
            }
        }
}

function Collect-ServiceEvents {
    Write-Section "SERVICE AND DRIVER INSTALLATION"

    $events = Get-WinEvent -FilterHashtable @{
        LogName   = "System"
        Id        = 7045
        StartTime = $script:StartTime
    }

    foreach ($event in @($events | Sort-Object TimeCreated -Descending)) {
        $map = Get-EventDataMap $event
        $serviceName = Get-EventDataValue -Map $map -Names @("ServiceName", "param1")
        $imagePath = Get-EventDataValue -Map $map -Names @("ImagePath", "ServiceFileName", "param2")
        $serviceType = Get-EventDataValue -Map $map -Names @("ServiceType", "param3")

        if (-not $imagePath) {
            $imagePath = Get-MessageValue -Message ([string]$event.Message) -Patterns @(
                'Service File Name:\s+(.+)',
                'Nome do Arquivo de Servico:\s+(.+)'
            )
        }

        $cleanPath = Normalize-ExecutablePath $imagePath
        $score = 30
        $reasons = @("Service installation observed")

        if ($serviceType -match "kernel|driver") {
            $score += 15
            $reasons += "Service type indicates driver/kernel component"
        }
        if (Test-SuspiciousPath $cleanPath) {
            $score += 15
            $reasons += "Unusual service image path"
        }

        Add-Evidence -Time $event.TimeCreated -Category "Service" -Source "System7045" -EventId 7045 -Path $cleanPath -Confidence $score -Reasons $reasons -Details $serviceName | Out-Null
        Add-CorrelationSignal -Source "SERVICE" -Time $event.TimeCreated -Path $cleanPath -Score 20 -Reasons $reasons

        $script:Report.Add("Time: $($event.TimeCreated)")
        $script:Report.Add("Service: $serviceName")
        $script:Report.Add("Path: $cleanPath")
        $script:Report.Add("Type: $serviceType")
        $script:Report.Add("")
    }
}

function Collect-RuntimeContext {
    Write-Section "RUNTIME AND OVERLAY CONTEXT"

    $processes = Get-Process
    $found = $false

    foreach ($family in $script:OverlayProcessPatterns.Keys) {
        $pattern = $script:OverlayProcessPatterns[$family]
        $matches = @($processes | Where-Object { $_.ProcessName -match $pattern })

        if ($matches.Count -eq 0) { continue }

        $found = $true
        $names = @($matches | Select-Object -ExpandProperty ProcessName -Unique)
        $details = "$family runtime active: $($names -join ', ')"

        Add-Evidence -Time (Get-Date) -Category "RuntimeContext" -Source $family -Confidence 20 -Reasons @("Common overlay/runtime process observed") -Details $details | Out-Null

        $script:Report.Add($details)
        $script:Report.Add("")
    }

    if (-not $found) {
        $script:Report.Add("No common GPU/overlay runtime process observed.")
        $script:Report.Add("")
    }
}

function Invoke-ScreenshotTrigger {
    if (-not $EnableScreenshotTrigger) { return }

    $runtimeEvidence = @($script:Evidence | Where-Object { $_.Category -eq "RuntimeContext" })
    if ($runtimeEvidence.Count -eq 0) { return }

    Write-Section "SCREENSHOT TRIGGER"
    $script:Report.Add("Screenshot trigger explicitly enabled. Returning focus to the game is required.")
    $script:Report.Add("")

    try {
        Add-Type -AssemblyName System.Windows.Forms
        Start-Sleep -Seconds 15

        if ($runtimeEvidence.Source -contains "NVIDIA") {
            [System.Windows.Forms.SendKeys]::SendWait("%{F1}")
            Add-Evidence -Time (Get-Date) -Category "RuntimeContext" -Source "NVIDIA" -Confidence 20 -Reasons @("Operator enabled screenshot trigger") -Details "NVIDIA ALT+F1 trigger sent" | Out-Null
            $script:Report.Add("NVIDIA ALT+F1 trigger sent.")
        }
        elseif ($runtimeEvidence.Source -contains "AMD") {
            [System.Windows.Forms.SendKeys]::SendWait("^+i")
            Add-Evidence -Time (Get-Date) -Category "RuntimeContext" -Source "AMD" -Confidence 20 -Reasons @("Operator enabled screenshot trigger") -Details "AMD CTRL+SHIFT+I trigger sent" | Out-Null
            $script:Report.Add("AMD CTRL+SHIFT+I trigger sent.")
        }
    }
    catch {
        $script:Report.Add("Screenshot trigger failed: $($_.Exception.Message)")
    }
}

function Complete-Correlation {
    Write-Section "CORRELATED EXECUTION INTELLIGENCE"

    foreach ($entry in @($script:Correlation.Values | Sort-Object LastSeen -Descending)) {
        $score = $entry.Score
        $reasons = @($entry.Reasons)
        $primaryPath = $entry.Paths | Where-Object { $_ } | Select-Object -First 1
        $primaryParentPath = $entry.ParentPaths | Where-Object { $_ } | Select-Object -First 1
        $primaryUserSid = $entry.UserSids | Where-Object { $_ } | Select-Object -First 1
        $trust = Get-FileTrustInfo $primaryPath

        if (@($entry.Sources | Select-Object -Unique).Count -ge 2) {
            $score += 20
            $reasons += "Multiple telemetry sources"
        }
        if (Test-SuspiciousName $entry.Name) {
            $score += 20
            $reasons += "Suspicious executable name"
        }
        if ($primaryPath -and (Test-SuspiciousPath $primaryPath)) {
            $score += 15
            $reasons += "Unusual execution path"
        }
        if ($primaryPath -and (Test-RemovablePath $primaryPath)) {
            $score += 35
            $reasons += "Removable drive execution"
        }
        if ($entry.LastSeen -and (Test-NearAnyTime -Time $entry.LastSeen -Times $script:GameSessionTimes -Minutes 45)) {
            $score += 25
            $reasons += "Near SCUM/BattlEye session"
        }
        if ($entry.LastSeen -and (Test-NearAnyTime -Time $entry.LastSeen -Times $script:UsbTimes -Minutes 45)) {
            $score += 15
            $reasons += "Near USB activity"
        }
        if ($entry.LastSeen -and (Test-NearAnyTime -Time $entry.LastSeen -Times $script:AntiForensicTimes -Minutes 60)) {
            $score += 20
            $reasons += "Near anti-forensic event"
        }
        if ($trust.Trusted -and (Test-SafePath $primaryPath)) {
            $score -= 25
            $reasons += "Trusted publisher and trusted path reduced score"
        }
        elseif ($primaryPath -and -not $trust.Signed) {
            $score += 10
            $reasons += "Unsigned or unavailable signature"
        }

        $score = [Math]::Max(0, [Math]::Min(100, $score))
        $uniqueReasons = @($reasons | Where-Object { $_ } | Select-Object -Unique)
        $show = $IncludeLowConfidence -or $score -ge 40

        if ($show) {
            Add-Evidence -Time $entry.LastSeen -Category "CorrelatedExecution" -Source ($entry.Sources -join ",") -ExeName $entry.Name -Path $primaryPath -ParentPath $primaryParentPath -UserSid $primaryUserSid -Confidence $score -Reasons $uniqueReasons -Details $entry.Name | Out-Null

            $script:Report.Add("[!] Correlated execution")
            $script:Report.Add("Executable: $($entry.Name)")
            $script:Report.Add("Confidence: $score")
            $script:Report.Add("Sources: $($entry.Sources -join ', ')")
            if ($primaryPath) { $script:Report.Add("Path: $primaryPath") }
            $script:Report.Add("Last seen: $($entry.LastSeen)")
            $script:Report.Add("Signature: $($trust.Status) / $($trust.Publisher)")
            $script:Report.Add("Reasons: $($uniqueReasons -join '; ')")
            $script:Report.Add("")
        }
    }
}

function Write-Summary {
    $high = @($script:Evidence | Where-Object { $_.Confidence -ge 70 }).Count
    $medium = @($script:Evidence | Where-Object { $_.Confidence -ge 40 -and $_.Confidence -lt 70 }).Count
    $low = @($script:Evidence | Where-Object { $_.Confidence -lt 40 }).Count

    $header = New-Object System.Collections.Generic.List[string]
    $header.Add("TraceUSB forensic report")
    $header.Add("Generated: $(Get-Date)")
    $header.Add("LookbackHours: $LookbackHours")
    $header.Add("High confidence: $high")
    $header.Add("Medium confidence: $medium")
    $header.Add("Low/context evidence: $low")
    $header.Add("")
    $header.Add("Important: confidence indicates forensic relevance, not proof of cheating.")
    $header.Add("")

    $script:Report.InsertRange(0, $header)
}

function Get-SeverityName {
    param([int]$Confidence)

    if ($Confidence -ge 70) { return "alert" }
    if ($Confidence -ge 40) { return "notice" }
    return "info"
}

function Convert-HexColorToInt {
    param(
        [string]$Hex,
        [string]$Fallback = "4E7DD9"
    )

    $clean = ($Hex -replace '#', '').Trim()
    if ($clean -notmatch '^[0-9A-Fa-f]{6}$') {
        $clean = $Fallback
    }

    return [Convert]::ToInt32($clean, 16)
}

function Get-DiscordColor {
    param([int]$HighestConfidence)

    if ($HighestConfidence -ge 70) {
        return Convert-HexColorToInt -Hex $DiscordAlertColor -Fallback "D64545"
    }
    if ($HighestConfidence -ge 40) {
        return Convert-HexColorToInt -Hex $DiscordNoticeColor -Fallback "E0A33A"
    }

    return Convert-HexColorToInt -Hex $DiscordInfoColor -Fallback "4E7DD9"
}

function Limit-Text {
    param(
        [string]$Text,
        [int]$MaxLength = 900
    )

    if (-not $Text) { return "" }
    if ($Text.Length -le $MaxLength) { return $Text }
    return $Text.Substring(0, [Math]::Max(0, $MaxLength - 3)) + "..."
}

function Test-CommonExecutableName {
    param([string]$Name)

    if (-not $Name) { return $false }
    return $Name -match '^(chrome|msedge|firefox|brave|opera|explorer|svchost|conhost|cmd|powershell|pwsh|steam|steamwebhelper|discord|nvidia|nvcontainer|runtimebroker)\.exe$'
}

function Get-DiscordEvidencePriority {
    param($Evidence)

    $priority = [int]$Evidence.Confidence
    $category = [string]$Evidence.Category
    $source = [string]$Evidence.Source
    $exeName = [string]$Evidence.ExeName
    $path = [string]$Evidence.Path
    $reasonText = (@($Evidence.Reasons) -join " | ")

    switch ($category) {
        "Defender" { $priority += 45 }
        "AntiForensic" { $priority += 45 }
        "BrowserHistory" { $priority += 35 }
        "Service" { $priority += 30 }
        "USB" { $priority += 25 }
        "Execution" { $priority += 20 }
        "CorrelatedExecution" { $priority += 10 }
        "GameContext" { $priority -= 30 }
        "RuntimeContext" { $priority -= 35 }
    }

    if ($source -match "4688|Security") { $priority += 20 }
    if ($reasonText -match "Defender|anti-forensic|Log|USB|Removable|SCUM|BattlEye|Suspicious") { $priority += 15 }
    if ($path -match '^[A-Z]:\\' -and (Test-RemovablePath $path)) { $priority += 25 }
    if ($path -match '\\AppData\\Local\\Temp\\|\\Downloads\\|\\Desktop\\') { $priority += 10 }
    if ($source -eq "PREFETCH,BAM") { $priority -= 25 }
    if ((Test-CommonExecutableName $exeName) -and $source -match "PREFETCH|BAM") { $priority -= 45 }

    return [Math]::Max(0, $priority)
}

function Get-DiscordSourceSummary {
    $sourceCounts = @{}
    $categoryCounts = @{}

    foreach ($item in $script:Evidence) {
        $category = if ($item.Category) { [string]$item.Category } else { "Unknown" }
        if (-not $categoryCounts.ContainsKey($category)) { $categoryCounts[$category] = 0 }
        $categoryCounts[$category]++

        foreach ($source in ([string]$item.Source -split ',')) {
            $clean = $source.Trim()
            if (-not $clean) { continue }
            if (-not $sourceCounts.ContainsKey($clean)) { $sourceCounts[$clean] = 0 }
            $sourceCounts[$clean]++
        }
    }

    $topSources = @(
        $sourceCounts.GetEnumerator() |
            Sort-Object Value -Descending |
            Select-Object -First 6 |
            ForEach-Object { "$($_.Key): $($_.Value)" }
    )
    $topCategories = @(
        $categoryCounts.GetEnumerator() |
            Sort-Object Value -Descending |
            Select-Object -First 6 |
            ForEach-Object { "$($_.Key): $($_.Value)" }
    )

    return [PSCustomObject]@{
        Sources = if ($topSources.Count -gt 0) { $topSources -join " | " } else { "Nenhuma fonte com evidencia." }
        Categories = if ($topCategories.Count -gt 0) { $topCategories -join " | " } else { "Nenhuma categoria com evidencia." }
    }
}

function Get-DiverseDiscordEvidence {
    param([object[]]$Evidence)

    $selected = New-Object System.Collections.Generic.List[object]
    $seenKeys = @{}

    $ranked = @(
        $Evidence |
            ForEach-Object {
                [PSCustomObject]@{
                    Evidence = $_
                    Priority = Get-DiscordEvidencePriority $_
                }
            } |
            Sort-Object -Property Priority, @{ Expression = { $_.Evidence.Confidence } }, @{ Expression = { $_.Evidence.Time } } -Descending
    )

    foreach ($item in $ranked) {
        if ($selected.Count -ge $DiscordMaxItems) { break }
        $evidence = $item.Evidence
        $key = "$($evidence.Category)|$($evidence.Source)"
        if ($seenKeys.ContainsKey($key) -and $item.Priority -lt 90) { continue }
        $seenKeys[$key] = $true
        $selected.Add($evidence)
    }

    if ($selected.Count -eq 0 -and $Evidence.Count -gt 0) {
        $selected.Add(($Evidence | Select-Object -First 1))
    }

    return @($selected.ToArray())
}

function Get-EvidenceTranslation {
    param($Evidence)

    $category = [string]$Evidence.Category
    $source = [string]$Evidence.Source
    $reasons = @($Evidence.Reasons)
    $reasonText = ($reasons -join " | ")

    $meaning = "Evidencia contextual coletada pelo TraceUSB."
    $operatorAction = "Revisar junto com os demais sinais e horario da sessao."
    $falsePositive = "Pode ser normal se aparecer isolado."

    if ($category -eq "CorrelatedExecution") {
        $meaning = "Execucao apareceu em mais de uma fonte do Windows, aumentando relevancia forense."
        $operatorAction = "Verifique caminho, assinatura, horario e proximidade com sessao SCUM/BattlEye."
        $falsePositive = "Instaladores, atualizadores e ferramentas legitimas tambem podem aparecer correlacionados."
    }
    elseif ($category -eq "Execution") {
        $meaning = "Processo recente com caracteristicas incomuns ou origem relevante."
        $operatorAction = "Compare o executavel com USB, pasta temporaria, assinatura e processo pai."
        $falsePositive = "Ferramentas portateis e launchers legitimos podem gerar esse sinal."
    }
    elseif ($category -eq "Defender") {
        $meaning = "Microsoft Defender registrou deteccao, acao, falha ou alteracao de protecao."
        $operatorAction = "Abrir o evento original e conferir ameaca, caminho e decisao tomada."
        $falsePositive = "Cracks, trainers genericos e ferramentas administrativas podem ser detectados sem relacao com SCUM."
    }
    elseif ($category -eq "AntiForensic") {
        $meaning = "Evento associado a limpeza de logs ou reducao de visibilidade historica."
        $operatorAction = "Tratar como sinal forte quando ocorrer perto de execucao suspeita ou sessao de jogo."
        $falsePositive = "Rotinas administrativas podem limpar logs legitimamente."
    }
    elseif ($category -eq "Service") {
        $meaning = "Servico ou driver foi instalado no periodo analisado."
        $operatorAction = "Verificar se o servico e conhecido, assinado e esperado para o usuario."
        $falsePositive = "Drivers de perifericos, VPN, anti-cheat e atualizadores podem instalar servicos."
    }
    elseif ($category -eq "RuntimeContext") {
        $meaning = "Runtime, overlay ou ecossistema grafico comum estava ativo."
        $operatorAction = "Usar como contexto. Nao tratar como suspeito isoladamente."
        $falsePositive = "NVIDIA, AMD, Steam, Discord, RTSS e similares sao comuns em jogadores legitimos."
    }
    elseif ($category -eq "USB") {
        $meaning = "Dispositivo USB conectado ou removido no periodo analisado."
        $operatorAction = "Correlacionar com execucao de arquivos removiveis e horario da partida."
        $falsePositive = "Headsets, teclados, mouses e pendrives legitimos aparecem normalmente."
    }
    elseif ($category -eq "GameContext") {
        $meaning = "Processo SCUM ou BattlEye observado e usado como ancora temporal."
        $operatorAction = "Usar apenas para correlacao de horario."
        $falsePositive = "Este sinal e esperado quando o jogador abriu o jogo."
    }
    elseif ($category -eq "BrowserHistory") {
        $meaning = "Historico de navegador teve correspondencia com palavras-chave configuradas."
        $operatorAction = "Revisar apenas os hits filtrados no anexo de historico; nao inferir culpa por busca isolada."
        $falsePositive = "Pesquisa curiosa, noticia, denuncia ou discussao em forum pode conter as mesmas palavras."
    }

    if ($reasonText -match "Removable|USB|remov") {
        $operatorAction += " Priorize checar se houve loader em unidade removivel."
    }
    if ($reasonText -match "SCUM|BattlEye") {
        $operatorAction += " O achado ocorreu perto da janela de jogo."
    }
    if ($reasonText -match "Unsigned|signature|assinatura") {
        $operatorAction += " Assinatura ausente aumenta a necessidade de revisao manual."
    }

    return [PSCustomObject]@{
        Category       = $category
        Source         = $source
        Confidence     = $Evidence.Confidence
        Severity       = Get-SeverityName -Confidence $Evidence.Confidence
        Subject        = @($Evidence.ExeName, $Evidence.Path, $Evidence.Device, $Evidence.Details) | Where-Object { $_ } | Select-Object -First 1
        Translation    = $meaning
        OperatorAction = $operatorAction
        FalsePositive  = $falsePositive
        Reasons        = $reasons
    }
}

function Get-TranslationSuggestions {
    $items = @(
        $script:Evidence |
            Where-Object { $DiscordIncludeLowConfidence -or $_.Confidence -ge 40 } |
            Sort-Object Confidence -Descending |
            Select-Object -First 30 |
            ForEach-Object { Get-EvidenceTranslation $_ }
    )

    return $items
}

function Get-TranslationSuggestionLines {
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("TraceUSB suggested translations")
    $lines.Add("Generated: $(Get-Date)")
    $lines.Add("Meaning: interpretacao humana de evidencia forense. Nao e prova automatica de cheat.")
    $lines.Add("")

    foreach ($item in Get-TranslationSuggestions) {
        $lines.Add("[$($item.Severity.ToUpperInvariant())] $($item.Category) / $($item.Source)")
        if ($item.Subject) { $lines.Add("Subject: $($item.Subject)") }
        $lines.Add("Translation: $($item.Translation)")
        $lines.Add("Operator action: $($item.OperatorAction)")
        $lines.Add("False-positive note: $($item.FalsePositive)")
        if ($item.Reasons.Count -gt 0) {
            $lines.Add("Reasons: $($item.Reasons -join '; ')")
        }
        $lines.Add("")
    }

    return @($lines)
}

function Add-DiscordAttachment {
    param(
        [string]$FileName,
        [string[]]$Lines,
        [string]$ContentType = "text/plain; charset=utf-8",
        [string]$LocalPath
    )

    if (-not $Lines) {
        $Lines = @("")
    }

    $content = ($Lines -join "`r`n")
    $bytes = [Text.Encoding]::UTF8.GetBytes($content)
    if ($bytes.Length -gt $DiscordMaxAttachmentBytes) {
        $keepBytes = [Math]::Max(1024, $DiscordMaxAttachmentBytes - 2048)
        $content = [Text.Encoding]::UTF8.GetString($bytes, 0, $keepBytes)
        $content += "`r`n`r`n[TraceUSB truncated this attachment from $($bytes.Length) bytes to fit DiscordMaxAttachmentBytes=$DiscordMaxAttachmentBytes.]"
        Write-RunLog "Attachment truncated: $FileName ($($bytes.Length) bytes)."
    }

    $script:DiscordAttachments.Add([PSCustomObject]@{
        FileName    = $FileName
        Content     = $content
        ContentType = $ContentType
    })

    if ($SaveDiscordAttachmentsLocal -and $LocalPath) {
        Set-Content -LiteralPath $LocalPath -Value $content -Encoding UTF8
    }
}

function Get-EvidenceJsonLines {
    return @(
        $script:Evidence |
            Sort-Object Time |
            ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 6 }
    )
}

function Resolve-SqliteCli {
    if ($SQLiteCliPath -and (Test-Path -LiteralPath $SQLiteCliPath)) {
        return $SQLiteCliPath
    }

    try {
        $cmd = Get-Command sqlite3.exe -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Source) { return $cmd.Source }
    }
    catch {}

    try {
        $cmd = Get-Command sqlite3 -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Source) { return $cmd.Source }
    }
    catch {}

    return $null
}

function Redact-Url {
    param([string]$Url)

    if (-not $Url) { return "" }
    if ($NoRedactUrls) { return $Url }

    try {
        $uri = [Uri]$Url
        $path = $uri.AbsolutePath
        if (-not $path) { $path = "/" }
        if ($uri.Query) {
            return ("{0}://{1}{2}?query_redacted=true" -f $uri.Scheme, $uri.Authority, $path)
        }
        return ("{0}://{1}{2}" -f $uri.Scheme, $uri.Authority, $path)
    }
    catch {
        return ($Url -replace '\?.*$', '?query_redacted=true')
    }
}

function Limit-HistoryText {
    param(
        [string]$Text,
        [int]$MaxLength = 240
    )

    if (-not $Text) { return "" }
    $clean = ($Text -replace "`r|`n", " ").Trim()
    if ($clean.Length -le $MaxLength) { return $clean }
    return $clean.Substring(0, $MaxLength - 3) + "..."
}

function Normalize-HistoryMatchText {
    param([string]$Text)

    if (-not $Text) { return "" }

    try {
        $Text = [System.Net.WebUtility]::UrlDecode($Text)
    }
    catch {}

    $Text = $Text.ToLowerInvariant()
    $Text = $Text -replace '\+', ' '
    $Text = $Text -replace '[^a-z0-9]+', ' '
    $Text = $Text -replace '\s+', ' '
    return $Text.Trim()
}

function Find-BrowserHistoryKeyword {
    param(
        [string]$Url,
        [string]$Title,
        [string]$SearchTerm
    )

    $haystack = Normalize-HistoryMatchText "$Url $Title $SearchTerm"
    foreach ($keyword in $BrowserHistoryKeywords) {
        if (-not $keyword) { continue }
        $normalizedKeyword = Normalize-HistoryMatchText $keyword
        if (-not $normalizedKeyword) { continue }

        if ($haystack -match "(^| )$([regex]::Escape($normalizedKeyword))( |$)") {
            return $keyword
        }

        $tokens = @($normalizedKeyword -split ' ' | Where-Object { $_ })
        if ($tokens.Count -gt 1) {
            $allTokensPresent = $true
            foreach ($token in $tokens) {
                if ($haystack -notmatch "(^| )$([regex]::Escape($token))( |$)") {
                    $allTokensPresent = $false
                    break
                }
            }
            if ($allTokensPresent) { return $keyword }
        }
    }

    return $null
}

function Get-BrowserHistoryKeywordPriority {
    param([string]$Keyword)

    $normalized = Normalize-HistoryMatchText $Keyword
    if (-not $normalized) { return 0 }
    if ($normalized -match 'ciroscript|project cheats|byster|crooked') { return 100 }
    if ($normalized -match 'scum (cheat|hack|esp|aimbot|script)') { return 95 }
    if ($normalized -match 'lag switch|fake lag|clumsy|windivert|battleye bypass') { return 90 }
    if ($normalized -match 'aimbot|wallhack|trainer|bypass|macro') { return 80 }
    if ($normalized -match 'cheat|cheats|hack|hacks|script') { return 70 }
    if ($normalized -eq 'esp') { return 60 }
    if ($normalized -eq 'scum') { return 25 }
    return 50
}

function Invoke-SqliteCsv {
    param(
        [string]$SqlitePath,
        [string]$DatabasePath,
        [string]$Query
    )

    $output = & $SqlitePath -readonly -header -csv $DatabasePath $Query 2>$null
    if (-not $output) { return @() }

    try {
        return @($output | ConvertFrom-Csv)
    }
    catch {
        return @()
    }
}

function Escape-SqlLikeLiteral {
    param([string]$Text)

    if (-not $Text) { return "" }
    return ($Text -replace "'", "''")
}

function Get-BrowserHistorySqlFilter {
    param([string]$Expression)

    $terms = New-Object System.Collections.Generic.List[string]
    foreach ($keyword in $BrowserHistoryKeywords) {
        $normalized = Normalize-HistoryMatchText $keyword
        if (-not $normalized) { continue }
        foreach ($token in @($normalized -split ' ' | Where-Object { $_ -and $_.Length -ge 3 })) {
            if (-not $terms.Contains($token)) { $terms.Add($token) }
        }
    }

    if ($terms.Count -eq 0) { return "1=1" }

    $parts = @(
        $terms |
            ForEach-Object {
                "$Expression LIKE '%$(Escape-SqlLikeLiteral $_)%'"
            }
    )
    return "(" + ($parts -join " OR ") + ")"
}

function Invoke-SqliteTsv {
    param(
        [string]$SqlitePath,
        [string]$DatabasePath,
        [string]$Query,
        [string[]]$Columns
    )

    $output = & $SqlitePath -readonly -separator "`t" $DatabasePath $Query 2>$null
    if (-not $output) { return @() }

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($line in @($output)) {
        if ($null -eq $line -or $line -eq "") { continue }
        $values = [string]$line -split "`t", $Columns.Count
        $row = [ordered]@{}
        for ($i = 0; $i -lt $Columns.Count; $i++) {
            $value = ""
            if ($i -lt $values.Count) { $value = $values[$i] }
            $row[$Columns[$i]] = $value
        }
        $rows.Add([PSCustomObject]$row)
    }

    return @($rows.ToArray())
}

function Get-BrowserProfileRoots {
    $roots = New-Object System.Collections.Generic.List[object]
    $seen = @{}

    function Add-BrowserProfileRoot {
        param(
            [string]$UserName,
            [string]$LocalAppData,
            [string]$RoamingAppData
        )

        $candidates = @(
            @{ Browser = "Chrome"; Root = Join-Path $LocalAppData "Google\Chrome\User Data" },
            @{ Browser = "Chrome Beta"; Root = Join-Path $LocalAppData "Google\Chrome Beta\User Data" },
            @{ Browser = "Chrome Dev"; Root = Join-Path $LocalAppData "Google\Chrome Dev\User Data" },
            @{ Browser = "Chrome Canary"; Root = Join-Path $LocalAppData "Google\Chrome SxS\User Data" },
            @{ Browser = "Edge"; Root = Join-Path $LocalAppData "Microsoft\Edge\User Data" },
            @{ Browser = "Edge Beta"; Root = Join-Path $LocalAppData "Microsoft\Edge Beta\User Data" },
            @{ Browser = "Edge Dev"; Root = Join-Path $LocalAppData "Microsoft\Edge Dev\User Data" },
            @{ Browser = "Edge Canary"; Root = Join-Path $LocalAppData "Microsoft\Edge SxS\User Data" },
            @{ Browser = "Brave"; Root = Join-Path $LocalAppData "BraveSoftware\Brave-Browser\User Data" },
            @{ Browser = "Chromium"; Root = Join-Path $LocalAppData "Chromium\User Data" },
            @{ Browser = "Vivaldi"; Root = Join-Path $LocalAppData "Vivaldi\User Data" },
            @{ Browser = "Yandex"; Root = Join-Path $LocalAppData "Yandex\YandexBrowser\User Data" },
            @{ Browser = "Arc"; Root = Join-Path $LocalAppData "Packages\TheBrowserCompany.Arc_ttt1ap7aakyb4\LocalCache\Local\Arc\User Data" },
            @{ Browser = "Opera"; Root = Join-Path $RoamingAppData "Opera Software\Opera Stable"; Opera = $true },
            @{ Browser = "Opera GX"; Root = Join-Path $RoamingAppData "Opera Software\Opera GX Stable"; Opera = $true },
            @{ Browser = "Firefox"; Root = Join-Path $RoamingAppData "Mozilla\Firefox\Profiles"; Firefox = $true }
        )

        foreach ($candidate in $candidates) {
            if (-not $candidate.Root) { continue }
            $key = "$($candidate.Browser)|$($candidate.Root)".ToLowerInvariant()
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            $roots.Add([PSCustomObject]@{
                UserName = $UserName
                Browser  = $candidate.Browser
                Root     = $candidate.Root
                Opera    = [bool]$candidate.Opera
                Firefox  = [bool]$candidate.Firefox
            })
        }
    }

    Add-BrowserProfileRoot -UserName $env:USERNAME -LocalAppData $env:LOCALAPPDATA -RoamingAppData $env:APPDATA

    try {
        Get-ChildItem -LiteralPath "C:\Users" -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin @("All Users", "Default", "Default User", "Public") } |
            ForEach-Object {
                Add-BrowserProfileRoot `
                    -UserName $_.Name `
                    -LocalAppData (Join-Path $_.FullName "AppData\Local") `
                    -RoamingAppData (Join-Path $_.FullName "AppData\Roaming")
            }
    }
    catch {}

    return @($roots.ToArray())
}

function Get-ChromiumHistoryDatabases {
    $items = New-Object System.Collections.Generic.List[object]
    $roots = Get-BrowserProfileRoots | Where-Object { -not $_.Firefox }

    foreach ($entry in $roots) {
        if (-not (Test-Path -LiteralPath $entry.Root)) { continue }

        if ($entry.Opera) {
            $historyPath = Join-Path $entry.Root "History"
            if (Test-Path -LiteralPath $historyPath) {
                $items.Add([PSCustomObject]@{
                    Browser = $entry.Browser
                    Profile = "$($entry.UserName)\Default"
                    Path    = $historyPath
                    Type    = "Chromium"
                })
            }
            continue
        }

        try {
            Get-ChildItem -LiteralPath $entry.Root -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq "Default" -or $_.Name -like "Profile *" -or $_.Name -eq "Guest Profile" } |
                ForEach-Object {
                    $historyPath = Join-Path $_.FullName "History"
                    if (Test-Path -LiteralPath $historyPath) {
                        $items.Add([PSCustomObject]@{
                            Browser = $entry.Browser
                            Profile = "$($entry.UserName)\$($_.Name)"
                            Path    = $historyPath
                            Type    = "Chromium"
                        })
                    }
                }
        }
        catch {}
    }

    return @($items.ToArray())
}

function Get-FirefoxHistoryDatabases {
    $items = New-Object System.Collections.Generic.List[object]
    $roots = Get-BrowserProfileRoots | Where-Object { $_.Firefox }

    foreach ($entry in $roots) {
        if (-not (Test-Path -LiteralPath $entry.Root)) { continue }

        try {
            Get-ChildItem -LiteralPath $entry.Root -Directory -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $placesPath = Join-Path $_.FullName "places.sqlite"
                    if (Test-Path -LiteralPath $placesPath) {
                        $items.Add([PSCustomObject]@{
                            Browser = "Firefox"
                            Profile = "$($entry.UserName)\$($_.Name)"
                            Path    = $placesPath
                            Type    = "Firefox"
                        })
                    }
                }
        }
        catch {}
    }

    return @($items.ToArray())
}

function Get-BrowserHistoryDatabases {
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($db in Get-ChromiumHistoryDatabases) { $items.Add($db) }
    foreach ($db in Get-FirefoxHistoryDatabases) { $items.Add($db) }
    return @($items.ToArray())
}

function Copy-BrowserHistoryDatabase {
    param(
        $Database,
        [string]$Destination
    )

    try {
        Copy-Item -LiteralPath $Database.Path -Destination $Destination -Force -ErrorAction Stop
        return $true
    }
    catch {
        Write-RunLog "Normal copy failed for browser history $($Database.Browser) $($Database.Profile): $($_.Exception.Message)"
    }

    try {
        $source = [System.IO.File]::Open($Database.Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $dest = [System.IO.File]::Create($Destination)
            try {
                $source.CopyTo($dest)
            }
            finally {
                $dest.Dispose()
            }
        }
        finally {
            $source.Dispose()
        }
        return $true
    }
    catch {
        Write-RunLog "Shared-read copy failed for browser history $($Database.Browser) $($Database.Profile): $($_.Exception.Message)"
        return $false
    }
}

<#
Legacy helpers kept intentionally removed from call path by Get-BrowserHistoryDatabases.
This marker prevents accidental reintroduction of single-user-only browser scans.
#>
function Get-ChromiumHistoryDatabases_LegacyDisabled {
    $items = New-Object System.Collections.Generic.List[object]
    $roots = @(
        @{ Browser = "Chrome"; Root = Join-Path $env:LOCALAPPDATA "Google\Chrome\User Data" },
        @{ Browser = "Edge"; Root = Join-Path $env:LOCALAPPDATA "Microsoft\Edge\User Data" },
        @{ Browser = "Brave"; Root = Join-Path $env:LOCALAPPDATA "BraveSoftware\Brave-Browser\User Data" }
    )

    foreach ($entry in $roots) {
        if (-not (Test-Path -LiteralPath $entry.Root)) { continue }
        Get-ChildItem -LiteralPath $entry.Root -Directory |
            Where-Object { $_.Name -eq "Default" -or $_.Name -like "Profile *" } |
            ForEach-Object {
                $historyPath = Join-Path $_.FullName "History"
                if (Test-Path -LiteralPath $historyPath) {
                    $items.Add([PSCustomObject]@{
                        Browser = $entry.Browser
                        Profile = $_.Name
                        Path    = $historyPath
                        Type    = "Chromium"
                    })
                }
            }
    }

    $operaHistory = Join-Path $env:APPDATA "Opera Software\Opera Stable\History"
    if (Test-Path -LiteralPath $operaHistory) {
        $items.Add([PSCustomObject]@{
            Browser = "Opera"
            Profile = "Default"
            Path    = $operaHistory
            Type    = "Chromium"
        })
    }

    return @($items)
}

function Get-FirefoxHistoryDatabases_LegacyDisabled {
    $items = New-Object System.Collections.Generic.List[object]
    $profilesRoot = Join-Path $env:APPDATA "Mozilla\Firefox\Profiles"
    if (-not (Test-Path -LiteralPath $profilesRoot)) { return @() }

    Get-ChildItem -LiteralPath $profilesRoot -Directory |
        ForEach-Object {
            $placesPath = Join-Path $_.FullName "places.sqlite"
            if (Test-Path -LiteralPath $placesPath) {
                $items.Add([PSCustomObject]@{
                    Browser = "Firefox"
                    Profile = $_.Name
                    Path    = $placesPath
                    Type    = "Firefox"
                })
            }
        }

    return @($items)
}

function Get-FilteredHistoryLines {
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("TraceUSB filtered browser history")
    $lines.Add("Generated: $(Get-Date)")
    $lines.Add("Privacy: only keyword matches are included; full browser history is not exported.")
    $lines.Add("LookbackDays: $BrowserHistoryLookbackDays")
    $lines.Add("Keywords: $($BrowserHistoryKeywords -join ', ')")
    $lines.Add("")

    if (-not $EnableBrowserHistoryScan) {
        $lines.Add("Browser history scan disabled. Use -EnableBrowserHistoryScan to enable.")
        return @($lines)
    }

    $sqlite = Resolve-SqliteCli
    if (-not $sqlite) {
        $lines.Add("Browser history scan skipped: sqlite3.exe was not found. Provide -SQLiteCliPath or add sqlite3 to PATH.")
        Add-Evidence -Time (Get-Date) -Category "BrowserHistory" -Source "BrowserHistoryScan" -Confidence 10 -Reasons @("Browser history scan requested but SQLite reader unavailable") -Details "sqlite3.exe unavailable" | Out-Null
        return @($lines)
    }

    $databases = @(Get-BrowserHistoryDatabases)

    if ($databases.Count -eq 0) {
        $lines.Add("No supported browser history databases were found.")
        $lines.Add("Checked browser profile roots:")
        foreach ($root in Get-BrowserProfileRoots) {
            $exists = Test-Path -LiteralPath $root.Root
            $lines.Add("- $($root.Browser) [$($root.UserName)]: $($root.Root) (exists=$exists)")
        }
        Add-Evidence -Time (Get-Date) -Category "BrowserHistory" -Source "BrowserHistoryScan" -Confidence 10 -Reasons @("Browser history scan found no supported databases") -Details "No Chrome/Edge/Brave/Opera/Firefox history database found in checked profile roots" | Out-Null
        return @($lines)
    }

    $lines.Add("Detected browser history databases: $($databases.Count)")
    foreach ($db in $databases) {
        $lines.Add("- $($db.Browser) [$($db.Profile)]")
    }
    $lines.Add("")

    $tempRoot = Join-Path $env:TEMP ("TraceUSB-history-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
    $readableDatabases = 0
    $internalMaxHistoryHits = [Math]::Max($BrowserHistoryMaxHits * 5, 500)

    try {
        foreach ($db in $databases) {
            if ($script:FilteredHistoryHits.Count -ge $internalMaxHistoryHits) { break }

            $copyPath = Join-Path $tempRoot ("history_" + [guid]::NewGuid().ToString("N") + ".sqlite")
            if (-not (Copy-BrowserHistoryDatabase -Database $db -Destination $copyPath)) {
                $lines.Add("Skipped $($db.Browser) [$($db.Profile)]: could not copy locked or inaccessible database.")
                continue
            }
            $readableDatabases++

            $queries = New-Object System.Collections.Generic.List[object]
            if ($db.Type -eq "Chromium") {
                $historyExpression = "lower(urls.url || ' ' || ifnull(urls.title,''))"
                $historyFilter = Get-BrowserHistorySqlFilter -Expression $historyExpression
                $searchExpression = "lower(keyword_search_terms.term || ' ' || keyword_search_terms.normalized_term || ' ' || urls.url || ' ' || ifnull(urls.title,''))"
                $searchFilter = Get-BrowserHistorySqlFilter -Expression $searchExpression
                $queries.Add([PSCustomObject]@{
                    Source = "History"
                    Sql = "SELECT datetime((visits.visit_time/1000000)-11644473600,'unixepoch','localtime') AS visit_time, urls.url AS url, replace(replace(ifnull(urls.title,''), char(10), ' '), char(13), ' ') AS title, '' AS search_term FROM urls JOIN visits ON urls.id=visits.url WHERE visits.visit_time >= ((strftime('%s','now') - ($BrowserHistoryLookbackDays*86400) + 11644473600)*1000000) AND $historyFilter ORDER BY visits.visit_time DESC LIMIT 30000;"
                })
                $queries.Add([PSCustomObject]@{
                    Source = "SearchTerms"
                    Sql = "SELECT datetime((urls.last_visit_time/1000000)-11644473600,'unixepoch','localtime') AS visit_time, urls.url AS url, replace(replace(ifnull(urls.title,''), char(10), ' '), char(13), ' ') AS title, replace(replace(ifnull(keyword_search_terms.term,''), char(10), ' '), char(13), ' ') AS search_term FROM keyword_search_terms JOIN urls ON urls.id=keyword_search_terms.url_id WHERE urls.last_visit_time >= ((strftime('%s','now') - ($BrowserHistoryLookbackDays*86400) + 11644473600)*1000000) AND $searchFilter ORDER BY urls.last_visit_time DESC LIMIT 10000;"
                })
            }
            else {
                $firefoxExpression = "lower(moz_places.url || ' ' || ifnull(moz_places.title,''))"
                $firefoxFilter = Get-BrowserHistorySqlFilter -Expression $firefoxExpression
                $queries.Add([PSCustomObject]@{
                    Source = "History"
                    Sql = "SELECT datetime(moz_historyvisits.visit_date/1000000,'unixepoch','localtime') AS visit_time, moz_places.url AS url, replace(replace(ifnull(moz_places.title,''), char(10), ' '), char(13), ' ') AS title, '' AS search_term FROM moz_places JOIN moz_historyvisits ON moz_places.id=moz_historyvisits.place_id WHERE moz_historyvisits.visit_date >= ((strftime('%s','now') - ($BrowserHistoryLookbackDays*86400))*1000000) AND $firefoxFilter ORDER BY moz_historyvisits.visit_date DESC LIMIT 30000;"
                })
            }

            foreach ($querySpec in $queries) {
                if ($script:FilteredHistoryHits.Count -ge $internalMaxHistoryHits) { break }

                $rows = Invoke-SqliteTsv -SqlitePath $sqlite -DatabasePath $copyPath -Query $querySpec.Sql -Columns @("visit_time", "url", "title", "search_term")
                if ($rows.Count -eq 0) {
                    $lines.Add("Read $($db.Browser) [$($db.Profile)] $($querySpec.Source): no rows returned in lookback window or SQLite query failed.")
                }

                foreach ($row in $rows) {
                    if ($script:FilteredHistoryHits.Count -ge $internalMaxHistoryHits) { break }

                    $keyword = Find-BrowserHistoryKeyword -Url $row.url -Title $row.title -SearchTerm $row.search_term
                    if (-not $keyword) { continue }
                    $priority = Get-BrowserHistoryKeywordPriority $keyword

                    $hit = [PSCustomObject]@{
                        Browser    = $db.Browser
                        Profile    = $db.Profile
                        Source     = $querySpec.Source
                        Time       = $row.visit_time
                        Keyword    = $keyword
                        SearchTerm = Limit-HistoryText $row.search_term
                        Url        = Redact-Url $row.url
                        Title      = Limit-HistoryText $row.title
                        Priority   = $priority
                    }
                    $script:FilteredHistoryHits.Add($hit)
                }
            }
        }
    }
    finally {
        try { Remove-Item -LiteralPath $tempRoot -Recurse -Force } catch {}
    }

    if ($script:FilteredHistoryHits.Count -eq 0) {
        $lines.Add("No browser history keyword matches were found.")
        $lines.Add("Readable databases: $readableDatabases / $($databases.Count)")
        return @($lines)
    }

    $selectedHistoryHits = @(
        $script:FilteredHistoryHits |
            Sort-Object -Property Priority, Time -Descending |
            Select-Object -First $BrowserHistoryMaxHits
    )

    if ($script:FilteredHistoryHits.Count -gt $selectedHistoryHits.Count) {
        $matchScope = if ($script:FilteredHistoryHits.Count -ge $internalMaxHistoryHits) {
            "$($script:FilteredHistoryHits.Count)+ collected before internal cap"
        } else {
            "$($script:FilteredHistoryHits.Count) found"
        }
        $lines.Add("Matches: $($selectedHistoryHits.Count) shown / $matchScope")
        $lines.Add("Selection: higher-risk keywords are prioritized over generic SCUM-only hits.")
    }
    else {
        $lines.Add("Matches: $($selectedHistoryHits.Count)")
    }
    $lines.Add("")

    foreach ($hit in $selectedHistoryHits) {
        $lines.Add("Browser: $($hit.Browser)")
        $lines.Add("Profile: $($hit.Profile)")
        $lines.Add("Source: $($hit.Source)")
        $lines.Add("Time: $($hit.Time)")
        $lines.Add("Keyword: $($hit.Keyword)")
        $lines.Add("Priority: $($hit.Priority)")
        if ($hit.SearchTerm) { $lines.Add("SearchTerm: $($hit.SearchTerm)") }
        $lines.Add("URL: $($hit.Url)")
        if ($hit.Title) { $lines.Add("Title: $($hit.Title)") }
        $lines.Add("")
    }

    Add-Evidence -Time (Get-Date) -Category "BrowserHistory" -Source "BrowserHistoryScan" -Confidence 45 -Reasons @("Filtered browser history keyword matches found") -Details "$($script:FilteredHistoryHits.Count) filtered browser history hit(s)" | Out-Null

    return @($lines)
}

function Build-DiscordEmbedPayload {
    $visibleEvidence = @(
        $script:Evidence |
            Where-Object { $DiscordIncludeLowConfidence -or $_.Confidence -ge 40 } |
            Sort-Object -Property Confidence, Time -Descending
    )

    $high = @($script:Evidence | Where-Object { $_.Confidence -ge 70 }).Count
    $medium = @($script:Evidence | Where-Object { $_.Confidence -ge 40 -and $_.Confidence -lt 70 }).Count
    $low = @($script:Evidence | Where-Object { $_.Confidence -lt 40 }).Count
    $sourceSummary = Get-DiscordSourceSummary
    $highest = 0
    if ($visibleEvidence.Count -gt 0) {
        $highest = ($visibleEvidence | Select-Object -First 1).Confidence
    }

    $fields = New-Object System.Collections.Generic.List[object]
    $fields.Add(@{
        name = "Resumo"
        value = "Alta: **$high** | Media: **$medium** | Contexto/baixa: **$low**`nJanela analisada: **$LookbackHours hora(s)**`nGerado: $($script:RunStamp)"
        inline = $false
    })
    $fields.Add(@{
        name = "Cobertura"
        value = "Categorias: $($sourceSummary.Categories)`nFontes: $($sourceSummary.Sources)"
        inline = $false
    })
    $attachmentNames = @($script:DiscordAttachments | Select-Object -ExpandProperty FileName)
    if ($attachmentNames.Count -gt 0) {
        $fields.Add(@{
            name = "Arquivos anexados"
            value = (Limit-Text -Text (($attachmentNames | ForEach-Object { "- $_" }) -join "`n") -MaxLength 1000)
            inline = $false
        })
    }
    $fields.Add(@{
        name = "Criterio"
        value = "Score indica relevancia forense e precisa de revisao humana. Nao e prova automatica de cheat."
        inline = $false
    })

    $prioritizedEvidence = Get-DiverseDiscordEvidence -Evidence $visibleEvidence
    if ($prioritizedEvidence.Count -eq 0) {
        $fields.Add(@{
            name = "Achados priorizados"
            value = "Nenhum achado acima do limiar configurado. Revise os anexos para contexto completo."
            inline = $false
        })
    }

    $itemNumber = 1
    foreach ($evidence in $prioritizedEvidence) {
        $translation = Get-EvidenceTranslation $evidence
        $subject = $translation.Subject
        if (-not $subject) { $subject = "N/A" }

        $timeText = if ($evidence.Time) { [datetime]$evidence.Time } else { "N/A" }
        $reasonText = @($evidence.Reasons | Select-Object -First 3) -join "; "
        $priority = Get-DiscordEvidencePriority $evidence
        $value = "**Score:** $($evidence.Confidence) | **Prioridade:** $priority | **Severidade:** $($translation.Severity)`n**Quando:** $timeText`n**Alvo:** $(Limit-Text -Text $subject -MaxLength 220)`n**Leitura:** $($translation.Translation)`n**Acao:** $($translation.OperatorAction)"
        if ($reasonText) {
            $value += "`n**Motivos:** $reasonText"
        }

        $fields.Add(@{
            name = (Limit-Text -Text "$itemNumber. $($evidence.Category) / $($evidence.Source)" -MaxLength 250)
            value = (Limit-Text -Text $value -MaxLength 1000)
            inline = $false
        })
        $itemNumber++
    }

    $description = [string]$DiscordSubtitle
    if (-not $description) {
        $description = "TraceUSB generated a local forensic report."
    }

    $embed = @{
        title = [string]$DiscordTitle
        description = (Limit-Text -Text $description -MaxLength 350)
        color = [int](Get-DiscordColor -HighestConfidence $highest)
        fields = @($fields.ToArray())
        footer = @{
            text = "TraceUSB local forensic analyzer"
        }
        timestamp = (Get-Date).ToUniversalTime().ToString("o")
    }

    return @{
        username = $DiscordUsername
        embeds = @($embed)
    }
}

function Write-DiscordPreview {
    param($Payload)

    if (-not $DiscordPreviewPath) { return }

    $previewFullPath = $DiscordPreviewPath
    if (-not [System.IO.Path]::IsPathRooted($previewFullPath)) {
        $previewFullPath = Join-Path $script:OutputDirectory $previewFullPath
    }

    $previewExtension = [System.IO.Path]::GetExtension($previewFullPath)
    if (-not $previewExtension) {
        $previewFullPath = Join-Path $previewFullPath "discord_preview_$($script:ArtifactSuffix).html"
    }
    else {
        $previewDirectory = Split-Path -Parent $previewFullPath
        $previewBaseName = [System.IO.Path]::GetFileNameWithoutExtension($previewFullPath)
        if ($previewBaseName -notmatch '\d{8}_\d{6}') {
            $previewFullPath = Join-Path $previewDirectory "$($previewBaseName)_$($script:ArtifactSuffix)$previewExtension"
        }
    }

    $previewDir = Split-Path -Parent $previewFullPath
    if ($previewDir -and -not (Test-Path -LiteralPath $previewDir)) {
        New-Item -ItemType Directory -Path $previewDir -Force | Out-Null
    }

    $embed = $Payload.embeds[0]
    $colorHex = "#{0:X6}" -f [int]$embed.color
    $encodedTitle = [System.Net.WebUtility]::HtmlEncode([string]$embed.title)
    $encodedDescription = [System.Net.WebUtility]::HtmlEncode([string]$embed.description)
    $fieldHtml = New-Object System.Collections.Generic.List[string]

    foreach ($field in $embed.fields) {
        $fieldName = [System.Net.WebUtility]::HtmlEncode([string]$field.name)
        $fieldValue = [System.Net.WebUtility]::HtmlEncode([string]$field.value) -replace "`r?`n", "<br>"
        $fieldHtml.Add("<div class='field'><div class='field-name'>$fieldName</div><div class='field-value'>$fieldValue</div></div>")
    }

    $attachmentHtml = New-Object System.Collections.Generic.List[string]
    foreach ($attachment in $script:DiscordAttachments) {
        $attachmentName = [System.Net.WebUtility]::HtmlEncode([string]$attachment.FileName)
        $attachmentBytes = [Text.Encoding]::UTF8.GetByteCount([string]$attachment.Content)
        $attachmentHtml.Add("<li>$attachmentName <span class='bytes'>($attachmentBytes bytes)</span></li>")
    }

    $html = @"
<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<title>TraceUSB Discord Preview</title>
<style>
body { background:#313338; color:#dbdee1; font-family:Segoe UI, Arial, sans-serif; padding:24px; }
.message { max-width:760px; }
.username { color:#f2f3f5; font-weight:700; margin-bottom:8px; }
.embed { background:#2b2d31; border-left:5px solid $colorHex; border-radius:4px; padding:16px; box-shadow:0 1px 2px rgba(0,0,0,.25); }
.title { color:#f2f3f5; font-size:18px; font-weight:700; margin-bottom:8px; }
.description { color:#dbdee1; margin-bottom:14px; line-height:1.35; }
.field { margin-top:12px; }
.field-name { color:#f2f3f5; font-weight:700; margin-bottom:4px; }
.field-value { color:#dbdee1; line-height:1.35; white-space:normal; }
.attachments { margin-top:16px; border-top:1px solid #404249; padding-top:12px; }
.attachments-title { color:#f2f3f5; font-weight:700; margin-bottom:6px; }
.attachments ul { margin:0; padding-left:18px; }
.bytes { color:#949ba4; }
.footer { color:#949ba4; font-size:12px; margin-top:14px; }
</style>
</head>
<body>
<div class="message">
<div class="username">$([System.Net.WebUtility]::HtmlEncode([string]$Payload.username))</div>
<div class="embed">
<div class="title">$encodedTitle</div>
<div class="description">$encodedDescription</div>
$($fieldHtml -join "`n")
<div class="attachments">
<div class="attachments-title">Arquivos anexados no webhook</div>
<ul>
$($attachmentHtml -join "`n")
</ul>
</div>
<div class="footer">$([System.Net.WebUtility]::HtmlEncode([string]$embed.footer.text))</div>
</div>
</div>
</body>
</html>
"@

    Set-Content -LiteralPath $previewFullPath -Value $html -Encoding UTF8
}

function Convert-SecureStringToPlainText {
    param([Security.SecureString]$SecureString)

    if (-not $SecureString) { return $null }

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
}

function Save-DiscordWebhookSecret {
    if (-not $DiscordWebhookSecretPath) {
        throw "-DiscordWebhookSecretPath is required with -SaveDiscordWebhookSecret."
    }
    if (-not $DiscordWebhookUrl) {
        throw "-DiscordWebhookUrl is required with -SaveDiscordWebhookSecret."
    }

    $secretFullPath = $DiscordWebhookSecretPath
    if (-not [System.IO.Path]::IsPathRooted($secretFullPath)) {
        $secretFullPath = Join-Path $script:OutputDirectory $secretFullPath
    }

    $secretDir = Split-Path -Parent $secretFullPath
    if ($secretDir -and -not (Test-Path -LiteralPath $secretDir)) {
        New-Item -ItemType Directory -Path $secretDir -Force | Out-Null
    }

    $secure = ConvertTo-SecureString -String $DiscordWebhookUrl -AsPlainText -Force
    $encrypted = $secure | ConvertFrom-SecureString
    Set-Content -LiteralPath $secretFullPath -Value $encrypted -Encoding UTF8

    Write-Host "Discord webhook secret saved with Windows DPAPI: $secretFullPath"
    Write-Host "This file can only be decrypted by the same Windows user profile on this machine."
}

function Get-DiscordWebhookUrl {
    if ($DiscordWebhookUrl) {
        return $DiscordWebhookUrl
    }

    if ($DiscordWebhookSecretPath) {
        $secretFullPath = $DiscordWebhookSecretPath
        if (-not [System.IO.Path]::IsPathRooted($secretFullPath)) {
            $secretFullPath = Join-Path $script:OutputDirectory $secretFullPath
        }

        if (Test-Path -LiteralPath $secretFullPath) {
            try {
                $encrypted = (Get-Content -Raw -LiteralPath $secretFullPath).Trim()
                $secure = $encrypted | ConvertTo-SecureString
                $plain = Convert-SecureStringToPlainText -SecureString $secure
                if ($plain) { return $plain }
            }
            catch {
                $script:Report.Add("")
                $script:Report.Add("Discord webhook secret could not be decrypted: $($_.Exception.Message)")
            }
        }
        else {
            $script:Report.Add("")
            $script:Report.Add("Discord webhook secret file not found: $secretFullPath")
        }
    }

    if ($DiscordWebhookEnvVar) {
        if ($DiscordWebhookEnvVar -match '^https://') {
            return $DiscordWebhookEnvVar
        }

        try {
            $envValue = [Environment]::GetEnvironmentVariable($DiscordWebhookEnvVar, "Process")
            if (-not $envValue) {
                $envValue = [Environment]::GetEnvironmentVariable($DiscordWebhookEnvVar, "User")
            }
            if (-not $envValue) {
                $envValue = [Environment]::GetEnvironmentVariable($DiscordWebhookEnvVar, "Machine")
            }
            if ($envValue) { return $envValue }
        }
        catch {}
    }

    return $null
}

function Send-DiscordWebhook {
    param($Payload)

    if (-not $EnableDiscordWebhook) {
        $script:DiscordStatus = "disabled"
        Write-RunLog "Discord webhook disabled."
        return
    }

    $resolvedWebhookUrl = Get-DiscordWebhookUrl

    if (-not $resolvedWebhookUrl) {
        $script:DiscordStatus = "skipped_no_webhook"
        $script:Report.Add("")
        $script:Report.Add("Discord webhook skipped: no URL, DPAPI secret, or environment variable was available.")
        Write-RunLog "Discord webhook skipped: no webhook URL was available."
        return
    }

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }
    catch {
        Write-RunLog "Could not force TLS 1.2: $($_.Exception.Message)"
    }

    $payloadJson = $Payload | ConvertTo-Json -Depth 10
    $attachmentCount = $script:DiscordAttachments.Count
    $script:DiscordAttachmentCount = $attachmentCount
    Write-RunLog "Discord send starting with $attachmentCount attachment(s), timeout $DiscordTimeoutSeconds second(s)."

    if ($attachmentCount -eq 0) {
        $jsonClient = $null
        $jsonContent = $null
        try {
            Add-Type -AssemblyName System.Net.Http
            $jsonClient = New-Object System.Net.Http.HttpClient
            $jsonClient.Timeout = [TimeSpan]::FromSeconds($DiscordTimeoutSeconds)
            $jsonContent = New-Object System.Net.Http.StringContent($payloadJson, [Text.Encoding]::UTF8, "application/json")
            $jsonResponse = $jsonClient.PostAsync($resolvedWebhookUrl, $jsonContent).GetAwaiter().GetResult()
            if (-not $jsonResponse.IsSuccessStatusCode) {
                $responseText = $jsonResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                throw "Discord returned HTTP $([int]$jsonResponse.StatusCode): $responseText"
            }

            $script:DiscordStatus = "sent_embed_only"
            $script:Report.Add("")
            $script:Report.Add("Discord webhook sent without attachments.")
            Write-RunLog "Discord webhook sent without attachments."
            return
        }
        catch {
            $script:DiscordStatus = "failed"
            $script:Report.Add("")
            $script:Report.Add("Discord webhook failed: $($_.Exception.Message)")
            Write-RunLog "Discord webhook failed: $($_.Exception.Message)"
            return
        }
        finally {
            if ($jsonContent) { $jsonContent.Dispose() }
            if ($jsonClient) { $jsonClient.Dispose() }
        }
    }

    $multipartError = $null
    try {
        Add-Type -AssemblyName System.Net.Http

        $client = New-Object System.Net.Http.HttpClient
        $client.Timeout = [TimeSpan]::FromSeconds($DiscordTimeoutSeconds)
        $multipart = New-Object System.Net.Http.MultipartFormDataContent

        $payloadContent = New-Object System.Net.Http.StringContent($payloadJson, [Text.Encoding]::UTF8, "application/json")
        $multipart.Add($payloadContent, "payload_json")

        $index = 0
        foreach ($attachment in $script:DiscordAttachments) {
            if (-not $attachment -or -not $attachment.FileName) { continue }

            $bytes = [Text.Encoding]::UTF8.GetBytes([string]$attachment.Content)
            $fileContent = New-Object -TypeName System.Net.Http.ByteArrayContent -ArgumentList (,$bytes)
            if ($attachment.ContentType) {
                $fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse([string]$attachment.ContentType)
            }
            $multipart.Add($fileContent, "files[$index]", [string]$attachment.FileName)
            $index++
        }

        $response = $client.PostAsync($resolvedWebhookUrl, $multipart).GetAwaiter().GetResult()
        if (-not $response.IsSuccessStatusCode) {
            $responseText = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            throw "Discord returned HTTP $([int]$response.StatusCode): $responseText"
        }

        $script:DiscordStatus = "sent_with_attachments"
        $script:Report.Add("")
        $script:Report.Add("Discord webhook sent with $index attachment(s).")
        Write-RunLog "Discord webhook sent with $index attachment(s)."
        return
    }
    catch {
        $multipartError = $_.Exception.Message
        $script:Report.Add("")
        $script:Report.Add("Discord webhook multipart failed: $multipartError")
        Write-RunLog "Discord multipart send failed: $multipartError"
    }
    finally {
        if ($multipart) { $multipart.Dispose() }
        if ($client) { $client.Dispose() }
    }

    $fallbackClient = $null
    $fallbackContent = $null
    try {
        Add-Type -AssemblyName System.Net.Http
        $fallbackClient = New-Object System.Net.Http.HttpClient
        $fallbackClient.Timeout = [TimeSpan]::FromSeconds($DiscordTimeoutSeconds)
        $fallbackContent = New-Object System.Net.Http.StringContent($payloadJson, [Text.Encoding]::UTF8, "application/json")
        $fallbackResponse = $fallbackClient.PostAsync($resolvedWebhookUrl, $fallbackContent).GetAwaiter().GetResult()
        if (-not $fallbackResponse.IsSuccessStatusCode) {
            $fallbackText = $fallbackResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            throw "Discord returned HTTP $([int]$fallbackResponse.StatusCode): $fallbackText"
        }

        $script:DiscordStatus = "sent_embed_only_after_attachment_failure"
        $script:Report.Add("Discord webhook fallback sent embed only; attachments were not delivered.")
        Write-RunLog "Discord fallback sent embed only after attachment failure."
    }
    catch {
        $script:DiscordStatus = "failed"
        $script:Report.Add("Discord webhook fallback failed: $($_.Exception.Message)")
        Write-RunLog "Discord fallback failed: $($_.Exception.Message)"
    }
    finally {
        if ($fallbackContent) { $fallbackContent.Dispose() }
        if ($fallbackClient) { $fallbackClient.Dispose() }
    }
}

function Build-DiscordArtifacts {
    $script:DiscordAttachments.Clear()
    Write-RunLog "Building Discord artifacts."

    $historyLines = $null
    if ($EnableBrowserHistoryScan) {
        Write-RunLog "Filtered browser-history scan starting."
        $historyLines = Get-FilteredHistoryLines
        Write-RunLog "Filtered browser-history scan finished with $($script:FilteredHistoryHits.Count) hit(s)."
    }

    $evidenceLines = Get-EvidenceJsonLines
    $translationLines = Get-TranslationSuggestionLines

    Add-DiscordAttachment -FileName $script:EvidenceFileName -Lines $evidenceLines -ContentType "application/x-ndjson; charset=utf-8" -LocalPath $script:EvidencePath
    Add-DiscordAttachment -FileName $script:TranslationsFileName -Lines $translationLines -ContentType "text/plain; charset=utf-8" -LocalPath $script:TranslationsPath

    if ($EnableBrowserHistoryScan) {
        Add-DiscordAttachment -FileName $script:FilteredHistoryFileName -Lines $historyLines -ContentType "text/plain; charset=utf-8" -LocalPath $script:FilteredHistoryPath
    }
    $script:DiscordAttachmentCount = $script:DiscordAttachments.Count
    Write-RunLog "Discord artifacts built: $($script:DiscordAttachments.Count) attachment(s)."
}

function Publish-DiscordArtifacts {
    if (-not $DiscordPreviewPath -and -not $EnableDiscordWebhook) { return }

    $payload = Build-DiscordEmbedPayload
    Write-DiscordPreview -Payload $payload
    Send-DiscordWebhook -Payload $payload
}

function Write-Outputs {
    Ensure-OutputDirectory
    Write-RunLog "Writing outputs to $script:OutputDirectory."
    Build-DiscordArtifacts
    Write-Summary

    [System.IO.File]::WriteAllLines($script:ReportPath, $script:Report, [System.Text.Encoding]::UTF8)

    $timelineLines = @(
        $script:Timeline |
            Where-Object { $_.Time } |
            Sort-Object Time |
            ForEach-Object {
                "$($_.Time) | [$($_.Category)] | $($_.Event) | $($_.Details)"
            }
    )
    Set-Content -LiteralPath $script:TimelinePath -Value $timelineLines -Encoding UTF8
    Write-RunLog "Local report written: $script:ReportPath"
    Write-RunLog "Local timeline written: $script:TimelinePath"

    Add-DiscordAttachment -FileName $script:ReportFileName -Lines $script:Report -ContentType "text/plain; charset=utf-8"
    Add-DiscordAttachment -FileName $script:TimelineFileName -Lines $timelineLines -ContentType "text/plain; charset=utf-8"
    $script:DiscordAttachmentCount = $script:DiscordAttachments.Count
    Write-RunLog "Local report and timeline added to Discord attachments."
    Write-RunLogFile

    Publish-DiscordArtifacts

    $script:Report.Add("")
    $script:Report.Add("==== Delivery ====")
    $script:Report.Add("")
    $script:Report.Add("Discord status: $script:DiscordStatus")
    $script:Report.Add("Discord attachments prepared: $script:DiscordAttachmentCount")
    $script:Report.Add("Run log: $script:RunLogPath")
    [System.IO.File]::WriteAllLines($script:ReportPath, $script:Report, [System.Text.Encoding]::UTF8)
    Write-RunLog "Final Discord status: $script:DiscordStatus"
    Write-RunLogFile
}

function Enable-ProcessAuditPolicy {
    if (-not $EnableAuditPolicy) { return }

    $isAdmin = (
        New-Object Security.Principal.WindowsPrincipal(
            [Security.Principal.WindowsIdentity]::GetCurrent()
        )
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Add-Evidence -Time (Get-Date) -Category "Operational" -Source "AuditPolicy" -Confidence 20 -Reasons @("Audit policy requested without administrator rights") -Details "Could not enable Process Creation auditing" | Out-Null
        return
    }

    try {
        auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
        Add-Evidence -Time (Get-Date) -Category "Operational" -Source "AuditPolicy" -Confidence 20 -Reasons @("Operator enabled Process Creation auditing") -Details "Process Creation auditing enabled" | Out-Null
    }
    catch {
        Add-Evidence -Time (Get-Date) -Category "Operational" -Source "AuditPolicy" -Confidence 20 -Reasons @("Audit policy change failed") -Details $_.Exception.Message | Out-Null
    }
}

function Invoke-DiscordSelfTest {
    Ensure-OutputDirectory
    Write-RunLog "Discord self-test started."
    $script:DiscordAttachments.Clear()
    Add-DiscordAttachment `
        -FileName "discord_selftest_$($script:ArtifactSuffix).txt" `
        -Lines @(
            "TraceUSB Discord self-test",
            "Generated: $(Get-Date)",
            "Purpose: validates Discord multipart upload without collecting forensic data."
        ) `
        -ContentType "text/plain; charset=utf-8"

    $payload = @{
        username = $DiscordUsername
        embeds = @(
            @{
                title = "TraceUSB webhook self-test"
                description = "Teste de conectividade do webhook com anexo multipart. Nenhuma coleta forense foi executada."
                color = [int](Convert-HexColorToInt -Hex $DiscordInfoColor -Fallback "4E7DD9")
                fields = @(
                    @{
                        name = "Origem"
                        value = "Execucao local do TraceUSB em modo DiscordSelfTest."
                        inline = $false
                    },
                    @{
                        name = "Janela"
                        value = "Timeout configurado: $DiscordTimeoutSeconds segundo(s)."
                        inline = $false
                    },
                    @{
                        name = "Anexo"
                        value = "Inclui um arquivo de autoteste sem dados forenses para validar upload multipart."
                        inline = $false
                    }
                )
                footer = @{
                    text = "TraceUSB local forensic analyzer"
                }
                timestamp = (Get-Date).ToUniversalTime().ToString("o")
            }
        )
    }

    Write-DiscordPreview -Payload $payload
    Send-DiscordWebhook -Payload $payload
    Write-RunLog "Discord self-test finished with status $script:DiscordStatus."
    Write-RunLogFile
    Write-ConsoleSummary
}

Write-RunLog "TraceUSB started. LookbackHours=$LookbackHours OutputDirectory=$script:OutputDirectory."

if ($SaveDiscordWebhookSecret) {
    Ensure-OutputDirectory
    Write-RunLog "Saving Discord webhook secret with DPAPI."
    Save-DiscordWebhookSecret
    Write-RunLog "Discord webhook secret save flow finished."
    Write-RunLogFile
    return
}

if ($DiscordSelfTest) {
    Invoke-DiscordSelfTest
    return
}

Enable-ProcessAuditPolicy
Collect-LogClearingEvents
Collect-UsbEvents
Collect-DefenderEvents
Collect-ProcessEvents
Collect-PrefetchEvents
Collect-BamEvents
Collect-ServiceEvents
Collect-RuntimeContext
Complete-Correlation
Invoke-ScreenshotTrigger
Write-Outputs

if (-not $NoOpen) {
    Start-Process notepad.exe $script:ReportPath
    Start-Process notepad.exe $script:TimelinePath
}

Write-ConsoleSummary
