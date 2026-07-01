[CmdletBinding()]
param(
    [ValidateRange(1, 720)]
    [int]$LookbackHours = 24,

    [datetime]$GameSessionDate = (Get-Date).Date,

    [string]$OutputDirectory = [Environment]::GetFolderPath("Desktop"),

    [switch]$NoOpen,

    [switch]$SaveLocalArtifacts,

    [switch]$EnableAuditPolicy,

    [switch]$EnableScreenshotTrigger,

    [switch]$KeepTriggeredOverlayScreenshot,

    [switch]$DisableScreenshotWindowFocus,

    [ValidateRange(0, 60)]
    [int]$ScreenshotFocusWaitSeconds = 3,

    [ValidateRange(1, 60)]
    [int]$ScreenshotPostTriggerWaitSeconds = 8,

    [switch]$IncludeLowConfidence,

    [switch]$EnableDiscordWebhook = $true,

    [switch]$DisableDiscordWebhook,

    [string]$DiscordWebhookUrl,

    [string]$DiscordWebhookSecretPath,

    [string]$DiscordWebhookEnvVar = "TRACEUSB_DISCORD_WEBHOOK_URL",

    [string]$DiscordRelayUrl = "https://long-dust-248e.devoxygenwp.workers.dev/",

    [string]$DiscordRelayEnvVar = "TRACEUSB_DISCORD_RELAY_URL",

    [string]$DiscordRelayToken,

    [string]$DiscordRelayTokenEnvVar = "TRACEUSB_DISCORD_RELAY_TOKEN",

    [switch]$SaveDiscordWebhookSecret,

    [switch]$DiscordDebug,

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

    [ValidateRange(1048576, 50000000)]
    [int]$DiscordMaxPayloadBytes = 24000000,

    [ValidateRange(1, 10)]
    [int]$DiscordMaxFilesPerMessage = 10,

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

    [switch]$EnableNetworkAnomalyScan = $true,

    [switch]$DisableNetworkAnomalyScan,

    [switch]$DisableGameSessionAnalysis,

    [switch]$EnableCaseBundle = $true,

    [switch]$DisableCaseBundle,

    [string]$SQLiteCliPath,

    [string]$PortableSQLitePath,

    [string]$PortableSQLiteDownloadUrl = "https://www.sqlite.org/2026/sqlite-tools-win-x64-3530300.zip",

    [string]$PortableSQLiteDownloadSha256 = "C90FE36442CF573E8A19B3E8733D121622B8E2D5A0C47CBDA97AEBA9517D1C45",

    [string]$PortableSQLiteExeSha256 = "0BF6020E303A1A49DD576BBE259F8C2A05DB689408A2F1F968714F5CF63714AF",

    [switch]$DisablePortableSQLiteDownload,

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

if ($DisableNetworkAnomalyScan) {
    $EnableNetworkAnomalyScan = $false
}

if ($DisableCaseBundle) {
    $EnableCaseBundle = $false
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
$script:GameSessionsFileName = "game_sessions_$($script:ArtifactSuffix).txt"
$script:NetworkSnapshotFileName = "network_snapshot_$($script:ArtifactSuffix).txt"
$script:SystemContextFileName = "system_context_$($script:ArtifactSuffix).txt"
$script:IntegrityHashesFileName = "integrity_hashes_$($script:ArtifactSuffix).txt"
$script:CaseBundleFileName = "TraceUSB_case_$($script:ArtifactSuffix).zip"
$script:RunLogFileName = "traceusb_run_$($script:ArtifactSuffix).log"
$script:DiscordDebugPayloadFileName = "discord_payload_$($script:ArtifactSuffix).json"
$script:DiscordDebugManifestFileName = "discord_attachments_$($script:ArtifactSuffix).txt"
$script:ReportPath = Join-Path $script:OutputDirectory $script:ReportFileName
$script:TimelinePath = Join-Path $script:OutputDirectory $script:TimelineFileName
$script:EvidencePath = Join-Path $script:OutputDirectory $script:EvidenceFileName
$script:TranslationsPath = Join-Path $script:OutputDirectory $script:TranslationsFileName
$script:FilteredHistoryPath = Join-Path $script:OutputDirectory $script:FilteredHistoryFileName
$script:GameSessionsPath = Join-Path $script:OutputDirectory $script:GameSessionsFileName
$script:NetworkSnapshotPath = Join-Path $script:OutputDirectory $script:NetworkSnapshotFileName
$script:SystemContextPath = Join-Path $script:OutputDirectory $script:SystemContextFileName
$script:IntegrityHashesPath = Join-Path $script:OutputDirectory $script:IntegrityHashesFileName
$script:CaseBundlePath = Join-Path $script:OutputDirectory $script:CaseBundleFileName
$script:RunLogPath = Join-Path $script:OutputDirectory $script:RunLogFileName
$script:DiscordDebugPayloadPath = Join-Path $script:OutputDirectory $script:DiscordDebugPayloadFileName
$script:DiscordDebugManifestPath = Join-Path $script:OutputDirectory $script:DiscordDebugManifestFileName

$script:Report = New-Object System.Collections.Generic.List[string]
$script:Timeline = New-Object System.Collections.Generic.List[object]
$script:Evidence = New-Object System.Collections.Generic.List[object]
$script:FilteredHistoryHits = New-Object System.Collections.Generic.List[object]
$script:GameSessions = New-Object System.Collections.ArrayList
$script:GameSessionLines = New-Object System.Collections.Generic.List[string]
$script:NetworkSnapshot = New-Object System.Collections.Generic.List[string]
$script:SystemContext = New-Object System.Collections.Generic.List[string]
$script:DiscordAttachments = New-Object System.Collections.ArrayList
$script:RunLog = New-Object System.Collections.Generic.List[string]
$script:DiscordStatus = if ($EnableDiscordWebhook) { "not_attempted" } else { "disabled" }
$script:DiscordAttachmentCount = 0
$script:DiscordLastError = $null
$script:ScreenshotCapturePath = $null
$script:ScreenshotCaptureFileName = $null
$script:ScreenshotCaptureContentType = $null
$script:PortableSQLiteTempRoot = $null
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
    if (-not $SaveLocalArtifacts -and -not $DiscordDebug) { return }
    Ensure-OutputDirectory
    Set-Content -LiteralPath $script:RunLogPath -Value $script:RunLog -Encoding UTF8
}

function Write-ConsoleSummary {
    Write-Host ""
    Write-Host "TraceUSB concluido."
    if ($SaveLocalArtifacts -and [System.IO.File]::Exists($script:ReportPath)) {
        Write-Host "Analise: $script:ReportPath"
    }
    else {
        Write-Host "Arquivos locais: nao salvos (envio somente via Discord)"
    }
    if ($SaveLocalArtifacts -and [System.IO.File]::Exists($script:TimelinePath)) {
        Write-Host "Timeline: $script:TimelinePath"
    }
    if ($SaveLocalArtifacts -and [System.IO.File]::Exists($script:RunLogPath)) {
        Write-Host "Run log: $script:RunLogPath"
    }
    Write-Host "Discord: $script:DiscordStatus"
    if ($script:DiscordLastError) {
        Write-Host "Discord erro: $script:DiscordLastError"
    }
    if ($SaveLocalArtifacts -and [System.IO.File]::Exists($script:CaseBundlePath)) {
        Write-Host "Case bundle: $script:CaseBundlePath"
    }
}

function Add-Line {
    param(
        [System.Collections.Generic.List[string]]$List,
        [string]$Line = ""
    )

    $List.Add($Line)
}

function Convert-TextToUtf8Bytes {
    param(
        [string]$Text,
        [switch]$Bom
    )

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $body = $utf8NoBom.GetBytes([string]$Text)
    if (-not $Bom) { return [byte[]]$body }

    $utf8Bom = New-Object System.Text.UTF8Encoding($true)
    $preamble = $utf8Bom.GetPreamble()
    $bytes = New-Object byte[] ($preamble.Length + $body.Length)
    if ($preamble.Length -gt 0) {
        [Buffer]::BlockCopy($preamble, 0, $bytes, 0, $preamble.Length)
    }
    [Buffer]::BlockCopy($body, 0, $bytes, $preamble.Length, $body.Length)
    return [byte[]]$bytes
}

function Test-DiscordAttachmentNeedsBom {
    param([string]$ContentType)

    return ([string]$ContentType -match '^text/plain\b')
}

function Test-IsAdministrator {
    try {
        return (
            New-Object Security.Principal.WindowsPrincipal(
                [Security.Principal.WindowsIdentity]::GetCurrent()
            )
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
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

function Convert-EventProcessId {
    param([string]$Value)

    if (-not $Value) { return $null }

    $clean = ([string]$Value).Trim()
    try {
        if ($clean -match '^0x[0-9a-fA-F]+$') {
            return [Convert]::ToInt32($clean.Substring(2), 16)
        }
        if ($clean -match '^\d+$') {
            return [int]$clean
        }
    }
    catch {}

    return $null
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
    $processId = Convert-EventProcessId (Get-EventDataValue -Map $map -Names @("NewProcessId", "ProcessId"))

    $cleanPath = Normalize-ExecutablePath $path
    $cleanParent = Normalize-ExecutablePath $parentPath
    $exeName = Get-ExeNameFromPath -Path $cleanPath -FallbackName $null

    return [PSCustomObject]@{
        Path       = $cleanPath
        ParentPath = $cleanParent
        ExeName    = $exeName
        UserSid    = $userSid
        ProcessId  = $processId
    }
}

function Get-ProcessTerminationData {
    param($Event)

    $map = Get-EventDataMap $Event
    $message = [string]$Event.Message

    $path = Get-EventDataValue -Map $map -Names @("ProcessName", "NewProcessName")
    if (-not $path) {
        $path = Get-MessageValue -Message $message -Patterns @(
            'Nome do Processo:\s+(.+)',
            'Process Name:\s+(.+)'
        )
    }

    $userSid = Get-EventDataValue -Map $map -Names @("SubjectUserSid", "TargetUserSid")
    $processId = Convert-EventProcessId (Get-EventDataValue -Map $map -Names @("ProcessId", "NewProcessId"))

    $cleanPath = Normalize-ExecutablePath $path
    $exeName = Get-ExeNameFromPath -Path $cleanPath -FallbackName $null

    return [PSCustomObject]@{
        Path      = $cleanPath
        ExeName   = $exeName
        UserSid   = $userSid
        ProcessId = $processId
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

function Format-TraceDuration {
    param([Nullable[TimeSpan]]$Duration)

    if (-not $Duration -or $Duration.Value.TotalSeconds -lt 0) { return "Unknown" }

    $span = $Duration.Value
    $parts = New-Object System.Collections.Generic.List[string]
    if ($span.Days -gt 0) { $parts.Add("$($span.Days)d") }
    if ($span.Hours -gt 0) { $parts.Add("$($span.Hours)h") }
    if ($span.Minutes -gt 0) { $parts.Add("$($span.Minutes)m") }
    if ($parts.Count -eq 0 -or $span.Seconds -gt 0) { $parts.Add("$($span.Seconds)s") }
    return ($parts -join " ")
}

function Get-GameProcessRole {
    param(
        [string]$ExeName,
        [string]$Path,
        [string]$ServiceName
    )

    $text = (@($ExeName, $Path, $ServiceName) | Where-Object { $_ }) -join " "
    if (-not $text) { return $null }

    if ($text -match '(?i)\bBEService(_x64)?(\.exe)?\b|BattlEye Service|\\BattlEye\\') {
        return "BattlEye Service"
    }
    if ($text -match '(?i)\bSCUM_Launcher\.exe\b') {
        return "SCUM Launcher / BattlEye Bootstrap"
    }
    if ($text -match '(?i)\bSCUM(-Win64-Shipping)?\.exe\b') {
        return "SCUM Game"
    }
    if ($ExeName -and (Test-NameMatchesAny -Name $ExeName -Patterns $GameProcessPatterns)) {
        return "SCUM/BattlEye Context"
    }

    return $null
}

function Get-GameSessionWindow {
    $start = $GameSessionDate.Date
    return [PSCustomObject]@{
        Start = $start
        End   = $start.AddDays(1)
    }
}

function Get-ProcessStartTimeSafe {
    param($Process)

    try {
        if ($Process.StartTime) { return [datetime]$Process.StartTime }
    }
    catch {}

    return $null
}

function Get-ProcessPathSafe {
    param($Process)

    try {
        if ($Process.Path) { return (Normalize-ExecutablePath $Process.Path) }
    }
    catch {}

    try {
        if ($Process.MainModule -and $Process.MainModule.FileName) {
            return (Normalize-ExecutablePath $Process.MainModule.FileName)
        }
    }
    catch {}

    return $null
}

function New-GameSessionPoint {
    param(
        [int]$Index,
        [datetime]$Time,
        [string]$Role,
        [string]$ProcessName,
        [Nullable[int]]$ProcessId,
        [string]$Path,
        [string]$ServiceName,
        [string]$Source,
        [Nullable[int]]$EventId
    )

    return [PSCustomObject]@{
        Index       = $Index
        Time        = $Time
        Role        = $Role
        ProcessName = $ProcessName
        ProcessId   = $ProcessId
        Path        = $Path
        ServiceName = $ServiceName
        Source      = $Source
        EventId     = $EventId
    }
}

function Test-GameSessionPointMatch {
    param(
        $Start,
        $Stop
    )

    if (-not $Start -or -not $Stop) { return $false }
    if ($Start.Role -ne $Stop.Role) { return $false }
    if ($Stop.Time -lt $Start.Time) { return $false }

    if ($Start.ProcessId -and $Stop.ProcessId -and $Start.ProcessId -eq $Stop.ProcessId) {
        return $true
    }

    if ($Start.Path -and $Stop.Path -and $Start.Path -ieq $Stop.Path) {
        return $true
    }

    if ($Start.ServiceName -and $Stop.ServiceName -and $Start.ServiceName -ieq $Stop.ServiceName) {
        return $true
    }

    if ($Start.ProcessName -and $Stop.ProcessName -and $Start.ProcessName -ieq $Stop.ProcessName) {
        return $true
    }

    return $false
}

function Add-GameSessionRecord {
    param(
        [string]$Role,
        [string]$Status,
        [AllowNull()]$Started,
        [AllowNull()]$Ended,
        [AllowNull()]$ObservedUntil,
        [string]$ProcessName,
        [Nullable[int]]$ProcessId,
        [string]$Path,
        [string]$ServiceName,
        [string]$StartSource,
        [string]$EndSource,
        [string]$Quality,
        [string[]]$Notes
    )

    $duration = $null
    if ($Started -and $Ended) {
        $duration = [datetime]$Ended - [datetime]$Started
    }
    elseif ($Started -and $ObservedUntil) {
        $duration = [datetime]$ObservedUntil - [datetime]$Started
    }

    $session = [PSCustomObject]@{
        Role          = $Role
        Status        = $Status
        Started       = $Started
        Ended         = $Ended
        ObservedUntil = $ObservedUntil
        Duration      = $duration
        ProcessName   = $ProcessName
        ProcessId     = $ProcessId
        Path          = $Path
        ServiceName   = $ServiceName
        StartSource   = $StartSource
        EndSource     = $EndSource
        Quality       = $Quality
        Notes         = @($Notes | Where-Object { $_ })
    }

    $script:GameSessions.Add($session) | Out-Null

    $confidence = if ($Started -and $Ended) { 40 } elseif ($Started -or $ObservedUntil) { 30 } else { 20 }
    $evidenceTime = if ($Started) { $Started } elseif ($Ended) { $Ended } else { Get-Date }
    $source = if ($StartSource) { $StartSource } elseif ($EndSource) { $EndSource } else { "GameSessionAnalysis" }
    $details = "$Role | Status=$Status"
    if ($ProcessName) { $details += " | Process=$ProcessName" }
    if ($ProcessId) { $details += " | PID=$ProcessId" }
    if ($Started) { $details += " | Started=$Started" }
    if ($Ended) { $details += " | Ended=$Ended" }
    if ($duration) { $details += " | Duration=$(Format-TraceDuration -Duration $duration)" }

    Add-Evidence -Time $evidenceTime -Category "GameSession" -Source $source -ExeName $ProcessName -Path $Path -Confidence $confidence -Reasons @("SCUM/BattlEye session activity reconstructed", $Quality) -Details $details | Out-Null

    if ($Started) {
        $script:GameSessionTimes.Add([datetime]$Started)
    }
    if ($Ended) {
        $script:GameSessionTimes.Add([datetime]$Ended)
        Add-TimelineEvent -Time $Ended -Category "GameSession" -Event "$Role ended" -Details $details
    }
}

function Get-ServiceStateData {
    param($Event)

    $map = Get-EventDataMap $Event
    $message = [string]$Event.Message

    $serviceName = Get-EventDataValue -Map $map -Names @("ServiceName", "param1")
    $state = Get-EventDataValue -Map $map -Names @("State", "param2")

    if (-not $serviceName -or -not $state) {
        $match = [regex]::Match($message, 'The\s+(.+?)\s+service entered the\s+(.+?)\s+state', "IgnoreCase")
        if (-not $match.Success) {
            $match = [regex]::Match($message, 'O servico\s+(.+?)\s+entrou no estado\s+(.+?)(\.|$)', "IgnoreCase")
        }
        if (-not $match.Success) {
            $match = [regex]::Match($message, 'O serviço\s+(.+?)\s+entrou no estado\s+(.+?)(\.|$)', "IgnoreCase")
        }
        if ($match.Success) {
            if (-not $serviceName) { $serviceName = $match.Groups[1].Value.Trim() }
            if (-not $state) { $state = $match.Groups[2].Value.Trim() }
        }
    }

    return [PSCustomObject]@{
        ServiceName = $serviceName
        State       = $state
    }
}

function Test-ServiceStateRunning {
    param([string]$State)

    return ([string]$State -match '(?i)running|run|em execucao|em execução|iniciado')
}

function Test-ServiceStateStopped {
    param([string]$State)

    return ([string]$State -match '(?i)stopped|stop|parado')
}

function Find-GameSessionStop {
    param(
        $Start,
        [object[]]$Stops,
        [hashtable]$UsedStops
    )

    return @(
        $Stops |
            Where-Object { -not $UsedStops.ContainsKey([string]$_.Index) -and (Test-GameSessionPointMatch -Start $Start -Stop $_) } |
            Sort-Object Time |
            Select-Object -First 1
    ) | Select-Object -First 1
}

function Find-ExistingOpenGameSession {
    param(
        [string]$Role,
        [Nullable[int]]$ProcessId,
        [string]$ProcessName,
        [string]$Path
    )

    foreach ($session in @($script:GameSessions)) {
        if ($session.Role -ne $Role) { continue }
        if ($session.Ended) { continue }

        if ($ProcessId -and $session.ProcessId -and $ProcessId -eq $session.ProcessId) { return $session }
        if ($Path -and $session.Path -and $Path -ieq $session.Path) { return $session }
        if ($ProcessName -and $session.ProcessName -and $ProcessName -ieq $session.ProcessName) { return $session }
    }

    return $null
}

function Get-GameSessionLines {
    $lines = New-Object System.Collections.Generic.List[string]
    $window = Get-GameSessionWindow
    $lines.Add("TraceUSB SCUM/BattlEye session activity")
    $lines.Add("Generated: $(Get-Date)")
    $lines.Add("GameSessionDate: $($window.Start.ToString('yyyy-MM-dd'))")
    $lines.Add("Window: $($window.Start) to $($window.End)")
    $lines.Add("Purpose: reconstruct game/anti-cheat activity windows for correlation. This is context, not proof of cheating.")
    $lines.Add("")

    if ($DisableGameSessionAnalysis) {
        $lines.Add("Game session analysis disabled by -DisableGameSessionAnalysis.")
        return @($lines)
    }

    if ($script:GameSessions.Count -eq 0) {
        $lines.Add("No SCUM/BattlEye process or service sessions were reconstructed for the selected day.")
        $lines.Add("Possible reasons: game was not run, Security 4688/4689 auditing was unavailable, service lifecycle events were absent, or relevant logs rolled over.")
        return @($lines)
    }

    $sessionNumber = 1
    foreach ($session in @($script:GameSessions | Sort-Object Started, ObservedUntil, Ended)) {
        $lines.Add("Session: $sessionNumber")
        $lines.Add("Role: $($session.Role)")
        $lines.Add("Status: $($session.Status)")
        $lines.Add("Started: $(if ($session.Started) { $session.Started } else { 'Unknown' })")
        $lines.Add("Ended: $(if ($session.Ended) { $session.Ended } else { 'Unknown' })")
        if ($session.ObservedUntil) { $lines.Add("ObservedUntil: $($session.ObservedUntil)") }
        $lines.Add("Duration: $(Format-TraceDuration -Duration $session.Duration)")
        if ($session.ProcessName) { $lines.Add("Process: $($session.ProcessName)") }
        if ($session.ProcessId) { $lines.Add("PID: $($session.ProcessId)") }
        if ($session.ServiceName) { $lines.Add("Service: $($session.ServiceName)") }
        if ($session.Path) { $lines.Add("Path: $($session.Path)") }
        $lines.Add("StartSource: $(if ($session.StartSource) { $session.StartSource } else { 'Unknown' })")
        $lines.Add("EndSource: $(if ($session.EndSource) { $session.EndSource } else { 'Unknown' })")
        $lines.Add("Quality: $($session.Quality)")
        foreach ($note in @($session.Notes)) {
            $lines.Add("Note: $note")
        }
        $lines.Add("")
        $sessionNumber++
    }

    return @($lines)
}

function Collect-GameSessionActivity {
    Write-Section "SCUM / BATTLEYE SESSION ACTIVITY"

    if ($DisableGameSessionAnalysis) {
        $script:Report.Add("Game session analysis disabled.")
        $script:Report.Add("")
        $script:GameSessionLines.Clear()
        foreach ($line in Get-GameSessionLines) {
            $script:GameSessionLines.Add($line)
        }
        return
    }

    $window = Get-GameSessionWindow
    $script:Report.Add("Game session date: $($window.Start.ToString('yyyy-MM-dd'))")
    $script:Report.Add("Window: $($window.Start) to $($window.End)")
    $script:Report.Add("")

    $starts = New-Object System.Collections.ArrayList
    $stops = New-Object System.Collections.ArrayList
    $pointIndex = 0
    $terminationEventsAvailable = $false

    try {
        $events4688 = Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            Id        = 4688
            StartTime = $window.Start
            EndTime   = $window.End
        } -ErrorAction Stop

        foreach ($event in @($events4688 | Sort-Object TimeCreated)) {
            $data = Get-ProcessCreationData $event
            $role = Get-GameProcessRole -ExeName $data.ExeName -Path $data.Path
            if (-not $role) { continue }

            $starts.Add((New-GameSessionPoint -Index $pointIndex -Time $event.TimeCreated -Role $role -ProcessName $data.ExeName -ProcessId $data.ProcessId -Path $data.Path -Source "Security 4688" -EventId 4688)) | Out-Null
            $pointIndex++
        }
    }
    catch {
        $script:Report.Add("Could not read Security 4688 for game session analysis: $($_.Exception.Message)")
        $script:Report.Add("")
    }

    try {
        $events4689 = Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            Id        = 4689
            StartTime = $window.Start
            EndTime   = $window.End
        } -ErrorAction Stop

        foreach ($event in @($events4689 | Sort-Object TimeCreated)) {
            $data = Get-ProcessTerminationData $event
            $role = Get-GameProcessRole -ExeName $data.ExeName -Path $data.Path
            if (-not $role) { continue }

            $terminationEventsAvailable = $true
            $stops.Add((New-GameSessionPoint -Index $pointIndex -Time $event.TimeCreated -Role $role -ProcessName $data.ExeName -ProcessId $data.ProcessId -Path $data.Path -Source "Security 4689" -EventId 4689)) | Out-Null
            $pointIndex++
        }
    }
    catch {
        $script:Report.Add("Could not read Security 4689 process termination events. Close time may be unavailable unless process termination auditing was enabled.")
        $script:Report.Add("")
    }

    try {
        $serviceEvents = Get-WinEvent -FilterHashtable @{
            LogName   = "System"
            Id        = 7036
            StartTime = $window.Start
            EndTime   = $window.End
        } -ErrorAction SilentlyContinue

        foreach ($event in @($serviceEvents | Sort-Object TimeCreated)) {
            $data = Get-ServiceStateData $event
            $role = Get-GameProcessRole -ServiceName $data.ServiceName
            if (-not $role) { continue }

            if (Test-ServiceStateRunning -State $data.State) {
                $starts.Add((New-GameSessionPoint -Index $pointIndex -Time $event.TimeCreated -Role $role -ServiceName $data.ServiceName -Source "System 7036" -EventId 7036)) | Out-Null
                $pointIndex++
            }
            elseif (Test-ServiceStateStopped -State $data.State) {
                $stops.Add((New-GameSessionPoint -Index $pointIndex -Time $event.TimeCreated -Role $role -ServiceName $data.ServiceName -Source "System 7036" -EventId 7036)) | Out-Null
                $pointIndex++
            }
        }
    }
    catch {
        Write-RunLog "Game session service lifecycle collection failed: $($_.Exception.Message)"
    }

    $usedStops = @{}
    foreach ($start in @($starts | Sort-Object Time)) {
        $stop = Find-GameSessionStop -Start $start -Stops @($stops) -UsedStops $usedStops
        if ($stop) {
            $usedStops[[string]$stop.Index] = $true
            Add-GameSessionRecord `
                -Role $start.Role `
                -Status "Closed" `
                -Started $start.Time `
                -Ended $stop.Time `
                -ProcessName $start.ProcessName `
                -ProcessId $start.ProcessId `
                -Path $start.Path `
                -ServiceName $start.ServiceName `
                -StartSource $start.Source `
                -EndSource $stop.Source `
                -Quality "Exact start/end from Windows event logs" `
                -Notes @()
        }
        else {
            $note = if ($terminationEventsAvailable) {
                "No matching termination/stop event was found for this start event."
            }
            else {
                "Close time unavailable because matching Security 4689/service stop evidence was not present."
            }

            Add-GameSessionRecord `
                -Role $start.Role `
                -Status "Start observed, close time unavailable" `
                -Started $start.Time `
                -ProcessName $start.ProcessName `
                -ProcessId $start.ProcessId `
                -Path $start.Path `
                -ServiceName $start.ServiceName `
                -StartSource $start.Source `
                -Quality "Start observed only" `
                -Notes @($note)
        }
    }

    foreach ($stop in @($stops | Where-Object { -not $usedStops.ContainsKey([string]$_.Index) } | Sort-Object Time)) {
        Add-GameSessionRecord `
            -Role $stop.Role `
            -Status "Close observed, start time unavailable" `
            -Ended $stop.Time `
            -ProcessName $stop.ProcessName `
            -ProcessId $stop.ProcessId `
            -Path $stop.Path `
            -ServiceName $stop.ServiceName `
            -EndSource $stop.Source `
            -Quality "End observed only" `
            -Notes @("A close/stop event was seen without a matching start event in the selected day/window.")
    }

    $now = Get-Date
    try {
        foreach ($process in @(Get-Process -ErrorAction SilentlyContinue)) {
            $processName = if ($process.ProcessName) { "$($process.ProcessName).exe" } else { $null }
            $path = Get-ProcessPathSafe -Process $process
            $role = Get-GameProcessRole -ExeName $processName -Path $path
            if (-not $role) { continue }

            $processIdValue = $null
            try { if ($process.Id) { $processIdValue = [int]$process.Id } } catch {}
            $startTime = Get-ProcessStartTimeSafe -Process $process
            if ($startTime -and ($startTime -lt $window.Start -or $startTime -ge $window.End)) { continue }

            $existing = Find-ExistingOpenGameSession -Role $role -ProcessId $processIdValue -ProcessName $processName -Path $path
            if ($existing) {
                $existing.Status = "Running at collection time"
                $existing.ObservedUntil = $now
                $existing.Quality = "Start observed and process still active"
                $existing.Notes += "Process was still running when TraceUSB collected live process data."
                continue
            }

            Add-GameSessionRecord `
                -Role $role `
                -Status "Running at collection time" `
                -Started $startTime `
                -ObservedUntil $now `
                -ProcessName $processName `
                -ProcessId $processIdValue `
                -Path $path `
                -StartSource "Live process snapshot" `
                -Quality "Live process snapshot" `
                -Notes @("Process was still running when TraceUSB collected live process data.")
        }
    }
    catch {
        Write-RunLog "Game session live process collection failed: $($_.Exception.Message)"
    }

    $script:GameSessionLines.Clear()
    foreach ($line in Get-GameSessionLines) {
        $script:GameSessionLines.Add($line)
    }

    if ($script:GameSessions.Count -eq 0) {
        $script:Report.Add("No SCUM/BattlEye process or service sessions were reconstructed for the selected day.")
        $script:Report.Add("")
        return
    }

    foreach ($session in @($script:GameSessions | Sort-Object Started, ObservedUntil, Ended)) {
        $script:Report.Add("$($session.Role) | $($session.Status)")
        $script:Report.Add("Started: $(if ($session.Started) { $session.Started } else { 'Unknown' })")
        $script:Report.Add("Ended: $(if ($session.Ended) { $session.Ended } else { 'Unknown' })")
        if ($session.ObservedUntil) { $script:Report.Add("ObservedUntil: $($session.ObservedUntil)") }
        $script:Report.Add("Duration: $(Format-TraceDuration -Duration $session.Duration)")
        if ($session.ProcessName) { $script:Report.Add("Process: $($session.ProcessName)") }
        if ($session.ProcessId) { $script:Report.Add("PID: $($session.ProcessId)") }
        if ($session.ServiceName) { $script:Report.Add("Service: $($session.ServiceName)") }
        if ($session.Path) { $script:Report.Add("Path: $($session.Path)") }
        $script:Report.Add("Quality: $($session.Quality)")
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

function Get-NetworkRiskCatalog {
    return @(
        [PSCustomObject]@{ Name = "WinDivert"; Pattern = "windivert"; Kind = "packet diversion driver"; BaseScore = 70 },
        [PSCustomObject]@{ Name = "clumsy"; Pattern = "(^|\\|/| )clumsy(\.exe)?$|clumsy"; Kind = "packet loss/latency tool"; BaseScore = 70 },
        [PSCustomObject]@{ Name = "NetLimiter"; Pattern = "netlimiter|nlclient|nlsvc"; Kind = "bandwidth shaping tool"; BaseScore = 60 },
        [PSCustomObject]@{ Name = "Proxifier"; Pattern = "proxifier|prxer"; Kind = "proxy routing tool"; BaseScore = 55 },
        [PSCustomObject]@{ Name = "Npcap"; Pattern = "npcap|\\npf\.sys|(^| )npf($| )"; Kind = "packet capture driver"; BaseScore = 45 },
        [PSCustomObject]@{ Name = "TAP"; Pattern = "tap-windows|tap0901|tapoas|tap adapter"; Kind = "VPN/TAP adapter"; BaseScore = 45 },
        [PSCustomObject]@{ Name = "Wintun"; Pattern = "wintun|wireguard"; Kind = "VPN tunnel driver"; BaseScore = 45 },
        [PSCustomObject]@{ Name = "Generic VPN/Tunnel"; Pattern = "vpn| tunnel |tun adapter|tun driver"; Kind = "VPN/tunnel component"; BaseScore = 35 },
        [PSCustomObject]@{ Name = "OpenVPN"; Pattern = "openvpn"; Kind = "VPN client"; BaseScore = 45 },
        [PSCustomObject]@{ Name = "WireGuard"; Pattern = "wireguard"; Kind = "VPN client"; BaseScore = 45 },
        [PSCustomObject]@{ Name = "ExitLag"; Pattern = "exitlag"; Kind = "gaming route/VPN tool"; BaseScore = 45 },
        [PSCustomObject]@{ Name = "Mudfish"; Pattern = "mudfish"; Kind = "gaming route/VPN tool"; BaseScore = 45 },
        [PSCustomObject]@{ Name = "WTFast"; Pattern = "wtfast"; Kind = "gaming route/VPN tool"; BaseScore = 45 },
        [PSCustomObject]@{ Name = "NoPing"; Pattern = "noping"; Kind = "gaming route/VPN tool"; BaseScore = 45 },
        [PSCustomObject]@{ Name = "Haste"; Pattern = "haste"; Kind = "gaming route/VPN tool"; BaseScore = 40 },
        [PSCustomObject]@{ Name = "ProtonVPN"; Pattern = "protonvpn|proton vpn"; Kind = "VPN client"; BaseScore = 40 },
        [PSCustomObject]@{ Name = "NordVPN"; Pattern = "nordvpn|nord vpn"; Kind = "VPN client"; BaseScore = 40 },
        [PSCustomObject]@{ Name = "Cloudflare WARP"; Pattern = "cloudflare warp|warp-svc|warp\.exe|warp service"; Kind = "VPN/tunnel client"; BaseScore = 35 },
        [PSCustomObject]@{ Name = "Fiddler"; Pattern = "fiddler|telerik"; Kind = "HTTP proxy/debug tool"; BaseScore = 35 },
        [PSCustomObject]@{ Name = "Charles Proxy"; Pattern = "charles"; Kind = "HTTP proxy/debug tool"; BaseScore = 35 },
        [PSCustomObject]@{ Name = "mitmproxy"; Pattern = "mitmproxy"; Kind = "HTTP proxy/debug tool"; BaseScore = 35 }
    )
}

function Get-NetworkRiskMatch {
    param([string]$Text)

    if (-not $Text) { return $null }
    foreach ($item in Get-NetworkRiskCatalog) {
        if ($Text -match $item.Pattern) { return $item }
    }
    return $null
}

function Test-BuiltInWindowsNetworkComponent {
    param(
        [string]$Name,
        [string]$PathName
    )

    if ($Name -match '^(RasMan|RasAgileVpn|SstpSvc|EapHost|Ikeext|PolicyAgent|NlaSvc|Dnscache|WinHttpAutoProxySvc)$') {
        return $true
    }
    if ($PathName -match '\\Windows\\System32\\(svchost\.exe|drivers\\AgileVpn\.sys)' -or $PathName -match '\\WINDOWS\\System32\\(svchost\.exe|drivers\\AgileVpn\.sys)') {
        return $true
    }
    return $false
}

function Get-ProcessNameByIdSafe {
    param([int]$ProcessId)

    if ($ProcessId -le 0) { return "" }
    try {
        $process = Get-Process -Id $ProcessId -ErrorAction Stop
        if ($process.ProcessName) { return "$($process.ProcessName).exe" }
    }
    catch {}
    return ""
}

function Add-NetworkEvidence {
    param(
        [string]$Source,
        [string]$Subject,
        [string]$Details,
        [int]$BaseScore,
        [string[]]$Reasons,
        [AllowNull()]$Time = (Get-Date)
    )

    $score = $BaseScore
    $cleanReasons = @($Reasons)
    if ($Time -and (Test-NearAnyTime -Time $Time -Times $script:GameSessionTimes -Minutes 45)) {
        $score += 15
        $cleanReasons += "Near SCUM/BattlEye session window"
    }
    $score = [Math]::Min(100, $score)

    Add-Evidence -Time $Time -Category "NetworkAnomaly" -Source $Source -Confidence $score -Reasons $cleanReasons -Details "$Subject - $Details" | Out-Null
}

function Collect-SystemContext {
    $script:SystemContext.Clear()
    Add-Line $script:SystemContext "TraceUSB system context"
    Add-Line $script:SystemContext "Generated: $(Get-Date)"
    Add-Line $script:SystemContext "Computer: $env:COMPUTERNAME"
    Add-Line $script:SystemContext "User: $env:USERNAME"
    Add-Line $script:SystemContext "Administrator: $(Test-IsAdministrator)"
    Add-Line $script:SystemContext "LookbackHours: $LookbackHours"
    Add-Line $script:SystemContext "SubjectLabel: $SubjectLabel"

    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        if ($os) {
            Add-Line $script:SystemContext "OS: $($os.Caption) $($os.Version) build $($os.BuildNumber)"
            Add-Line $script:SystemContext "InstallDate: $($os.InstallDate)"
            Add-Line $script:SystemContext "LastBootUpTime: $($os.LastBootUpTime)"
        }
    }
    catch {}

    try {
        $tz = Get-TimeZone -ErrorAction SilentlyContinue
        if ($tz) { Add-Line $script:SystemContext "TimeZone: $($tz.Id) / $($tz.DisplayName)" }
    }
    catch {}

    Add-Line $script:SystemContext "PowerShell: $($PSVersionTable.PSVersion)"
    Add-Line $script:SystemContext "ScriptRunStamp: $script:RunStamp"
}

function Collect-NetworkAnomalies {
    if (-not $EnableNetworkAnomalyScan) {
        Write-RunLog "Network anomaly scan disabled."
        return
    }

    Write-Section "NETWORK ANOMALY CONTEXT"
    $script:NetworkSnapshot.Clear()
    Add-Line $script:NetworkSnapshot "TraceUSB network anomaly snapshot"
    Add-Line $script:NetworkSnapshot "Generated: $(Get-Date)"
    Add-Line $script:NetworkSnapshot "Privacy: metadata only. TraceUSB does not sniff packet contents."
    Add-Line $script:NetworkSnapshot ""

    $found = $false
    $seenEvidence = @{}

    function Add-UniqueNetworkEvidence {
        param(
            [string]$Key,
            [string]$Source,
            [string]$Subject,
            [string]$Details,
            [int]$BaseScore,
            [string[]]$Reasons,
            [AllowNull()]$Time = (Get-Date)
        )

        if ($seenEvidence.ContainsKey($Key)) { return }
        $seenEvidence[$Key] = $true
        Add-NetworkEvidence -Source $Source -Subject $Subject -Details $Details -BaseScore $BaseScore -Reasons $Reasons -Time $Time
    }

    Add-Line $script:NetworkSnapshot "== Adapters =="
    try {
        Get-NetAdapter -ErrorAction SilentlyContinue |
            Sort-Object Status, Name |
            ForEach-Object {
                $line = "$($_.Name) | Status=$($_.Status) | Interface=$($_.InterfaceDescription) | Mac=$($_.MacAddress) | LinkSpeed=$($_.LinkSpeed)"
                Add-Line $script:NetworkSnapshot $line
                $match = Get-NetworkRiskMatch "$($_.Name) $($_.InterfaceDescription)"
                if ($match) {
                    $found = $true
                    $script:Report.Add("Network adapter indicator: $line")
                    Add-UniqueNetworkEvidence -Key "adapter:$($_.Name):$($match.Name)" -Source "NetworkAdapter" -Subject $match.Name -Details "$($match.Kind): $($_.Name)" -BaseScore $match.BaseScore -Reasons @("Network adapter matched $($match.Name)")
                }
            }
    }
    catch {
        Add-Line $script:NetworkSnapshot "Adapter collection failed: $($_.Exception.Message)"
    }
    Add-Line $script:NetworkSnapshot ""

    Add-Line $script:NetworkSnapshot "== IP Configuration =="
    try {
        Get-NetIPConfiguration -ErrorAction SilentlyContinue |
            ForEach-Object {
                $ipv4 = @($_.IPv4Address | ForEach-Object { $_.IPAddress }) -join ", "
                $dns = @($_.DNSServer.ServerAddresses) -join ", "
                Add-Line $script:NetworkSnapshot "$($_.InterfaceAlias) | IPv4=$ipv4 | Gateway=$($_.IPv4DefaultGateway.NextHop) | DNS=$dns"
            }
    }
    catch {
        Add-Line $script:NetworkSnapshot "IP configuration collection failed: $($_.Exception.Message)"
    }
    Add-Line $script:NetworkSnapshot ""

    Add-Line $script:NetworkSnapshot "== Proxy =="
    try {
        $proxy = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
        if ($proxy) {
            Add-Line $script:NetworkSnapshot "HKCU ProxyEnable=$($proxy.ProxyEnable) ProxyServer=$($proxy.ProxyServer) AutoConfigURL=$($proxy.AutoConfigURL)"
            if ($proxy.ProxyEnable -eq 1 -or $proxy.ProxyServer -or $proxy.AutoConfigURL) {
                $found = $true
                Add-UniqueNetworkEvidence -Key "proxy:hkcu" -Source "ProxyConfig" -Subject "Windows proxy" -Details "Proxy configuration enabled or present" -BaseScore 35 -Reasons @("Proxy configuration present")
            }
        }
    }
    catch {}
    try {
        $winHttp = netsh winhttp show proxy 2>$null
        foreach ($line in @($winHttp)) { Add-Line $script:NetworkSnapshot $line }
        if (($winHttp -join " ") -notmatch "Direct access|Direto") {
            $found = $true
            Add-UniqueNetworkEvidence -Key "proxy:winhttp" -Source "ProxyConfig" -Subject "WinHTTP proxy" -Details (($winHttp -join " ") -replace '\s+', ' ') -BaseScore 35 -Reasons @("WinHTTP proxy configuration present")
        }
    }
    catch {}
    Add-Line $script:NetworkSnapshot ""

    Add-Line $script:NetworkSnapshot "== Active Risk Processes =="
    try {
        Get-Process -ErrorAction SilentlyContinue |
            Sort-Object ProcessName |
            ForEach-Object {
                $path = ""
                try { $path = $_.Path } catch {}
                $text = "$($_.ProcessName) $path"
                $match = Get-NetworkRiskMatch $text
                if ($match) {
                    $found = $true
                    $line = "$($_.ProcessName).exe | PID=$($_.Id) | Path=$path | Indicator=$($match.Name)"
                    Add-Line $script:NetworkSnapshot $line
                    $script:Report.Add("Network process indicator: $line")
                    Add-UniqueNetworkEvidence -Key "process:$($_.Id):$($match.Name)" -Source "Process" -Subject "$($_.ProcessName).exe" -Details "$($match.Kind): $path" -BaseScore $match.BaseScore -Reasons @("Active process matched $($match.Name)")
                }
            }
    }
    catch {
        Add-Line $script:NetworkSnapshot "Process network-risk collection failed: $($_.Exception.Message)"
    }
    Add-Line $script:NetworkSnapshot ""

    Add-Line $script:NetworkSnapshot "== Network Services and Drivers =="
    try {
        Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
            Where-Object {
                $match = Get-NetworkRiskMatch "$($_.Name) $($_.DisplayName) $($_.PathName) $($_.Description)"
                $null -ne $match -and -not ($match.Name -eq "Generic VPN/Tunnel" -and (Test-BuiltInWindowsNetworkComponent -Name $_.Name -PathName $_.PathName))
            } |
            ForEach-Object {
                $match = Get-NetworkRiskMatch "$($_.Name) $($_.DisplayName) $($_.PathName) $($_.Description)"
                $line = "Driver $($_.Name) | State=$($_.State) | Path=$($_.PathName) | Indicator=$($match.Name)"
                Add-Line $script:NetworkSnapshot $line
                $script:Report.Add("Network driver indicator: $line")
                $found = $true
                Add-UniqueNetworkEvidence -Key "driver:$($_.Name):$($match.Name)" -Source "Driver" -Subject $match.Name -Details "$($match.Kind): $($_.PathName)" -BaseScore $match.BaseScore -Reasons @("System driver matched $($match.Name)")
            }

        Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
            Where-Object {
                $match = Get-NetworkRiskMatch "$($_.Name) $($_.DisplayName) $($_.PathName) $($_.Description)"
                $null -ne $match -and -not ($match.Name -eq "Generic VPN/Tunnel" -and (Test-BuiltInWindowsNetworkComponent -Name $_.Name -PathName $_.PathName))
            } |
            ForEach-Object {
                $match = Get-NetworkRiskMatch "$($_.Name) $($_.DisplayName) $($_.PathName) $($_.Description)"
                $line = "Service $($_.Name) | State=$($_.State) | Path=$($_.PathName) | Indicator=$($match.Name)"
                Add-Line $script:NetworkSnapshot $line
                $script:Report.Add("Network service indicator: $line")
                $found = $true
                Add-UniqueNetworkEvidence -Key "service:$($_.Name):$($match.Name)" -Source "Service" -Subject $match.Name -Details "$($match.Kind): $($_.PathName)" -BaseScore $match.BaseScore -Reasons @("Service matched $($match.Name)")
            }
    }
    catch {
        Add-Line $script:NetworkSnapshot "Service/driver collection failed: $($_.Exception.Message)"
    }
    Add-Line $script:NetworkSnapshot ""

    Add-Line $script:NetworkSnapshot "== Active TCP Connections (sample) =="
    try {
        Get-NetTCPConnection -ErrorAction SilentlyContinue |
            Where-Object { $_.State -in @("Established", "Listen", "SynSent") } |
            Sort-Object State, LocalPort |
            Select-Object -First 150 |
            ForEach-Object {
                $processName = Get-ProcessNameByIdSafe -ProcessId $_.OwningProcess
                $line = "$($_.State) | $($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort) | PID=$($_.OwningProcess) $processName"
                Add-Line $script:NetworkSnapshot $line
                $match = Get-NetworkRiskMatch $processName
                if ($match) {
                    $found = $true
                    Add-UniqueNetworkEvidence -Key "tcp:$($_.OwningProcess):$($match.Name)" -Source "TCPConnection" -Subject $processName -Details "$($match.Kind) has active TCP connection" -BaseScore $match.BaseScore -Reasons @("Risk process has active TCP socket")
                }
            }
    }
    catch {
        Add-Line $script:NetworkSnapshot "TCP connection collection failed: $($_.Exception.Message)"
    }
    Add-Line $script:NetworkSnapshot ""

    Add-Line $script:NetworkSnapshot "== DNS Cache Indicators =="
    try {
        Get-DnsClientCache -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Entry -match "ciroscript|projectcheats|byster|crooked|clumsy|windivert|exitlag|mudfish|wtfast|noping|netlimiter|proxifier"
            } |
            Select-Object -First 100 |
            ForEach-Object {
                $line = "$($_.Entry) | Type=$($_.Type) | Data=$($_.Data)"
                Add-Line $script:NetworkSnapshot $line
                $found = $true
                Add-UniqueNetworkEvidence -Key "dns:$($_.Entry)" -Source "DnsCache" -Subject $_.Entry -Details "DNS cache matched network/cheat-related keyword" -BaseScore 40 -Reasons @("DNS cache indicator")
            }
    }
    catch {
        Add-Line $script:NetworkSnapshot "DNS cache collection failed: $($_.Exception.Message)"
    }
    Add-Line $script:NetworkSnapshot ""

    Add-Line $script:NetworkSnapshot "== Network Profile Events =="
    try {
        Get-WinEvent -FilterHashtable @{ LogName = "Microsoft-Windows-NetworkProfile/Operational"; Id = 10000, 10001; StartTime = $script:StartTime } -ErrorAction SilentlyContinue |
            Sort-Object TimeCreated -Descending |
            Select-Object -First 50 |
            ForEach-Object {
                $eventText = ([string]$_.Message -replace "`r|`n", " ")
                $line = "$($_.TimeCreated) | EventID=$($_.Id) | $(Limit-Text -Text $eventText -MaxLength 240)"
                Add-Line $script:NetworkSnapshot $line
                if ($_.TimeCreated -and (Test-NearAnyTime -Time $_.TimeCreated -Times $script:GameSessionTimes -Minutes 30)) {
                    $found = $true
                    Add-UniqueNetworkEvidence -Key "netprofile:$($_.RecordId)" -Source "NetworkProfile" -Subject "Network connect/disconnect" -Details "Network profile changed near SCUM/BattlEye session" -BaseScore 35 -Reasons @("Network profile event near game session") -Time $_.TimeCreated
                }
            }
    }
    catch {
        Add-Line $script:NetworkSnapshot "NetworkProfile event collection failed: $($_.Exception.Message)"
    }

    if (-not $found) {
        $script:Report.Add("No known network manipulation, VPN/tunnel, proxy, route-optimizer, or packet driver indicators were observed.")
        $script:Report.Add("")
    }
    else {
        $script:Report.Add("")
    }
}

function Get-OverlayScreenshotRoots {
    $roots = New-Object System.Collections.Generic.List[string]

    function Add-RootIfPresent {
        param([string]$Path)
        if ($Path -and (Test-Path -LiteralPath $Path)) {
            $roots.Add([System.IO.Path]::GetFullPath($Path))
        }
    }

    if ($env:USERPROFILE) {
        Add-RootIfPresent (Join-Path $env:USERPROFILE "Videos\Captures")
        Add-RootIfPresent (Join-Path $env:USERPROFILE "Videos\NVIDIA")
        Add-RootIfPresent (Join-Path $env:USERPROFILE "Videos\NVIDIA Share")
        Add-RootIfPresent (Join-Path $env:USERPROFILE "Videos\Radeon ReLive")
        Add-RootIfPresent (Join-Path $env:USERPROFILE "Pictures\Screenshots")
        Add-RootIfPresent (Join-Path $env:USERPROFILE "Pictures\NVIDIA Share")
    }

    if ($env:OneDrive) {
        Add-RootIfPresent (Join-Path $env:OneDrive "Pictures\Screenshots")
        Add-RootIfPresent (Join-Path $env:OneDrive "Videos\Captures")
    }

    return @($roots | Select-Object -Unique)
}

function Ensure-WindowApi {
    if ("TraceUsbWindowApi" -as [type]) { return }

    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class TraceUsbWindowApi
{
    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    public static extern bool IsIconic(IntPtr hWnd);
}
"@
}

function Test-ProcessMatchesGamePattern {
    param($Process)

    if (-not $Process -or -not $Process.ProcessName) { return $false }

    $candidateNames = @(
        [string]$Process.ProcessName,
        "$($Process.ProcessName).exe"
    )

    foreach ($candidate in $candidateNames) {
        if (Test-NameMatchesAny -Name $candidate -Patterns $GameProcessPatterns) {
            return $true
        }
    }

    return $false
}

function Get-ScreenshotTargetProcess {
    $candidates = New-Object System.Collections.Generic.List[object]

    foreach ($process in @(Get-Process -ErrorAction SilentlyContinue)) {
        if (-not (Test-ProcessMatchesGamePattern -Process $process)) { continue }
        if (-not $process.MainWindowHandle -or $process.MainWindowHandle -eq [IntPtr]::Zero) { continue }

        $rank = 50
        if ($process.ProcessName -match '^SCUM$') { $rank = 0 }
        elseif ($process.ProcessName -match 'SCUM.*Shipping') { $rank = 5 }
        elseif ($process.ProcessName -match 'SCUM_Launcher') { $rank = 30 }
        elseif ($process.ProcessName -match 'BEService') { $rank = 90 }

        $candidates.Add([PSCustomObject]@{
            Process = $process
            Rank    = $rank
            Title   = [string]$process.MainWindowTitle
        }) | Out-Null
    }

    return @($candidates | Sort-Object Rank, Title | Select-Object -First 1)
}

function Set-ScreenshotTargetWindowFocus {
    if ($DisableScreenshotWindowFocus) {
        $script:Report.Add("Automatic SCUM window focus is disabled by parameter.")
        Write-RunLog "Screenshot window focus disabled by parameter."
        return $false
    }

    $target = Get-ScreenshotTargetProcess
    if (-not $target) {
        $script:Report.Add("Automatic SCUM window focus failed: no SCUM/BattlEye process with a visible window was found.")
        Write-RunLog "Screenshot window focus failed: no visible game window found."
        return $false
    }

    try {
        Ensure-WindowApi
        $handle = [IntPtr]$target.Process.MainWindowHandle
        if ([TraceUsbWindowApi]::IsIconic($handle)) {
            [TraceUsbWindowApi]::ShowWindowAsync($handle, 9) | Out-Null
        }
        else {
            [TraceUsbWindowApi]::ShowWindowAsync($handle, 5) | Out-Null
        }

        Start-Sleep -Milliseconds 300
        $focused = [TraceUsbWindowApi]::SetForegroundWindow($handle)
        $details = "Target=$($target.Process.ProcessName).exe PID=$($target.Process.Id) Title=$($target.Title)"

        if ($focused) {
            $script:Report.Add("Focused SCUM window before overlay screenshot trigger. $details")
            Write-RunLog "Focused screenshot target window. $details"
            return $true
        }

        $script:Report.Add("Attempted to focus SCUM window before overlay screenshot trigger, but Windows did not confirm foreground focus. $details")
        Write-RunLog "Screenshot target focus attempted but not confirmed. $details"
        return $false
    }
    catch {
        $script:Report.Add("Automatic SCUM window focus failed: $($_.Exception.Message)")
        Write-RunLog "Screenshot window focus failed: $($_.Exception.Message)"
        return $false
    }
}

function Get-ImageContentType {
    param([string]$Path)

    $extension = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    switch ($extension) {
        ".jpg"  { return "image/jpeg" }
        ".jpeg" { return "image/jpeg" }
        ".png"  { return "image/png" }
        ".bmp"  { return "image/bmp" }
        ".webp" { return "image/webp" }
        default { return "application/octet-stream" }
    }
}

function Find-NewOverlayScreenshot {
    param(
        [datetime]$Since,
        [string[]]$Roots
    )

    if (-not $Roots -or $Roots.Count -eq 0) { return $null }

    $extensions = @(".png", ".jpg", ".jpeg", ".bmp", ".webp")
    $threshold = $Since.AddSeconds(-5)
    $candidates = New-Object System.Collections.Generic.List[object]

    foreach ($root in $Roots) {
        try {
            Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.Length -gt 0 -and
                    $_.LastWriteTime -ge $threshold -and
                    ($extensions -contains $_.Extension.ToLowerInvariant())
                } |
                ForEach-Object { $candidates.Add($_) }
        }
        catch {
            Write-RunLog "Screenshot folder scan failed for $root`: $($_.Exception.Message)"
        }
    }

    return @($candidates | Sort-Object LastWriteTime, Length -Descending | Select-Object -First 1)
}

function Invoke-ScreenshotTrigger {
    if (-not $EnableScreenshotTrigger) { return }

    Write-Section "SCREENSHOT TRIGGER"
    $script:Report.Add("Screenshot trigger explicitly enabled.")
    $script:Report.Add("No desktop screenshot fallback is used; TraceUSB only attaches an overlay-generated file when one is found.")
    $script:Report.Add("")

    $runtimeEvidence = @($script:Evidence | Where-Object { $_.Category -eq "RuntimeContext" })
    $runtimeSources = @($runtimeEvidence | ForEach-Object { $_.Source } | Select-Object -Unique)
    $target = $null

    if ($runtimeSources -contains "NVIDIA") {
        $target = [PSCustomObject]@{
            Source = "NVIDIA"
            Hotkey = "%{F1}"
            Label  = "ALT+F1"
        }
    }
    elseif ($runtimeSources -contains "AMD") {
        $target = [PSCustomObject]@{
            Source = "AMD"
            Hotkey = "^+i"
            Label  = "CTRL+SHIFT+I"
        }
    }

    if (-not $target) {
        $script:Report.Add("Screenshot trigger skipped: no NVIDIA or AMD overlay runtime context was observed.")
        Add-Evidence -Time (Get-Date) -Category "RuntimeContext" -Source "ScreenshotTrigger" -Confidence 10 -Reasons @("Screenshot trigger enabled but no supported GPU overlay runtime was observed") -Details "No NVIDIA/AMD runtime context" | Out-Null
        return
    }

    $roots = @(Get-OverlayScreenshotRoots)
    if ($roots.Count -gt 0) {
        $script:Report.Add("Monitoring screenshot folders:")
        foreach ($root in $roots) { $script:Report.Add("- $root") }
        $script:Report.Add("")
    }
    else {
        $script:Report.Add("No known overlay screenshot folders were found before triggering.")
        $script:Report.Add("")
    }

    try {
        Add-Type -AssemblyName System.Windows.Forms
        $focusSucceeded = Set-ScreenshotTargetWindowFocus
        if ($focusSucceeded) {
            Start-Sleep -Seconds $ScreenshotFocusWaitSeconds
        }
        else {
            $script:Report.Add("Return focus to the SCUM game window manually before the fallback countdown finishes.")
            Start-Sleep -Seconds 15
        }

        $triggerTime = Get-Date
        [System.Windows.Forms.SendKeys]::SendWait([string]$target.Hotkey)
        $script:Report.Add("$($target.Source) screenshot hotkey sent: $($target.Label).")
        Write-RunLog "$($target.Source) screenshot hotkey sent: $($target.Label)."

        Start-Sleep -Seconds $ScreenshotPostTriggerWaitSeconds
        $captured = Find-NewOverlayScreenshot -Since $triggerTime -Roots $roots

        if ($captured) {
            $extension = [System.IO.Path]::GetExtension($captured.FullName)
            if (-not $extension) { $extension = ".png" }

            $script:ScreenshotCapturePath = $captured.FullName
            $script:ScreenshotCaptureFileName = "overlay_screenshot_$($script:ArtifactSuffix)$extension"
            $script:ScreenshotCaptureContentType = Get-ImageContentType -Path $captured.FullName

            $details = "$($target.Source) $($target.Label) trigger sent; new screenshot detected at $($captured.FullName)"
            Add-Evidence -Time (Get-Date) -Category "RuntimeContext" -Source $target.Source -Confidence 25 -Reasons @("Operator enabled screenshot trigger", "Overlay screenshot file was detected after hotkey") -Details $details | Out-Null
            $script:Report.Add("Overlay screenshot detected and queued for Discord/case bundle: $($script:ScreenshotCaptureFileName)")
            Write-RunLog "Overlay screenshot detected: $($captured.FullName)"
        }
        else {
            $details = "$($target.Source) $($target.Label) trigger sent; no new screenshot file detected in known folders"
            Add-Evidence -Time (Get-Date) -Category "RuntimeContext" -Source $target.Source -Confidence 15 -Reasons @("Operator enabled screenshot trigger", "No overlay screenshot file was detected after hotkey") -Details $details | Out-Null
            $script:Report.Add("No new overlay screenshot file was detected after the hotkey.")
            Write-RunLog "No overlay screenshot file detected after trigger."
        }
    }
    catch {
        $script:Report.Add("Screenshot trigger failed: $($_.Exception.Message)")
        Write-RunLog "Screenshot trigger failed: $($_.Exception.Message)"
        Add-Evidence -Time (Get-Date) -Category "RuntimeContext" -Source "ScreenshotTrigger" -Confidence 10 -Reasons @("Screenshot trigger failed") -Details $_.Exception.Message | Out-Null
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
        "NetworkAnomaly" { $priority += 35 }
        "Service" { $priority += 30 }
        "USB" { $priority += 25 }
        "Execution" { $priority += 20 }
        "CorrelatedExecution" { $priority += 10 }
        "GameContext" { $priority -= 30 }
        "RuntimeContext" { $priority -= 35 }
    }

    if ($source -match "4688|Security") { $priority += 20 }
    if ($reasonText -match "Defender|anti-forensic|Log|USB|Removable|SCUM|BattlEye|Suspicious|proxy|VPN|packet|driver|network") { $priority += 15 }
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
        if ($seenKeys.ContainsKey($key)) { continue }
        $seenKeys[$key] = $true
        $selected.Add($evidence)
    }

    if ($selected.Count -lt $DiscordMaxItems) {
        foreach ($item in $ranked) {
            if ($selected.Count -ge $DiscordMaxItems) { break }
            if ($selected.Contains($item.Evidence)) { continue }
            $selected.Add($item.Evidence)
        }
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
    elseif ($category -eq "NetworkAnomaly") {
        $meaning = "Contexto de rede incomum foi observado, como proxy, VPN/tunel, driver de pacote, route optimizer ou ferramenta de manipulacao de latencia."
        $operatorAction = "Correlacionar com horario da partida, processos ativos e adaptadores. Este sinal sugere investigacao de possivel fake lag, nao prova abuso sozinho."
        $falsePositive = "VPNs, ferramentas de diagnostico, capturadores de pacote e otimizadores de rota tambem podem ser usados legitimamente."
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
    if ($reasonText -match "VPN|proxy|packet|WinDivert|clumsy|network") {
        $operatorAction += " Verifique se a ferramenta estava ativa durante a sessao e se ha justificativa operacional."
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
        [string]$LocalPath,
        [byte[]]$Bytes
    )

    if (-not $Bytes -and -not $Lines) {
        $Lines = @("")
    }

    $content = $null
    $attachmentBytes = $Bytes

    if (-not $attachmentBytes) {
        $content = ($Lines -join "`r`n")
        $attachmentBytes = Convert-TextToUtf8Bytes -Text $content -Bom:(Test-DiscordAttachmentNeedsBom -ContentType $ContentType)
    }

    if ($attachmentBytes.Length -gt $DiscordMaxAttachmentBytes -and -not $Bytes) {
        $keepBytes = [Math]::Max(1024, $DiscordMaxAttachmentBytes - 2048)
        $content = [Text.Encoding]::UTF8.GetString($attachmentBytes, 0, $keepBytes)
        $content += "`r`n`r`n[TraceUSB truncated this attachment from $($attachmentBytes.Length) bytes to fit DiscordMaxAttachmentBytes=$DiscordMaxAttachmentBytes.]"
        $attachmentBytes = Convert-TextToUtf8Bytes -Text $content -Bom:(Test-DiscordAttachmentNeedsBom -ContentType $ContentType)
        Write-RunLog "Attachment truncated: $FileName ($($attachmentBytes.Length) bytes after truncation)."
    }
    elseif ($attachmentBytes.Length -gt $DiscordMaxAttachmentBytes) {
        Write-RunLog "Attachment skipped because it exceeds DiscordMaxAttachmentBytes: $FileName ($($attachmentBytes.Length) bytes)."
        return
    }

    $script:DiscordAttachments.Add([PSCustomObject]@{
        FileName    = $FileName
        Content     = $content
        Bytes       = $attachmentBytes
        ContentType = $ContentType
    }) | Out-Null

    if ($SaveDiscordAttachmentsLocal -and $LocalPath) {
        [System.IO.File]::WriteAllBytes($LocalPath, $attachmentBytes)
    }
}

function Get-EvidenceJsonLines {
    return @(
        $script:Evidence |
            Sort-Object Time |
            ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 6 }
    )
}

function Get-TraceUsbScriptDirectory {
    if ($PSScriptRoot) { return $PSScriptRoot }
    if ($PSCommandPath) { return Split-Path -Parent $PSCommandPath }
    if ($MyInvocation.MyCommand.Path) { return Split-Path -Parent $MyInvocation.MyCommand.Path }
    try { return (Get-Location).Path } catch { return $null }
}

function Get-SidecarSha256 {
    param([string]$Path)

    if (-not $Path) { return $null }

    $candidates = @(
        "$Path.sha256",
        ([System.IO.Path]::ChangeExtension($Path, ".sha256"))
    ) | Select-Object -Unique

    foreach ($candidate in $candidates) {
        if (-not (Test-Path -LiteralPath $candidate)) { continue }

        try {
            $raw = (Get-Content -Raw -LiteralPath $candidate).Trim()
            $hash = ($raw -split '\s+')[0]
            if ($hash -match '^[a-fA-F0-9]{64}$') {
                return $hash.ToUpperInvariant()
            }
        }
        catch {
            Write-RunLog "Could not read SHA256 sidecar $candidate`: $($_.Exception.Message)"
        }
    }

    return $null
}

function Test-Sha256Hash {
    param(
        [string]$Path,
        [string]$ExpectedHash,
        [string]$Label = "file"
    )

    if (-not $Path -or -not $ExpectedHash) { return $false }

    try {
        $expected = $ExpectedHash.Trim().ToUpperInvariant()
        $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($actual -eq $expected) { return $true }

        Write-RunLog "$Label SHA256 mismatch. Expected=$expected Actual=$actual Path=$Path"
        return $false
    }
    catch {
        Write-RunLog "$Label SHA256 validation failed for $Path`: $($_.Exception.Message)"
        return $false
    }
}

function Resolve-PortableSQLiteExecutable {
    param(
        [string]$Path,
        [string]$ExpectedSha256,
        [switch]$RequireHash,
        [string]$SourceLabel = "portable SQLite"
    )

    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $null }

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if ([System.IO.Path]::GetExtension($fullPath) -ne ".exe") { return $null }

    $expected = $ExpectedSha256
    if (-not $expected) {
        $expected = Get-SidecarSha256 -Path $fullPath
    }

    if ($expected) {
        if (-not (Test-Sha256Hash -Path $fullPath -ExpectedHash $expected -Label $SourceLabel)) {
            return $null
        }
        Write-RunLog "$SourceLabel accepted after SHA256 validation: $fullPath"
        return $fullPath
    }

    if ($RequireHash) {
        Write-RunLog "$SourceLabel skipped because no SHA256 sidecar or expected hash was available: $fullPath"
        return $null
    }

    Write-RunLog "$SourceLabel accepted without SHA256 validation because it was explicitly provided: $fullPath"
    return $fullPath
}

function Expand-PortableSQLiteZip {
    param(
        [string]$ZipPath,
        [string]$ZipSha256,
        [string]$ExeSha256,
        [string]$SourceLabel = "portable SQLite zip"
    )

    if (-not $ZipPath -or -not (Test-Path -LiteralPath $ZipPath)) { return $null }

    $fullZipPath = [System.IO.Path]::GetFullPath($ZipPath)
    if ([System.IO.Path]::GetExtension($fullZipPath) -ne ".zip") { return $null }

    $expectedZipHash = $ZipSha256
    if (-not $expectedZipHash) {
        $expectedZipHash = Get-SidecarSha256 -Path $fullZipPath
    }
    if ($expectedZipHash -and -not (Test-Sha256Hash -Path $fullZipPath -ExpectedHash $expectedZipHash -Label $SourceLabel)) {
        return $null
    }

    $tempRoot = Join-Path $env:TEMP ("TraceUSB-sqlite-" + [guid]::NewGuid().ToString("N"))
    try {
        New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
        Expand-Archive -LiteralPath $fullZipPath -DestinationPath $tempRoot -Force

        $sqliteExe = Get-ChildItem -LiteralPath $tempRoot -Recurse -Filter "sqlite3.exe" -File -ErrorAction SilentlyContinue |
            Select-Object -First 1

        if (-not $sqliteExe) {
            Write-RunLog "$SourceLabel did not contain sqlite3.exe: $fullZipPath"
            Remove-Item -LiteralPath $tempRoot -Recurse -Force
            return $null
        }

        $expectedExeHash = $ExeSha256
        if (-not $expectedExeHash) {
            $expectedExeHash = Get-SidecarSha256 -Path $sqliteExe.FullName
        }
        if ($expectedExeHash -and -not (Test-Sha256Hash -Path $sqliteExe.FullName -ExpectedHash $expectedExeHash -Label "portable sqlite3.exe")) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force
            return $null
        }

        if (-not $expectedExeHash) {
            Write-RunLog "$SourceLabel skipped because extracted sqlite3.exe could not be hash-validated."
            Remove-Item -LiteralPath $tempRoot -Recurse -Force
            return $null
        }

        $script:PortableSQLiteTempRoot = $tempRoot
        Write-RunLog "$SourceLabel extracted and accepted: $($sqliteExe.FullName)"
        return $sqliteExe.FullName
    }
    catch {
        Write-RunLog "$SourceLabel extraction failed: $($_.Exception.Message)"
        try { Remove-Item -LiteralPath $tempRoot -Recurse -Force } catch {}
        return $null
    }
}

function Remove-PortableSQLiteTemp {
    if (-not $script:PortableSQLiteTempRoot) { return }

    try {
        if (Test-Path -LiteralPath $script:PortableSQLiteTempRoot) {
            Remove-Item -LiteralPath $script:PortableSQLiteTempRoot -Recurse -Force
            Write-RunLog "Portable SQLite temporary folder removed: $script:PortableSQLiteTempRoot"
        }
    }
    catch {
        Write-RunLog "Portable SQLite temporary cleanup failed: $($_.Exception.Message)"
    }
    finally {
        $script:PortableSQLiteTempRoot = $null
    }
}

function Resolve-BundledPortableSQLite {
    $roots = New-Object System.Collections.Generic.List[string]
    $scriptDir = Get-TraceUsbScriptDirectory
    if ($scriptDir) { $roots.Add($scriptDir) }
    try { $roots.Add((Get-Location).Path) } catch {}

    $uniqueRoots = @($roots | Where-Object { $_ } | Select-Object -Unique)
    $downloadFileName = $null
    try {
        if ($PortableSQLiteDownloadUrl) {
            $downloadFileName = [System.IO.Path]::GetFileName(([uri]$PortableSQLiteDownloadUrl).AbsolutePath)
        }
    }
    catch {}

    foreach ($root in $uniqueRoots) {
        $exeCandidates = @(
            (Join-Path $root "tools\sqlite\win-x64\sqlite3.exe"),
            (Join-Path $root "tools\sqlite\sqlite3.exe")
        )

        foreach ($candidate in $exeCandidates) {
            $resolved = Resolve-PortableSQLiteExecutable -Path $candidate -ExpectedSha256 (Get-SidecarSha256 -Path $candidate) -RequireHash -SourceLabel "bundled portable sqlite3.exe"
            if ($resolved) { return $resolved }
        }

        if ($downloadFileName) {
            $zipCandidate = Join-Path $root "tools\sqlite\win-x64\$downloadFileName"
            $resolvedZip = Expand-PortableSQLiteZip -ZipPath $zipCandidate -ZipSha256 (Get-SidecarSha256 -Path $zipCandidate) -ExeSha256 $PortableSQLiteExeSha256 -SourceLabel "bundled portable SQLite zip"
            if ($resolvedZip) { return $resolvedZip }
        }
    }

    return $null
}

function Invoke-PortableSQLiteDownload {
    if ($DisablePortableSQLiteDownload) {
        Write-RunLog "Portable SQLite download disabled."
        return $null
    }
    if (-not $PortableSQLiteDownloadUrl -or -not $PortableSQLiteDownloadSha256 -or -not $PortableSQLiteExeSha256) {
        Write-RunLog "Portable SQLite download skipped because URL or SHA256 pin is missing."
        return $null
    }

    $tempRoot = Join-Path $env:TEMP ("TraceUSB-sqlite-download-" + [guid]::NewGuid().ToString("N"))
    try {
        New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
        $zipPath = Join-Path $tempRoot ([System.IO.Path]::GetFileName(([uri]$PortableSQLiteDownloadUrl).AbsolutePath))

        Write-RunLog "Downloading portable SQLite from official pinned URL."
        Invoke-WebRequest -Uri $PortableSQLiteDownloadUrl -OutFile $zipPath -UseBasicParsing -TimeoutSec 45 -ErrorAction Stop

        $resolved = Expand-PortableSQLiteZip -ZipPath $zipPath -ZipSha256 $PortableSQLiteDownloadSha256 -ExeSha256 $PortableSQLiteExeSha256 -SourceLabel "downloaded portable SQLite zip"
        if ($resolved) {
            try { Remove-Item -LiteralPath $tempRoot -Recurse -Force } catch {}
            return $resolved
        }
    }
    catch {
        Write-RunLog "Portable SQLite download failed: $($_.Exception.Message)"
    }

    try { Remove-Item -LiteralPath $tempRoot -Recurse -Force } catch {}
    return $null
}

function Resolve-SqliteCli {
    if ($SQLiteCliPath -and (Test-Path -LiteralPath $SQLiteCliPath)) {
        Write-RunLog "SQLite reader resolved from -SQLiteCliPath: $SQLiteCliPath"
        return $SQLiteCliPath
    }

    if ($PortableSQLitePath) {
        $resolvedPortable = Resolve-PortableSQLiteExecutable -Path $PortableSQLitePath -ExpectedSha256 $PortableSQLiteExeSha256 -SourceLabel "-PortableSQLitePath sqlite3.exe"
        if ($resolvedPortable) { return $resolvedPortable }
    }

    $bundledPortable = Resolve-BundledPortableSQLite
    if ($bundledPortable) { return $bundledPortable }

    try {
        $cmd = Get-Command sqlite3.exe -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Source) {
            Write-RunLog "SQLite reader resolved from PATH: $($cmd.Source)"
            return $cmd.Source
        }
    }
    catch {}

    try {
        $cmd = Get-Command sqlite3 -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Source) {
            Write-RunLog "SQLite reader resolved from PATH: $($cmd.Source)"
            return $cmd.Source
        }
    }
    catch {}

    $downloadedPortable = Invoke-PortableSQLiteDownload
    if ($downloadedPortable) { return $downloadedPortable }

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

    $sqlite = Resolve-SqliteCli
    if (-not $sqlite) {
        $lines.Add("Browser history scan skipped: no SQLite reader was available.")
        $lines.Add("Resolution order: -SQLiteCliPath, -PortableSQLitePath, bundled tools\\sqlite\\win-x64\\sqlite3.exe, sqlite3 on PATH, pinned temporary portable download.")
        $lines.Add("Use -DisablePortableSQLiteDownload to prevent the trusted temporary download attempt.")
        Add-Evidence -Time (Get-Date) -Category "BrowserHistory" -Source "BrowserHistoryScan" -Confidence 10 -Reasons @("Browser history scan requested but SQLite reader unavailable") -Details "No sqlite3 reader available after explicit, bundled, PATH, and portable download attempts" | Out-Null
        Remove-PortableSQLiteTemp
        return @($lines)
    }

    $lines.Add("Detected browser history databases: $($databases.Count)")
    $lines.Add("SQLite reader: $sqlite")
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
        Remove-PortableSQLiteTemp
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
        $attachmentBytes = if ($attachment.Bytes) { $attachment.Bytes.Length } else { [Text.Encoding]::UTF8.GetByteCount([string]$attachment.Content) }
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

function Get-EnvVarValue {
    param([string]$Name)

    if (-not $Name) { return $null }

    try {
        $envValue = [Environment]::GetEnvironmentVariable($Name, "Process")
        if (-not $envValue) {
            $envValue = [Environment]::GetEnvironmentVariable($Name, "User")
        }
        if (-not $envValue) {
            $envValue = [Environment]::GetEnvironmentVariable($Name, "Machine")
        }
        if ($envValue) { return $envValue }
    }
    catch {}

    return $null
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
        if ($DiscordWebhookEnvVar -match '^https?://') {
            Write-RunLog "-DiscordWebhookEnvVar received a URL directly. This is supported only for local/internal use; prefer -DiscordWebhookUrl or a relay."
            return $DiscordWebhookEnvVar
        }

        $envValue = Get-EnvVarValue -Name $DiscordWebhookEnvVar
        if ($envValue) { return $envValue }
    }

    return $null
}

function Get-DiscordRelayUrl {
    if ($DiscordRelayUrl) { return $DiscordRelayUrl }
    if ($DiscordRelayEnvVar) { return (Get-EnvVarValue -Name $DiscordRelayEnvVar) }
    return $null
}

function Get-DiscordRelayToken {
    if ($DiscordRelayToken) { return $DiscordRelayToken }
    if ($DiscordRelayTokenEnvVar) { return (Get-EnvVarValue -Name $DiscordRelayTokenEnvVar) }
    return $null
}

function Get-SafeEndpointSummary {
    param([string]$Url)

    if (-not $Url) { return "none" }
    try {
        $uri = [uri]$Url
        return "$($uri.Scheme)://$($uri.Host)$($uri.AbsolutePath)"
    }
    catch {
        return "unparseable endpoint"
    }
}

function Get-DiscordDeliveryTarget {
    $relay = Get-DiscordRelayUrl
    if ($relay) {
        $headers = @{}
        $relayToken = Get-DiscordRelayToken
        if ($relayToken) {
            $headers["X-TraceUSB-Relay-Token"] = $relayToken
        }

        return [PSCustomObject]@{
            Kind    = "relay"
            Url     = $relay
            Headers = $headers
        }
    }

    $webhook = Get-DiscordWebhookUrl
    if ($webhook) {
        return [PSCustomObject]@{
            Kind    = "webhook"
            Url     = $webhook
            Headers = @{}
        }
    }

    return $null
}

function Add-DiscordTargetHeaders {
    param(
        $Client,
        $Target
    )

    if (-not $Client -or -not $Target -or -not $Target.Headers) { return }

    foreach ($key in $Target.Headers.Keys) {
        $value = [string]$Target.Headers[$key]
        if (-not $value) { continue }
        try {
            $Client.DefaultRequestHeaders.Remove($key) | Out-Null
            $Client.DefaultRequestHeaders.Add($key, $value)
        }
        catch {
            Write-RunLog "Could not set HTTP header $key`: $($_.Exception.Message)"
        }
    }
}

function Get-DiscordAttachmentBytes {
    param($Attachment)

    if (-not $Attachment) { return @() }
    if ($Attachment.Bytes) { return [byte[]]$Attachment.Bytes }
    return [Text.Encoding]::UTF8.GetBytes([string]$Attachment.Content)
}

function Get-DiscordAttachmentBatches {
    param([object[]]$Attachments)

    $batches = New-Object System.Collections.Generic.List[object]
    $current = New-Object System.Collections.Generic.List[object]
    $currentBytes = 0

    foreach ($attachment in @($Attachments)) {
        if (-not $attachment -or -not $attachment.FileName) { continue }

        $bytes = Get-DiscordAttachmentBytes -Attachment $attachment
        $byteCount = if ($bytes) { $bytes.Length } else { 0 }
        if ($byteCount -gt $DiscordMaxPayloadBytes) {
            Write-RunLog "Attachment skipped because it exceeds DiscordMaxPayloadBytes: $($attachment.FileName) ($byteCount bytes)."
            continue
        }

        $wouldExceedCount = $current.Count -ge $DiscordMaxFilesPerMessage
        $wouldExceedBytes = ($current.Count -gt 0 -and ($currentBytes + $byteCount) -gt $DiscordMaxPayloadBytes)
        if ($wouldExceedCount -or $wouldExceedBytes) {
            $batches.Add([PSCustomObject]@{
                Attachments = @($current.ToArray())
                Bytes       = $currentBytes
            })
            $current.Clear()
            $currentBytes = 0
        }

        $current.Add($attachment)
        $currentBytes += $byteCount
    }

    if ($current.Count -gt 0) {
        $batches.Add([PSCustomObject]@{
            Attachments = @($current.ToArray())
            Bytes       = $currentBytes
        })
    }

    return @($batches.ToArray())
}

function Build-DiscordBatchPayload {
    param(
        $OriginalPayload,
        [int]$BatchIndex,
        [int]$BatchCount
    )

    if ($BatchIndex -eq 1) { return $OriginalPayload }

    return @{
        username = $DiscordUsername
        content = "TraceUSB attachments batch $BatchIndex/$BatchCount for run $($script:RunStamp)."
    }
}

function Write-DiscordDebugArtifacts {
    param(
        [string]$PayloadJson,
        $Target,
        [object[]]$Batches
    )

    Ensure-OutputDirectory
    Set-Content -LiteralPath $script:DiscordDebugPayloadPath -Value $PayloadJson -Encoding UTF8

    $manifest = New-Object System.Collections.Generic.List[string]
    $manifest.Add("TraceUSB Discord debug manifest")
    $manifest.Add("Generated: $(Get-Date)")
    $manifest.Add("DeliveryKind: $($Target.Kind)")
    $manifest.Add("Endpoint: $(Get-SafeEndpointSummary -Url $Target.Url)")
    $manifest.Add("HTTP send skipped because -DiscordDebug was used.")
    $manifest.Add("")

    $batchNumber = 1
    foreach ($batch in @($Batches)) {
        $manifest.Add("Batch $batchNumber")
        $manifest.Add("Bytes: $($batch.Bytes)")
        foreach ($attachment in @($batch.Attachments)) {
            $bytes = Get-DiscordAttachmentBytes -Attachment $attachment
            $manifest.Add("- $($attachment.FileName) ($($bytes.Length) bytes, $($attachment.ContentType))")
        }
        $manifest.Add("")
        $batchNumber++
    }

    if ($Batches.Count -eq 0) {
        $manifest.Add("No attachments.")
    }

    Set-Content -LiteralPath $script:DiscordDebugManifestPath -Value $manifest -Encoding UTF8
    $script:DiscordStatus = "debug_saved_no_send"
    $script:Report.Add("")
    $script:Report.Add("Discord debug enabled: payload and attachment manifest were saved without sending HTTP.")
    $script:Report.Add("Discord debug payload: $script:DiscordDebugPayloadPath")
    $script:Report.Add("Discord debug manifest: $script:DiscordDebugManifestPath")
    Write-RunLog "Discord debug artifacts saved without sending HTTP."
}

function Invoke-DiscordJsonPost {
    param(
        $Target,
        [string]$PayloadJson
    )

    $jsonClient = $null
    $jsonContent = $null
    try {
        Add-Type -AssemblyName System.Net.Http
        $jsonClient = New-Object System.Net.Http.HttpClient
        $jsonClient.Timeout = [TimeSpan]::FromSeconds($DiscordTimeoutSeconds)
        Add-DiscordTargetHeaders -Client $jsonClient -Target $Target

        $jsonContent = New-Object System.Net.Http.StringContent($PayloadJson, [Text.Encoding]::UTF8, "application/json")
        $jsonResponse = $jsonClient.PostAsync([string]$Target.Url, $jsonContent).GetAwaiter().GetResult()
        if (-not $jsonResponse.IsSuccessStatusCode) {
            $responseText = $jsonResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            throw "$($Target.Kind) returned HTTP $([int]$jsonResponse.StatusCode): $(Limit-Text -Text $responseText -MaxLength 800)"
        }
    }
    finally {
        if ($jsonContent) { $jsonContent.Dispose() }
        if ($jsonClient) { $jsonClient.Dispose() }
    }
}

function Invoke-DiscordMultipartPost {
    param(
        $Target,
        [string]$PayloadJson,
        [object[]]$Attachments
    )

    $client = $null
    $multipart = $null
    try {
        Add-Type -AssemblyName System.Net.Http
        $client = New-Object System.Net.Http.HttpClient
        $client.Timeout = [TimeSpan]::FromSeconds($DiscordTimeoutSeconds)
        Add-DiscordTargetHeaders -Client $client -Target $Target

        $multipart = New-Object System.Net.Http.MultipartFormDataContent
        $payloadContent = New-Object System.Net.Http.StringContent($PayloadJson, [Text.Encoding]::UTF8, "application/json")
        $multipart.Add($payloadContent, "payload_json")

        $index = 0
        foreach ($attachment in @($Attachments)) {
            if (-not $attachment -or -not $attachment.FileName) { continue }

            $bytes = Get-DiscordAttachmentBytes -Attachment $attachment
            $fileContent = New-Object -TypeName System.Net.Http.ByteArrayContent -ArgumentList (,$bytes)
            if ($attachment.ContentType) {
                $fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse([string]$attachment.ContentType)
            }
            $multipart.Add($fileContent, "files[$index]", [string]$attachment.FileName)
            $index++
        }

        $response = $client.PostAsync([string]$Target.Url, $multipart).GetAwaiter().GetResult()
        if (-not $response.IsSuccessStatusCode) {
            $responseText = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            throw "$($Target.Kind) returned HTTP $([int]$response.StatusCode): $(Limit-Text -Text $responseText -MaxLength 800)"
        }

        return $index
    }
    finally {
        if ($multipart) { $multipart.Dispose() }
        if ($client) { $client.Dispose() }
    }
}

function Send-DiscordWebhook {
    param($Payload)

    if (-not $EnableDiscordWebhook) {
        $script:DiscordStatus = "disabled"
        Write-RunLog "Discord delivery disabled."
        return
    }

    $target = Get-DiscordDeliveryTarget

    if (-not $target) {
        $script:DiscordStatus = "skipped_no_endpoint"
        $script:Report.Add("")
        $script:Report.Add("Discord delivery skipped: no relay URL, webhook URL, DPAPI secret, or environment variable was available.")
        Write-RunLog "Discord delivery skipped: no endpoint was available."
        return
    }

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }
    catch {
        Write-RunLog "Could not force TLS 1.2: $($_.Exception.Message)"
    }

    $payloadJson = $Payload | ConvertTo-Json -Depth 10
    $attachments = @($script:DiscordAttachments)
    $batches = @(Get-DiscordAttachmentBatches -Attachments $attachments)
    $script:DiscordAttachmentCount = $attachments.Count
    Write-RunLog "Discord delivery starting via $($target.Kind) with $($attachments.Count) attachment(s), $($batches.Count) batch(es), timeout $DiscordTimeoutSeconds second(s)."

    if ($DiscordDebug) {
        Write-DiscordDebugArtifacts -PayloadJson $payloadJson -Target $target -Batches $batches
        return
    }

    if ($attachments.Count -eq 0 -or $batches.Count -eq 0) {
        try {
            Invoke-DiscordJsonPost -Target $target -PayloadJson $payloadJson
            $script:DiscordStatus = "sent_embed_only_$($target.Kind)"
            $script:Report.Add("")
            $script:Report.Add("Discord delivery sent without attachments via $($target.Kind).")
            Write-RunLog "Discord delivery sent without attachments via $($target.Kind)."
            return
        }
        catch {
            $script:DiscordStatus = "failed"
            $script:DiscordLastError = $_.Exception.Message
            $script:Report.Add("")
            $script:Report.Add("Discord delivery failed via $($target.Kind): $($_.Exception.Message)")
            Write-RunLog "Discord delivery failed via $($target.Kind): $($_.Exception.Message)"
            return
        }
    }

    $sentFiles = 0
    $batchIndex = 1
    foreach ($batch in $batches) {
        $batchPayload = Build-DiscordBatchPayload -OriginalPayload $Payload -BatchIndex $batchIndex -BatchCount $batches.Count
        $batchPayloadJson = $batchPayload | ConvertTo-Json -Depth 10

        try {
            $sentInBatch = Invoke-DiscordMultipartPost -Target $target -PayloadJson $batchPayloadJson -Attachments $batch.Attachments
            $sentFiles += $sentInBatch
            Write-RunLog "Discord delivery batch $batchIndex/$($batches.Count) sent via $($target.Kind) with $sentInBatch attachment(s)."
        }
        catch {
            $multipartError = $_.Exception.Message
            $script:Report.Add("")
            $script:Report.Add("Discord delivery multipart batch $batchIndex/$($batches.Count) failed via $($target.Kind): $multipartError")
            Write-RunLog "Discord multipart batch $batchIndex/$($batches.Count) failed via $($target.Kind): $multipartError"

            if ($sentFiles -gt 0) {
                $script:DiscordStatus = "sent_partial_attachments_$($target.Kind)"
                $script:DiscordLastError = $multipartError
                $script:Report.Add("Discord delivery stopped after partial attachment delivery: $sentFiles file(s) sent.")
                return
            }

            try {
                Invoke-DiscordJsonPost -Target $target -PayloadJson $payloadJson
                $script:DiscordStatus = "sent_embed_only_after_attachment_failure_$($target.Kind)"
                $script:Report.Add("Discord delivery fallback sent embed only; attachments were not delivered.")
                Write-RunLog "Discord fallback sent embed only after attachment failure."
                return
            }
            catch {
                $script:DiscordStatus = "failed"
                $script:DiscordLastError = $_.Exception.Message
                $script:Report.Add("Discord delivery fallback failed via $($target.Kind): $($_.Exception.Message)")
                Write-RunLog "Discord fallback failed via $($target.Kind): $($_.Exception.Message)"
                return
            }
        }

        $batchIndex++
    }

    $script:DiscordStatus = "sent_with_attachments_$($target.Kind)"
    $script:Report.Add("")
    $script:Report.Add("Discord delivery sent with $sentFiles attachment(s) across $($batches.Count) batch(es) via $($target.Kind).")
    Write-RunLog "Discord delivery sent with $sentFiles attachment(s) across $($batches.Count) batch(es) via $($target.Kind)."
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

    if ($script:GameSessionLines.Count -gt 0) {
        Add-DiscordAttachment -FileName $script:GameSessionsFileName -Lines @($script:GameSessionLines) -ContentType "text/plain; charset=utf-8" -LocalPath $script:GameSessionsPath
    }

    if ($EnableBrowserHistoryScan) {
        Add-DiscordAttachment -FileName $script:FilteredHistoryFileName -Lines $historyLines -ContentType "text/plain; charset=utf-8" -LocalPath $script:FilteredHistoryPath
    }

    if ($script:ScreenshotCapturePath -and [System.IO.File]::Exists($script:ScreenshotCapturePath)) {
        try {
            $screenshotBytes = [System.IO.File]::ReadAllBytes($script:ScreenshotCapturePath)
            Add-DiscordAttachment -FileName $script:ScreenshotCaptureFileName -Bytes $screenshotBytes -ContentType $script:ScreenshotCaptureContentType
            Write-RunLog "Overlay screenshot added to Discord attachments: $script:ScreenshotCaptureFileName ($($screenshotBytes.Length) bytes)."

            if (-not $KeepTriggeredOverlayScreenshot) {
                try {
                    Remove-Item -LiteralPath $script:ScreenshotCapturePath -Force
                    Write-RunLog "Triggered overlay screenshot removed after being queued in memory: $script:ScreenshotCapturePath"
                }
                catch {
                    Write-RunLog "Could not remove triggered overlay screenshot $script:ScreenshotCapturePath`: $($_.Exception.Message)"
                }
            }
        }
        catch {
            Write-RunLog "Overlay screenshot attachment failed: $($_.Exception.Message)"
            $script:Report.Add("Overlay screenshot attachment failed: $($_.Exception.Message)")
        }
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

function Get-SafeArtifactFileName {
    param([string]$FileName)

    if (-not $FileName) { return "artifact.txt" }
    return ($FileName -replace '[\\/:*?"<>|]+', '_')
}

function Write-DiscordAttachmentToFile {
    param(
        $Attachment,
        [string]$Directory
    )

    if (-not $Attachment -or -not $Attachment.FileName) { return $null }
    $safeName = Get-SafeArtifactFileName $Attachment.FileName
    $path = Join-Path $Directory $safeName
    if ($Attachment.Bytes) {
        [System.IO.File]::WriteAllBytes($path, [byte[]]$Attachment.Bytes)
    }
    else {
        Set-Content -LiteralPath $path -Value ([string]$Attachment.Content) -Encoding UTF8
    }
    return $path
}

function Convert-BytesToSha256Hex {
    param([byte[]]$Bytes)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha.ComputeHash($Bytes)
        return (($hashBytes | ForEach-Object { $_.ToString("x2") }) -join "").ToUpperInvariant()
    }
    finally {
        if ($sha) { $sha.Dispose() }
    }
}

function Add-ZipEntryBytes {
    param(
        $ZipArchive,
        [string]$FileName,
        [byte[]]$Bytes
    )

    if (-not $ZipArchive -or -not $FileName) { return }

    $entry = $ZipArchive.CreateEntry((Get-SafeArtifactFileName $FileName), [System.IO.Compression.CompressionLevel]::Optimal)
    $stream = $entry.Open()
    try {
        if ($Bytes -and $Bytes.Length -gt 0) {
            $stream.Write($Bytes, 0, $Bytes.Length)
        }
    }
    finally {
        if ($stream) { $stream.Dispose() }
    }
}

function New-CaseBundle {
    if (-not $EnableCaseBundle) {
        Write-RunLog "Case bundle disabled."
        return
    }

    try {
        Add-Type -AssemblyName System.IO.Compression

        $bundleAttachments = @($script:DiscordAttachments)
        $hashLines = New-Object System.Collections.Generic.List[string]
        $hashLines.Add("TraceUSB integrity hashes")
        $hashLines.Add("Generated: $(Get-Date)")
        $hashLines.Add("CaseBundle: $script:CaseBundleFileName")
        $hashLines.Add("HashAlgorithm: SHA256")
        $hashLines.Add("")

        foreach ($attachment in @($bundleAttachments | Sort-Object FileName)) {
            if (-not $attachment -or -not $attachment.FileName) { continue }
            $bytes = Get-DiscordAttachmentBytes -Attachment $attachment
            $hash = Convert-BytesToSha256Hex -Bytes $bytes
            $hashLines.Add("$hash  $($attachment.FileName)")
        }

        Add-DiscordAttachment -FileName $script:IntegrityHashesFileName -Lines $hashLines -ContentType "text/plain; charset=utf-8"
        $integrityAttachment = @($script:DiscordAttachments | Where-Object { $_.FileName -eq $script:IntegrityHashesFileName } | Select-Object -Last 1)

        $memoryStream = New-Object System.IO.MemoryStream
        $zip = New-Object System.IO.Compression.ZipArchive($memoryStream, [System.IO.Compression.ZipArchiveMode]::Create, $true)
        try {
            foreach ($attachment in @($bundleAttachments)) {
                if (-not $attachment -or -not $attachment.FileName) { continue }
                Add-ZipEntryBytes -ZipArchive $zip -FileName $attachment.FileName -Bytes (Get-DiscordAttachmentBytes -Attachment $attachment)
            }
            foreach ($attachment in @($integrityAttachment)) {
                if (-not $attachment -or -not $attachment.FileName) { continue }
                Add-ZipEntryBytes -ZipArchive $zip -FileName $attachment.FileName -Bytes (Get-DiscordAttachmentBytes -Attachment $attachment)
            }
        }
        finally {
            if ($zip) { $zip.Dispose() }
        }

        $zipBytes = $memoryStream.ToArray()
        if ($memoryStream) { $memoryStream.Dispose() }

        Add-DiscordAttachment -FileName $script:CaseBundleFileName -Bytes $zipBytes -ContentType "application/zip"
        Write-RunLog "Case bundle created in memory: $script:CaseBundleFileName ($($zipBytes.Length) bytes)."

        if ($SaveLocalArtifacts) {
            Ensure-OutputDirectory
            Set-Content -LiteralPath $script:IntegrityHashesPath -Value $hashLines -Encoding UTF8
            [System.IO.File]::WriteAllBytes($script:CaseBundlePath, $zipBytes)
            Write-RunLog "Case bundle also saved locally: $script:CaseBundlePath"
        }
    }
    catch {
        Write-RunLog "Case bundle creation failed: $($_.Exception.Message)"
        $script:Report.Add("")
        $script:Report.Add("Case bundle creation failed: $($_.Exception.Message)")
    }
}

function Write-Outputs {
    if ($SaveLocalArtifacts) {
        Ensure-OutputDirectory
        Write-RunLog "Writing local artifacts to $script:OutputDirectory."
    }
    else {
        Write-RunLog "Local artifact writing disabled; reports will be prepared in memory for Discord delivery only."
    }

    Build-DiscordArtifacts
    Write-Summary

    $timelineLines = @(
        $script:Timeline |
            Where-Object { $_.Time } |
            Sort-Object Time |
            ForEach-Object {
                "$($_.Time) | [$($_.Category)] | $($_.Event) | $($_.Details)"
            }
    )

    if ($SaveLocalArtifacts) {
        [System.IO.File]::WriteAllLines($script:ReportPath, $script:Report, [System.Text.Encoding]::UTF8)
        Set-Content -LiteralPath $script:TimelinePath -Value $timelineLines -Encoding UTF8
        if ($script:GameSessionLines.Count -gt 0) {
            Set-Content -LiteralPath $script:GameSessionsPath -Value $script:GameSessionLines -Encoding UTF8
        }
    }

    if ($script:NetworkSnapshot.Count -gt 0) {
        if ($SaveLocalArtifacts) {
            Set-Content -LiteralPath $script:NetworkSnapshotPath -Value $script:NetworkSnapshot -Encoding UTF8
        }
        Add-DiscordAttachment -FileName $script:NetworkSnapshotFileName -Lines $script:NetworkSnapshot -ContentType "text/plain; charset=utf-8"
    }
    if ($script:SystemContext.Count -gt 0) {
        if ($SaveLocalArtifacts) {
            Set-Content -LiteralPath $script:SystemContextPath -Value $script:SystemContext -Encoding UTF8
        }
        Add-DiscordAttachment -FileName $script:SystemContextFileName -Lines $script:SystemContext -ContentType "text/plain; charset=utf-8"
    }
    if ($SaveLocalArtifacts) {
        Write-RunLog "Local report written: $script:ReportPath"
        Write-RunLog "Local timeline written: $script:TimelinePath"
    }

    Add-DiscordAttachment -FileName $script:ReportFileName -Lines $script:Report -ContentType "text/plain; charset=utf-8"
    Add-DiscordAttachment -FileName $script:TimelineFileName -Lines $timelineLines -ContentType "text/plain; charset=utf-8"
    $script:DiscordAttachmentCount = $script:DiscordAttachments.Count
    Write-RunLog "Report and timeline added to Discord attachments."
    Write-RunLogFile
    Add-DiscordAttachment -FileName $script:RunLogFileName -Lines $script:RunLog -ContentType "text/plain; charset=utf-8"
    New-CaseBundle
    $script:DiscordAttachmentCount = $script:DiscordAttachments.Count

    Publish-DiscordArtifacts

    $script:Report.Add("")
    $script:Report.Add("==== Delivery ====")
    $script:Report.Add("")
    $script:Report.Add("Discord status: $script:DiscordStatus")
    $script:Report.Add("Discord attachments prepared: $script:DiscordAttachmentCount")
    if ($script:DiscordLastError) { $script:Report.Add("Discord error: $script:DiscordLastError") }
    if ($SaveLocalArtifacts) {
        $script:Report.Add("Run log: $script:RunLogPath")
        if ([System.IO.File]::Exists($script:GameSessionsPath)) { $script:Report.Add("Game sessions: $script:GameSessionsPath") }
        if ([System.IO.File]::Exists($script:NetworkSnapshotPath)) { $script:Report.Add("Network snapshot: $script:NetworkSnapshotPath") }
        if ([System.IO.File]::Exists($script:SystemContextPath)) { $script:Report.Add("System context: $script:SystemContextPath") }
        if ([System.IO.File]::Exists($script:IntegrityHashesPath)) { $script:Report.Add("Integrity hashes: $script:IntegrityHashesPath") }
        if ([System.IO.File]::Exists($script:CaseBundlePath)) { $script:Report.Add("Case bundle: $script:CaseBundlePath") }
        [System.IO.File]::WriteAllLines($script:ReportPath, $script:Report, [System.Text.Encoding]::UTF8)
    }
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
        Add-Evidence -Time (Get-Date) -Category "Operational" -Source "AuditPolicy" -Confidence 20 -Reasons @("Audit policy requested without administrator rights") -Details "Could not enable Process Creation/Termination auditing" | Out-Null
        return
    }

    try {
        auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
        auditpol /set /subcategory:"Process Termination" /success:enable /failure:disable | Out-Null
        Add-Evidence -Time (Get-Date) -Category "Operational" -Source "AuditPolicy" -Confidence 20 -Reasons @("Operator enabled Process Creation/Termination auditing") -Details "Process Creation and Process Termination auditing enabled" | Out-Null
    }
    catch {
        Add-Evidence -Time (Get-Date) -Category "Operational" -Source "AuditPolicy" -Confidence 20 -Reasons @("Audit policy change failed") -Details $_.Exception.Message | Out-Null
    }
}

function Invoke-DiscordSelfTest {
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

Collect-SystemContext
Enable-ProcessAuditPolicy
Collect-LogClearingEvents
Collect-UsbEvents
Collect-DefenderEvents
Collect-ProcessEvents
Collect-PrefetchEvents
Collect-BamEvents
Collect-ServiceEvents
Collect-GameSessionActivity
Collect-RuntimeContext
Collect-NetworkAnomalies
Complete-Correlation
Invoke-ScreenshotTrigger
Write-Outputs

if ($SaveLocalArtifacts -and -not $NoOpen) {
    Start-Process notepad.exe $script:ReportPath
    Start-Process notepad.exe $script:TimelinePath
}

Write-ConsoleSummary
