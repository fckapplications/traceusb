# ======================================
# INICIALIZAÇÃO
# ======================================

$desktop = [Environment]::GetFolderPath("Desktop")
$output = "$desktop\analise.txt"
$timelinePath = "$desktop\timeline.txt"

$result = New-Object System.Collections.Generic.List[string]
$timeline = @()

# ======================================
# HABILITAR AUDITORIA DE PROCESSOS (4688)
# ======================================

$isAdmin = (
    New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if ($isAdmin) {

    try {
        auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
    }
    catch {}
}

function Write-Section {
    param($title)
    $result.Add("")
    $result.Add("==== $title ====")
    $result.Add("")
}

function Add-TimelineEvent {
    param(
        [datetime]$Time,
        [string]$Tipo,
        [string]$Evento,
        [string]$Detalhes
    )

    $timeline += [PSCustomObject]@{
        Time      = $Time
        Tipo      = $Tipo
        Evento    = $Evento
        Detalhes  = $Detalhes
    }
}

function Get-USBTipo {
    param($name)

    if ($name -match "Mass Storage|Storage|Flash|Disk") { return "Armazenamento" }
    if ($name -match "Audio|Headset|Microphone") { return "Audio" }
    if ($name -match "Keyboard|Mouse|Input") { return "Entrada" }
    if ($name -match "Camera|Imaging") { return "Camera" }

    return "Desconhecido"
}

function Get-Duration {
    param($start, $end)

    if (-not $start -or -not $end) { return $null }

    $span = New-TimeSpan -Start $start -End $end
    return "{0:hh\:mm\:ss}" -f $span
}
function Test-RemovablePath {
    param($path)

    if (-not $path) {
        return $false
    }

    $driveLetter = $path.Substring(0,1)

    try {
        $disk = Get-CimInstance Win32_LogicalDisk |
            Where-Object {
                $_.DeviceID -eq "$driveLetter`:"
            }

        if ($disk -and $disk.DriveType -eq 2) {
            return $true
        }
    }
    catch {}

    return $false
}

# ======================================
# 1. LIMPEZA DE LOGS
# ======================================

Write-Section "LIMPEZA DE LOGS"

Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    Id = 104
} -ErrorAction SilentlyContinue |
Sort-Object TimeCreated -Descending |
ForEach-Object {

    $msg = $_.Message
    $logMatch = [regex]::Match($msg, "log\s+(.+?)\s+foi", "IgnoreCase")

    $logName = if ($logMatch.Success) {
        $logMatch.Groups[1].Value
    } else {
        "Desconhecido"
    }

    $result.Add("Log: $logName")
    $result.Add("Data/Horario: $($_.TimeCreated)")
    $result.Add("")

    $timeline += [PSCustomObject]@{
        Time = $_.TimeCreated
        Tipo = "SYSTEM"
        Evento = "Log limpo"
        Detalhes = $logName
    }
}

# ======================================
# 2. COLETA USB
# ======================================

$usbHistorico = @()

$devices = Get-PnpDevice -Class USB -PresentOnly:$false -ErrorAction SilentlyContinue

foreach ($dev in $devices) {

    if (-not $dev.FriendlyName) { continue }
    if ($dev.FriendlyName -match "Hub|Host Controller|Root") { continue }

    $tipo = Get-USBTipo $dev.FriendlyName

    $props = Get-PnpDeviceProperty -InstanceId $dev.InstanceId -ErrorAction SilentlyContinue
    if (-not $props) { continue }

    $arrival = ($props | Where-Object { $_.KeyName -like "*LastArrivalDate*" }).Data
    $removal = ($props | Where-Object { $_.KeyName -like "*LastRemovalDate*" }).Data

    if ($arrival -or $removal) {

        if ($arrival) {
            $timeline += [PSCustomObject]@{
                Time = $arrival
                Tipo = "USB"
                Evento = "Conectado"
                Detalhes = "$($dev.FriendlyName) ($tipo)"
            }
        }

        if ($removal) {
            $timeline += [PSCustomObject]@{
                Time = $removal
                Tipo = "USB"
                Evento = "Removido"
                Detalhes = "$($dev.FriendlyName) ($tipo)"
            }
        }

        $usbHistorico += [PSCustomObject]@{
            Nome      = $dev.FriendlyName
            Tipo      = $tipo
            Conectado = $arrival
            Removido  = $removal
        }
    }
}

# ======================================
# 3. USB (CONECTADO E REMOVIDO)
# ======================================

Write-Section "USB (CONECTADO E REMOVIDO)"

$usbHistorico |
Where-Object { $_.Conectado -and $_.Removido } |
Sort-Object Conectado -Descending |
ForEach-Object {

    $duracao = Get-Duration $_.Conectado $_.Removido

    $result.Add("Nome do dispositivo: $($_.Nome)")
    $result.Add("Tipo: $($_.Tipo)")
    $result.Add("Data/Horario de Conexao: $($_.Conectado)")
    $result.Add("Data/Horario de Desconexao: $($_.Removido)")

    if ($duracao) {
        $result.Add("Duracao de uso: $duracao")
    }

    $result.Add("")
}

# ======================================
# 4. USB (APENAS CONECTADO)
# ======================================

Write-Section "USB (APENAS CONECTADO)"

$usbHistorico |
Where-Object { $_.Conectado -and -not $_.Removido } |
Sort-Object Conectado -Descending |
ForEach-Object {

    $result.Add("Nome do dispositivo: $($_.Nome)")
    $result.Add("Tipo: $($_.Tipo)")
    $result.Add("Data/Horario de Conexao: $($_.Conectado)")
    $result.Add("Data/Horario de Desconexao: NAO REGISTRADO")
    $result.Add("")
}

# ======================================
# 5. USB ATIVOS
# ======================================

Write-Section "USB ATIVOS NO MOMENTO"

Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
Where-Object {
    $_.InstanceId -match "^USB" -and
    $_.FriendlyName -and
    $_.FriendlyName -notmatch "Hub|Host Controller|Root"
} |
Sort-Object FriendlyName |
ForEach-Object {

    $tipo = Get-USBTipo $_.FriendlyName
    $result.Add("Nome do dispositivo: $($_.FriendlyName)")
    $result.Add("Tipo: $tipo")
}

# ======================================
# 6. WINDOWS DEFENDER (1116/1117)
# ======================================

Write-Section "WINDOWS DEFENDER"

Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Windows Defender/Operational'
    Id = 1116,1117
} -ErrorAction SilentlyContinue |
Sort-Object TimeCreated -Descending |
ForEach-Object {

    $msg = $_.Message

    $threatMatch = [regex]::Match($msg, "Nome da ameaça:\s*(.+)")
    $pathMatch   = [regex]::Match($msg, "Caminho:\s*(.+)")

    $threat = if ($threatMatch.Success) { $threatMatch.Groups[1].Value } else { "N/A" }
    $path   = if ($pathMatch.Success) { $pathMatch.Groups[1].Value } else { "N/A" }

    $result.Add("Data/Horario: $($_.TimeCreated)")
    $result.Add("Ameaca: $threat")
    $result.Add("Arquivo: $path")
    $result.Add("")

    # Timeline
    $timeline += [PSCustomObject]@{
        Time = $_.TimeCreated
        Tipo = "DEFENDER"
        Evento = "Deteccao"
        Detalhes = $threat
    }
}

# ======================================
# 7. DEFENDER (5004 / 5010)
# ======================================

Write-Section "WINDOWS DEFENDER (CONFIGURACAO E FALHAS)"

Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Windows Defender/Operational'
    Id = 5004,5010
} -ErrorAction SilentlyContinue |
Sort-Object TimeCreated -Descending |
ForEach-Object {

    $cleanMsg = ($_.Message -replace "`r|`n", " ").Trim()

    $evento = switch ($_.Id) {
        5004 { "Configuracao alterada" }
        5010 { "Falha no engine" }
    }

    $result.Add("Data/Horario: $($_.TimeCreated)")
    $result.Add("Evento: $evento")
    $result.Add("Detalhes: $cleanMsg")
    $result.Add("")

    # Timeline
    $timeline += [PSCustomObject]@{
        Time = $_.TimeCreated
        Tipo = "DEFENDER"
        Evento = $evento
        Detalhes = $cleanMsg
    }
}

# ======================================
# 8. DEFENDER (5001)
# ======================================

Write-Section "WINDOWS DEFENDER (STATUS)"

Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Windows Defender/Operational'
    Id = 5001
} -ErrorAction SilentlyContinue |
Sort-Object TimeCreated -Descending |
ForEach-Object {

    $cleanMsg = ($_.Message -replace "`r|`n", " ").Trim()

    $result.Add("Data/Horario: $($_.TimeCreated)")
    $result.Add("Evento: Windows Defender desativado")
    $result.Add("Detalhes: $cleanMsg")
    $result.Add("")

    # Timeline
    $timeline += [PSCustomObject]@{
        Time = $_.TimeCreated
        Tipo = "DEFENDER"
        Evento = "Desativado"
        Detalhes = $cleanMsg
    }
}

# ======================================
# 9. PROCESSOS RECENTES (4688)
# ======================================

Write-Section "PROCESSOS RECENTES"

try {

    $processEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id = 4688
        StartTime = (Get-Date).AddHours(-24)
    } -ErrorAction Stop |
    Sort-Object TimeCreated -Descending

    foreach ($evt in $processEvents) {

        $msg = $evt.Message

        $processMatch = [regex]::Match($msg, 'Novo Nome do Processo:\s+(.+)')
        $parentMatch  = [regex]::Match($msg, 'Nome do Processo Criador:\s+(.+)')

        $processPath = if ($processMatch.Success) {
            $processMatch.Groups[1].Value.Trim()
        } else {
            "N/A"
        }

        $parentPath = if ($parentMatch.Success) {
            $parentMatch.Groups[1].Value.Trim()
        } else {
            "N/A"
        }

        $processName = Split-Path $processPath -Leaf
        $isUSB = Test-RemovablePath $processPath

        if ($isUSB) {

            $result.Add("Processo: $processName")
            $result.Add("Origem: Unidade removivel")
            $result.Add("Caminho: $processPath")
            $result.Add("Processo Pai: $parentPath")
            $result.Add("Data/Horario: $($evt.TimeCreated)")
            $result.Add("")

            $timeline += [PSCustomObject]@{
                Time = $evt.TimeCreated
                Tipo = "PROCESS"
                Evento = "Execucao via USB"
                Detalhes = $processPath
            }
        }
    }
}
catch {

    $result.Add("Nao foi possivel acessar Event ID 4688.")
    $result.Add("Execute o PowerShell como Administrador.")
    $result.Add("")
}

# ======================================
# 10. PREFETCH RELEVANTE
# ======================================

Write-Section "PREFETCH RELEVANTE"

$prefetchPath = "C:\Windows\Prefetch"

# Padrões interessantes
$suspiciousPatterns = @(
    "TEMP",
    "TMP",
    "SETUP",
    "UPDATE",
    "UPDATER",
    "INSTALL",
    "PATCH",
    "_UNINS",
    "LOADER"
)

if (Test-Path $prefetchPath) {

    Get-ChildItem "$prefetchPath\*.pf" -ErrorAction SilentlyContinue |
    Where-Object {
        $_.LastWriteTime -ge (Get-Date).AddHours(-24)
    } |
    Sort-Object LastWriteTime -Descending |
    ForEach-Object {

        $exeName = ($_.BaseName -replace "-.*", "").ToUpper()

        $isRelevant = $false

        # Nome altamente randomizado
        if ($exeName -match '^[A-Z0-9]{10,}$') {
            $isRelevant = $true
        }

        # Caracteres unicode / idiomas diferentes
        elseif ($exeName -match '[^\u0000-\u007F]') {
            $isRelevant = $true
        }

        # TMP / transient loaders
        elseif (
            $exeName.Contains("TMP") -or
            $exeName.Contains("_UNINS") -or
            $exeName.Contains("LOADER")
        ) {
            $isRelevant = $true
        }

        $isKnownNoise = $false

        foreach ($noise in $knownTransitionalNoise) {

        if ($exeName.Contains($noise)) {
        $isKnownNoise = $true
        break
        }
        }

        if ($isKnownNoise) {
        return
        }

        # Padrões transitórios
        foreach ($pattern in $suspiciousPatterns) {

            if ($exeName.Contains($pattern)) {
                $isRelevant = $true
                break
            }
        }

        if (-not $isRelevant) {
            return
        }

        $result.Add("[!] Execucao relevante detectada")
        $result.Add("Executavel: $exeName")
        $result.Add("Ultima execucao: $($_.LastWriteTime)")
        $result.Add("Arquivo: $($_.Name)")
        $result.Add("")

        Add-TimelineEvent `
            -Time $_.LastWriteTime `
            -Tipo "PREFETCH" `
            -Evento "Execucao relevante registrada" `
            -Detalhes $exeName
    }
}

# ======================================
# 11. BAM (EXECUCOES RECENTES)
# ======================================

Write-Section "BAM (EXECUCOES RECENTES)"

$bamPath = "HKLM:\System\CurrentControlSet\Services\bam\State\UserSettings"

# Ignorar ruido do sistema
$bamIgnore = @(
    "SVCHOST",
    "CONHOST",
    "RUNDLL32",
    "DWM",
    "TASKHOSTW",
    "DLLHOST",
    "SEARCHHOST",
    "SEARCHFILTERHOST",
    "SEARCHPROTOCOLHOST",
    "STARTMENUEXPERIENCEHOST",
    "SHELLEXPERIENCEHOST",
    "CTFMON",
    "EXPLORER",
    "CONSENT"
)

if (Test-Path $bamPath) {

    Get-ChildItem $bamPath -ErrorAction SilentlyContinue |
    ForEach-Object {

        try {

            $props = Get-ItemProperty $_.PSPath

            foreach ($property in $props.PSObject.Properties) {

                $name = $property.Name

                # Apenas executáveis e apps relevantes
                if (
                    $name -match "\.exe" -or
                    $name -match "Microsoft\."
                ) {

                    # Nome amigável
                    $displayName = Split-Path $name -Leaf

                    if (-not $displayName) {
                        $displayName = $name
                    }

                    $displayUpper = $displayName.ToUpper()

                    # Ignorar ruído
                    $skip = $false

                    foreach ($ignored in $bamIgnore) {

                        if ($displayUpper.StartsWith($ignored)) {
                            $skip = $true
                            break
                        }
                    }

                    if ($skip) {
                        continue
                    }

                    # Timestamp BAM
                    $bamTime = $null

                    try {

                        if ($property.Value.Length -ge 8) {

                            $fileTime = [BitConverter]::ToInt64(
                                $property.Value,
                                0
                            )

                            $bamTime = [datetime]::FromFileTime($fileTime)
                        }

                    }
                    catch {}

                    $result.Add("Executavel: $displayName")

                    if ($bamTime) {
                        $result.Add("Ultima execucao: $bamTime")
                    }

                    $result.Add("Origem: $name")
                    $result.Add("")

                    if ($bamTime) {

                        Add-TimelineEvent `
                            -Time $bamTime `
                            -Tipo "BAM" `
                            -Evento "Execucao registrada no BAM" `
                            -Detalhes $displayName
                    }
                }
            }

        }
        catch {}
    }
}

# ======================================
# 12. ARTIFACTS RECENTES
# ======================================

Write-Section "ARTIFACTS RECENTES"

$artifactPaths = @(
    "$env:USERPROFILE\Downloads",
    "$env:TEMP",
    "$env:LOCALAPPDATA\Temp"
)

foreach ($path in $artifactPaths) {

    if (-not (Test-Path $path)) {
        continue
    }

    Get-ChildItem $path -Recurse -ErrorAction SilentlyContinue |
    Where-Object {
        -not $_.PSIsContainer -and
        $_.LastWriteTime -ge (Get-Date).AddDays(-1) -and
        (
            $_.Extension -eq ".exe" -or
            $_.Extension -eq ".dll"
        )
    } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 50 |
    ForEach-Object {

        $result.Add("Arquivo: $($_.FullName)")
        $result.Add("Ultima modificacao: $($_.LastWriteTime)")
        $result.Add("")

        Add-TimelineEvent `
            -Time $_.LastWriteTime `
            -Tipo "ARTIFACT" `
            -Evento "Arquivo recente" `
            -Detalhes $_.FullName
    }
}

# ======================================
# FINAL
# ======================================

# Arquivo principal
[System.IO.File]::WriteAllLines($output, $result, [System.Text.Encoding]::UTF8)

# Timeline
$timeline |
Sort-Object Time |
ForEach-Object {

    "$($_.Time) | [$($_.Tipo)] | $($_.Evento) | $($_.Detalhes)"

} | Set-Content $timelinePath -Encoding UTF8

[System.IO.File]::WriteAllLines($timelinePath, $timelineOutput, [System.Text.Encoding]::UTF8)

# Abrir ambos
Start-Process notepad.exe $output
Start-Process notepad.exe $timelinePath