# ======================================
# INICIALIZAÇÃO
# ======================================

$desktop = [Environment]::GetFolderPath("Desktop")
$output = "$desktop\analise.txt"
$timelinePath = "$desktop\timeline.txt"

$result = New-Object System.Collections.Generic.List[string]
$timeline = @()

function Write-Section {
    param($title)
    $result.Add("")
    $result.Add("==== $title ====")
    $result.Add("")
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
# FINAL
# ======================================

# Arquivo principal
[System.IO.File]::WriteAllLines($output, $result, [System.Text.Encoding]::UTF8)

# Timeline
$timelineOutput = $timeline |
Sort-Object Time -Descending |
ForEach-Object {
    "{0} | {1} | {2} | {3}" -f $_.Time, $_.Tipo, $_.Evento, $_.Detalhes
}

[System.IO.File]::WriteAllLines($timelinePath, $timelineOutput, [System.Text.Encoding]::UTF8)

# Abrir ambos
Start-Process notepad.exe $output
Start-Process notepad.exe $timelinePath