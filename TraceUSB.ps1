# ======================================
# INICIALIZAÇÃO
# ======================================

$desktop = [Environment]::GetFolderPath("Desktop")
$output = "$desktop\analise.txt"

$result = New-Object System.Collections.Generic.List[string]

function Write-Section {
    param($title)
    $result.Add("")
    $result.Add("==== $title ====")
    $result.Add("")
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
}

# ======================================
# 2. COLETA USB
# ======================================

$usbHistorico = @()

$devices = Get-PnpDevice -Class USB -PresentOnly:$false -ErrorAction SilentlyContinue

foreach ($dev in $devices) {

    if (-not $dev.FriendlyName) { continue }
    if ($dev.FriendlyName -match "Hub|Host Controller|Root") { continue }

    $props = Get-PnpDeviceProperty -InstanceId $dev.InstanceId -ErrorAction SilentlyContinue
    if (-not $props) { continue }

    $arrival = ($props | Where-Object { $_.KeyName -like "*LastArrivalDate*" }).Data
    $removal = ($props | Where-Object { $_.KeyName -like "*LastRemovalDate*" }).Data

    if ($arrival -or $removal) {
        $usbHistorico += [PSCustomObject]@{
            Nome      = $dev.FriendlyName
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

    $result.Add("Nome do dispositivo: $($_.Nome)")
    $result.Add("Data/Horario de Conexao: $($_.Conectado)")
    $result.Add("Data/Horario de Desconexao: $($_.Removido)")
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
    $result.Add("Nome do dispositivo: $($_.FriendlyName)")
}

# ======================================
# 6. WINDOWS DEFENDER
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
}

# ======================================
# 7. WINDOWS DEFENDER (CONFIGURACAO E FALHAS)
# ======================================

Write-Section "WINDOWS DEFENDER (CONFIGURACAO E FALHAS)"

Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Windows Defender/Operational'
    Id = 5004,5010
} -ErrorAction SilentlyContinue |
Sort-Object TimeCreated -Descending |
ForEach-Object {

    $msg = $_.Message
    $cleanMsg = ($msg -replace "`r|`n", " ").Trim()

    $evento = switch ($_.Id) {
        5004 { "Configuracao alterada" }
        5010 { "Falha no engine" }
        default { "Evento desconhecido" }
    }

    $result.Add("Data/Horario: $($_.TimeCreated)")
    $result.Add("Evento: $evento")
    $result.Add("Detalhes: $cleanMsg")
    $result.Add("")
}

# ======================================
# 8. WINDOWS DEFENDER (STATUS - DESATIVACAO)
# ======================================

Write-Section "WINDOWS DEFENDER (STATUS)"

Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Windows Defender/Operational'
    Id = 5001
} -ErrorAction SilentlyContinue |
Sort-Object TimeCreated -Descending |
ForEach-Object {

    $msg = $_.Message

    # opcional: limpar mensagem (remover quebra de linha excessiva)
    $cleanMsg = ($msg -replace "`r|`n", " ").Trim()

    $result.Add("Data/Horario: $($_.TimeCreated)")
    $result.Add("Evento: Windows Defender desativado")
    $result.Add("Detalhes: $cleanMsg")
    $result.Add("")
}

# ======================================
# FINAL
# ======================================

[System.IO.File]::WriteAllLines($output, $result, [System.Text.Encoding]::UTF8)
Start-Process notepad.exe $output