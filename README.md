# TraceUSB

Lightweight Windows USB and system event analyzer with clean, local-only output.

---

## Overview

TraceUSB is a PowerShell-based utility designed to extract **objective system event data** related to USB activity and security-relevant logs on Windows systems.

It generates a **structured, human-readable report** without interpretation, scoring, or behavioral assumptions.

The goal is simple: provide **clear visibility** into what happened on the machine.

---

## Features

* USB connection and removal timestamps
* Detection of Windows log clearing events (Event ID 104)
* Windows Defender detections (Event IDs 1116 / 1117)
* Windows Defender status changes (Event ID 5001)
* Windows Defender configuration changes (Event ID 5004)
* Windows Defender engine failures (Event ID 5010)
* Listing of currently connected USB devices
* Clean and structured output

---

## Output

The script generates a report at:

```text
Desktop\analise.txt
```

---

## What the Script Analyzes

TraceUSB collects data from multiple native Windows sources.

---

### 1. Log Clearing Events (Event ID 104)

Source: Windows Event Log (System)

Detects when a Windows log has been manually cleared.

Collected data:

* Log name (e.g. System, Security, Setup)
* Date and time

Purpose:

* Identify potential attempts to remove activity traces

---

### 2. USB Device Activity

Source: Plug and Play (PnP)

#### Connected and Removed Devices

Collected data:

* Device name
* Connection timestamp
* Removal timestamp

Source:

```
Get-PnpDeviceProperty → LastArrivalDate / LastRemovalDate
```

---

#### Only Connected Devices

Devices that:

* Have a connection timestamp
* Do not have a recorded removal

Possible scenarios:

* Device still connected
* Removal not recorded by the system

---

### 3. Active USB Devices

Snapshot of all currently connected USB devices.

Filtering removes:

* Hubs
* Host controllers
* Root devices

Purpose:

* Show what is physically connected at execution time

---

### 4. Windows Defender — Detection Events (1116 / 1117)

Source:
`Microsoft-Windows-Windows Defender/Operational`

* **1116 → Threat detected**
* **1117 → Action taken**

Collected data:

* Date and time
* Threat name
* File path

---

### 5. Windows Defender — Status (5001)

Indicates that Microsoft Defender Antivirus was **disabled**.

Collected data:

* Date and time
* Full event message

Purpose:

* Detect when system protection was turned off

---

### 6. Windows Defender — Configuration Changes (5004)

Indicates that a Defender setting was modified.

Examples:

* Exclusions added
* Protection toggled
* Policy changes

Collected data:

* Date and time
* Event message

---

### 7. Windows Defender — Engine Failures (5010)

Indicates that Defender failed to execute an operation.

Possible causes:

* Internal error
* Scan failure
* External interference

Collected data:

* Date and time
* Event message

---

## Data Sources

* `Get-WinEvent`
* `Get-PnpDevice`
* `Get-PnpDeviceProperty`

No external dependencies.

---

## Privacy & Security

TraceUSB is **fully local and non-invasive**.

It does NOT:

* Read personal files
* Access file contents
* Collect credentials
* Monitor network activity
* Send any data externally

It only reads:

* System event metadata
* USB device metadata

No data leaves the machine.

---

## Requirements

* Windows 10 / 11
* PowerShell 5.1+
* Standard user permissions

---

## Usage

### Run locally

```powershell
.\TraceUSB.ps1
```

---

### Run remotely

```powershell
irm https://raw.githubusercontent.com/fckapplications/traceusb/main/TraceUSB.ps1 | iex
```

---

### Run with execution policy bypass

```powershell
powershell -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/fckapplications/traceusb/main/TraceUSB.ps1 | iex"
```

---

### Safer method

```powershell
irm https://raw.githubusercontent.com/fckapplications/traceusb/main/TraceUSB.ps1 -OutFile traceusb.ps1
powershell -ExecutionPolicy Bypass -File traceusb.ps1
```

---

## Output Structure

The report is divided into:

* Log clearing events
* USB (connected and removed)
* USB (only connected)
* Active USB devices
* Windows Defender detections
* Windows Defender configuration & failures
* Windows Defender status changes

---

## Limitations

* Not all USB devices expose timestamps
* Data depends on drivers and Windows internals
* Does not reconstruct full activity sessions

---

## Project Structure

```
.
├── TraceUSB.ps1
├── README.md
├── LICENSE
├── .gitignore
└── CHANGELOG.md
```

---

## Contributing

Contributions are welcome:

* Parsing improvements
* New event sources
* Performance optimizations

---

## Disclaimer

This tool is intended for:

* Educational use
* Local diagnostics
* System auditing

Use responsibly.

---

## License

MIT License
