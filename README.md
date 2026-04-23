# TraceUSB

Lightweight Windows USB and system event analyzer with clean, local-only output.

---

## Overview

TraceUSB is a PowerShell-based utility designed to extract **objective system event data** related to USB activity and security-relevant logs on Windows systems.

It generates a **structured, human-readable report** without performing interpretation, scoring, or behavioral assumptions.

---

## Features

* USB connection and removal timestamps
* Detection of Windows log clearing events (Event ID 104)
* Windows Defender detection events (Event IDs 1116 / 1117)
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

TraceUSB collects data from three main sources:

---

### 1. Log Clearing Events (Event ID 104)

Source: Windows Event Log (System)

Detects when a Windows event log has been manually cleared.

Collected data:

* Log name (e.g. System, Security, Setup)
* Date and time of the action

Purpose:

* Identify potential attempts to remove system activity traces

---

### 2. USB Device Activity

Source: Plug and Play (PnP) subsystem

#### Connected and Removed Devices

Collected data:

* Device name (FriendlyName)
* Date and time of connection
* Date and time of removal

These timestamps come from:

```text
Get-PnpDeviceProperty → LastArrivalDate / LastRemovalDate
```

#### Only Connected Devices

Devices that:

* Have a connection timestamp
* Do not have a recorded removal event

This may indicate:

* Device still connected
* Removal not recorded by the system

---

### 3. Active USB Devices

Source: Current device state via PnP

Collected data:

* Device name of all currently connected USB devices

Filtering removes:

* USB hubs
* Host controllers
* Root devices

Purpose:

* Provide a snapshot of what is physically connected at execution time

---

### 4. Windows Defender Events (1116 / 1117)

Source:
`Microsoft-Windows-Windows Defender/Operational`

#### Event ID 1116 — Malware Detected

Indicates that Windows Defender detected a threat.

#### Event ID 1117 — Action Taken

Indicates that Defender took action (removal, quarantine, etc.)

Collected data:

* Date and time of the event
* Threat name
* File path associated with the detection

Important:

* Only metadata is collected
* No file content is accessed

Purpose:

* Provide visibility into recent security detections on the system

---

## Data Sources

TraceUSB relies exclusively on native Windows components:

* `Get-WinEvent` → Event logs
* `Get-PnpDevice` → Device enumeration
* `Get-PnpDeviceProperty` → USB timestamps

No external dependencies.

---

## Privacy & Security

TraceUSB is **fully local and non-invasive**.

It **does NOT collect, access, or transmit**:

* Personal files
* File contents
* Browser history
* Credentials or tokens
* Network traffic
* Any external data

It only reads:

* System event metadata
* USB device metadata (name and timestamps)

No data leaves the machine.

---

## Requirements

* Windows 10 / 11
* PowerShell 5.1 or higher
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

### Safer method (download + execute)

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

---

## Limitations

* Not all USB devices expose connection/removal timestamps
* Data depends on drivers and Windows internals
* Does not reconstruct full usage sessions

---

## Project Structure

```text
.
├── TraceUSB.ps1
├── README.md
├── LICENSE
├── .gitignore
└── CHANGELOG.md
```

---

## Versioning

Semantic versioning is used.

---

## Contributing

Contributions are welcome, especially for:

* Improved parsing
* Additional event sources
* Performance optimization

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
