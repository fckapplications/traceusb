# TraceUSB

Lightweight Windows USB and system event analyzer with clean, local-only output.

---

## Overview

TraceUSB is a PowerShell-based utility designed to extract **objective system event data** related to USB activity and security-relevant logs on Windows systems.

It provides a **structured, human-readable report** without performing any interpretation, scoring, or behavioral assumptions.

---

## Features

* USB connection and removal timestamps
* Detection of Windows log clearing events (Event ID 104)
* Windows Defender detections (Event IDs 1116 / 1117)
* List of currently connected USB devices
* Clean, structured output for quick analysis

---

## Output

The script generates a report at:

```text
Desktop\analise.txt
```

---

## Data Sources

TraceUSB relies exclusively on native Windows components:

* `Get-WinEvent` → Event logs
* `Get-PnpDevice` → Device enumeration
* `Get-PnpDeviceProperty` → USB timestamps

No external dependencies are required.

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

### Run remotely (quick execution)

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
* Data availability depends on drivers and Windows internals
* Does not reconstruct full device usage sessions

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

This project follows semantic versioning.

---

## Contributing

Contributions are welcome, especially for:

* Improved parsing
* Additional log sources
* Performance optimizations

---

## Disclaimer

This tool is intended for:

* Educational purposes
* Local diagnostics
* System auditing

Use responsibly.

---

## License

MIT License
