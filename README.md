# TraceUSB

Lightweight Windows USB and execution intelligence analyzer with local-only forensic output.

---

## Overview

TraceUSB is a PowerShell-based forensic utility designed to extract objective Windows telemetry related to:

- USB device activity
- Process execution
- Runtime overlays
- Windows Defender events
- Behavioral correlation

The project focuses on:

- Low-noise forensic visibility
- Correlated execution evidence
- Context-aware analysis
- Chronological reconstruction
- Human-readable output

Instead of dumping every available artifact, TraceUSB prioritizes suspicious and behaviorally relevant activity.

All analysis is performed locally using native Windows telemetry sources.

---

## Core Capabilities

### USB Analysis

TraceUSB can reconstruct USB-related activity using native Plug and Play telemetry.

Features include:

- USB connection timestamps
- USB removal timestamps
- Connected-only device detection
- Active USB device snapshot
- USB device type classification
- USB session duration tracking

Supported device categories:

- Storage devices
- HID/input devices
- Audio devices
- Generic USB peripherals

---

### Windows Defender Visibility

TraceUSB analyzes Microsoft Defender operational logs to identify security-relevant events.

Supported Event IDs:

| Event ID | Description |
|---|---|
| 1116 | Threat detected |
| 1117 | Action taken |
| 5001 | Defender disabled |
| 5004 | Defender configuration modified |
| 5010 | Defender engine failure |

Collected data includes:

- Detection timestamps
- Threat names
- File paths
- Configuration modifications
- Protection status changes

---

### Process Execution Analysis

TraceUSB supports behavioral reconstruction through Windows Security Auditing.

Features include:

- Process creation monitoring (4688)
- Full executable path extraction
- Parent/child process correlation
- Execution timestamp visibility
- Automatic Process Creation auditing enablement

Additional visibility:

- Executables launched from removable drives
- Transitional executable detection
- Short-lived execution visibility

---

### Correlated Execution Intelligence

Instead of independently dumping BAM, Prefetch, and process artifacts, TraceUSB now correlates execution evidence across multiple telemetry sources.

Current correlation sources:

- BAM
- Windows Prefetch
- Event ID 4688
- Removable drive execution traces

This dramatically reduces forensic noise and improves contextual relevance.

Behavioral prioritization includes:

- Randomized executable names
- Transitional loaders
- Temporary executables
- Unusual execution paths
- Multi-source execution correlation

---

### Contextual Filtering

TraceUSB uses contextual filtering to reduce common forensic noise.

Implemented filtering layers include:

- Known publisher filtering
- Known-safe path filtering
- Suspicious executable heuristics
- Artifact prioritization
- Noise reduction logic

Known-safe publishers include:

- Microsoft
- Google
- Valve
- Discord
- NVIDIA
- AMD
- Mozilla
- OBS

The goal is to surface operationally relevant events instead of overwhelming raw telemetry.

---

### Runtime & Overlay Detection

TraceUSB can identify active runtime overlay ecosystems commonly associated with GPU rendering environments.

Supported runtime visibility:

- NVIDIA ShadowPlay
- AMD Radeon/ReLive
- RTSS
- MSI Afterburner
- Overlay-based rendering runtimes

Collected data:

- Active runtime processes
- Overlay-related modules
- Runtime ecosystem visibility

Additional capabilities:

- NVIDIA screenshot trigger (ALT + F1)
- AMD screenshot trigger (CTRL + SHIFT + I)

---

## Timeline Reconstruction

TraceUSB generates chronological forensic reconstruction using multiple event sources.

Timeline correlation currently includes:

- USB activity
- Defender events
- Process execution
- Overlay/runtime detections
- Correlated executions

Generated output:

```text
Desktop\timeline.txt
````

---

## Output

TraceUSB generates:

```text
Desktop\analise.txt
Desktop\timeline.txt
```

The report is structured into sections for easier forensic review.

Current sections include:

* Log clearing events
* USB activity
* Connected-only USB devices
* Active USB devices
* Windows Defender events
* Correlated executions
* Runtime overlay detections
* Behavioral timeline reconstruction

---

## Data Sources

TraceUSB relies exclusively on native Windows telemetry sources.

Sources currently used:

* `Get-WinEvent`
* `Get-PnpDevice`
* `Get-PnpDeviceProperty`
* `Get-Process`
* `auditpol`
* BAM registry entries
* Windows Prefetch
* Windows Security Auditing

No external dependencies are required.

---

## Privacy & Security

TraceUSB is fully local and non-invasive.

The tool does NOT:

* Upload data
* Read personal files
* Collect credentials
* Access file contents
* Monitor network traffic
* Communicate externally

Only metadata and forensic telemetry are analyzed.

No data leaves the machine.

---

## Requirements

* Windows 10 / 11
* PowerShell 5.1+
* Administrative privileges recommended

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

## Limitations

* Some USB devices do not expose timestamps
* Event ID 4688 depends on Security Auditing availability
* Some systems restrict Security Log access
* Runtime overlays vary between GPU vendors
* Some private overlays intentionally evade visibility
* Correlation depends on Windows artifact availability

---

## Project Structure

```text
.
├── TraceUSB.ps1
├── README.md
├── CHANGELOG.md
├── LICENSE
└── .gitignore
```

---

## Contributing

Contributions are welcome:

* New telemetry sources
* Better correlation logic
* Performance improvements
* Contextual filtering improvements

---

## Disclaimer

TraceUSB is intended for:

* Local diagnostics
* Educational purposes
* System auditing
* Forensic visibility

Use responsibly.

---

## License

MIT License

```
```