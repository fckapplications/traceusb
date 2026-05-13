# Changelog

## [1.4.0] - Correlated Execution Intelligence & Runtime Detection

### Added
- Correlated execution analysis (BAM + Prefetch)
- Execution context filtering system
- Publisher trust filtering
- Suspicious executable name heuristics
- Runtime GPU overlay detection
- NVIDIA runtime detection
- AMD Radeon/ReLive runtime detection
- Automatic NVIDIA screenshot trigger (ALT + F1)
- Automatic AMD screenshot trigger (CTRL + SHIFT + I)
- Overlay/runtime process visibility
- Timeline integration for runtime detections

### Improved
- Massive reduction of Prefetch noise
- Massive reduction of BAM noise
- Better focus on suspicious executions only
- Stronger behavioral correlation
- Cleaner forensic output
- Better contextual relevance for investigations

### Changed
- TraceUSB now prioritizes correlated behavioral evidence instead of raw artifact dumping
- Artifact analysis became context-oriented instead of enumeration-oriented

---

## [1.3.0] - Process Correlation & Behavioral Timeline

### Added
- Process creation monitoring (Event ID 4688)
- Detection of executables launched from removable drives
- Parent/child process correlation
- Automatic enabling of Process Creation auditing
- Behavioral timeline reconstruction

### Improved
- Stronger USB-to-process correlation
- Expanded chronological analysis capabilities
- Better visibility into short-lived executable activity

---

## [1.2.0] - USB Context & Timeline Improvements

### Added
- USB device type classification
- USB session duration calculation
- Dedicated timeline output (timeline.txt)

### Improved
- Better contextual understanding of USB activity
- Enhanced chronological correlation of events

---

## [1.1.0] - Enhanced Defender Visibility

### Added
- Windows Defender status tracking (Event ID 5001)
- Windows Defender configuration changes (Event ID 5004)
- Windows Defender engine failure detection (Event ID 5010)

### Improved
- Expanded Defender coverage for better system visibility
- More complete reporting of security-relevant events

---

## [1.0.0] - Initial Release

### Added
- USB connection and removal tracking
- Log clearing detection (Event ID 104)
- Windows Defender detection events (1116 / 1117)
- Structured TXT output