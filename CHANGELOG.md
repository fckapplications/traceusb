# Changelog

## [1.5.0] - Forensic Correlation Worktree

### Added
- Safe runtime parameters: `-LookbackHours`, `-OutputDirectory`, `-NoOpen`, `-EnableAuditPolicy`, `-EnableScreenshotTrigger`, `-IncludeLowConfidence`, and `-GameProcessPatterns`.
- Structured evidence output at `evidence.jsonl`.
- Operator translation suggestions at `suggested_translations.txt`.
- Timeline output at `timeline.txt`.
- Correlated execution model across Security 4688, BAM, Prefetch, Defender, USB activity, service installation, and SCUM/BattlEye session context.
- Confidence scoring with explicit evidence reasons.
- Event ID 1102 and 104 anti-forensic visibility.
- Event ID 7045 service and driver installation visibility.
- Common runtime/overlay context for NVIDIA, AMD, RTSS, MSI Afterburner, Steam, Discord, Overwolf, and ReShade.
- Optional Discord embed reporting with preview HTML/JSON, configurable colors, title, username, and item limits.
- Optional Discord webhook secret loading from Windows DPAPI encrypted files or environment variables.
- Discord webhook delivery now uses multipart attachments for evidence JSONL, translations, and optional filtered browser history.
- Timestamped artifact names with optional `-SubjectLabel`.
- Opt-in keyword-only browser history scan with URL query redaction.
- `-SaveDiscordAttachmentsLocal` for local debugging of files otherwise sent only to Discord.
- Internal-review defaults now enable Discord posting and filtered browser-history scanning when a webhook source is configured.
- Added `-DisableDiscordWebhook` and `-DisableBrowserHistoryScan` for dry runs.
- Pester tests with mocked Windows telemetry sources.

### Changed
- Process Creation auditing is no longer enabled automatically; it now requires `-EnableAuditPolicy`.
- GPU screenshot hotkeys are no longer sent automatically; they now require `-EnableScreenshotTrigger`.
- The readable report now distinguishes forensic relevance from proof of cheating.
- Event parsing prefers XML/EventData fields and keeps message regex as fallback.
- Sensitive evidence JSONL and translation artifacts are no longer saved locally by default.

### Fixed
- Timeline events are added through a functional helper.
- Correlation no longer depends on a missing `Path` property.
- Publisher/signature trust is used during scoring when a real path is available.

---

## [1.0.0] - Initial Release

### Added
- USB connection and removal tracking.
- Log clearing detection (Event ID 104).
- Windows Defender event parsing.
- Structured TXT output.
