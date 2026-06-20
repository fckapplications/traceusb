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
- Added `traceusb_run_*.log` with operational status and Discord delivery diagnostics.
- Added `-DiscordSelfTest` to validate webhook connectivity and multipart attachment upload without collecting forensic data.
- Added `-DiscordTimeoutSeconds`, `-DiscordMaxAttachmentBytes`, and `-VerboseConsole` for webhook reliability and `irm ... | iex` visibility.
- Discord uploads now include `analise_*.txt` and `timeline_*.txt` alongside evidence, translations, and filtered browser-history attachments.
- Pester tests with mocked Windows telemetry sources.

### Changed
- Process Creation auditing is no longer enabled automatically; it now requires `-EnableAuditPolicy`.
- GPU screenshot hotkeys are no longer sent automatically; they now require `-EnableScreenshotTrigger`.
- The readable report now distinguishes forensic relevance from proof of cheating.
- Event parsing prefers XML/EventData fields and keeps message regex as fallback.
- Sensitive evidence JSONL and translation artifacts are no longer saved locally by default.
- Local `analise_*.txt` and `timeline_*.txt` are written before Discord delivery is attempted.
- Discord delivery now forces TLS 1.2 where supported, uses an explicit timeout, and falls back to embed-only delivery if multipart attachments fail.
- Discord embeds now use a review-priority model and source/category coverage summary instead of showing only the highest raw scores.
- `-NoOpen` is now opt-in again; local TXT reports open by default after a normal run.
- Browser-history discovery now scans accessible `C:\Users` profiles, reports detected databases, and distinguishes "no keyword matches" from "no database found".
- Browser-history matching now normalizes URL/title/search text, queries Chromium `keyword_search_terms`, supports more Chromium-family browsers, and prioritizes high-risk keywords over generic SCUM-only hits.

### Fixed
- Timeline events are added through a functional helper.
- Correlation no longer depends on a missing `Path` property.
- Publisher/signature trust is used during scoring when a real path is available.
- Fixed Discord attachment iteration/counting so multipart uploads include the prepared files.
- Fixed browser-history discovery that could miss installed Chrome/Firefox profiles.
- Fixed browser-history parsing that could miss matches because of sqlite CSV output and URL-encoded search text.
- Fixed redacted URLs with query strings being rendered as malformed `=true` suffixes.

---

## [1.0.0] - Initial Release

### Added
- USB connection and removal tracking.
- Log clearing detection (Event ID 104).
- Windows Defender event parsing.
- Structured TXT output.
