# TraceUSB

Lightweight Windows forensic analyzer for USB activity, process execution, runtime context, and security-relevant event correlation.

TraceUSB is built for local review of possible suspicious runtime behavior around SCUM sessions while staying conservative: it collects native Windows metadata, correlates signals, and reports forensic relevance. It does not decide that a player cheated.

---

## What It Does

TraceUSB analyzes local Windows telemetry from:

* USB Plug and Play metadata
* Windows Security process creation events (`4688`)
* Microsoft Defender operational events
* BAM execution artifacts
* Windows Prefetch artifacts
* Windows event log clearing signals
* Service and driver installation events (`7045`)
* Common GPU and overlay runtime processes

The report prioritizes correlated, explainable evidence instead of dumping every artifact.

---

## Safe Defaults

This internal review build is configured to run the Discord delivery path and
filtered browser-history keyword scan by default when a webhook source is
available. Use `-DisableDiscordWebhook -DisableBrowserHistoryScan` for a fully
local dry run.

TraceUSB still:

* Does not change Windows audit policy
* Does not send GPU screenshot hotkeys
* Does not inspect process memory
* Does not dump full browser history
* Does not read arbitrary personal file contents

Two sensitive actions are opt-in only:

* `-EnableAuditPolicy` enables Process Creation auditing with `auditpol`
* `-EnableScreenshotTrigger` sends native NVIDIA/AMD screenshot hotkeys when runtime context is present

---

## Output

TraceUSB writes timestamped local files:

```text
Desktop\analise_yyyyMMdd_HHmmss.txt
Desktop\timeline_yyyyMMdd_HHmmss.txt
Desktop\traceusb_run_yyyyMMdd_HHmmss.log
```

`analise.txt` is operator-readable.  
`timeline.txt` is chronological.  
`traceusb_run.log` records operational status, including Discord delivery
success/failure and timeout details.

When Discord reporting is used, TraceUSB builds these sensitive artifacts as
Discord download attachments instead of saving them locally by default:

```text
evidence_yyyyMMdd_HHmmss.jsonl
translations_yyyyMMdd_HHmmss.txt
filtered_history_yyyyMMdd_HHmmss.txt
```

Use `-SaveDiscordAttachmentsLocal` only when you explicitly want those attachment
files written to the local output folder.

Each structured evidence item includes:

* `Time`
* `Category`
* `Source`
* `EventId`
* `ExeName`
* `Path`
* `ParentPath`
* `UserSid`
* `Device`
* `Confidence`
* `Reasons`
* `Details`

Confidence means forensic relevance:

* `70-100`: high relevance
* `40-69`: medium relevance
* `0-39`: low/context evidence

It is not proof of cheating.

---

## Usage

Run an internal review with the configured Discord webhook:

```powershell
.\TraceUSB.ps1
```

By default this internal build:

* writes timestamped `analise_*.txt` and `timeline_*.txt` locally;
* writes `traceusb_run_*.log` locally so network or webhook failures are visible;
* sends a Discord embed when a webhook is configured;
* attaches `evidence_*.jsonl` and `translations_*.txt`;
* runs the filtered browser-history scan and attaches `filtered_history_*.txt`;
* does not open Notepad.

Test only the Discord webhook path, including a small non-forensic attachment:

```powershell
.\TraceUSB.ps1 -DiscordSelfTest -VerboseConsole
```

This mode does not collect Windows events and does not scan browser history.

Run without Discord or browser-history scanning:

```powershell
.\TraceUSB.ps1 -DisableDiscordWebhook -DisableBrowserHistoryScan
```

Write output to a custom folder:

```powershell
.\TraceUSB.ps1 -OutputDirectory C:\Temp\TraceUSB -NoOpen
```

Analyze a larger time window:

```powershell
.\TraceUSB.ps1 -LookbackHours 72 -NoOpen
```

Include low-confidence/context evidence in the readable report:

```powershell
.\TraceUSB.ps1 -IncludeLowConfidence -NoOpen
```

Opt in to enabling Security 4688 auditing:

```powershell
.\TraceUSB.ps1 -EnableAuditPolicy
```

Opt in to GPU screenshot hotkeys:

```powershell
.\TraceUSB.ps1 -EnableScreenshotTrigger
```

Create a Discord embed preview without sending anything:

```powershell
.\TraceUSB.ps1 -NoOpen -DiscordPreviewPath .\discord_preview.html
```

This writes a timestamped preview such as
`discord_preview_yyyyMMdd_HHmmss.html`.

Send a formatted Discord webhook with an explicit URL:

```powershell
.\TraceUSB.ps1 -DiscordWebhookUrl "https://discord.com/api/webhooks/..."
```

Save the Discord webhook locally with Windows DPAPI encryption:

```powershell
.\TraceUSB.ps1 `
  -SaveDiscordWebhookSecret `
  -DiscordWebhookUrl "https://discord.com/api/webhooks/..." `
  -DiscordWebhookSecretPath "$env:APPDATA\TraceUSB\discord_webhook.secret"
```

Use the saved DPAPI secret:

```powershell
.\TraceUSB.ps1 `
  -DiscordWebhookSecretPath "$env:APPDATA\TraceUSB\discord_webhook.secret"
```

Or use an environment variable instead of passing the URL on the command line:

```powershell
$env:TRACEUSB_DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/..."
.\TraceUSB.ps1
```

Run Discord attachments and filtered browser-history scan explicitly:

```powershell
.\TraceUSB.ps1 `
  -EnableDiscordWebhook `
  -EnableBrowserHistoryScan `
  -DiscordPreviewPath .\discord_preview.html
```

Save Discord attachments locally for debugging:

```powershell
.\TraceUSB.ps1 -NoOpen -DiscordPreviewPath .\discord_preview.html -SaveDiscordAttachmentsLocal
```

Customize Discord identity, title, colors, and number of findings:

```powershell
.\TraceUSB.ps1 -NoOpen `
  -DiscordPreviewPath .\discord_preview.html `
  -DiscordUsername "TraceUSB Audit" `
  -DiscordTitle "SCUM endpoint review" `
  -DiscordAlertColor "D64545" `
  -DiscordNoticeColor "E0A33A" `
  -DiscordInfoColor "4E7DD9" `
  -DiscordMaxItems 10
```

Customize game/session anchors:

```powershell
.\TraceUSB.ps1 -GameProcessPatterns "SCUM.exe","SCUM-Win64-Shipping.exe","BEService.exe" -NoOpen
```

---

## Parameters

| Parameter | Default | Purpose |
|---|---:|---|
| `-LookbackHours` | `24` | Event and artifact lookback window |
| `-OutputDirectory` | Desktop | Output folder |
| `-NoOpen` | On | Prevents Notepad from opening outputs |
| `-EnableAuditPolicy` | Off | Enables Process Creation auditing when running as admin |
| `-EnableScreenshotTrigger` | Off | Sends native GPU screenshot hotkeys when runtime context exists |
| `-IncludeLowConfidence` | Off | Includes low/context evidence in the readable report |
| `-EnableDiscordWebhook` | On | Sends a Discord embed when a webhook source is configured |
| `-DisableDiscordWebhook` | Off | Disables Discord posting for dry runs |
| `-DiscordWebhookUrl` | Empty | Discord webhook endpoint |
| `-DiscordWebhookSecretPath` | Empty | Reads a Windows DPAPI encrypted webhook secret |
| `-DiscordWebhookEnvVar` | `TRACEUSB_DISCORD_WEBHOOK_URL` | Environment variable fallback for webhook URL |
| `-SaveDiscordWebhookSecret` | Off | Saves `-DiscordWebhookUrl` to `-DiscordWebhookSecretPath` using DPAPI and exits |
| `-DiscordPreviewPath` | Empty | Writes local HTML preview and matching JSON payload |
| `-DiscordUsername` | `TraceUSB` | Webhook display name |
| `-DiscordTitle` | TraceUSB summary | Embed title |
| `-DiscordSubtitle` | Disclaimer | Embed description |
| `-DiscordMaxItems` | `8` | Maximum findings in the embed |
| `-DiscordTimeoutSeconds` | `20` | HTTP timeout for Discord sends |
| `-DiscordMaxAttachmentBytes` | `7000000` | Per-attachment truncation threshold before upload |
| `-DiscordSelfTest` | Off | Sends a small non-forensic test embed and attachment, then exits |
| `-VerboseConsole` | Off | Prints progress lines, useful for `irm ... \| iex` runs |
| `-DiscordAlertColor` | `D64545` | Embed border color for high confidence |
| `-DiscordNoticeColor` | `E0A33A` | Embed border color for medium confidence |
| `-DiscordInfoColor` | `4E7DD9` | Embed border color for low/context-only findings |
| `-DiscordIncludeLowConfidence` | Off | Includes low-confidence evidence in Discord preview/webhook |
| `-SaveDiscordAttachmentsLocal` | Off | Writes Discord attachment files locally for debugging |
| `-SubjectLabel` | Empty | Adds a safe player label to generated artifact names |
| `-EnableBrowserHistoryScan` | On | Enables keyword-only browser history scan |
| `-DisableBrowserHistoryScan` | Off | Disables browser history scan |
| `-BrowserHistoryKeywords` | SCUM cheat/fake-lag terms | Keyword list for filtered history |
| `-BrowserHistoryLookbackDays` | `30` | Browser history lookback window |
| `-BrowserHistoryMaxHits` | `100` | Maximum filtered history hits |
| `-SQLiteCliPath` | Auto-detect | Optional path to `sqlite3.exe` |
| `-NoRedactUrls` | Off | Keeps full matched URLs instead of redacting query strings |
| `-GameProcessPatterns` | SCUM/BattlEye defaults | Process names used as temporal anchors |

---

## Discord Reporting

Discord reporting is enabled by default in this internal build. Posting still
requires a webhook source. The webhook source can be `-DiscordWebhookUrl`,
`-DiscordWebhookSecretPath`, a hardcoded direct URL in `-DiscordWebhookEnvVar`,
or the configured environment variable. Use `-DisableDiscordWebhook` for dry
runs.

The Discord embed summarizes findings and includes operator-friendly suggested
translations. `evidence_*.jsonl`, `translations_*.txt`, and optional
`filtered_history_*.txt` are sent as Discord download attachments below the
embed. They are not saved locally unless `-SaveDiscordAttachmentsLocal` is used.
TraceUSB writes local `analise_*.txt`, `timeline_*.txt`, and
`traceusb_run_*.log` before attempting Discord delivery, so a webhook outage
does not prevent local report generation.

Discord delivery uses an explicit timeout, forces TLS 1.2 where supported, and
first attempts multipart upload with attachments. If multipart upload fails,
TraceUSB falls back to sending the embed only and records that degraded status
in `analise_*.txt` and `traceusb_run_*.log`.

For review before posting, use `-DiscordPreviewPath`; this writes:

```text
discord_preview_yyyyMMdd_HHmmss.html
```

The HTML file approximates Discord's embed layout, including the left border
color chosen from the highest confidence finding.

### Webhook Secret Storage

`-SaveDiscordWebhookSecret` uses Windows DPAPI through PowerShell's
`ConvertFrom-SecureString`. This prevents the webhook from being stored as plain
text in the project or command history, but it is not a portable shared secret.
The encrypted file can normally only be decrypted by the same Windows user
profile on the same machine.

If you need to distribute TraceUSB to players without exposing the Discord
webhook, use a small server-side relay endpoint instead of embedding the real
Discord URL in the script.

---

## Filtered Browser History

Browser history scanning is enabled by default in this internal build. It is
meant for consent-based reviews and only exports entries matching configured
keywords. It does not dump full browser history. Use
`-DisableBrowserHistoryScan` for dry runs or when the review does not include
browser checks.

Supported targets:

* Chrome
* Edge
* Brave
* Opera
* Firefox

TraceUSB reads browser history SQLite databases through `sqlite3.exe` when
available. If SQLite is unavailable, the scan is skipped cleanly and noted in
the report.

URLs are redacted by default: query strings are replaced with
`query_redacted=true`. Use `-NoRedactUrls` only when the review process
explicitly allows full matched URLs.

---

## Correlation Model

TraceUSB increases confidence when signals reinforce each other:

* Executable appears in multiple sources
* Execution occurs from a removable drive
* Execution occurs near USB activity
* Execution occurs near a SCUM/BattlEye session
* Defender references the same path
* Event logs are cleared near execution
* Name or path looks transitional, random, temporary, or loader-like
* Service or driver installation appears near the investigation window

Confidence is reduced when an executable is signed by a known trusted publisher and runs from a trusted path such as `C:\Windows` or `C:\Program Files`.

---

## Requirements

* Windows 10 / 11
* PowerShell 5.1+
* Administrator privileges recommended for Security log access

No external runtime dependencies are required.

---

## Limitations

* Some systems do not retain all event sources.
* Event ID `4688` depends on Security auditing being enabled before the activity occurred.
* Prefetch may be disabled or unavailable.
* BAM timestamps and paths vary by Windows version.
* Runtime/overlay detection is context only and may miss private overlays.
* TraceUSB does not inspect game memory, kernel memory, or network traffic.

---

## Development

Run a syntax check:

```powershell
$tokens=$null;$errors=$null;[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path .\TraceUSB.ps1),[ref]$tokens,[ref]$errors) | Out-Null; $errors
```

Run tests when Pester is available:

```powershell
Invoke-Pester .\tests
```

---

## Privacy

All analysis is local. TraceUSB does not communicate with external services and does not upload investigation data.

---

## Disclaimer

TraceUSB is for local diagnostics, education, system auditing, and forensic visibility. Its output should be reviewed by a human operator and treated as indicators, not automatic proof of misconduct.
