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
filtered browser-history keyword scan by default when a relay or webhook endpoint is
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
Desktop\network_snapshot_yyyyMMdd_HHmmss.txt
Desktop\system_context_yyyyMMdd_HHmmss.txt
Desktop\integrity_hashes_yyyyMMdd_HHmmss.txt
Desktop\TraceUSB_case_yyyyMMdd_HHmmss.zip
```

`analise.txt` is operator-readable.  
`timeline.txt` is chronological.  
`traceusb_run.log` records operational status, including Discord delivery
success/failure and timeout details.
`network_snapshot.txt` records network metadata for fake-lag/VPN/proxy review.
`system_context.txt` records host context such as OS, boot time, timezone, and
administrator state.
`integrity_hashes.txt` records SHA256 hashes for the case bundle contents.
`TraceUSB_case_*.zip` packages the run artifacts for review.

When Discord reporting is used, TraceUSB builds these sensitive artifacts as
Discord download attachments instead of saving them locally by default:

```text
analise_yyyyMMdd_HHmmss.txt
timeline_yyyyMMdd_HHmmss.txt
evidence_yyyyMMdd_HHmmss.jsonl
translations_yyyyMMdd_HHmmss.txt
filtered_history_yyyyMMdd_HHmmss.txt
network_snapshot_yyyyMMdd_HHmmss.txt
system_context_yyyyMMdd_HHmmss.txt
traceusb_run_yyyyMMdd_HHmmss.log
integrity_hashes_yyyyMMdd_HHmmss.txt
TraceUSB_case_yyyyMMdd_HHmmss.zip
overlay_screenshot_yyyyMMdd_HHmmss.png
```

`analise_*.txt`, `timeline_*.txt`, `network_snapshot_*.txt`,
`system_context_*.txt`, `traceusb_run_*.log`, `integrity_hashes_*.txt`, and the
case ZIP are written locally and are also attached to Discord when available.
`overlay_screenshot_*.png/.jpg` is attached only when
`-EnableScreenshotTrigger` is used and a new NVIDIA/AMD overlay screenshot file
is detected after the hotkey.
Use `-SaveDiscordAttachmentsLocal` only when you explicitly want the
sensitive attachment-only files written to the local output folder.

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

Run an internal review with the configured Discord relay or local webhook:

```powershell
.\TraceUSB.ps1
```

By default this internal build:

* writes timestamped `analise_*.txt` and `timeline_*.txt` locally;
* writes `traceusb_run_*.log` locally so network or webhook failures are visible;
* writes `network_snapshot_*.txt`, `system_context_*.txt`, and a hashed case ZIP;
* sends a Discord embed when a relay or webhook endpoint is configured;
* attaches `analise_*.txt`, `timeline_*.txt`, `evidence_*.jsonl`, and `translations_*.txt`;
* runs the filtered browser-history scan and attaches `filtered_history_*.txt`;
* opens the local TXT files unless `-NoOpen` is used.

Test only the Discord delivery path, including a small non-forensic attachment:

```powershell
.\TraceUSB.ps1 -DiscordSelfTest -VerboseConsole
```

This mode does not collect Windows events and does not scan browser history.

Run without Discord, browser-history scanning, network scan, or case bundle:

```powershell
.\TraceUSB.ps1 -DisableDiscordWebhook -DisableBrowserHistoryScan -DisableNetworkAnomalyScan -DisableCaseBundle
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

This sends the detected NVIDIA/AMD overlay hotkey, searches known overlay
screenshot folders for a new image, and attaches that image to Discord/case
outputs when found. TraceUSB does not take a desktop screenshot fallback.

Create a Discord embed preview without sending anything:

```powershell
.\TraceUSB.ps1 -NoOpen -DiscordPreviewPath .\discord_preview.html
```

This writes a timestamped preview such as
`discord_preview_yyyyMMdd_HHmmss.html`.

Use a server-side Discord relay, recommended for public GitHub distribution:

```powershell
$env:TRACEUSB_DISCORD_RELAY_URL = "https://your-relay.example/traceusb"
$env:TRACEUSB_DISCORD_RELAY_TOKEN = "optional-shared-token"
.\TraceUSB.ps1
```

The relay keeps the real Discord webhook outside the public script. A reference
Cloudflare Worker is provided in `relay/cloudflare-worker.js`.

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

Direct webhook usage is intended for local/internal operation only. Do not put a
real Discord webhook URL in `TraceUSB.ps1`, README examples, commits, issues, or
public release notes.

Save Discord payload details without sending HTTP:

```powershell
.\TraceUSB.ps1 -DiscordDebug -NoOpen
```

This writes `discord_payload_*.json` and `discord_attachments_*.txt` for
diagnostics.

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
| `-NoOpen` | Off | Prevents Notepad from opening outputs |
| `-EnableAuditPolicy` | Off | Enables Process Creation auditing when running as admin |
| `-EnableScreenshotTrigger` | Off | Sends native GPU screenshot hotkeys when runtime context exists |
| `-IncludeLowConfidence` | Off | Includes low/context evidence in the readable report |
| `-EnableDiscordWebhook` | On | Sends a Discord embed when a relay or webhook endpoint is configured |
| `-DisableDiscordWebhook` | Off | Disables Discord posting for dry runs |
| `-DiscordWebhookUrl` | Empty | Direct Discord webhook endpoint for local/internal use |
| `-DiscordWebhookSecretPath` | Empty | Reads a Windows DPAPI encrypted webhook secret |
| `-DiscordWebhookEnvVar` | `TRACEUSB_DISCORD_WEBHOOK_URL` | Environment variable fallback for webhook URL |
| `-DiscordRelayUrl` | Empty | Server-side relay endpoint that forwards to Discord without exposing the real webhook |
| `-DiscordRelayEnvVar` | `TRACEUSB_DISCORD_RELAY_URL` | Environment variable fallback for relay URL |
| `-DiscordRelayToken` | Empty | Optional shared token sent to the relay as `X-TraceUSB-Relay-Token` |
| `-DiscordRelayTokenEnvVar` | `TRACEUSB_DISCORD_RELAY_TOKEN` | Environment variable fallback for relay token |
| `-SaveDiscordWebhookSecret` | Off | Saves `-DiscordWebhookUrl` to `-DiscordWebhookSecretPath` using DPAPI and exits |
| `-DiscordDebug` | Off | Saves Discord payload/attachment manifest and skips HTTP send |
| `-DiscordPreviewPath` | Empty | Writes local HTML preview and matching JSON payload |
| `-DiscordUsername` | `TraceUSB` | Webhook display name |
| `-DiscordTitle` | TraceUSB summary | Embed title |
| `-DiscordSubtitle` | Disclaimer | Embed description |
| `-DiscordMaxItems` | `8` | Maximum findings in the embed |
| `-DiscordTimeoutSeconds` | `20` | HTTP timeout for Discord sends |
| `-DiscordMaxAttachmentBytes` | `7000000` | Per-attachment truncation threshold before upload |
| `-DiscordMaxPayloadBytes` | `24000000` | Approximate total attachment bytes per Discord/relay request |
| `-DiscordMaxFilesPerMessage` | `10` | Maximum files per Discord/relay request before batching |
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
| `-EnableNetworkAnomalyScan` | On | Collects network metadata and indicators relevant to fake-lag review |
| `-DisableNetworkAnomalyScan` | Off | Disables network metadata collection |
| `-EnableCaseBundle` | On | Creates a timestamped ZIP with run artifacts and SHA256 hashes |
| `-DisableCaseBundle` | Off | Disables local case bundle ZIP creation |
| `-SQLiteCliPath` | Auto-detect | Optional path to `sqlite3.exe` |
| `-PortableSQLitePath` | Empty | Optional path to a portable, hash-pinned `sqlite3.exe` |
| `-PortableSQLiteDownloadUrl` | SQLite 3.53.3 tools | Pinned temporary SQLite tools download used when no local reader exists |
| `-PortableSQLiteDownloadSha256` | Pinned | SHA256 expected for the configured SQLite tools ZIP |
| `-PortableSQLiteExeSha256` | Pinned | SHA256 expected for extracted `sqlite3.exe` |
| `-DisablePortableSQLiteDownload` | Off | Prevents the trusted temporary SQLite download attempt |
| `-NoRedactUrls` | Off | Keeps full matched URLs instead of redacting query strings |
| `-GameProcessPatterns` | SCUM/BattlEye defaults | Process names used as temporal anchors |

---

## Discord Reporting

Discord reporting is enabled by default in this internal build. Posting still
requires a delivery endpoint. For public GitHub distribution, use
`-DiscordRelayUrl` or `TRACEUSB_DISCORD_RELAY_URL`; the relay forwards to
Discord with the real webhook stored server-side. Direct webhook delivery via
`-DiscordWebhookUrl`, `-DiscordWebhookSecretPath`, or
`TRACEUSB_DISCORD_WEBHOOK_URL` remains available for controlled local/internal
use. Use `-DisableDiscordWebhook` for local dry runs or `-DiscordDebug` to save
the JSON payload and attachment manifest without sending HTTP.

The Discord embed summarizes findings and includes operator-friendly suggested
translations. The embed prioritizes review-worthy categories such as Defender,
anti-forensic events, browser-history keyword hits, service/driver installs,
USB/removable context, and 4688-backed execution instead of simply listing the
highest raw scores. Common browser/system executables seen only through
Prefetch/BAM are de-prioritized in the embed but remain available in
`evidence_*.jsonl`.

`analise_*.txt`, `timeline_*.txt`, `evidence_*.jsonl`, `translations_*.txt`,
optional `filtered_history_*.txt`, and optional overlay screenshots are sent as
Discord download attachments below the embed. Sensitive attachment-only files
are not saved locally unless `-SaveDiscordAttachmentsLocal` is used.
TraceUSB writes local `analise_*.txt`, `timeline_*.txt`, and
`traceusb_run_*.log` before attempting Discord delivery, so a webhook outage
does not prevent local report generation.

Discord delivery uses an explicit timeout, forces TLS 1.2 where supported, and
splits attachments into batches when file count or payload size crosses the
configured limits. If the first multipart upload fails, TraceUSB falls back to
sending the embed only and records that degraded status in `analise_*.txt` and
`traceusb_run_*.log`.

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

### Discord Relay

`relay/cloudflare-worker.js` is a ready reference relay for Cloudflare Workers.
Configure these Worker secrets/variables:

```text
DISCORD_WEBHOOK_URL=<real Discord webhook URL>
TRACEUSB_RELAY_TOKEN=<optional shared token>
```

Then configure TraceUSB with:

```powershell
$env:TRACEUSB_DISCORD_RELAY_URL = "https://your-worker.example/traceusb"
$env:TRACEUSB_DISCORD_RELAY_TOKEN = "same optional shared token"
```

The client sends the same Discord-compatible JSON or multipart payload to the
relay. The relay forwards it to Discord. This is materially safer than
obfuscating or encrypting a webhook inside open-source client code, because the
client never receives the real Discord URL.

---

## Network Anomaly Review

Network anomaly scanning is metadata-only. TraceUSB does not capture packet
contents and does not inspect live game traffic. It records:

* active network adapters and IP configuration;
* Windows proxy and WinHTTP proxy settings;
* active TCP connection sample with owning process names;
* DNS cache indicators for known cheat/network tooling terms;
* network profile connect/disconnect events near the SCUM/BattlEye window;
* active processes, services, drivers, and adapters matching VPN/tunnel,
  packet-diversion, packet-capture, proxy, route-optimizer, or bandwidth-shaping
  tools.

Examples of indicators include WinDivert, clumsy, NetLimiter, Proxifier, Npcap,
TAP/Wintun/WireGuard/OpenVPN, ExitLag, Mudfish, WTFast, NoPing, Haste, and
similar VPN/proxy tooling. These are review indicators only: VPNs, packet
capture tools, and route optimizers can be legitimate.

---

## Case Bundle

When enabled, TraceUSB creates:

```text
TraceUSB_case_yyyyMMdd_HHmmss.zip
integrity_hashes_yyyyMMdd_HHmmss.txt
```

The ZIP contains the run artifacts generated by TraceUSB, including analysis,
timeline, evidence JSONL, translations, optional filtered history, network
snapshot, system context, and run log. `integrity_hashes_*.txt` records SHA256
hashes for the files inside the case bundle so reviewers can detect accidental
or intentional changes after collection.

---

## Filtered Browser History

Browser history scanning is enabled by default in this internal build. It is
meant for consent-based reviews and only exports entries matching configured
keywords. It does not dump full browser history. Use
`-DisableBrowserHistoryScan` for dry runs or when the review does not include
browser checks.

TraceUSB checks the current Windows profile and other accessible profiles under
`C:\Users`, then copies browser databases to a temporary folder before querying
them. The output lists detected databases and records whether each database was
readable. If no keyword matches are found, the file says so explicitly instead
of implying that the browser was unsupported.

Chromium-family coverage includes Chrome Stable/Beta/Dev/Canary, Edge
Stable/Beta/Dev/Canary, Brave, Chromium, Vivaldi, Opera, Opera GX, Yandex, and
Arc when their Windows profile folders are present. Firefox profiles are scanned
separately.

For Chromium browsers, TraceUSB queries both normal visit history and
`keyword_search_terms`, which catches many searches that do not appear cleanly in
page titles. URL/title/search text is normalized before matching, so
`scum+cheat`, `scum%20cheat`, and `SCUM Cheat` are treated consistently. The
result list prioritizes stronger keywords such as `ciroscript`, `project
cheats`, `scum cheat`, `aimbot`, and `wallhack` above broad `scum`-only hits.

Supported targets:

* Chrome
* Edge
* Brave
* Opera
* Firefox

TraceUSB reads browser history SQLite databases through a SQLite reader resolved
in this order:

1. explicit `-SQLiteCliPath`;
2. explicit `-PortableSQLitePath`;
3. bundled `tools\sqlite\win-x64\sqlite3.exe` with a `.sha256` sidecar;
4. `sqlite3.exe` or `sqlite3` on `PATH`;
5. the pinned temporary SQLite tools download configured in `TraceUSB.ps1`.

The temporary download is hash-validated, extracted under `%TEMP%`, used only
for the browser-history scan, and then removed. Use
`-DisablePortableSQLiteDownload` when the review must not contact the official
SQLite download host. If no reader is available, the scan is skipped cleanly and
the report records the resolution order that was attempted.

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
