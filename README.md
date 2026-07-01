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

* `-EnableAuditPolicy` enables Process Creation and Process Termination auditing with `auditpol`
* `-EnableScreenshotTrigger` focuses the SCUM window when possible and sends native NVIDIA/AMD screenshot hotkeys when runtime context is present

---

## Output

By default, TraceUSB does not write final report artifacts to the reviewed
computer. It builds the report, timeline, evidence, translations, browser
history matches, game sessions, run log, hashes, and case bundle in memory and
sends them as Discord attachments through the configured relay.

Default Discord attachments:

```text
analise_yyyyMMdd_HHmmss.txt
timeline_yyyyMMdd_HHmmss.txt
game_sessions_yyyyMMdd_HHmmss.txt
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

`analise.txt` is operator-readable.  
`timeline.txt` is chronological.  
`game_sessions.txt` reconstructs SCUM/BattlEye process and service activity
for the selected day, including start, close, observed duration, and evidence
quality when available.
`traceusb_run.log` records operational status, including Discord delivery
success/failure and timeout details.
`network_snapshot.txt` records network metadata for fake-lag/VPN/proxy review.
`system_context.txt` records host context such as OS, boot time, timezone, and
administrator state.
`integrity_hashes.txt` records SHA256 hashes for the case bundle contents.
`TraceUSB_case_*.zip` packages the run artifacts for review.

`overlay_screenshot_*.png/.jpg` is attached only when
`-EnableScreenshotTrigger` is used and a new NVIDIA/AMD overlay screenshot file
is detected after the hotkey. The triggered overlay screenshot is deleted after
being read into memory unless `-KeepTriggeredOverlayScreenshot` is used.

Use `-SaveLocalArtifacts` only when you explicitly want final artifacts written
to `-OutputDirectory`. Use `-SaveDiscordAttachmentsLocal` only for local
debugging of files that are normally attachment-only.

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

Run an internal review with the built-in Discord relay:

```powershell
irm "https://raw.githubusercontent.com/fckapplications/traceusb/main/TraceUSB.ps1" | iex
```

By default this internal build:

* sends a Discord embed when a relay or webhook endpoint is configured;
* attaches `analise_*.txt`, `timeline_*.txt`, `game_sessions_*.txt`, `evidence_*.jsonl`, and `translations_*.txt`;
* runs the filtered browser-history scan and attaches `filtered_history_*.txt`;
* builds hashes and a case ZIP in memory;
* does not save final artifacts locally unless `-SaveLocalArtifacts` is used.

Local clone usage is still supported:

```powershell
.\TraceUSB.ps1
```

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
outputs when found. TraceUSB first tries to bring the SCUM game window to the
foreground, so the operator normally does not need to alt-tab manually. TraceUSB
does not take a desktop screenshot fallback.

Create a Discord embed preview without sending anything:

```powershell
.\TraceUSB.ps1 -NoOpen -DiscordPreviewPath .\discord_preview.html
```

This writes a timestamped preview such as
`discord_preview_yyyyMMdd_HHmmss.html`.

The public build already includes the team relay URL:

```powershell
https://long-dust-248e.devoxygenwp.workers.dev/
```

The relay keeps the real Discord webhook outside the public script. A reference
Cloudflare Worker is provided in `relay/cloudflare-worker.js`. Use
`-DiscordRelayUrl` only when testing another relay.

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
| `-GameSessionDate` | Today | Full local day used for SCUM/BattlEye session reconstruction |
| `-OutputDirectory` | Desktop | Output folder used only by explicit local/debug modes |
| `-NoOpen` | Off | Prevents Notepad from opening outputs when `-SaveLocalArtifacts` is used |
| `-SaveLocalArtifacts` | Off | Writes final artifacts locally; public player runs should leave this off |
| `-EnableAuditPolicy` | Off | Enables Process Creation and Process Termination auditing when running as admin |
| `-EnableScreenshotTrigger` | Off | Focuses SCUM when possible, sends native GPU screenshot hotkeys, and attaches a detected overlay image |
| `-KeepTriggeredOverlayScreenshot` | Off | Keeps the overlay screenshot file that TraceUSB triggered instead of deleting it after queueing the attachment |
| `-DisableScreenshotWindowFocus` | Off | Keeps the old manual-focus behavior before sending the screenshot hotkey |
| `-ScreenshotFocusWaitSeconds` | `3` | Wait after automatic SCUM focus before sending the overlay hotkey |
| `-ScreenshotFocusAttempts` | `3` | Number of foreground-focus attempts before falling back to the manual countdown |
| `-ScreenshotPostTriggerWaitSeconds` | `8` | Wait after hotkey before scanning for a new screenshot file |
| `-IncludeLowConfidence` | Off | Includes low/context evidence in the readable report |
| `-EnableDiscordWebhook` | On | Sends a Discord embed when a relay or webhook endpoint is configured |
| `-DisableDiscordWebhook` | Off | Disables Discord posting for dry runs |
| `-DiscordWebhookUrl` | Empty | Direct Discord webhook endpoint for local/internal use |
| `-DiscordWebhookSecretPath` | Empty | Reads a Windows DPAPI encrypted webhook secret |
| `-DiscordWebhookEnvVar` | `TRACEUSB_DISCORD_WEBHOOK_URL` | Environment variable fallback for webhook URL |
| `-DiscordRelayUrl` | Team Worker URL | Server-side relay endpoint that forwards to Discord without exposing the real webhook |
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
| `-DisableGameSessionAnalysis` | Off | Disables SCUM/BattlEye session reconstruction |
| `-EnableCaseBundle` | On | Creates an in-memory ZIP attachment with run artifacts and SHA256 hashes |
| `-DisableCaseBundle` | Off | Disables case bundle ZIP creation |
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

Discord reporting is enabled by default in this internal build. The public
script includes the team Cloudflare Worker relay URL, so players can run the
single `irm ... | iex` command without configuring environment variables. The
relay forwards to Discord with the real webhook stored server-side. Direct
webhook delivery via
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
are not saved locally unless `-SaveDiscordAttachmentsLocal` or
`-SaveLocalArtifacts` is used.

Discord delivery uses an explicit timeout, forces TLS 1.2 where supported, and
splits attachments into batches when file count or payload size crosses the
configured limits. If the first multipart upload fails, TraceUSB falls back to
sending the embed only and prints the degraded/failed status in the console.
Use `-VerboseConsole` for live progress lines.

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

`TRACEUSB_RELAY_TOKEN` is optional. If you set it in Cloudflare, every TraceUSB
client must provide the same token through `-DiscordRelayToken` or
`TRACEUSB_DISCORD_RELAY_TOKEN`, which is not ideal for the one-command player
flow. For the public command flow, leave the token unset and rely on the Worker
URL plus Cloudflare-side abuse controls/rate limiting.

If the Worker still has `TRACEUSB_RELAY_TOKEN` configured and the player runs
the one-command public flow, Discord delivery will fail with HTTP `401`.

The current public relay default is:

```text
https://long-dust-248e.devoxygenwp.workers.dev/
```

The client sends the same Discord-compatible JSON or multipart payload to the
relay. The relay forwards it to Discord. This is materially safer than
obfuscating or encrypting a webhook inside open-source client code, because the
client never receives the real Discord URL.

---

## Overlay Screenshot Trigger

`-EnableScreenshotTrigger` is designed for consent-based review when the game is
running. TraceUSB searches for visible windows owned by the configured
SCUM/BattlEye process patterns, prioritizes `SCUM.exe`, brings that window to
the foreground when Windows allows it, verifies that the foreground process is
the game, then sends the detected GPU overlay screenshot hotkey.

This path intentionally favors NVIDIA/AMD overlay screenshots because those
capture paths can include game-layer visuals that ordinary desktop sharing or
desktop screenshots may miss. If the player has disabled NVIDIA/AMD overlay
screenshot support, TraceUSB records that no overlay screenshot was detected
instead of silently substituting a lower-value desktop capture.

AMD support uses the default Radeon screenshot hotkey and the common Radeon
ReLive screenshot folder. Because AMD overlay configuration varies more between
driver versions, verify it with a collaborator before relying on it operationally.

Windows can still block foreground changes in some exclusive-fullscreen,
elevated, anti-cheat, or locked-input states. When that happens TraceUSB records
the failed focus confirmation, waits for the manual fallback countdown, and only
attaches a screenshot if the NVIDIA/AMD overlay actually creates a new image.

---

## SCUM / BattlEye Session Activity

TraceUSB reconstructs game and anti-cheat activity for `-GameSessionDate`
using a full local-day window. The default is the current date on the reviewed
computer. The output is written to `game_sessions_*.txt`, added to
`timeline_*.txt`, represented in `evidence_*.jsonl`, and attached to Discord.

Sources used:

* Security `4688` process creation for `SCUM.exe`, `SCUM-Win64-Shipping.exe`,
  `SCUM_Launcher.exe`, `BEService.exe`, and `BEService_x64.exe`;
* Security `4689` process termination when process termination auditing was
  already enabled;
* System `7036` service running/stopped transitions for BattlEye service names;
* live process snapshot when SCUM/BattlEye is still running during collection.

The report labels each reconstructed session with its evidence quality:

* `Exact start/end from Windows event logs`;
* `Start observed only`;
* `End observed only`;
* `Start observed and process still active`;
* `Live process snapshot`.

Close time is only exact when Windows recorded a matching termination or service
stop event. If Security `4689` was not enabled before the game was closed,
TraceUSB records `close time unavailable` instead of estimating a false
duration.

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

When enabled, TraceUSB creates an in-memory ZIP attachment:

```text
TraceUSB_case_yyyyMMdd_HHmmss.zip
integrity_hashes_yyyyMMdd_HHmmss.txt
```

The ZIP contains the run artifacts generated by TraceUSB, including analysis,
timeline, evidence JSONL, translations, optional filtered history, network
snapshot, system context, and run log. `integrity_hashes_*.txt` records SHA256
hashes for the files inside the case bundle so reviewers can detect accidental
or intentional changes after collection. These files are not saved locally
unless `-SaveLocalArtifacts` is used.

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

TraceUSB collects native Windows metadata locally, builds artifacts in memory,
and sends them to the configured Discord relay by default. It does not store the
real Discord webhook in the public script. Final report artifacts are not saved
locally unless an operator explicitly enables local/debug output.

---

## Disclaimer

TraceUSB is for local diagnostics, education, system auditing, and forensic visibility. Its output should be reviewed by a human operator and treated as indicators, not automatic proof of misconduct.
