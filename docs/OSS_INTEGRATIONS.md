# OSS integration guide

The workbench borrows architecture and workflows from established mobile
security projects without copying their source code or rule content. Every
integration is optional, reports an honest capability state, and preserves its
own raw output before findings are normalized.

## Integration matrix

| Project | Workbench use | Boundary | Upstream license / review |
|---|---|---|---|
| [Androguard](https://github.com/androguard/androguard) | APK binary XML and metadata enrichment | Python dependency | Apache-2.0 |
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | Optional APK/IPA scan federation | REST API to a separately operated instance | GPL-3.0; review deployment/distribution obligations |
| [APKiD](https://github.com/rednaga/APKiD) | Packer, compiler, obfuscation and anti-analysis signatures | Optional subprocess | GPL/commercial options; review before installation/distribution |
| [Semgrep](https://github.com/semgrep/semgrep) | Local rules against JADX output | Optional subprocess | See upstream component licenses; this repo vendors only original local rules |
| [objection](https://github.com/sensepost/objection) | Gated runtime exploration | Optional subprocess | GPL-3.0 |
| [drozer](https://github.com/WithSecureLabs/drozer) | Android IPC and attack-surface inspection | Optional subprocess plus approved device agent | BSD-3-Clause |
| [pymobiledevice3](https://github.com/doronz88/pymobiledevice3) | Windows USB iOS discovery/apps/launch/forwarding adapters | Optional subprocess | GPL-3.0 |
| [libimobiledevice](https://github.com/libimobiledevice/libimobiledevice) | Windows iOS info/apps/syslog/screenshot commands | Optional subprocess | LGPL/GPL split by component/tool |
| [OWASP MASTG](https://github.com/OWASP/owasp-mastg) | Test IDs, source links and a local execution ledger | Attribution-only curated catalog | CC BY-SA 4.0 |

This table is engineering guidance, not legal advice. A subprocess or REST
boundary does not by itself settle license obligations. Review the exact
version, distribution model and upstream license before shipping a bundled
installer.

## Finding federation

Each analyzer returns a common envelope:

- tool name/version/status and exact argument array;
- raw output path and SHA-256;
- source rule ID and a stable finding fingerprint;
- location, category, confidence and upstream references.

The correlation layer groups close location/category signals but keeps a
`FindingSource` row for every raw result. The UI therefore shows one review item
without losing which tool and rule produced it.

## Control ledger

`backend/app/catalog/mastg.py` contains a deliberately small curated mapping,
not a copy of the MASTG prose. It records the legacy test ID, replacement IDs
where the upstream repository marks a test as deprecated, automation class and
the canonical upstream URL. Static analysis creates the baseline; a diagnostic
run clones it and links evidence IDs as checks execute.

## Runtime approval boundary

Read-only objection and drozer actions may run from the diagnostic setup.
Direct device, runtime and Frida operations are scoped to a `safely_paused`
diagnostic run and its device lease. A pause request first becomes
`pause_requested`; manual work remains blocked until the active command finishes
and the orchestrator reaches a checkpoint. Actions that change app behavior, dump sensitive
stores or invoke exposed components require a server-issued, five-minute,
single-use approval token. Only its SHA-256 is stored, together with approver,
scope, issue time and consume time. AI-generated Frida code is always stored as
`pending_approval`; it is never executed in the generation request or automatic
repair step.

Deep-link and exported-component verification never accepts a free-form Intent
from the browser. The server rebuilds candidates from the active static-analysis
record and binds the one-time token to the candidate fingerprint. Android VIEW
intents are package-restricted and only activities/activity aliases are invoked;
services, receivers, providers and iOS candidates remain `manual_required`.
Before/after screenshots, command output and logs are attached to the matching
static Finding. Live execution additionally requires a still-valid approved
control-validation scope.

Manual-operation tasks are tracked per run. Normal stop and resume requests are
rejected while one is active, so the device lease cannot be released to another
run while a pull, runtime command or Frida load still owns it. Server shutdown
cancels and awaits those tasks and detaches the persistent Frida session before
releasing the lease.

An empty Frida selection means no Frida execution. Optional automatic selection
is explicit and is restricted to approved built-in, low-risk scripts whose
platform, framework and analysis conditions match the selected app. Custom, AI,
medium and high-risk scripts remain in the per-run manual approval path.

Automatic Frida execution uses the Python binding to spawn or attach once per
run. All selected scripts are loaded into that session, their messages remain
available through login and dynamic/network stages, and scripts are unloaded and
the session detached from the orchestrator's final cleanup.

Attach keeps the verified baseline process alive. Spawn first captures the
baseline, stops the app, verifies that its process exited, then spawns, loads the
scripts, resumes and verifies the new process before continuing. Session messages
are normalized into a configurable 500–2000 item ring and an append-only per-run
JSONL transcript. Binary data is base64 encoded; per-message and per-run limits
increment truncation/drop counters instead of failing the diagnostic. WebSocket
delivery is sampled independently from the full on-disk transcript.

iOS USB sessions use the selected UDID. A jailbroken SSH profile must provide a
validated `host:port` Frida endpoint; the Python binding connects through
`DeviceManager.add_remote_device`. The configured route and the actual connected
Frida device are exposed in device discovery and Run health instead of treating
an SSH process probe as a usable transport.

## Android navigation and dynamic data boundary

Android automatic navigation uses only ADB, UIAutomator XML and the fixed
`UIDriver` operation set. The local planner ranks clickable elements that exist
in the current tree; the executor rejects stale element IDs and never accepts AI
coordinates or shell commands. The policy is default-deny: only labelled
TextView/ViewGroup/tab containers with explicit list, detail or information
semantics are eligible for automatic taps. Buttons, toggles, confirmation/save,
unknown or unlabelled controls and browser/phone/map/system intent hints remain
in the approval queue. Structural fingerprints bound visits while content hashes
record dynamic text and state changes separately. Mock Android exposes the same
graph and policy path with a deterministic synthetic UI.

Optional AI candidate ranking runs only after that local policy has produced the
current screen's low-risk allowlist. NVIDIA with Claude fallback, or the Mock
provider, receives bounded labels/resource hints and the selected assessment
focus; it returns exact candidate IDs with advisory scores. The engine drops
unknown and duplicate IDs, appends omitted local candidates in deterministic
order, and rechecks the live UI and local risk immediately before every tap.
Provider failure preserves the local order. Ranking calls and the effective
order are audited on the Run but are not vulnerability evidence or verdicts.

Every executed transition records Before screenshot/tree, the fixed action, and
After screenshot/tree in sequence. `navigation-graph.json` links those evidence
IDs. Password fields are masked in normalized state; raw local trees remain
authenticated evidence rather than default UI content.

Optional Android storage capture is root-only and strictly scoped to
`/data/data/<validated-package>`. ADB stdout streams directly to a bounded
temporary file and is atomically promoted only after success. Entry, path and
link violations are rejected. Archive hashing and SQLite inspection run outside
the event loop, and SQLite queries have a progress-handler deadline. Before/After
metadata identifies created, modified and deleted files. SQLite files below the
configured limit are opened read-only and show table/column/count data with masked previews. ADB Clipboard
collection is explicitly `unsupported` because it cannot reliably attribute a
global clipboard value to the target app; Mock provides only a synthetic,
masked change signal.

## API candidate boundary

Proxy flows are locally normalized into method, endpoint, content type,
authentication scheme, cookie names, parameter shapes, object-ID candidates,
pagination, upload/GraphQL signals and sensitive response field names. Candidate
generation does not send requests. Passive metadata work runs locally; Mock may
perform a marked synthetic GET replay for comparator testing. Live GET replay,
all state-changing methods, uploads and object-boundary changes remain approval
candidates. The response comparator evaluates status, body length, JSON shape,
key/type changes, sensitive fields, redirects and authentication/authorization
responses instead of treating HTTP status as the only signal.

Default flow and Frida stream views are structurally masked. Full proxy and
Frida transcripts remain authenticated raw evidence; the explicit raw-flow API
uses `Cache-Control: no-store`. Project Raw access is disabled by default and
the normal Run console no longer requests raw flows. The dedicated local data
view requires the project policy to be enabled before it loads the path-free
raw index and packet bodies.

Each project has a bounded retention period, but expiry is a review signal and
never an automatic delete. The inventory calculates terminal Run expiry and
safe data-root sizes. Retention apply requires the exact previewed Run IDs,
project-name confirmation and a non-recoverable acknowledgement; the server
recomputes the candidate set before deleting. Active Runs, uploaded app files
and app-scoped static analysis remain outside this operation. SQLite schema V7
is backed up before the project data-policy columns are added.

Frida callbacks enqueue serialized messages into a bounded queue. One writer
opens the JSONL transcript once and drains it without blocking the callback;
queue saturation increments the drop counter. Remote devices registered through
Frida's device manager are explicitly removed during session teardown.

Every runtime command is bound to the selected device. pymobiledevice3 receives
the selected UDID, iOS Frida uses `-D <device-id>`, and drozer gets a per-run ADB
forward to the selected Android device instead of sharing its default port.

## Live execution safety boundary

Projects have an immutable-after-use `mock` or `live` run mode. Live runs reject
Mock device, proxy and AI adapters; unknown adapter names return an error instead
of falling back to Mock. Synthetic apps, runs, findings, evidence, flows, tool
results and AI invocations carry a persistent marker.

Approved control validation binds the authorization reference, approver, expiry,
selected device ID, test-account reference and a normalized destination-host
allowlist to the Run. The scope is checked when execution starts and again after
the final proxy drain. An expired authorization or device mismatch ends as
`manual_required`. In mitmproxy mode the addon applies the destination allowlist
before upstream forwarding and returns a local HTTP 451 response for a denied
host. Imported Burp/Fiddler flows are evaluated after capture; any out-of-scope
origin stops later automatic network testing and AI classification. Both the
approval record and scope-enforcement audit evidence remain local and are
excluded from the external AI evidence catalog.

mitmproxy binds to a user-selected Windows LAN IP, uses a dynamically allocated
port and requires an allowed client IP. The addon rejects other source addresses.
The orchestrator stops the complete proxy process tree on completion, stop,
failure and server shutdown, then drains the final JSONL capture. Listener bind
failures trigger a new leased port and retry up to three times inside a shared
startup critical section.

Burp and Fiddler remain manually operated products. Selecting either pauses the
run first at `proxy_manual_setup` to confirm the LAN listener and device proxy.
After app installation, launch and dynamic interaction, it pauses again at
`proxy_capture_import`; only then is a non-empty, structurally validated HAR/JSON
accepted. The imported original and normalized final flows are both retained as
evidence.

A pipeline reaching its last stage is not automatically a successful
diagnostic. App launch/process state, screenshot, logs, selected Frida session
health, proxy flow or explicit user confirmation are evaluated into `completed`,
`completed_with_gaps`, `manual_required` or `failed`, with missing required
stages retained on the run.

APK/IPA input is rejected before external tools run when archive entry, expanded
size, compression-ratio, nested archive, duplicate-name, traversal, encryption or
symlink limits are exceeded. Optional analyzer subprocesses and Androguard run
outside the FastAPI process with wall-time, process-tree memory and CPU-time
limits.

MobSF upload is disabled per project unless `external_analyzer_allowed` was
explicitly approved. Approval is bound to the normalized destination, every
resolved A/AAAA address and the HTTPS certificate SHA-256. A settings, DNS or
certificate change invalidates approval. Each upload also requires a second UI
confirmation of the destination and current APK/IPA SHA-256. HTTP environment
proxies and redirects are disabled. The transfer connects directly to an
approved snapshot IP while preserving the original HTTP Host and TLS SNI, then
rechecks the actual peer IP and certificate before sending data. The destination,
addresses, certificate, artifact hash and approval metadata are retained in the
analyzer tool run.

The pinned MobSF transport intentionally uses an `httpcore` backend hook because
the public `httpx` transport API cannot both preserve Host/SNI and connect only
to the approved IP snapshot. Security checks are not weakened: dependencies are
pinned to `httpx>=0.28,<0.29` and `httpcore>=1.0.9,<1.1`, startup validates the
required backend interfaces, and compatibility tests exercise peer-IP and TLS
revalidation.

Static reanalysis uses an app-scoped in-process lease and a unique output
directory per attempt. A concurrent request returns `409 analysis_in_progress`;
each attempt has an `AnalysisRun` row. Successful output is validated and
activated through an atomically replaced `latest.json` before a single database
transaction switches `active_analysis_run_id` and all normalized results. A
pointer failure leaves the prior active run and normalized database state intact.

The HTTP API is loopback-only by default. LAN mode requires a specific bind
address, an ephemeral Bearer token, a separate administrator token for state
changes, and Trusted Host validation. OpenAPI, Swagger UI and ReDoc are disabled
unless explicitly enabled. WebSockets use a 30-second, single-use, run- and
client-scoped ticket issued through Bearer-authenticated `/api/ws-ticket`; API
and administrator tokens are not placed in URLs or browser storage.

Evidence images, source downloads and HTML reports are fetched with the Bearer
header and exposed to the browser through short-lived Blob object URLs. The UI
does not embed unauthenticated `/api` URLs, so the same flows work in LAN mode.

GitHub Actions runs Python 3.12 compile/test and the frontend `npm ci`, build and
high-severity audit on Windows. Hardware, external API keys and live analyzer
services are not required; CI exercises unit and synthetic Mock paths only.

## Windows installation

The base installer includes Androguard because it is the default isolated APK
parser worker. Other tools are opt-in:

```powershell
.\install_oss_tools.ps1 -Frida -Mitmproxy -Semgrep
.\install_oss_tools.ps1 -APKiD -Objection -Pymobiledevice3 -Drozer -AcceptCopyleftLicenses
```

MobSF, jadx, apktool, Android SDK and libimobiledevice are configured by path or
URL. A failed installation is not converted into success; the settings page
will continue to show `not_configured` or `failed`.
