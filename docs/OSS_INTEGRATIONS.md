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

An empty Frida selection means no Frida execution. Optional automatic selection
is explicit and is restricted to approved built-in, low-risk scripts whose
platform, framework and analysis conditions match the selected app. Custom, AI,
medium and high-risk scripts remain in the per-run manual approval path.

Every runtime command is bound to the selected device. pymobiledevice3 receives
the selected UDID, iOS Frida uses `-D <device-id>`, and drozer gets a per-run ADB
forward to the selected Android device instead of sharing its default port.

## Live execution safety boundary

Projects have an immutable-after-use `mock` or `live` run mode. Live runs reject
Mock device, proxy and AI adapters; unknown adapter names return an error instead
of falling back to Mock. Synthetic apps, runs, findings, evidence, flows, tool
results and AI invocations carry a persistent marker.

mitmproxy binds to a user-selected Windows LAN IP, uses a dynamically allocated
port and requires an allowed client IP. The addon rejects other source addresses.
The orchestrator stops the complete proxy process tree on completion, stop,
failure and server shutdown, then drains the final JSONL capture. Listener bind
failures trigger a new leased port and retry up to three times inside a shared
startup critical section.

Burp and Fiddler remain manually operated products. Selecting either pauses the
run at `proxy_manual_setup`, displays the exact LAN listener instructions and
requires a non-empty, structurally validated HAR/JSON import before resume. The
imported original and normalized final flows are both retained as evidence.

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
proxies and redirects are disabled; the destination, addresses, certificate,
artifact hash and approval metadata are retained in the analyzer tool run.

Static reanalysis uses an app-scoped in-process lease and a unique output
directory per attempt. A concurrent request returns `409 analysis_in_progress`;
successful output is activated through an atomically replaced `latest.json`.

The HTTP API is loopback-only by default. LAN mode requires a specific bind
address, an ephemeral Bearer token, a separate administrator token for state
changes, and Trusted Host validation. OpenAPI, Swagger UI and ReDoc are disabled
unless explicitly enabled. WebSockets use a 30-second, single-use, run- and
client-scoped ticket issued through Bearer-authenticated `/api/ws-ticket`; API
and administrator tokens are not placed in URLs or browser storage.

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
