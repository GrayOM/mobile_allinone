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
Actions that change app behavior, dump sensitive stores or invoke exposed
components return `manual_required` until the API request includes explicit
approval. AI-generated Frida code is always stored as `pending_approval`; it is
never executed in the generation request or automatic repair step.

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
failure and server shutdown, then drains the final JSONL capture.

APK/IPA input is rejected before external tools run when archive entry, expanded
size, compression-ratio, nested archive, duplicate-name, traversal, encryption or
symlink limits are exceeded. Optional analyzer subprocesses run in their own
process group with wall-time, process-tree memory and CPU-time limits.

## Windows installation

The base installer includes Androguard because it is the default in-process APK
parser. Other tools are opt-in:

```powershell
.\install_oss_tools.ps1 -Frida -Mitmproxy -Semgrep
.\install_oss_tools.ps1 -APKiD -Objection -Pymobiledevice3 -Drozer -AcceptCopyleftLicenses
```

MobSF, jadx, apktool, Android SDK and libimobiledevice are configured by path or
URL. A failed installation is not converted into success; the settings page
will continue to show `not_configured` or `failed`.
