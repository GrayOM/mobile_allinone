# Third-party notices

Mobile Security Workbench can interoperate with third-party open-source tools.
Only Androguard is installed as a default Python dependency. The remaining
projects are optional user-installed programs or separately operated services.

See [docs/OSS_INTEGRATIONS.md](docs/OSS_INTEGRATIONS.md) for upstream links,
integration boundaries and license identifiers. Upstream names and trademarks
belong to their respective owners. OWASP MASTG identifiers and links are used
with attribution under CC BY-SA 4.0; the full MASTG content is not vendored.

Frida 17 runtime bridges (`frida-java-bridge`, `frida-objc-bridge`, LGPL-2.0
WITH wxWindows-exception-3.1) are installed locally under
`scripts/frida/runtime/node_modules` and are not committed. sslyze (AGPL-3.0)
and zsign (MIT) are optional user-installed executables invoked as subprocesses.

The domestic advisory guidance is extracted locally from the customer-provided
DOCX advisories by `scripts/extract_korean_guidance.py` and is gitignored. It is
customer reference material, not open-source content; do not commit or
redistribute it outside the engagement.
