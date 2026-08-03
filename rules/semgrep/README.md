# Workbench Semgrep rules

These rules are original, conservative triage rules maintained by this project.
They run against JADX Java output and create review candidates rather than final
vulnerability verdicts. Each rule records the relevant MASVS/MASTG mapping in
metadata so the normalized finding keeps its provenance.

Run locally:

```powershell
semgrep scan --json --metrics=off -c rules/semgrep data\analysis\<app-id>\jadx
```

These files were authored for this workbench; no external ruleset text is
vendored. Set `MSW_SEMGREP_RULES_PATH` to use an approved local rules directory.
