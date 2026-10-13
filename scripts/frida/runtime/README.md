# Frida 17+ runtime bridges

Frida 17 no longer embeds the Java/ObjC bridges in its GumJS runtime. The
workbench therefore bundles approved scripts with these bridges at load time
through the Python `frida.Compiler` API. The approved script text and its
SHA-256 are never modified; the loader only adds:

1. `frida-java-bridge` / `frida-objc-bridge` exposed as the legacy `Java` and
   `ObjC` globals.
2. A compatibility shim that restores the removed static `Module.*` lookups
   (`findExportByName`, `getExportByName`, `findBaseAddress`, `getBaseAddress`)
   on top of the Frida 17 instance APIs.

Install once per checkout (Node.js 18+ required):

```powershell
.\install_oss_tools.ps1 -FridaRuntime
```

```bash
scripts/install_frida_runtime.sh
```

`node_modules/` stays local and is excluded from Git. Frida 16.x does not need
the bridges; the loader then only applies the shim.
