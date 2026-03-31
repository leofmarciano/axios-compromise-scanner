# axios-compromise-scanner

Single-file Python scanner for Windows, macOS, and Linux focused on the March 31, 2026 axios/plain-crypto-js incident.

## What it does

The scanner looks for:
- **Known file/path artifacts** associated with the incident (platform-specific)
- **Suspicious running processes** (via `ps` on macOS/Linux or WMI on Windows)
- **Persistence mechanisms** (LaunchAgents/LaunchDaemons on macOS, common Windows autoruns/tasks, systemd/cron on Linux)
- **Network indicators** (best-effort via `lsof` or `netstat`)
- **Project indicators** in common JS lockfiles and dependency paths (e.g. `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `node_modules/...`)
- **npm/shell history hints** (best-effort)

## Requirements

- Python 3 (no external dependencies)

## Run

### macOS / Linux

```bash
curl -fsSL https://raw.githubusercontent.com/leofmarciano/axios-compromise-scanner/main/axios_ioc_scan.py -o axios_ioc_scan.py
python3 axios_ioc_scan.py
```

### Windows PowerShell

```powershell
curl.exe -fsSL https://raw.githubusercontent.com/leofmarciano/axios-compromise-scanner/main/axios_ioc_scan.py -o axios_ioc_scan.py
py .\axios_ioc_scan.py
```

## Optional: restrict scanning to specific directories

By default the script scans a small set of common locations. You can override the scan roots with `SCAN_ROOTS`.

- On **macOS/Linux**, separate roots with `:` (colon).
- On **Windows**, separate roots with `;` (semicolon).

### macOS / Linux

```bash
SCAN_ROOTS="$HOME/projects:/srv/apps" python3 axios_ioc_scan.py
```

### Windows PowerShell

```powershell
$env:SCAN_ROOTS = "$HOME\projects;D:\apps"
py .\axios_ioc_scan.py
```

## Output

The script writes a folder like `axios-ioc-scan-YYYYMMDD-HHMMSS` containing:
- `summary.txt` (human-readable summary + recommended next steps)
- `result.json` (machine-readable report)
- supporting artifacts (process/network/persistence dumps, and `project_findings.json`)

## Notes

- This tool is **best-effort** and cannot guarantee detection. If you have strong reason to suspect exposure, treat the host as untrusted and follow an incident response playbook (credential rotation, CI token rotation, etc.).
