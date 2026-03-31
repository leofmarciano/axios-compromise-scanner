#!/usr/bin/env python3
import base64
import datetime as dt
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple

AFFECTED_PACKAGES = {
    "axios": ["0.30.4", "1.14.1"],
    "plain-crypto-js": ["4.2.0", "4.2.1"],
    "@shadanai/openclaw": ["2026.3.28-2", "2026.3.28-3", "2026.3.31-1", "2026.3.31-2"],
    "@qqbrowser/openclaw-qbot": ["0.0.130"],
}

IOC_STRINGS = [
    "sfrclak.com",
    "142.11.206.73",
    "packages.npm.org/product0",
    "packages.npm.org/product1",
    "packages.npm.org/product2",
    "6202033",
    "plain-crypto-js",
    "com.apple.act.mond",
    "wt.exe",
    "ld.py",
]

# Word-boundary regexes to avoid false positives (e.g. "ld.py" inside "build.py")
IOC_PATTERNS = [re.compile(r'(?<![a-zA-Z0-9_/\\])' + re.escape(s) + r'(?![a-zA-Z0-9_])') for s in IOC_STRINGS]

PATH_IOCS = {
    "darwin": [
        "/Library/Caches/com.apple.act.mond",
        "~/Library/LaunchAgents",
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
    ],
    "windows": [
        r"%PROGRAMDATA%\wt.exe",
        r"%TEMP%\6202033.ps1",
        r"%TEMP%\6202033.vbs",
    ],
    "linux": [
        "/tmp/ld.py",
        "/var/tmp/ld.py",
    ],
}

SEARCH_FILE_NAMES = {
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "setup.js",
    "package.md",
}

SUSPICIOUS_PATH_PARTS = [
    "node_modules/plain-crypto-js",
    "node_modules/@shadanai/openclaw",
    "node_modules/@qqbrowser/openclaw-qbot",
]

DEFAULT_SCAN_ROOTS = []
HOME = str(Path.home())
if platform.system().lower() == "windows":
    DEFAULT_SCAN_ROOTS = [HOME]
else:
    DEFAULT_SCAN_ROOTS = [HOME, "/tmp", "/var/tmp"]

class Finding:
    def __init__(self, msg: str, evidence: List[str] | None = None):
        self.msg = msg
        self.evidence: List[str] = evidence or []

    def __str__(self):
        return self.msg


class Report:
    def __init__(self):
        self.hits: List[Finding] = []
        self.warnings: List[Finding] = []
        self.info: List[str] = []
        self.artifacts: Dict[str, str] = {}

    def hit(self, msg: str, evidence: List[str] | None = None):
        self.hits.append(Finding(msg, evidence))

    def warn(self, msg: str, evidence: List[str] | None = None):
        self.warnings.append(Finding(msg, evidence))

    def note(self, msg: str):
        self.info.append(msg)


def find_ioc_matches(text: str, max_context: int = 120) -> List[Tuple[str, List[str]]]:
    """Search text for IOC patterns with word boundaries. Returns list of (ioc_string, [evidence_lines])."""
    results = []
    lines = text.splitlines()
    for ioc, pat in zip(IOC_STRINGS, IOC_PATTERNS):
        evidence = []
        for lineno, line in enumerate(lines, 1):
            if pat.search(line):
                snippet = line.strip()
                if len(snippet) > max_context:
                    snippet = snippet[:max_context] + "..."
                evidence.append(f"  line {lineno}: {snippet}")
        if evidence:
            results.append((ioc, evidence[:10]))
    return results


def run_cmd(cmd: List[str], timeout: int = 20) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 999, "", str(e)


def safe_read_text(path: Path, limit: int = 1024 * 512) -> str:
    try:
        with path.open("rb") as f:
            data = f.read(limit)
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def expand_env_path(p: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(p)))


def get_platform_key() -> str:
    s = platform.system().lower()
    if s.startswith("darwin"):
        return "darwin"
    if s.startswith("windows"):
        return "windows"
    return "linux"


def find_ioc_files(report: Report, outdir: Path):
    pk = get_platform_key()
    for raw in PATH_IOCS.get(pk, []):
        p = expand_env_path(raw)
        if p.exists():
            sha = ""
            try:
                sha = sha256_file(p)
            except Exception:
                pass
            ev = [f"Path exists: {p}"]
            if sha:
                ev.append(f"SHA256: {sha}")
            report.hit(f"IOC artifact found at known path: {p}", ev)
        else:
            report.note(f"Path not found: {p}")


def process_scan(report: Report, outdir: Path):
    pk = get_platform_key()
    commands = []
    if pk in ("linux", "darwin"):
        commands = [["ps", "aux"]]
    else:
        commands = [["powershell", "-NoProfile", "-Command", "Get-CimInstance Win32_Process | Select-Object ProcessId,Name,CommandLine | Format-List"]]
    evidence = []
    for cmd in commands:
        rc, out, err = run_cmd(cmd, timeout=30)
        (outdir / "processes.txt").write_text(out + ("\nSTDERR:\n" + err if err else ""), encoding="utf-8")
        blob = out + "\n" + err
        matches = find_ioc_matches(blob)
        for ioc, lines in matches:
            evidence.append(f"[process list] IOC '{ioc}':")
            evidence.extend(lines)
    if evidence:
        report.hit("Processes with suspicious indicators", evidence)


def persistence_scan(report: Report, outdir: Path):
    pk = get_platform_key()
    evidence = []
    persist_needles = [re.compile(r'(?<![a-zA-Z0-9_/\\])' + re.escape(s) + r'(?![a-zA-Z0-9_])') for s in
                       ["sfrclak.com", "6202033", "com.apple.act.mond", "wt.exe", "ld.py", "powershell -w hidden", "ep bypass"]]
    persist_names = ["sfrclak.com", "6202033", "com.apple.act.mond", "wt.exe", "ld.py", "powershell -w hidden", "ep bypass"]
    if pk == "darwin":
        scan_dirs = [Path(HOME) / "Library/LaunchAgents", Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons")]
        for d in scan_dirs:
            if not d.exists():
                continue
            for file in d.rglob("*.plist"):
                text = safe_read_text(file)
                for name, pat in zip(persist_names, persist_needles):
                    if pat.search(text):
                        evidence.append(f"[plist] {file} matches '{name}'")
        rc, out, err = run_cmd(["launchctl", "list"], timeout=20)
        (outdir / "launchctl.txt").write_text(out + ("\nSTDERR:\n" + err if err else ""), encoding="utf-8")
        for name, pat in zip(persist_names, persist_needles):
            if pat.search(out):
                evidence.append(f"[launchctl list] matches '{name}'")
    elif pk == "windows":
        cmds = [
            ["powershell", "-NoProfile", "-Command", "Get-ScheduledTask | Select-Object TaskName,TaskPath,State | Format-List"],
            ["powershell", "-NoProfile", "-Command", "Get-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run,HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -ErrorAction SilentlyContinue | Format-List"],
        ]
        for idx, cmd in enumerate(cmds):
            rc, out, err = run_cmd(cmd, timeout=30)
            (outdir / f"windows_persistence_{idx}.txt").write_text(out + ("\nSTDERR:\n" + err if err else ""), encoding="utf-8")
            blob = out + err
            for name, pat in zip(persist_names, persist_needles):
                if pat.search(blob):
                    evidence.append(f"[windows persistence {idx}] matches '{name}'")
    else:
        dirs = [Path("/etc/systemd/system"), Path(HOME) / ".config/systemd/user", Path("/etc/cron.d"), Path("/var/spool/cron")]
        for d in dirs:
            if not d.exists():
                continue
            for file in d.rglob("*"):
                if file.is_file():
                    text = safe_read_text(file)
                    for name, pat in zip(persist_names, persist_needles):
                        if pat.search(text):
                            evidence.append(f"[systemd/cron] {file} matches '{name}'")
    if evidence:
        report.hit("Possible persistence mechanism detected", evidence)


def network_scan(report: Report, outdir: Path):
    evidence = []
    tools = []
    if shutil.which("lsof"):
        tools.append(["lsof", "-nPi"])
    elif shutil.which("netstat"):
        tools.append(["netstat", "-an"])
    net_needles = [re.compile(r'(?<![a-zA-Z0-9_/\\])' + re.escape(s) + r'(?![a-zA-Z0-9_])') for s in ["142.11.206.73", "sfrclak.com"]]
    net_names = ["142.11.206.73", "sfrclak.com"]
    for idx, cmd in enumerate(tools):
        rc, out, err = run_cmd(cmd, timeout=20)
        (outdir / f"network_{idx}.txt").write_text(out + ("\nSTDERR:\n" + err if err else ""), encoding="utf-8")
        blob = out + err
        for name, pat in zip(net_names, net_needles):
            for line in blob.splitlines():
                if pat.search(line):
                    snippet = line.strip()[:120]
                    evidence.append(f"[{' '.join(cmd[:2])}] '{name}': {snippet}")
    try:
        ip = socket.gethostbyname("sfrclak.com")
        report.note(f"Current resolution of sfrclak.com: {ip}")
    except Exception as e:
        report.note(f"Could not resolve sfrclak.com: {e}")
    if evidence:
        report.hit("Network indicators of C2 connection", evidence)


def version_regexes() -> List[re.Pattern]:
    regs = []
    for pkg, versions in AFFECTED_PACKAGES.items():
        pkg_re = re.escape(pkg)
        for ver in versions:
            regs.append(re.compile(rf'("{pkg_re}"\s*:\s*"[^"]*{re.escape(ver)}[^"]*")'))
            regs.append(re.compile(rf'({pkg_re}@{re.escape(ver)})'))
    return regs


def scan_project_files(report: Report, outdir: Path, roots: List[Path]):
    regs = version_regexes()
    version_findings = []
    version_evidence = []
    ioc_findings = []
    ioc_evidence = []
    searched = 0
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            name = path.name
            path_str = str(path).replace("\\", "/")
            if name in SEARCH_FILE_NAMES or any(part in path_str for part in SUSPICIOUS_PATH_PARTS):
                searched += 1
                text = safe_read_text(path)
                if not text:
                    continue
                for rg in regs:
                    m = rg.search(text)
                    if m:
                        version_findings.append(str(path))
                        version_evidence.append(f"[{path}] matched: {m.group(0)}")
                        break
                matches = find_ioc_matches(text)
                for ioc, lines in matches:
                    ioc_findings.append(f"{path}: {ioc}")
                    ioc_evidence.append(f"[{path}] IOC '{ioc}':")
                    ioc_evidence.extend(lines)
    (outdir / "project_findings.json").write_text(json.dumps({
        "version_hits": version_findings[:500],
        "ioc_hits": ioc_findings[:500],
        "files_checked": searched,
    }, indent=2), encoding="utf-8")
    if version_findings:
        report.hit(f"Found project/lockfile files with affected versions: {len(version_findings)} occurrence(s)", version_evidence[:50])
    if ioc_findings:
        report.hit(f"Found textual indicators in project files: {len(ioc_findings)} occurrence(s)", ioc_evidence[:50])
    report.note(f"Files checked in project scan: {searched}")


def npm_logs_scan(report: Report, outdir: Path):
    candidates = [
        Path(HOME) / ".npm/_logs",
        Path(HOME) / ".zsh_history",
        Path(HOME) / ".bash_history",
    ]
    if get_platform_key() == "windows":
        local = os.environ.get("LocalAppData")
        if local:
            candidates.append(Path(local) / "npm-cache/_logs")
        appdata = os.environ.get("APPDATA")
        if appdata:
            candidates.append(Path(appdata) / "npm-cache/_logs")
    npm_needles = ["plain-crypto-js", "axios@1.14.1", "axios@0.30.4", "sfrclak.com"]
    npm_pats = [re.compile(r'(?<![a-zA-Z0-9_/\\])' + re.escape(s) + r'(?![a-zA-Z0-9_])') for s in npm_needles]
    hits = []
    evidence = []

    def _check_file(fpath: Path, limit: int = 1024 * 512):
        text = safe_read_text(fpath, limit=limit)
        for name, pat in zip(npm_needles, npm_pats):
            for lineno, line in enumerate(text.splitlines(), 1):
                if pat.search(line):
                    hits.append(str(fpath))
                    snippet = line.strip()[:120]
                    evidence.append(f"[{fpath}] line {lineno}: '{name}' -> {snippet}")
                    return

    for c in candidates:
        if not c.exists():
            continue
        if c.is_file():
            _check_file(c)
        else:
            for f in c.rglob("*"):
                if f.is_file():
                    _check_file(f, limit=1024 * 256)
    (outdir / "npm_log_hits.txt").write_text("\n".join(hits), encoding="utf-8")
    if hits:
        report.warn(f"Found traces in npm logs or shell history: {len(hits)}", evidence[:20])


def temp_artifacts_scan(report: Report, outdir: Path):
    roots = []
    pk = get_platform_key()
    if pk == "windows":
        for envvar in ["TEMP", "TMP"]:
            val = os.environ.get(envvar)
            if val:
                roots.append(Path(val))
    else:
        roots.extend([Path("/tmp"), Path("/var/tmp"), Path(tempfile.gettempdir())])
    found = []
    evidence = []
    for r in roots:
        if not r.exists():
            continue
        for name in ["6202033.ps1", "6202033.vbs", "ld.py", "6202033"]:
            p = r / name
            if p.exists():
                found.append(str(p))
                try:
                    sha = sha256_file(p)
                    evidence.append(f"[{p}] SHA256: {sha}")
                except Exception:
                    evidence.append(f"[{p}] file exists")
    (outdir / "temp_artifacts.txt").write_text("\n".join(found), encoding="utf-8")
    if found:
        report.hit("Suspicious temporary artifacts found: " + ", ".join(found), evidence)


def summarize(report: Report) -> str:
    if report.hits:
        return "POSSIBLE_COMPROMISE"
    if report.warnings:
        return "NO_STRONG_IOC_BUT_REVIEW_WARNINGS"
    return "NO_OBVIOUS_IOC_FOUND"


def main():
    roots = [Path(p) for p in os.environ.get("SCAN_ROOTS", os.pathsep.join(DEFAULT_SCAN_ROOTS)).split(os.pathsep) if p]
    timestamp = dt.datetime.now(dt.UTC).strftime("%Y%m%d-%H%M%S")
    outdir = Path.cwd() / f"axios-ioc-scan-{timestamp}"
    outdir.mkdir(parents=True, exist_ok=True)

    report = Report()
    report.note(f"UTC: {dt.datetime.now(dt.UTC).isoformat()}Z")
    report.note(f"Host: {platform.node()}")
    report.note(f"OS: {platform.platform()}")
    report.note(f"Python: {sys.version}")
    report.note(f"Scan roots: {', '.join(str(x) for x in roots)}")

    find_ioc_files(report, outdir)
    process_scan(report, outdir)
    persistence_scan(report, outdir)
    network_scan(report, outdir)
    scan_project_files(report, outdir, roots)
    npm_logs_scan(report, outdir)
    temp_artifacts_scan(report, outdir)

    verdict = summarize(report)
    result = {
        "verdict": verdict,
        "hits": [{"finding": f.msg, "evidence": f.evidence} for f in report.hits],
        "warnings": [{"finding": f.msg, "evidence": f.evidence} for f in report.warnings],
        "info": report.info,
        "generated_at_utc": dt.datetime.now(dt.UTC).isoformat() + "Z",
        "scan_roots": [str(x) for x in roots],
    }

    json_path = outdir / "result.json"
    txt_path = outdir / "summary.txt"
    json_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = []
    sep = "-" * 60
    lines.append(sep)
    lines.append(f"  VERDICT: {verdict}")
    lines.append(sep)
    lines.append("")
    if report.hits:
        lines.append(f"STRONG INDICATORS ({len(report.hits)}):")
        lines.append("")
        for i, f in enumerate(report.hits, 1):
            lines.append(f"  [{i}] {f.msg}")
            if f.evidence:
                for ev in f.evidence:
                    lines.append(f"      {ev}")
            lines.append("")
    if report.warnings:
        lines.append(f"WARNINGS ({len(report.warnings)}):")
        lines.append("")
        for i, f in enumerate(report.warnings, 1):
            lines.append(f"  [{i}] {f.msg}")
            if f.evidence:
                for ev in f.evidence:
                    lines.append(f"      {ev}")
            lines.append("")
    lines.append("INFO:")
    lines.extend([f"  - {x}" for x in report.info])
    lines.append("")
    if verdict == "POSSIBLE_COMPROMISE":
        lines.append("Recommended next steps:")
        lines.append("- Treat the host as untrusted.")
        lines.append("- Rotate credentials used on this machine: npm, GitHub, cloud, SSH keys, CI tokens, browser sessions, API keys.")
        lines.append("- Preserve the output folder for incident response.")
        lines.append("- Rebuild the machine from a trusted source if a platform payload path is present.")
    elif verdict == "NO_STRONG_IOC_BUT_REVIEW_WARNINGS":
        lines.append("Recommended next steps:")
        lines.append("- Review lockfiles, npm logs, and package caches.")
        lines.append("- Check CI/CD, feature branches, and open PRs for affected versions.")
    else:
        lines.append("Recommended next steps:")
        lines.append("- No obvious IOC was found in this scan, but anti-forensics can hide traces. Review npm logs and recent installs if exposure is likely.")
    txt_path.write_text("\n".join(lines), encoding="utf-8")

    print(txt_path.read_text(encoding="utf-8"))
    print(f"\nArtifacts directory: {outdir}")

if __name__ == "__main__":
    main()
