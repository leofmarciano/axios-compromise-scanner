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

class Report:
    def __init__(self):
        self.hits: List[str] = []
        self.warnings: List[str] = []
        self.info: List[str] = []
        self.artifacts: Dict[str, str] = {}

    def hit(self, msg: str):
        self.hits.append(msg)

    def warn(self, msg: str):
        self.warnings.append(msg)

    def note(self, msg: str):
        self.info.append(msg)


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
            report.hit(f"Encontrado artefato de IOC no caminho conhecido: {p}")
            try:
                report.note(f"SHA256 {p}: {sha256_file(p)}")
            except Exception:
                pass
        else:
            report.note(f"Caminho não encontrado: {p}")


def process_scan(report: Report, outdir: Path):
    pk = get_platform_key()
    commands = []
    if pk in ("linux", "darwin"):
        commands = [["ps", "aux"]]
    else:
        commands = [["powershell", "-NoProfile", "-Command", "Get-CimInstance Win32_Process | Select-Object ProcessId,Name,CommandLine | Format-List"]]
    suspicious = []
    for cmd in commands:
        rc, out, err = run_cmd(cmd, timeout=30)
        (outdir / "processes.txt").write_text(out + ("\nSTDERR:\n" + err if err else ""), encoding="utf-8")
        blob = (out + "\n" + err).lower()
        for needle in ["sfrclak.com", "6202033", "com.apple.act.mond", "wt.exe", "ld.py", "plain-crypto-js"]:
            if needle.lower() in blob:
                suspicious.append(needle)
    if suspicious:
        report.hit("Processos com indicadores suspeitos: " + ", ".join(sorted(set(suspicious))))


def persistence_scan(report: Report, outdir: Path):
    pk = get_platform_key()
    findings = []
    if pk == "darwin":
        scan_dirs = [Path(HOME) / "Library/LaunchAgents", Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons")]
        for d in scan_dirs:
            if not d.exists():
                continue
            for file in d.rglob("*.plist"):
                text = safe_read_text(file)
                if any(s in text for s in ["sfrclak.com", "6202033", "com.apple.act.mond"]):
                    findings.append(str(file))
        rc, out, err = run_cmd(["launchctl", "list"], timeout=20)
        (outdir / "launchctl.txt").write_text(out + ("\nSTDERR:\n" + err if err else ""), encoding="utf-8")
        if any(x in out.lower() for x in ["mond", "6202033", "sfrclak"]):
            findings.append("launchctl:list")
    elif pk == "windows":
        cmds = [
            ["powershell", "-NoProfile", "-Command", "Get-ScheduledTask | Select-Object TaskName,TaskPath,State | Format-List"],
            ["powershell", "-NoProfile", "-Command", "Get-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run,HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -ErrorAction SilentlyContinue | Format-List"],
        ]
        merged = []
        for idx, cmd in enumerate(cmds):
            rc, out, err = run_cmd(cmd, timeout=30)
            (outdir / f"windows_persistence_{idx}.txt").write_text(out + ("\nSTDERR:\n" + err if err else ""), encoding="utf-8")
            merged.append(out + err)
        blob = "\n".join(merged).lower()
        if any(x in blob for x in ["wt.exe", "6202033", "sfrclak", "powershell -w hidden", "ep bypass"]):
            findings.append("windows:persistence")
    else:
        dirs = [Path("/etc/systemd/system"), Path(HOME) / ".config/systemd/user", Path("/etc/cron.d"), Path("/var/spool/cron")]
        for d in dirs:
            if not d.exists():
                continue
            for file in d.rglob("*"):
                if file.is_file():
                    text = safe_read_text(file)
                    if any(x in text for x in ["ld.py", "6202033", "sfrclak.com"]):
                        findings.append(str(file))
    if findings:
        report.hit("Possível persistência encontrada em: " + ", ".join(findings[:20]))


def network_scan(report: Report, outdir: Path):
    findings = []
    tools = []
    if shutil.which("lsof"):
        tools.append(["lsof", "-nPi"])
    elif shutil.which("netstat"):
        tools.append(["netstat", "-an"])
    for idx, cmd in enumerate(tools):
        rc, out, err = run_cmd(cmd, timeout=20)
        (outdir / f"network_{idx}.txt").write_text(out + ("\nSTDERR:\n" + err if err else ""), encoding="utf-8")
        blob = (out + err).lower()
        for x in ["142.11.206.73", "sfrclak.com", ":8000"]:
            if x.lower() in blob:
                findings.append(x)
    try:
        ip = socket.gethostbyname("sfrclak.com")
        report.note(f"Resolução atual de sfrclak.com: {ip}")
    except Exception as e:
        report.note(f"Não foi possível resolver sfrclak.com: {e}")
    if findings:
        report.hit("Indícios de rede ao C2 ou porta associada: " + ", ".join(sorted(set(findings))))


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
    findings = []
    ioc_findings = []
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
                    if rg.search(text):
                        findings.append(str(path))
                        break
                for ioc in IOC_STRINGS:
                    if ioc in text or ioc in path_str:
                        ioc_findings.append(f"{path}: {ioc}")
    (outdir / "project_findings.json").write_text(json.dumps({
        "version_hits": findings[:500],
        "ioc_hits": ioc_findings[:500],
        "files_checked": searched,
    }, indent=2), encoding="utf-8")
    if findings:
        report.hit(f"Encontrados arquivos de projeto/lockfile com versões afetadas: {len(findings)} ocorrência(s)")
    if ioc_findings:
        report.hit(f"Encontrados indicadores textuais em arquivos de projeto: {len(ioc_findings)} ocorrência(s)")
    report.note(f"Arquivos verificados na varredura de projetos: {searched}")


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
    hits = []
    for c in candidates:
        if not c.exists():
            continue
        if c.is_file():
            text = safe_read_text(c)
            if any(x in text for x in ["plain-crypto-js", "axios@1.14.1", "axios@0.30.4", "sfrclak.com"]):
                hits.append(str(c))
        else:
            for f in c.rglob("*"):
                if f.is_file():
                    text = safe_read_text(f, limit=1024 * 256)
                    if any(x in text for x in ["plain-crypto-js", "axios@1.14.1", "axios@0.30.4", "sfrclak.com"]):
                        hits.append(str(f))
    (outdir / "npm_log_hits.txt").write_text("\n".join(hits), encoding="utf-8")
    if hits:
        report.warn(f"Encontrados vestígios em histórico/logs npm ou shell: {len(hits)}")


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
    for r in roots:
        if not r.exists():
            continue
        for name in ["6202033.ps1", "6202033.vbs", "ld.py", "6202033"]:
            p = r / name
            if p.exists():
                found.append(str(p))
    (outdir / "temp_artifacts.txt").write_text("\n".join(found), encoding="utf-8")
    if found:
        report.hit("Artefatos temporários suspeitos encontrados: " + ", ".join(found))


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
        "hits": report.hits,
        "warnings": report.warnings,
        "info": report.info,
        "generated_at_utc": dt.datetime.now(dt.UTC).isoformat() + "Z",
        "scan_roots": [str(x) for x in roots],
    }

    json_path = outdir / "result.json"
    txt_path = outdir / "summary.txt"
    json_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = []
    lines.append(f"Verdict: {verdict}")
    lines.append("")
    if report.hits:
        lines.append("Strong indicators:")
        lines.extend([f"- {x}" for x in report.hits])
        lines.append("")
    if report.warnings:
        lines.append("Warnings:")
        lines.extend([f"- {x}" for x in report.warnings])
        lines.append("")
    lines.append("Info:")
    lines.extend([f"- {x}" for x in report.info])
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
