"""Unzip + malware check for everything in /input. Results go to /output.

Per file: ClamAV scan, magic-byte type detection, executable detection,
and (for PDFs) a scan for active-content markers. Archives are extracted
safely (zip-slip, symlink, size, file-count, depth limits) and every member
is checked. Clean files -> /output/clean, anything flagged -> /output/quarantine.
"""
import hashlib, itertools, json, os, re, shutil, subprocess, sys, tarfile, zipfile
from pathlib import Path

import magic

sys.path.insert(0, "/app")  # python -I omits the script dir; /app is our own trusted code
import checks

_uid = itertools.count(1)

INPUT, OUTPUT, WORK = Path("/input"), Path("/output"), Path("/work")
MAX_TOTAL = 4 * 1024**3      # total extracted bytes per archive
MAX_FILES = 20000
MAX_DEPTH = 4                # nested archive depth
MAX_RATIO = 200              # compression ratio guard (zip bomb)

ARCHIVE_EXT = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".gz", ".7z", ".rar")
EXEC_MIMES = {
    "application/x-dosexec", "application/x-executable", "application/x-sharedlib",
    "application/x-mach-binary", "application/x-msdownload", "application/vnd.microsoft.portable-executable",
    "application/x-elf", "application/java-archive", "application/x-java-applet",
    "application/x-sh", "application/x-shellscript", "application/x-bat",
}
EXEC_EXT = {".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".msi", ".ps1", ".vbs", ".vbe", ".js", ".jse",
            ".wsf", ".hta", ".jar", ".sh", ".app", ".pkg", ".dmg", ".apk", ".lnk", ".cpl", ".reg", ".iso"}
# Patterns anchored to PDF dictionary syntax so random compressed bytes rarely match.
PDF_MARKERS = {
    "/JavaScript": rb"/JavaScript(?![A-Za-z])",
    "/JS": rb"/JS\s*[(<\[]",
    "/Launch": rb"/S\s*/Launch",
    "/EmbeddedFile": rb"/Type\s*/EmbeddedFile",
    "/RichMedia": rb"/Subtype\s*/RichMedia",
    "/OpenAction": rb"/OpenAction(?![A-Za-z])",
    "/AA": rb"/AA\s*<<",
    "/XFA": rb"/XFA\s*[\[<(]",
    "/SubmitForm": rb"/S\s*/SubmitForm",
}
HIGH_RISK_PDF = {"/JavaScript", "/JS", "/Launch", "/EmbeddedFile", "/RichMedia"}


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def is_archive(p: Path) -> bool:
    n = p.name.lower()
    return n.endswith(ARCHIVE_EXT) or zipfile.is_zipfile(p) and not n.endswith((".docx", ".xlsx", ".pptx", ".jar"))


def safe_target(dest: Path, name: str) -> Path | None:
    t = (dest / name).resolve()
    return t if t == dest.resolve() or dest.resolve() in t.parents else None


def extract(archive: Path, dest: Path) -> list[str]:
    """Extract defensively. Returns list of warnings; raises on bombs."""
    dest.mkdir(parents=True)
    warns, total, count = [], 0, 0
    n = archive.name.lower()
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as z:
            for i in z.infolist():
                count += 1; total += i.file_size
                if count > MAX_FILES or total > MAX_TOTAL:
                    raise RuntimeError("archive exceeds size/file-count limits (possible zip bomb)")
                if i.compress_size and i.file_size / i.compress_size > MAX_RATIO and i.file_size > 50 * 1024**2:
                    raise RuntimeError(f"suspicious compression ratio on {i.filename}")
                if i.flag_bits & 0x1:
                    warns.append(f"encrypted member skipped (cannot scan): {i.filename}"); continue
                t = safe_target(dest, i.filename)
                if t is None:
                    warns.append(f"path traversal entry blocked: {i.filename}"); continue
                if (i.external_attr >> 16) & 0o170000 == 0o120000:
                    warns.append(f"symlink entry skipped: {i.filename}"); continue
                if i.is_dir():
                    t.mkdir(parents=True, exist_ok=True); continue
                t.parent.mkdir(parents=True, exist_ok=True)
                with z.open(i) as src, t.open("wb") as out:
                    shutil.copyfileobj(src, out)
    elif tarfile.is_tarfile(archive):
        with tarfile.open(archive) as tf:
            for m in tf:
                count += 1; total += m.size
                if count > MAX_FILES or total > MAX_TOTAL:
                    raise RuntimeError("archive exceeds size/file-count limits")
                t = safe_target(dest, m.name)
                if t is None:
                    warns.append(f"path traversal entry blocked: {m.name}"); continue
                if not (m.isfile() or m.isdir()):
                    warns.append(f"special/link entry skipped: {m.name}"); continue
                if m.isdir():
                    t.mkdir(parents=True, exist_ok=True); continue
                t.parent.mkdir(parents=True, exist_ok=True)
                with tf.extractfile(m) as src, t.open("wb") as out:
                    shutil.copyfileobj(src, out)
    else:  # 7z / rar / gz via p7zip
        r = subprocess.run(["7z", "x", "-y", "-snl-", f"-o{dest}", "-p-", str(archive)],
                           capture_output=True, text=True, timeout=600)
        if r.returncode not in (0, 1):
            raise RuntimeError(f"7z failed: {r.stderr.strip()[:300] or r.stdout.strip()[-300:]}")
        for p in list(dest.rglob("*")):  # strip anything unsafe 7z may have created
            if p.is_symlink():
                p.unlink(); warns.append(f"symlink removed: {p.relative_to(dest)}")
        if sum(f.stat().st_size for f in dest.rglob("*") if f.is_file()) > MAX_TOTAL:
            raise RuntimeError("extracted size exceeds limit")
    return warns


def clamscan(target: Path) -> dict[str, str]:
    """Returns {file: signature} for infected files."""
    tmpdir = WORK / "clamtmp"
    tmpdir.mkdir(exist_ok=True)
    r = subprocess.run(["clamscan", "-r", "--infected", "--no-summary", f"--tempdir={tmpdir}", "--max-filesize=2000M",
                        "--max-scansize=4000M", "--max-files=2000000", "--max-recursion=40", "--max-scantime=3000000", "--detect-pua=yes", "--heuristic-alerts=yes",
                        "--alert-encrypted=yes", "--alert-broken=yes", "--alert-exceeds-max=yes",
                        "--alert-macros=yes", "--alert-phishing-ssl=yes", "--alert-phishing-cloak=yes",
                        "--alert-partition-intersection=yes", str(target)],
                       capture_output=True, text=True, timeout=3600)
    if r.returncode not in (0, 1):
        raise RuntimeError(f"clamscan error (rc={r.returncode}): {r.stderr.strip()[:300]}")
    if "LibClamAV Error" in r.stderr or "LibClamAV Error" in r.stdout:  # fail closed: never report clean on engine errors
        raise RuntimeError(f"ClamAV engine error: {(r.stderr or r.stdout).strip()[:300]}")
    out = {}
    for line in r.stdout.splitlines():
        m = re.match(r"(.+): (.+) FOUND$", line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def inspect_file(p: Path, rel: str, derived: Path) -> tuple[list[dict], dict, list[Path]]:
    """All per-file checks. PDF JS/embedded files are written into `derived` for re-scanning."""
    findings, info, extracted = [], {}, []
    mime = magic.from_file(str(p), mime=True)
    desc = magic.from_file(str(p))
    ext = p.suffix.lower()
    if mime in EXEC_MIMES or ext in EXEC_EXT or "executable" in desc.lower():
        findings.append({"file": rel, "severity": "high", "issue": f"executable/script content ({desc[:80]})"})
    findings += checks.name_check(p, rel, mime)
    findings += checks.yara_scan(p, rel)
    with p.open("rb") as f:
        head = f.read(1024)
    if mime == "application/pdf" or ext == ".pdf" or b"%PDF-" in head:
        if head.find(b"%PDF-") != 0:
            findings.append({"file": rel, "severity": "medium", "issue": "PDF header not at start of file"})
        sub = derived / f"d{next(_uid)}"
        pf, info = checks.pdf_deep(p, rel, sub)
        findings += pf
        extracted = [d for d in sub.rglob("*") if d.is_file()]
    if ext in checks.OFFICE_EXT or mime.startswith(("application/msword", "application/vnd.ms-", "application/vnd.openxmlformats", "application/CDFV2", "application/rtf")):
        findings += checks.office_check(p, rel)
    return findings, info, extracted


def scan_item(item: Path, depth: int = 0) -> dict:
    result = {"name": item.name, "sha256": sha256(item), "size": item.stat().st_size,
              "type": magic.from_file(str(item)), "findings": [], "warnings": [], "extracted_files": 0, "pdf_info": {}}
    for algo in ("md5", "sha1"):
        h = hashlib.new(algo)
        with item.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        result[algo] = h.hexdigest()
    result["virustotal"] = f"https://www.virustotal.com/gui/file/{result['sha256']}"
    scan_root, tmp = item, None
    if is_archive(item) and depth < MAX_DEPTH:
        tmp = WORK / f"x{next(_uid)}"
        try:
            result["warnings"] += extract(item, tmp)
            scan_root = tmp
            for inner in [f for f in tmp.rglob("*") if f.is_file() and is_archive(f)]:
                sub = scan_item(inner, depth + 1)
                for f in sub["findings"]:
                    f["file"] = f"{inner.relative_to(tmp)} > {f['file']}"
                    result["findings"].append(f)
                result["warnings"] += sub["warnings"]
        except Exception as e:
            result["findings"].append({"file": item.name, "severity": "high", "issue": f"extraction refused: {e}"})
            scan_root = item
    elif is_archive(item):
        result["findings"].append({"file": item.name, "severity": "high", "issue": "archive nesting too deep"})

    def clam(root: Path, label: str):
        for sig_file, sig in clamscan(root).items():
            rel = os.path.relpath(sig_file, root) if root.is_dir() else item.name
            result["findings"].append({"file": f"{label}{rel}", "severity": "critical", "issue": f"ClamAV: {sig}"})

    clam(scan_root, "")

    derived = WORK / f"derived{next(_uid)}"
    derived.mkdir()
    files = [f for f in scan_root.rglob("*") if f.is_file()] if scan_root.is_dir() else [item]
    result["extracted_files"] = len(files) if scan_root.is_dir() else 0
    queue = [(f, str(f.relative_to(scan_root)) if scan_root.is_dir() else item.name, 0) for f in files]
    while queue:
        f, rel, lvl = queue.pop()
        fnd, info, extracted = inspect_file(f, rel, derived)
        result["findings"] += fnd
        if info:
            result["pdf_info"][rel] = info
        # anything pulled out of a PDF (JS, embedded files) gets the full treatment too
        if extracted and lvl < 3:
            for d in extracted:
                for sig_file, sig in clamscan(d).items():
                    result["findings"].append({"file": f"{rel} [embedded] > {d.name}", "severity": "critical", "issue": f"ClamAV: {sig}"})
                queue.append((d, f"{rel} [embedded] > {d.name}", lvl + 1))
        elif extracted:
            result["findings"].append({"file": rel, "severity": "high", "issue": "embedded files nested too deep"})
    if tmp:
        shutil.rmtree(tmp, ignore_errors=True)
    shutil.rmtree(derived, ignore_errors=True)
    return result


def verdict(findings: list[dict]) -> str:
    sev = {f["severity"] for f in findings}
    if "critical" in sev or "high" in sev:
        return "FLAGGED"
    return "REVIEW" if "medium" in sev else "CLEAN"


def main() -> int:
    items = sorted(p for p in INPUT.iterdir() if p.is_file() and not p.name.startswith("."))
    if not items:
        print("Nothing in to-check/."); return 0
    for d in ("clean", "quarantine", "reports"):
        (OUTPUT / d).mkdir(parents=True, exist_ok=True)
    exit_code = 0
    for item in items:
        print(f"\n== Scanning: {item.name}", flush=True)
        try:
            res = scan_item(item)
        except Exception as e:
            res = {"name": item.name, "findings": [{"file": item.name, "severity": "high", "issue": f"scan failed: {e}"}],
                   "warnings": []}
        res["verdict"] = verdict(res["findings"])
        for f in res["findings"]:
            print(f"   [{f['severity']:8}] {f['file']}: {f['issue']}")
        for w in res["warnings"]:
            print(f"   [warn    ] {w}")
        print(f"   => {res['verdict']}")
        dest = OUTPUT / ("clean" if res["verdict"] == "CLEAN" else "quarantine")
        (OUTPUT / "reports" / f"{item.name}.json").write_text(json.dumps(res, indent=2))
        shutil.move(str(item), dest / item.name)
        if dest.name == "quarantine":
            os.chmod(dest / item.name, 0o400)
            exit_code = 2
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
