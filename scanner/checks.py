"""Deep per-file checks: YARA, PDF structure, Office macros, polyglot/disguise detection.
Every function returns findings: {"file","severity","issue"}. Any internal failure is
reported as a finding rather than silently passing (fail closed)."""
import re, zipfile
from pathlib import Path

import yara

_RULES = None
RLO = "‮"  # right-to-left override: used to fake extensions (invoice_exe.pdf)

EXT_MIME = {  # extension -> acceptable mime prefixes
    ".pdf": ("application/pdf",), ".jpg": ("image/jpeg",), ".jpeg": ("image/jpeg",), ".png": ("image/png",),
    ".gif": ("image/gif",), ".zip": ("application/zip",), ".txt": ("text/",), ".csv": ("text/", "application/csv"),
    ".docx": ("application/vnd.openxmlformats", "application/zip", "application/octet-stream"),
    ".xlsx": ("application/vnd.openxmlformats", "application/zip", "application/octet-stream"),
    ".pptx": ("application/vnd.openxmlformats", "application/zip", "application/octet-stream"),
}
OFFICE_EXT = {".doc", ".docx", ".docm", ".dot", ".dotm", ".xls", ".xlsx", ".xlsm", ".xlsb", ".xlt", ".ppt", ".pptx", ".pptm", ".ppsm", ".rtf"}
OOXML_EXT = {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".dotm", ".ppsm"}


def F(rel, sev, issue):
    return {"file": rel, "severity": sev, "issue": issue}


# ---------------------------------------------------------------- YARA
# Reviewed false positives. Every suppression is reported as a "low" finding, never hidden.
YARA_SUPPRESS = {
    "invalid_trailer_structure": "expects legacy 'trailer' keyword; modern PDFs use xref streams (structure is parsed by pdf_deep instead)",
    "Warp": "depends on a 4-byte string match; fires by chance on large compressed files",
    "WarpStrings": "4-byte string match; fires by chance on large compressed files",
}


def yara_scan(p: Path, rel: str) -> list[dict]:
    global _RULES
    try:
        if _RULES is None:
            _RULES = yara.load("/opt/rules.yarc")
        ext = {"filename": p.name, "filepath": str(p), "extension": p.suffix.lower(), "filetype": p.suffix.upper().lstrip("."), "owner": ""}
        out = []
        for m in _RULES.match(str(p), timeout=600, externals=ext):
            if m.rule in YARA_SUPPRESS:
                out.append(F(rel, "low", f"YARA {m.rule} suppressed: {YARA_SUPPRESS[m.rule]}"))
                continue
            lens = [len(i.matched_data) for st in m.strings for i in st.instances]
            if lens and max(lens) < 6:
                out.append(F(rel, "low", f"YARA {m.rule}: only matched tiny strings (<6 bytes), treated as chance"))
                continue
            score = int(m.meta.get("score", 75)) if str(m.meta.get("score", "75")).isdigit() else 75
            sev = "high" if score >= 70 else "medium"
            out.append(F(rel, sev, f"YARA: {m.rule} ({m.namespace.split('_')[0]})" + (f" - {m.meta['description'][:100]}" if m.meta.get("description") else "")))
        return out
    except Exception as e:
        return [F(rel, "medium", f"YARA scan failed (not verified): {str(e)[:150]}")]


# ---------------------------------------------------------------- PDF
def pdf_deep(p: Path, rel: str, derived: Path) -> tuple[list[dict], dict]:
    """Structural PDF analysis. Extracts JavaScript + embedded files into `derived` for further scanning."""
    import pikepdf
    findings, info = [], {}
    derived.mkdir(parents=True, exist_ok=True)

    # raw-bytes checks (tail data, embedded PE, obfuscated names)
    size = p.stat().st_size
    with p.open("rb") as f:
        f.seek(max(0, size - (4 << 20)))
        tail = f.read()
    pos = tail.rfind(b"%%EOF")
    if pos < 0:
        findings.append(F(rel, "medium", "no %%EOF marker near end of file (truncated/malformed)"))
    elif len(tail[pos + 5:].strip(b"\r\n \t\x00")) > 16:
        findings.append(F(rel, "high", f"{len(tail) - pos - 5} bytes of data after final %%EOF (appended payload / polyglot)"))
    obf = re.compile(rb"/[A-Za-z0-9]{0,20}#[0-9A-Fa-f]{2}[A-Za-z0-9#]{0,20}")
    keywords = {b"/JavaScript", b"/JS", b"/Launch", b"/EmbeddedFile", b"/OpenAction", b"/AA", b"/RichMedia",
                b"/URI", b"/SubmitForm", b"/XFA", b"/GoToR", b"/ImportData"}
    unhex = lambda m: bytes([int(m.group(1), 16)])
    with p.open("rb") as f:
        tailb = b""
        while chunk := f.read(8 << 20):
            buf = tailb + chunk
            if b"This program cannot be run in DOS mode" in buf or b"This program must be run under" in buf:
                findings.append(F(rel, "high", "embedded Windows executable (PE) bytes inside PDF"))
            for m in obf.finditer(buf):  # only flag if the decoded name is a real action keyword
                if re.sub(rb"#([0-9A-Fa-f]{2})", unhex, m.group(0)) in keywords:
                    findings.append(F(rel, "high", f"obfuscated PDF name {m.group(0)[:30].decode('latin1')} (hides an action keyword)"))
                    break
            tailb = buf[-96:]
    findings = list({(x["issue"]): x for x in findings}.values())

    try:
        pdf = pikepdf.open(str(p), attempt_recovery=True, suppress_warnings=True)
    except pikepdf.PasswordError:
        return findings + [F(rel, "high", "PDF is password-protected: contents cannot be inspected")], info
    except Exception as e:
        return findings + [F(rel, "medium", f"PDF structure unparseable (malformed - common in exploits): {str(e)[:120]}")], info

    counters = {"js": 0, "emb": 0}
    uris, seen = [], set()

    def name(o, key):
        try:
            v = o.get(key)
            return str(v) if v is not None else None
        except Exception:
            return None

    def save(kind, data, ext):
        counters[kind] += 1
        (derived / f"{kind}{counters[kind]}{ext}").write_bytes(data)

    def visit(o, depth=0):
        if depth > 40:
            return
        try:
            keys = list(o.keys())
        except Exception:
            try:
                for item in o:
                    if not getattr(item, "is_indirect", False):
                        visit(item, depth + 1)
            except Exception:
                pass
            return
        s = name(o, "/S")
        if s == "/Launch":
            findings.append(F(rel, "high", "PDF Launch action (can run programs)"))
        elif s in ("/GoToR", "/GoToE"):
            findings.append(F(rel, "medium", f"PDF {s} action (opens remote/embedded document)"))
        elif s in ("/SubmitForm", "/ImportData"):
            findings.append(F(rel, "medium", f"PDF {s} action (form data leaves the document)"))
        elif s == "/URI":
            try:
                uris.append(str(o.get("/URI")))
            except Exception:
                pass
        if "/JS" in keys or s == "/JavaScript":
            try:
                js = o.get("/JS")
                code = js.read_bytes() if isinstance(js, pikepdf.Stream) else str(js).encode("utf-8", "replace")
            except Exception:
                code = b""
            save("js", code, ".js")
            findings.append(F(rel, "high", f"PDF contains JavaScript ({len(code)} bytes) - extracted and scanned"))
        if "/RichMedia" in keys or name(o, "/Subtype") == "/RichMedia":
            findings.append(F(rel, "high", "PDF RichMedia (Flash/embedded media)"))
        if "/XFA" in keys:
            findings.append(F(rel, "medium", "PDF XFA form (frequent exploit vector)"))
        if name(o, "/Type") == "/EmbeddedFile":
            try:
                if int(o.get("/Length", 0)) < 300 * 1024**2:
                    save("emb", o.read_bytes(), ".bin")
            except Exception as e:
                findings.append(F(rel, "medium", f"embedded file could not be extracted: {str(e)[:80]}"))
            findings.append(F(rel, "medium", "PDF contains an embedded file - extracted and scanned"))
        for k in keys:
            try:
                child = o[k]
            except Exception:
                continue
            if k != "/Parent" and not getattr(child, "is_indirect", False):
                visit(child, depth + 1)

    try:
        for obj in pdf.objects:
            visit(obj)
    except Exception as e:
        findings.append(F(rel, "medium", f"PDF object walk aborted (incomplete analysis): {str(e)[:100]}"))

    bad = [u for u in uris if re.match(r"(?i)^(file|smb|javascript|data|ftp|vbscript):", u.strip())]
    if bad:
        findings.append(F(rel, "high", f"suspicious URI scheme in links: {bad[0][:80]}"))
    info.update(pages=len(pdf.pages), objects=len(pdf.objects), uris=len(uris), encrypted=pdf.is_encrypted,
                producer=str(pdf.docinfo.get("/Producer", ""))[:80] if pdf.docinfo else "")
    pdf.close()
    return list({(x["issue"]): x for x in findings}.values()), info


# ---------------------------------------------------------------- Office
def office_check(p: Path, rel: str) -> list[dict]:
    ext, out = p.suffix.lower(), []
    if ext in OOXML_EXT and zipfile.is_zipfile(p):
        try:
            with zipfile.ZipFile(p) as z:
                for n in z.namelist():
                    if n.endswith(".rels") and z.getinfo(n).file_size < 5 << 20:
                        data = z.read(n)
                        if re.search(rb'TargetMode="External"[^>]*Target="(?:https?|file|\\\\)|Target="(?:https?|file)[^"]*"[^>]*TargetMode="External"', data):
                            out.append(F(rel, "medium", f"external relationship in {n} (remote template/content injection)"))
                    if n.lower().endswith("vbaproject.bin") or "/embeddings/" in n.lower() or n.lower().endswith(".exe"):
                        out.append(F(rel, "medium", f"contains {n}"))
        except Exception as e:
            out.append(F(rel, "medium", f"OOXML inspection failed: {str(e)[:100]}"))
    try:
        from oletools.olevba import VBA_Parser, FileOpenError
        try:
            vp = VBA_Parser(str(p))
        except FileOpenError:
            return out
        if vp.detect_vba_macros():
            kinds = {r[0] for r in vp.analyze_macros()}
            if kinds & {"AutoExec", "Suspicious", "IOC"}:
                out.append(F(rel, "high", f"VBA macros with {'/'.join(sorted(kinds & {'AutoExec', 'Suspicious', 'IOC'}))} indicators"))
            else:
                out.append(F(rel, "medium", "contains VBA macros"))
        if getattr(vp, "xlm_macros", None):
            out.append(F(rel, "high", "Excel 4.0 (XLM) macros"))
        vp.close()
    except Exception as e:
        if ext in OFFICE_EXT:
            out.append(F(rel, "medium", f"macro analysis failed (not verified): {str(e)[:100]}"))
    return out


# ---------------------------------------------------------------- disguise / naming
def name_check(p: Path, rel: str, mime: str) -> list[dict]:
    out, ext = [], p.suffix.lower()
    if RLO in p.name:
        out.append(F(rel, "high", "filename contains right-to-left override character (fake extension trick)"))
    want = EXT_MIME.get(ext)
    if want and not any(mime.startswith(w) for w in want):
        out.append(F(rel, "high", f"extension {ext} but content is {mime} (disguised file)"))
    return out
