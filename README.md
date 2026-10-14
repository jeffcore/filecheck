# filecheck

Drop files or archives into a folder, run one command, and get a verdict: **clean** or **quarantined**.
Everything runs inside a locked-down Docker container with **no network access**, so a hostile file
can't phone home or touch your machine.

## Why

Files from untrusted sources are a common way to get infected: shadow libraries and mirror sites
(Anna's Archive is a typical example), file-sharing links, forum attachments, and email. PDFs and zip files from
places like these can carry embedded JavaScript, launch actions, hidden executables, or macro-laden
documents. `filecheck` is a cheap, repeatable "airlock" you run **before** you open anything.

> This tool is about safety, not sourcing. Only download and keep files you have the right to.

## Usage

Requires Docker.

```bash
./run.sh            # scan everything in ./to-check
./run.sh --rebuild  # rebuild first (refreshes ClamAV signatures + YARA rules)
```

| Folder | Contents |
|---|---|
| `to-check/` | Put files and archives here |
| `checked/clean/` | Files that passed every check |
| `checked/quarantine/` | Anything flagged (made read-only) |
| `checked/reports/` | One JSON report per file: hashes, findings, PDF info, VirusTotal link |

Exit code is `2` if anything was quarantined, so it can be scripted.

## What it checks

1. **ClamAV** in strict mode: PUA, heuristics, broken/encrypted files, macros, phishing tricks, scan-limit overruns.
2. **YARA**: ~9,000 community malware rules ([Yara-Rules](https://github.com/Yara-Rules/rules), [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base)).
3. **Deep PDF parsing** (pikepdf): JavaScript, Launch actions, embedded files, remote/form-submit actions,
   RichMedia, XFA, `file:`/`smb:` links, data appended after `%%EOF`, embedded Windows executables, obfuscated
   keywords like `/J#61vaScript`. JavaScript and embedded files are extracted and re-scanned.
4. **Office documents**: VBA and Excel 4.0 macros (oletools), remote-template links in OOXML.
5. **Disguise detection**: wrong extension for the real content, executables hiding under other names,
   right-to-left-override filenames.
6. **Safe archive extraction**: `.zip .tar* .gz .7z .rar`, nested archives, with protection against path traversal,
   symlinks, zip bombs, and excessive nesting.

The scanner **fails closed**: if any check errors, the file is not reported clean.

## Container hardening

No network, read-only root filesystem, all capabilities dropped, `no-new-privileges`, non-root user,
memory and PID limits, extraction in a tmpfs. Signatures are baked in at build time, so rebuild regularly.

## Limits (be honest with yourself)

- Finds **known** malware and suspicious structure. A brand-new exploit with no signature and no
  suspicious features can pass. "Clean" is not "proven safe". For high-risk files, also check the hash on VirusTotal
  (link in each report).
- Password-protected archive members can't be scanned and are flagged.
- Strict by default: legitimate PDFs with JavaScript or embedded files (fillable forms) will be quarantined for review.
- Weak YARA rules that fire by chance on big compressed files are listed in `scanner/checks.py` (`YARA_SUPPRESS`);
  suppressed hits still appear in reports as low-severity notes.
- Macro detection is implemented but not yet tested against a real macro document.

## Layout

```
run.sh  Dockerfile  docker-compose.yml
scanner/scan.py          orchestration, archive extraction, ClamAV, verdicts
scanner/checks.py        YARA, PDF, Office, disguise checks
scanner/compile_rules.py build-time YARA rule compiler
```
