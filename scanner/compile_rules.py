"""Build-time: compile community YARA rule sets into a single /opt/rules.yarc.
Files that don't compile standalone are skipped (and listed) rather than breaking the build."""
import sys
from pathlib import Path
import yara

EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": "", "owner": ""}
SOURCES = {
    "yararules": ("/src/yara-rules", ["malware", "maldocs", "webshells", "exploit_kits", "cve_rules", "capabilities"]),
    "sigbase": ("/src/signature-base/yara", [""]),
}
files, skipped = {}, []
for ns, (root, subs) in SOURCES.items():
    for sub in subs:
        for f in sorted(Path(root, sub).rglob("*")):
            if f.suffix.lower() not in (".yar", ".yara") or "index" in f.name.lower():
                continue
            key = f"{ns}_{f.stem}_{len(files)}"
            try:
                yara.compile(filepath=str(f), externals=EXTERNALS)
                files[key] = str(f)
            except Exception as e:
                skipped.append((f.name, str(e)[:80]))
rules = yara.compile(filepaths=files, externals=EXTERNALS)
rules.save("/opt/rules.yarc")
print(f"compiled {len(files)} rule files, skipped {len(skipped)}")
for s in skipped[:15]:
    print("  skipped:", s)
