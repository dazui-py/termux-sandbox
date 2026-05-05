#!/usr/bin/env python3
from pathlib import Path
import shutil
import re
import sys

p = Path("src/proot.c")

if not p.exists():
    print("ERROR: src/proot.c not found")
    sys.exit(1)

s = p.read_text()
shutil.copy2(p, "src/proot.c.bak-fix-broken-ro-fprintf")

# Fix broken generated C string like:
# fprintf(stderr, "Grant mode ro ...
# ");
s2 = re.sub(
    r'fprintf\s*\(\s*stderr\s*,\s*"Grant mode r[^"]*?\n"\s*\)\s*;',
    'fprintf(stderr, "Grant mode \\"ro\\" is not supported because PRoot does not kernel-enforce read-only binds. Use \\"rw\\" or remove the grant.\\\\n");',
    s,
    flags=re.DOTALL,
)

if s2 == s:
    print("ERROR: broken fprintf pattern not found")
    print("Show the broken block with:")
    print("nl -ba src/proot.c | sed -n '260,290p'")
    sys.exit(1)

p.write_text(s2)
print("[+] Fixed broken ro-grant fprintf in src/proot.c")
