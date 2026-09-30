#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
manifest = ROOT / "Cargo.toml"
text = manifest.read_text(encoding="utf-8")
match = re.search(r"(?ms)^\[workspace\]\s*(.*?)(?=^\[|\Z)", text)
if not match:
    raise SystemExit("missing [workspace] section")
section = match.group(1)
if 'exclude = ["vendor/arti"]' not in section:
    raise SystemExit("vendor/arti is not explicitly excluded from the ZTSEC workspace")
members = re.search(r"(?ms)^members\s*=\s*\[(.*?)\]", section)
if members and "vendor/arti" in members.group(1):
    raise SystemExit("vendor/arti must not be listed as a workspace member")
print("OK: vendor/arti is excluded from the ZTSEC application workspace")
