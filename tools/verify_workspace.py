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
server_manifest = ROOT / "server" / "Cargo.toml"
server_text = server_manifest.read_text(encoding="utf-8")
if '[[' + 'bin]]' not in server_text:
    raise SystemExit("server/Cargo.toml must explicitly declare the ztsec-server binary target")
bin_match = re.search(r'(?ms)^\[\[bin\]\]\s*name\s*=\s*"([^"]+)"\s*path\s*=\s*"([^"]+)"', server_text)
if not bin_match or bin_match.group(1) != "ztsec-server" or bin_match.group(2) != "src/main.rs":
    raise SystemExit("server/Cargo.toml binary target must be ztsec-server from src/main.rs")
print("OK: vendor/arti is excluded and ztsec-server is the explicit Linux binary target")
