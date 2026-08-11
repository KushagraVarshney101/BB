#!/usr/bin/env python3
"""Fail-closed scope resolver. An asset is in-scope only if scope.json says so.

Referenced by bb-recon (go-live gate) and web-recon (00_scope_guard.sh).
Default is deny: a missing scope.json, a missing program, or a missing asset
all resolve to NOT IN SCOPE. This is deliberate — program_details.py reflects
what a program *advertises*; this file is what's been checked and cleared.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SCOPE_FILE = ROOT / "scope.json"


def load_scope():
    if not SCOPE_FILE.exists():
        return {}
    return json.loads(SCOPE_FILE.read_text()).get("programs", {})


def resolve(asset, programs=None):
    programs = programs if programs is not None else load_scope()
    hits = []
    for handle, prog in programs.items():
        for asset_key, meta in prog.get("assets", {}).items():
            if asset_key == asset or asset in asset_key or asset_key in asset:
                hits.append((handle, prog["platform"], asset_key, meta))
    return hits


def main(argv):
    if not argv:
        print("usage: scope_check.py <asset>")
        return 2

    asset = argv[0]
    hits = resolve(asset)

    if not hits:
        print(f"DENY  {asset}  — not found in scope.json (default-deny)")
        return 1

    exit_code = 1
    for handle, platform, asset_key, meta in hits:
        decision = meta.get("decision")
        ok = decision == "paid"
        exit_code = 0 if ok and exit_code != 0 else exit_code
        exit_code = 0 if ok else exit_code
        tag = "ALLOW" if ok else "DENY "
        reason = f" — {meta.get('reason')}" if meta.get("reason") else ""
        print(f"{tag} {asset}  [{platform}/{handle}] {asset_key}  decision={decision} tier={meta.get('tier')}{reason}")

    return 0 if any(m.get("decision") == "paid" for _, _, _, m in hits) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
