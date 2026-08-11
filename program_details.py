#!/usr/bin/env python3
"""Unifier over the four bounty-targets-data platform dumps.

Backs the `bb-recon` skill. Schema-per-platform is normalized just enough to
answer: what is this program, what's in/out of scope, and is it worth my time.
See .claude/skills/bb-recon/SKILL.md for the documented CLI.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

FILES = {
    "hackerone": ROOT / "hackerone_data.json",
    "bugcrowd": ROOT / "bugcrowd_data.json",
    "yeswehack": ROOT / "yeswehack_data.json",
    "intigriti": ROOT / "intigriti_data.json",
}

SOURCE_HINT_RE = re.compile(r"github\.com|gitlab\.com|bitbucket\.org|source[\s_-]?code|\bsvn\b|\btrac\b", re.I)
WILDCARD_RE = re.compile(r"^\*\.|/\*$")


def load(platform):
    path = FILES.get(platform)
    if not path or not path.exists():
        return []
    return json.loads(path.read_text())


def load_all():
    out = {}
    for platform in FILES:
        out[platform] = load(platform)
    return out


def normalize_h1(p):
    assets = p.get("targets", {}).get("in_scope", []) or []
    return {
        "platform": "hackerone",
        "handle": p.get("handle"),
        "name": p.get("name"),
        "url": p.get("url"),
        "gates": {
            "offers_bounties": p.get("offers_bounties"),
            "managed": p.get("managed_program"),
            "submission_state": p.get("submission_state"),
            "response_efficiency_percentage": p.get("response_efficiency_percentage"),
            "avg_days_to_first_response": p.get("average_time_to_first_program_response"),
            "avg_days_to_bounty_awarded": p.get("average_time_to_bounty_awarded"),
        },
        "min_bounty": None,
        "max_bounty": None,
        "in_scope": [
            {
                "identifier": a.get("asset_identifier"),
                "type": a.get("asset_type"),
                "eligible_for_bounty": a.get("eligible_for_bounty"),
                "max_severity": a.get("max_severity"),
            }
            for a in assets
        ],
        "out_of_scope_count": len(p.get("targets", {}).get("out_of_scope", []) or []),
        "raw": p,
    }


def normalize_bugcrowd(p):
    assets = p.get("targets", {}).get("in_scope", []) or []
    return {
        "platform": "bugcrowd",
        "handle": p.get("code") or p.get("id") or p.get("name"),
        "name": p.get("name"),
        "url": p.get("url") or p.get("bugcrowd_url"),
        "gates": {
            "max_payout": p.get("max_payout"),
            "safe_harbor": p.get("safe_harbor_label") or p.get("safe_harbor"),
            "allows_disclosure": p.get("allows_disclosure"),
        },
        "min_bounty": None,
        "max_bounty": p.get("max_payout"),
        "in_scope": [
            {
                "identifier": a.get("target") or a.get("name"),
                "type": a.get("type") or a.get("category"),
                "eligible_for_bounty": None,
                "max_severity": None,
            }
            for a in assets
        ],
        "out_of_scope_count": len(p.get("targets", {}).get("out_of_scope", []) or []),
        "raw": p,
    }


def normalize_ywh(p):
    assets = p.get("targets", {}).get("in_scope", []) or []
    return {
        "platform": "yeswehack",
        "handle": p.get("id"),
        "name": p.get("name"),
        "url": f"https://yeswehack.com/programs/{p.get('id')}" if p.get("id") else None,
        "gates": {
            "public": p.get("public"),
            "disabled": p.get("disabled"),
            "managed": p.get("managed"),
        },
        "min_bounty": p.get("min_bounty"),
        "max_bounty": p.get("max_bounty"),
        "in_scope": [
            {
                "identifier": a.get("target"),
                "type": a.get("type"),
                "eligible_for_bounty": None,
                "max_severity": None,
            }
            for a in assets
        ],
        "out_of_scope_count": len(p.get("targets", {}).get("out_of_scope", []) or []),
        "raw": p,
    }


def normalize_intigriti(p):
    assets = p.get("targets", {}).get("in_scope", []) or []
    min_b = (p.get("min_bounty") or {}).get("value")
    max_b = (p.get("max_bounty") or {}).get("value")
    return {
        "platform": "intigriti",
        "handle": p.get("handle"),
        "name": p.get("name"),
        "url": p.get("url"),
        "gates": {
            "status": p.get("status"),
            "confidentiality_level": p.get("confidentiality_level"),
            "tac_required": p.get("tacRequired"),
            "2fa_required": p.get("twoFactorRequired"),
        },
        "min_bounty": min_b,
        "max_bounty": max_b,
        "in_scope": [
            {
                "identifier": a.get("endpoint"),
                "type": a.get("type"),
                "eligible_for_bounty": None,
                "max_severity": a.get("impact"),
            }
            for a in assets
        ],
        "out_of_scope_count": len(p.get("targets", {}).get("out_of_scope", []) or []),
        "raw": p,
    }


NORMALIZERS = {
    "hackerone": normalize_h1,
    "bugcrowd": normalize_bugcrowd,
    "yeswehack": normalize_ywh,
    "intigriti": normalize_intigriti,
}


def all_programs(platform=None):
    platforms = [platform] if platform else list(FILES)
    for plat in platforms:
        norm = NORMALIZERS[plat]
        for p in load(plat):
            yield norm(p)


def matches(program, term):
    term = term.lower()
    hay = " ".join(
        str(x)
        for x in [program.get("handle"), program.get("name"), program.get("url")]
        if x
    ).lower()
    return term in hay


def extract_wildcards_and_source(program):
    wildcards, source = [], []
    for a in program["in_scope"]:
        ident = a.get("identifier") or ""
        typ = (a.get("type") or "").upper()
        if typ == "WILDCARD" or WILDCARD_RE.search(ident):
            wildcards.append(ident)
        if typ in ("SOURCE_CODE",) or SOURCE_HINT_RE.search(ident) or SOURCE_HINT_RE.search(
            a.get("identifier") or ""
        ):
            source.append(ident)
    return wildcards, source


def print_program(program, show_assets=False):
    print(f"[{program['platform']}] {program['name']}  ({program['handle']})")
    print(f"  url: {program.get('url')}")
    bounty = ""
    if program.get("min_bounty") is not None or program.get("max_bounty") is not None:
        bounty = f"{program.get('min_bounty')}-{program.get('max_bounty')}"
    print(f"  bounty: {bounty or 'n/a'}")
    print(f"  gates: {program['gates']}")
    print(f"  in_scope: {len(program['in_scope'])}  out_of_scope: {program['out_of_scope_count']}")
    wildcards, source = extract_wildcards_and_source(program)
    if wildcards:
        print(f"  WILDCARDS: {wildcards[:10]}")
    if source:
        print(f"  SOURCE/REPO: {source[:10]}")
    if show_assets:
        print("  --- all assets ---")
        for a in program["in_scope"]:
            print(f"    {a['type']:>16}  {a['identifier']}  (bounty={a.get('eligible_for_bounty')} sev={a.get('max_severity')})")


def cmd_list(platform):
    for p in all_programs(platform):
        print(f"{p['handle']}\t{p['name']}")


def main(argv):
    if not argv:
        print(__doc__)
        return 1

    if argv[0] == "--list":
        platform = argv[1] if len(argv) > 1 else None
        cmd_list(platform)
        return 0

    platform = None
    show_assets = False
    as_json = False
    term = None
    args = argv[:]
    while args:
        a = args.pop(0)
        if a == "--platform":
            platform = args.pop(0)
        elif a == "--assets":
            show_assets = True
        elif a == "--json":
            as_json = True
        else:
            term = a

    if term is None:
        print("usage: program_details.py <term> [--platform NAME] [--assets] [--json]")
        return 1

    found = [p for p in all_programs(platform) if matches(p, term)]
    if not found:
        print(f"no match for {term!r}" + (f" on {platform}" if platform else ""))
        return 1

    if as_json:
        for p in found:
            out = {k: v for k, v in p.items() if k != "raw"}
            print(json.dumps(out, indent=2))
    else:
        for p in found:
            print_program(p, show_assets=show_assets)
            print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
