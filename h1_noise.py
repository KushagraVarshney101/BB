#!/usr/bin/env python3
"""H1 GraphQL noise oracle — reports_received_last_90_days per program handle.

Referenced by bb-recon, bug-hunter (gate #2), web-recon.

STATUS: written against the documented public H1 GraphQL schema but NOT
exercised live from this environment — the outbound gateway here rejects the
CONNECT to hackerone.com at the policy layer (confirmed via direct curl, see
NOISE_SCREEN.md). Test this for real the first time you run it somewhere with
open egress before trusting its numbers.
"""
import json
import sys
import urllib.request

ENDPOINT = "https://hackerone.com/graphql"

QUERY = """
query($handle: String!) {
  team(handle: $handle) {
    handle
    reports_received_last_90_days: reports(first: 0) {
      total_count
    }
    recent(first: 50, order_by: {field: latest_disclosable_activity_at, direction: DESC}) {
      edges {
        node {
          ... on Report {
            title
            severity_rating
            disclosed_at
          }
        }
      }
    }
  }
}
"""


def fetch(handle, timeout=15):
    payload = json.dumps({"query": QUERY, "variables": {"handle": handle}}).encode()
    req = urllib.request.Request(
        ENDPOINT,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def main(argv):
    if not argv:
        print("usage: h1_noise.py <program-handle>")
        return 1
    handle = argv[0]
    try:
        data = fetch(handle)
    except Exception as e:
        print(f"live query failed ({e}); this is expected in a network-restricted "
              f"environment — see NOISE_SCREEN.md for the offline fallback for {handle!r}.")
        return 2
    print(json.dumps(data, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
