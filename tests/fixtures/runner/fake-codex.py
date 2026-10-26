#!/usr/bin/env python3
"""Synthetic adapter fixture. It parses supplied test data and never executes it."""
import json
from pathlib import Path
import sys

args = sys.argv[1:]
if "--version" in args:
    print("codex-cli 0.164.0")
elif "mcp" in args:
    print("[]")
else:
    prompt = sys.stdin.read()
    output = Path(args[args.index("--output-last-message") + 1])
    if prompt.startswith("Extract software dependencies"):
        assert 'web_search="disabled"' in args
        task = json.loads(prompt.split("\n\nInput:\n", 1)[1])
        chunk = task["workspace"][0]
        packages = []
        if "example-tool==1.0.0" in chunk["content"]:
            packages.append({"component": {"ref": "example-tool", "version": "1.0.0"}, "excerpt": "example-tool==1.0.0"})
        value = {"phase": "workspace", "schema_version": 1, "project_id": task["project_id"], "scope_sha256": task["scope_sha256"], "reviews": [{"file_id": chunk["file_id"], "offset": chunk["offset"], "sha256": chunk["sha256"], "coverage": "complete", "rationale": "Synthetic read-only extraction", "packages": packages}]}
    elif prompt.startswith("Discover official public sources"):
        assert 'web_search="live"' in args
        task = json.loads(prompt.split("\n\nPublic targets:\n", 1)[1])
        value = {"phase": "sources", "schema_version": 1, "project_id": task["project_id"], "scope_sha256": task["scope_sha256"], "observations": [{"instance_id": item["instance_id"], "fingerprint": item["fingerprint"], "version": None, "cpe_product": None, "rationale": "Synthetic fixture has no real public sources", "sources": [{"kind": kind, "state": "unavailable", "url": None, "detail": "Synthetic source is unavailable", "evidence": []} for kind in item["required_sources"]]} for item in task["components"]]}
    elif prompt.startswith("You are VulnBell's public security researcher"):
        task = json.loads(prompt.split("\n\nResearch plan (data):\n", 1)[1])
        value = {"schema_version": 1, "project_id": task["project_id"], "snapshot_id": task["snapshot_id"], "sources": [{"upstream": item["upstream"], "from": item["from"], "until": item["until"], "coverage": "partial", "detail": "Synthetic fixture cannot inspect public trackers"} for item in task["targets"]], "events": []}
    else:
        assert 'web_search="disabled"' in args
        output.write_text("# Synthetic VulnBell report\n\nCoverage is partial.\n", encoding="utf-8")
        raise SystemExit(0)
    output.write_text(json.dumps(value), encoding="utf-8")
