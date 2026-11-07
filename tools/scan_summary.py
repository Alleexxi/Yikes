"""Summarize finished scan directories: native programs, issue reasons, unclaimed controls.

usage: scan_summary.py <scan dir> [...]
"""
import collections
import json
import sys
from pathlib import Path

for arg in sys.argv[1:]:
    d = Path(arg)
    try:
        summary = json.loads((d / 'summary.json').read_text(encoding='utf-8'))
    except OSError:
        print(f'== {d.name}: no summary yet')
        continue
    issues = json.loads((d / 'issues.json').read_text(encoding='utf-8')) if (d / 'issues.json').exists() else []
    unclaimed = json.loads((d / 'unclaimed-controls.json').read_text(encoding='utf-8')) \
        if (d / 'unclaimed-controls.json').exists() else []
    print(f'== {d.name}: {summary["native_instruction_stage_blobs"]} native programs; '
          f'{len(issues)} issues; {len(unclaimed)} unclaimed; {summary["elapsed_seconds"]:.0f}s')
    for reason, n in collections.Counter(f'{i["kind"]}: {i["reason"][:90]}' for i in issues).most_common(6):
        print(f'   {n:5} {reason}')
    for item in issues[:2]:
        print(f'         e.g. {item["path"][-120:]}')
    if unclaimed:
        print(f'   unclaimed e.g. {json.dumps(unclaimed[0])[:200]}')
