"""Hash-checked offline audits, grouped failures, and comparisons between emulator changes."""

import csv
import hashlib
import json
import re
import sqlite3
import subprocess
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager, nullcontext
from datetime import datetime, timezone
from pathlib import Path

from .adapter import build_adapter
from .corpus import stored_programs, uses_native_files
from .storage import atomic_json

NATIVE_NAME = re.compile(r'([0-9a-f]{64})\.(vs|hs|ds|gs|ps|cs|ts|ms)\.bin\Z')


@contextmanager
def connect(output):
    """Open an existing extraction database in read-only mode."""
    path = (Path(output).resolve() / 'shaders.sqlite').as_uri() + '?mode=ro'
    connection = sqlite3.connect(path, uri=True)
    try:
        yield connection
    finally:
        connection.close()


def portable_records(output):
    """Validate the metadata needed to retest an exported corpus without its extraction DB."""
    metadata = json.loads((Path(output) / 'corpus.json').read_text(encoding='utf-8'))
    if not isinstance(metadata, dict) or metadata.get('schema_version') != 1:
        raise ValueError('Unsupported portable shader corpus format')
    records, sources = {}, {}
    programs = metadata.get('programs')
    if not isinstance(programs, list):
        raise ValueError('Invalid portable shader program list')
    for program in programs:
        if not isinstance(program, dict) or not isinstance(program.get('file'), str):
            raise ValueError('Invalid portable shader metadata')
        filename = program.get('file', '')
        match = NATIVE_NAME.fullmatch(filename)
        size = program.get('bytes')
        if (match is None or program.get('stage') != match[2]
                or not isinstance(size, int) or size <= 0 or size % 16):
            raise ValueError('Invalid portable shader metadata')
        key = match[1], match[2]
        if key in records:
            raise ValueError('Duplicate portable shader metadata')
        records[key] = size
        paths = program.get('sources', [])
        if not isinstance(paths, list) or any(not isinstance(path, str) for path in paths):
            raise ValueError('Invalid portable shader provenance')
        sources[filename] = paths
    manifest_hash = hashlib.sha256((Path(output) / 'native-audit.tsv').read_bytes()).hexdigest()
    if metadata.get('corpus_sha256') != manifest_hash:
        raise ValueError('Portable shader manifest fingerprint changed')
    if metadata.get('storage') == 'sqlite' and not (Path(output) / 'corpus.sqlite').is_file():
        raise ValueError('Portable shader database is missing')
    return records, sources


def verify_manifest(output):
    """Check every audited file against its DB or portable metadata, stage and content hash."""
    output = Path(output)
    database_storage = (output / 'corpus.sqlite').is_file()
    if (output / 'shaders.sqlite').is_file():
        with connect(output) as db:
            database_storage = database_storage or not uses_native_files(db)
            records = {(sha, stage): length for sha, stage, length in db.execute(
                "SELECT instruction_hash,stage,instruction_bytes FROM shaders WHERE arch='sm86'")}
    else:
        records, _ = portable_records(output)
    seen = set()
    entries = []
    manifest = output / 'native-audit.tsv'
    for line in manifest.read_text(encoding='utf-8').splitlines():
        fields = line.split('\t')
        match = NATIVE_NAME.fullmatch(fields[0]) if len(fields) == 2 else None
        if match is None or fields[1] != match[2]:
            raise ValueError('Invalid native audit manifest entry')
        key = match[1], match[2]
        if key in seen or key not in records:
            raise ValueError('Duplicate or unknown shader in audit manifest')
        seen.add(key)
        entries.append((fields[0], key, records[key]))
    if seen != records.keys():
        raise ValueError('Manifest does not cover every extracted native program')

    if database_storage:
        stored = set()
        with closing(stored_programs(output)) as programs:
            for filename, stage, size, raw in programs:
                match = NATIVE_NAME.fullmatch(filename)
                key = (match[1], match[2]) if match else None
                if (key not in records or key in stored or stage != key[1] or size != records[key]
                        or len(raw) != size or hashlib.sha256(raw).hexdigest() != key[0]):
                    raise ValueError('Stored shader changed or is incomplete')
                stored.add(key)
        if stored != records.keys():
            raise ValueError('Shader database does not cover every exported program')
        return len(seen), hashlib.sha256(manifest.read_bytes()).hexdigest()

    def check_entry(entry):
        filename, key, length = entry
        raw = (output / 'native' / filename).read_bytes()
        if len(raw) != length or hashlib.sha256(raw).hexdigest() != key[0]:
            raise ValueError(f'Exported shader changed or is incomplete: {filename}')

    # Small exports incur filesystem latency; overlap reads, keeping the queue bounded.
    if len(entries) < 64:
        for entry in entries:
            check_entry(entry)
    else:
        with ThreadPoolExecutor(max_workers=8) as workers:
            for start in range(0, len(entries), 512):
                list(workers.map(check_entry, entries[start:start + 512]))
    return len(seen), hashlib.sha256(manifest.read_bytes()).hexdigest()


def source_examples(db, filename):
    """Resolve a program to a few original archive paths without assuming one active variant."""
    sha, stage, _ = filename.split('.')
    return [row[0] for row in db.execute(
        "SELECT DISTINCT p.path FROM shaders s JOIN origins o ON s.key=o.shader "
        "JOIN paths p ON p.hash=o.blob WHERE s.instruction_hash=? AND s.stage=? LIMIT 4", (sha, stage))]


def compare_reports(before, after):
    """Compare the same shader corpus, identifying new passes and new rejections."""
    if before['corpus_sha256'] != after['corpus_sha256']:
        raise ValueError('Baseline uses a different shader corpus; counts cannot be compared as regressions')
    old = {row['file']: row for row in before['cases']}
    new = {row['file']: row for row in after['cases']}
    if old.keys() != new.keys():
        raise ValueError('Baseline has a different case list')
    improved = [name for name in old if old[name]['status'] != 'accepted' and new[name]['status'] == 'accepted']
    regressed = [name for name in old if old[name]['status'] == 'accepted' and new[name]['status'] != 'accepted']
    changed = [name for name in old if old[name]['status'] == new[name]['status'] == 'rejected'
               and (old[name]['error_offset'], old[name]['reason']) != (new[name]['error_offset'], new[name]['reason'])]
    return {'newly_accepted': improved, 'regressions': regressed, 'changed_first_failures': changed}


def run_database_adapter(output, executable, raw_report):
    """Feed verified SQLite shader blobs directly to the adapter, avoiding tiny file exports."""
    with subprocess.Popen([str(executable), '--stdin', str(raw_report)], stdin=subprocess.PIPE) as process:
        try:
            with closing(stored_programs(output)) as programs:
                for filename, stage, size, raw in programs:
                    match = NATIVE_NAME.fullmatch(filename)
                    if (match is None or stage != match[2] or len(raw) != size
                            or hashlib.sha256(raw).hexdigest() != match[1]):
                        raise ValueError('Stored shader changed while preparing the audit')
                    process.stdin.write(f'{filename}\t{stage}\t{size}\n'.encode('ascii'))
                    process.stdin.write(raw)
            process.stdin.close()
            return process.wait()
        except BaseException:
            if process.poll() is None:
                process.kill()
            raise


def audit(output, emulator, baseline=None, allow_incomplete=False):
    """Test the entire stored native corpus using the selected emulator's current translator."""
    output = Path(output).resolve()
    extraction = json.loads((output / 'summary.json').read_text(encoding='utf-8'))
    coverage_complete = (extraction['finished'] and extraction['issue_count'] == 0
                         and extraction['unclaimed_control_candidates'] == 0
                         and extraction['root_status_counts'].get('ok') == extraction['expected_root_paths'])
    if not coverage_complete and not allow_incomplete:
        raise ValueError('Extraction has gaps; resume the scan, or explicitly use --allow-incomplete')
    print('Verifying extracted shader hashes...', flush=True)
    expected, corpus_hash = verify_manifest(output)
    portable_sources = None
    if not (output / 'shaders.sqlite').is_file():
        _, portable_sources = portable_records(output)
        if baseline is None and (output / 'audit/report.json').is_file():
            baseline = output / 'audit/report.json'
    executable, build = build_adapter(emulator)
    name = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:6]
    directory = output / 'audits' / name
    directory.mkdir(parents=True)
    raw_report = directory / 'lowering.tsv'
    database_storage = (output / 'corpus.sqlite').is_file()
    if portable_sources is None:
        with connect(output) as db:
            database_storage = database_storage or not uses_native_files(db)
    if database_storage:
        returncode = run_database_adapter(output, executable, raw_report)
    else:
        returncode = subprocess.run([str(executable), str(output / 'native-audit.tsv'), str(raw_report)]).returncode
    if returncode:
        raise ValueError(f'Audit failed with exit code {returncode}; see {raw_report}')
    with raw_report.open(newline='', encoding='utf-8') as stream:
        cases = list(csv.DictReader(stream, delimiter='\t'))
    if len(cases) != expected or any(row['status'] not in ('accepted', 'rejected') for row in cases):
        raise ValueError('Audit result is incomplete or contains malformed inputs')
    if len({row['file'] for row in cases}) != expected:
        raise ValueError('Audit returned duplicate cases')
    groups = {}
    with (connect(output) if portable_sources is None else nullcontext(None)) as db:
        for row in cases:
            row['error_offset'] = int(row['error_offset']) if row['error_offset'] else None
            row['input_bytes'] = int(row['input_bytes'])
            row['consumed_bytes'] = int(row['consumed_bytes'])
            if row['status'] != 'rejected':
                continue
            row['sources'] = (source_examples(db, row['file']) if db is not None
                              else portable_sources.get(row['file'], []))
            key = hashlib.sha256((row['opcode'] + '\0' + row['reason']).encode()).hexdigest()[:12]
            row['group'] = key
            group = groups.setdefault(key, {'id': key, 'opcode': row['opcode'], 'reason': row['reason'], 'files': []})
            group['files'].append(row['file'])
    report = {'schema_version': 1, 'created_utc': datetime.now(timezone.utc).isoformat(),
              'extraction': str(output), 'corpus_sha256': corpus_hash, 'coverage_complete_for_recognized_formats': coverage_complete,
              'build': build, 'counts': dict(Counter(row['status'] for row in cases)), 'total': len(cases),
              'groups': sorted(groups.values(), key=lambda group: (-len(group['files']), group['id'])),
              'cases': cases,
              'limits': ['Stored variants may be unused; runtime-generated or patched outputs are not exhaustively enumerated.',
                         'Only native-to-Maxwell lowering is tested; acceptance does not prove rendering correctness.',
                         'Only the first rejection in each program is reported.']}
    if baseline:
        report['comparison'] = compare_reports(load_report(baseline), report)
        report['baseline'] = str(Path(baseline).resolve())
    atomic_json(directory / 'report.json', report)
    atomic_json(directory / 'build-metadata.json', build)
    write_markdown(directory / 'REPORT.md', report)
    atomic_json(output / 'latest.json', {'report': str((directory / 'report.json').relative_to(output))})
    print(f"{report['total']} tested: {report['counts'].get('accepted', 0)} accepted, {report['counts'].get('rejected', 0)} rejected", flush=True)
    if 'comparison' in report:
        comparison = report['comparison']
        print(f"Compared with baseline: {len(comparison['newly_accepted'])} new passes; {len(comparison['regressions'])} regressions", flush=True)
    print(f'Report: {directory / "REPORT.md"}', flush=True)
    return report, directory


def load_report(location):
    """Resolve either a report JSON file or an extraction's latest audit pointer."""
    path = Path(location).resolve()
    if path.is_dir():
        pointer = json.loads((path / 'latest.json').read_text(encoding='utf-8'))
        candidate = (path / pointer['report']).resolve()
        if not candidate.is_relative_to(path):
            raise ValueError('Report pointer escapes the extraction directory')
        path = candidate
    result = json.loads(path.read_text(encoding='utf-8'))
    if result.get('schema_version') != 1 or 'cases' not in result:
        raise ValueError('Unsupported audit report format')
    return result


def write_markdown(path, report):
    """Write a short readable result alongside the full machine-readable report."""
    lines = ['# Shader instruction audit', '', f"Emulator commit: `{report['build']['git_head']}`",
             f"Source fingerprint: `{report['build']['fingerprint']}`", '',
             f"Tested {report['total']} programs: {report['counts'].get('accepted', 0)} accepted; {report['counts'].get('rejected', 0)} rejected.",
             f"Extraction has no recognized-format gaps: {report['coverage_complete_for_recognized_formats']}.", '',
             '## First-failure groups', '']
    for group in report['groups']:
        lines.append(f"- `{group['id']}`: {len(group['files'])} programs; `{group['opcode']}`; {group['reason']}")
    if 'comparison' in report:
        value = report['comparison']
        lines += ['', f"Baseline comparison: {len(value['newly_accepted'])} new passes, {len(value['regressions'])} regressions, {len(value['changed_first_failures'])} changed first failures."]
    lines += ['', '## Scope', ''] + ['- ' + line for line in report['limits']]
    lines += ['', 'Raw encodings and source paths are in `report.json`. Game bytes remain local.', '']
    path.write_text('\n'.join(lines), encoding='utf-8')
