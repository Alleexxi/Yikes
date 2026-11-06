"""Collect complete portable shader regression corpora without copying NUPs."""

import hashlib
import json
import os
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from .audit import NATIVE_NAME
from .corpus import write_compact_corpus


def write_batch_bundle(output_root, entries, progress=None):
    """Atomically publish reports, errors and every tested native shader for this batch."""
    output_root = Path(output_root)
    output_root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
    destination = output_root / f'batch-results-{stamp}-{uuid.uuid4().hex[:6]}.zip'
    temporary = destination.with_suffix('.zip.tmp')
    manifest = []
    program_total = sum(entry.get('total', 0) for entry in entries)
    packed = 0
    lines = ['# Batch shader audit', '', 'Reports and all tested native programs from this batch.', '']
    try:
        with zipfile.ZipFile(temporary, 'w', compression=zipfile.ZIP_DEFLATED,
                             compresslevel=1, allowZip64=True) as archive:
            for entry in entries:
                relative = PurePosixPath(entry['name'])
                if relative.is_absolute() or '..' in relative.parts:
                    raise ValueError('Invalid batch input name')
                prefix = 'games/' + relative.as_posix()
                record = {key: value for key, value in entry.items()
                          if key not in ('output', 'report_directory')}
                record['archive_directory'] = prefix
                manifest.append(record)
                lines.append(f'- {entry["name"]}: {entry["status"]}; '
                             f'{entry.get("rejected", 0)} rejected programs'
                             + (f'; {entry["error"]}' if entry.get('error') else ''))
                output = Path(entry['output'])
                for name in ('summary.json', 'issues.json', 'unclaimed-controls.json', 'recovered-issues.json'):
                    path = output / name
                    if path.is_file():
                        target = name if name == 'summary.json' else f'scan/{name}'
                        archive.write(path, f'{prefix}/{target}')
                if entry.get('report_directory') is None:
                    continue
                report_directory = Path(entry['report_directory'])
                for name in ('REPORT.md', 'report.json', 'lowering.tsv', 'build-metadata.json'):
                    archive.write(report_directory / name, f'{prefix}/audit/{name}')
                report = json.loads((report_directory / 'report.json').read_text(encoding='utf-8'))
                native_manifest = (output / 'native-audit.tsv').read_bytes()
                manifest_hash = hashlib.sha256(native_manifest).hexdigest()
                if manifest_hash != report['corpus_sha256']:
                    raise ValueError('Shader manifest changed while creating batch ZIP')
                pairs = [tuple(line.split('\t')) for line in native_manifest.decode('utf-8').splitlines()]
                if sorted(pairs) != sorted((case['file'], case['stage']) for case in report['cases']):
                    raise ValueError('Audit report does not cover the exported shader manifest')
                programs = []
                for case in report['cases']:
                    filename = case['file']
                    match = NATIVE_NAME.fullmatch(filename)
                    if match is None or case['stage'] != match[2]:
                        raise ValueError('Invalid shader program filename or stage')
                    programs.append({'file': filename, 'stage': match[2], 'bytes': case['input_bytes'],
                                     'sources': case.get('sources', [])})
                compact_path = output_root / f'.corpus-{uuid.uuid4().hex}.sqlite.tmp'
                try:
                    offset = packed
                    notify = (lambda count: progress(offset + count, program_total)) if progress else None
                    write_compact_corpus(output, compact_path, report['cases'], progress=notify)
                    archive.write(compact_path, f'{prefix}/corpus.sqlite')
                finally:
                    compact_path.unlink(missing_ok=True)
                packed += len(programs)
                archive.writestr(f'{prefix}/native-audit.tsv', native_manifest)
                archive.writestr(f'{prefix}/corpus.json', json.dumps({
                    'schema_version': 1, 'storage': 'sqlite',
                    'corpus_sha256': manifest_hash, 'programs': programs}))
                archive.writestr(f'{prefix}/latest.json', json.dumps({'report': 'audit/report.json'}))
            archive.writestr('batch.json', json.dumps({'schema_version': 1, 'entries': manifest}, indent=2))
            lines += ['', 'Each program reports its first rejection. Acceptance checks lowering only.',
                      'Full NUP files and extraction databases are excluded.', '',
                      'Extract this ZIP and run `shader-audit.cmd audit <game-folder>` to retest every',
                      'included program against current source and compare with the bundled baseline.', '']
            archive.writestr('BATCH.md', '\n'.join(lines))
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination
