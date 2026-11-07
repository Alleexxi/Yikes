"""User-facing commands for local extraction, audits and agent evidence packs."""

import argparse
import json
import os
import re
import sys
import sqlite3
import struct
from contextlib import closing
from pathlib import Path

from . import __version__
from .container.format import NupError
from .corpus import uses_native_files
from .adapter import ROOT
from .audit import audit, load_report
from .scanner import SCANNER_REVISION, Scanner
from .storage import atomic_json, source_identity
from .tasks import create_task
from .upstream import git, sync_emulator
from .bundle import write_batch_bundle


def default_emulator():
    """Use an explicit local override, otherwise update the managed experimental checkout."""
    override = os.environ.get('NUP_SHADER_EMULATOR')
    if override:
        return override
    config = ROOT / 'config.local.json'
    saved = json.loads(config.read_text(encoding='utf-8')) if config.is_file() else {}
    if saved.get('manual_emulator'):
        return saved['manual_emulator']
    return sync_emulator()


def scan_input(source, output, resume, checkpoint_every=5000, workers=4, export_native=False):
    """Start a fresh extraction or resume its committed checkpoint."""
    if workers < 1 or checkpoint_every < 1:
        raise ValueError('worker count and checkpoint interval must be positive')
    source = Path(source).resolve()
    if not source.is_file():
        raise ValueError(f'NUP file does not exist: {source}')
    name = re.sub(r'[^A-Za-z0-9._-]', '_', source.stem).strip('.') or 'game'
    output = Path(output).resolve() if output else ROOT / 'results' / name
    database = output / 'shaders.sqlite'
    if database.exists() and not resume:
        raise ValueError('Output already contains an extraction; use --resume or choose a new --output')
    if resume and not database.is_file():
        raise ValueError('No extraction checkpoint exists; omit --resume for a fresh scan')
    if resume:
        with closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)) as db:
            if export_native and not uses_native_files(db):
                raise ValueError('Cannot add --export-native on resume; choose a fresh output directory')
            row = db.execute("SELECT value FROM state WHERE key='checkpoint'").fetchone()
        checkpoint = json.loads(row[0]) if row else {}
        if checkpoint.get('identity') != source_identity(source):
            raise ValueError('NUP changed since the checkpoint; choose a fresh output directory')
        summary_path = output / 'summary.json'
        summary = json.loads(summary_path.read_text(encoding='utf-8')) if summary_path.is_file() else {}
        if (checkpoint.get('scanner_revision') == SCANNER_REVISION
                and checkpoint.get('finished') and summary.get('finished')
                and summary.get('root_status_counts') == checkpoint.get('root_status_counts')
                and (output / 'native-audit.tsv').is_file() and not checkpoint.get('issue_count')
                and not checkpoint.get('unclaimed_control_candidates')
                and checkpoint.get('root_status_counts') == {'ok': checkpoint.get('expected_root_paths')}):
            print(f'Reusing completed extraction: {output}', flush=True)
            return output
    if output.exists() and not database.exists() and any(output.iterdir()):
        raise ValueError('Fresh output must be empty')
    scanner = Scanner(output, resume=resume, checkpoint_every=checkpoint_every,
                      progress=make_progress(f'Scan {source.name}'), workers=workers,
                      export_native=export_native)
    try:
        scanner.run(source)
    finally:
        scanner.close()
    print(f'Extraction: {output}', flush=True)
    return output


def make_progress(label):
    """Render a compact real progress bar, updating once per percentage point."""
    last = [-1]

    def update(current, total):
        total = max(total, 1)
        percent = min(100, current * 100 // total)
        if percent == last[0]:
            return
        last[0] = percent
        width = 28
        filled = width * percent // 100
        bar = '#' * filled + '-' * (width - filled)
        print(f'\r{label} [{bar}] {percent:3d}% ({current}/{total})',
              end='\n' if percent == 100 else '', file=sys.stderr, flush=True)

    return update


def find_nups(folder):
    """Find all NUP files below a folder, ignoring extension case."""
    folder = Path(folder).expanduser().resolve()
    if not folder.is_dir():
        raise ValueError(f'Not a folder: {folder}')
    return folder, sorted((path for path in folder.rglob('*')
                           if path.is_file() and path.suffix.lower() == '.nup'),
                          key=lambda path: str(path).casefold())


def run_batch(folder, output_root=None, emulator=None, allow_incomplete=False,
              checkpoint_every=5000, workers=4, export_native=False):
    """Scan and audit every NUP under a folder, continuing after individual failures."""
    folder, nups = find_nups(folder)
    if not nups:
        raise ValueError(f'No .nup files found under {folder}')
    output_root = (Path(output_root).expanduser().resolve() if output_root else
                   ROOT / 'results' / re.sub(r'[^A-Za-z0-9._-]', '_', folder.name))
    selected_emulator = emulator or default_emulator()
    failures = 0
    incomplete = 0
    rejected_total = 0
    batch_progress = make_progress(f'Batch ({len(nups)} NUPs)')
    entries = []
    try:
        for index, nup in enumerate(nups, 1):
            relative_output = nup.relative_to(folder).with_suffix('')
            output = output_root / relative_output
            entry = {'name': nup.relative_to(folder).as_posix(), 'output': output, 'status': 'cancelled'}
            entries.append(entry)
            print(f'\n[{index}/{len(nups)}] {nup}', flush=True)
            try:
                output = scan_input(nup, output, resume=(output / 'shaders.sqlite').is_file(),
                                    checkpoint_every=checkpoint_every, workers=workers,
                                    export_native=export_native)
                report, directory = audit(output, selected_emulator, allow_incomplete=allow_incomplete)
                rejected = report['counts'].get('rejected', 0)
                rejected_total += rejected
                coverage_complete = report['coverage_complete_for_recognized_formats']
                if not coverage_complete:
                    incomplete += 1
                entry.update(status='completed', rejected=rejected, total=report['total'],
                             coverage_complete_for_recognized_formats=coverage_complete,
                             report_directory=directory)
                print(f'[{index}/{len(nups)}] finished: {report["total"]} shaders, '
                      f'{rejected} rejected'
                      + ('; WARNING: extraction has coverage gaps' if not coverage_complete else '')
                      + f'; report: {directory / "REPORT.md"}', flush=True)
            except (ValueError, OSError, NupError, sqlite3.Error, struct.error, RuntimeError) as exc:
                failures += 1
                entry.update(status='error', error=str(exc))
                print(f'[{index}/{len(nups)}] FAILED: {exc}', file=sys.stderr, flush=True)
            batch_progress(index, len(nups))
    finally:
        if entries:
            archive = write_batch_bundle(output_root, entries, progress=make_progress('Packing shaders'))
            print(f'Batch ZIP: {archive}', flush=True)
    print(f'Batch complete: {len(nups) - failures}/{len(nups)} NUPs processed; '
          f'{rejected_total} shaders rejected; {failures} NUPs failed to scan or audit. '
          f'{incomplete} audits have extraction coverage gaps. '
          f'Results: {output_root}', flush=True)
    return 2 if failures or incomplete else (1 if rejected_total else 0)


def tui():
    """Interactive folder picker and batch runner for terminal use."""
    print('Yikes — nx2-experimental shader audit\n')
    folder = input('Folder containing NUP files (searched recursively): ').strip().strip('"')
    if not folder:
        raise ValueError('No folder was entered')
    resolved, nups = find_nups(folder)
    print(f'Found {len(nups)} NUP file(s) in {resolved}')
    if not nups:
        raise ValueError(f'No .nup files found under {resolved}')
    for item in nups[:20]:
        print(f'  {item.relative_to(resolved)}')
    if len(nups) > 20:
        print(f'  ... and {len(nups) - 20} more')
    answer = input('Start scanning and auditing all of them? [Y/n] ').strip().lower()
    if answer not in ('', 'y', 'yes'):
        print('Cancelled.')
        return 0
    return run_batch(resolved)


def parser():
    """Define explicit scan/audit/task commands and a default combined run."""
    command = argparse.ArgumentParser(prog='yikes', description='Local NUP shader extraction and instruction audit')
    command.add_argument('--version', action='version', version=__version__)
    subs = command.add_subparsers(dest='command', required=True)
    for name, help_text in [('run', 'Scan a NUP and audit every extracted native program'),
                            ('scan', 'Extract only; no compiler required')]:
        part = subs.add_parser(name, help=help_text)
        part.add_argument('nup', type=Path)
        part.add_argument('-o', '--output', type=Path)
        part.add_argument('--resume', action='store_true')
        part.add_argument('--export-native', action='store_true',
                          help='Also write individual native .bin files (slower; default stores bytes in SQLite)')
        part.add_argument('--checkpoint-every', type=int, default=5000, metavar='FILES',
                          help='Commit scan progress every N root files (default: 5000)')
        part.add_argument('--workers', type=int, default=4,
                          help='Parallel read/decompression/hash workers (default: 4; 1 disables prefetch)')
        if name == 'run':
            part.add_argument('--emulator', type=Path)
            part.add_argument('--allow-incomplete', action='store_true')
    part = subs.add_parser('audit', help='Retest an extraction against current emulator source')
    part.add_argument('output', type=Path)
    part.add_argument('--emulator', type=Path)
    part.add_argument('--baseline', type=Path)
    part.add_argument('--allow-incomplete', action='store_true')
    part = subs.add_parser('batch', help='Scan and audit every NUP in a folder recursively')
    part.add_argument('--export-native', action='store_true',
                      help='Also write individual native .bin files for each game')
    part.add_argument('folder', type=Path)
    part.add_argument('-o', '--output', type=Path, help='Root folder for per-NUP results')
    part.add_argument('--emulator', type=Path)
    coverage = part.add_mutually_exclusive_group()
    coverage.add_argument('--allow-incomplete', action='store_true', default=False,
                          help='Explicitly audit recovered programs despite extraction gaps')
    coverage.add_argument('--strict-coverage', dest='allow_incomplete', action='store_false',
                          help='Refuse audits when extraction has coverage gaps (default)')
    part.add_argument('--checkpoint-every', type=int, default=5000, metavar='FILES')
    part.add_argument('--workers', type=int, default=4,
                      help='Parallel read/decompression/hash workers (default: 4)')
    part = subs.add_parser('report', help='Print the latest report without rescanning')
    part.add_argument('location', type=Path)
    part = subs.add_parser('task', help='Create an evidence pack and instructions for a coding agent')
    part.add_argument('location', type=Path)
    part.add_argument('--group', dest='group_id')
    part.add_argument('--samples', type=int, default=3)
    part = subs.add_parser('configure', help='Save the default emulator checkout locally')
    part.add_argument('--emulator', type=Path, required=True)
    subs.add_parser('update', help='Clone or fast-forward the managed nx2-experimental checkout')
    subs.add_parser('tui', help='Interactive terminal UI for choosing a folder and auditing all NUPs')
    return command


def main(arguments=None):
    """Run a local command; use distinct status codes for rejections and tool failures."""
    arguments = list(sys.argv[1:] if arguments is None else arguments)
    known = {'run', 'scan', 'audit', 'batch', 'report', 'task', 'configure', 'update', 'tui'}
    if arguments and arguments[0] not in known and not arguments[0].startswith('-'):
        arguments.insert(0, 'run')
    args = parser().parse_args(arguments)
    try:
        if args.command == 'configure':
            emulator = args.emulator.resolve()
            if not (emulator / 'src/shader_recompiler/frontend/ampere/lower_to_maxwell.h').is_file():
                raise ValueError('Selected checkout does not contain the native shader translator')
            atomic_json(ROOT / 'config.local.json', {'manual_emulator': str(emulator)})
            print(f'Manual emulator override: {emulator}')
            return 0
        if args.command == 'update':
            emulator = sync_emulator()
            print(f'Updated {emulator} to {git("-C", emulator, "rev-parse", "HEAD")}')
            return 0
        if args.command == 'tui':
            return tui()
        if args.command == 'batch':
            return run_batch(args.folder, args.output, args.emulator,
                             args.allow_incomplete, args.checkpoint_every, args.workers, args.export_native)
        if args.command in ('scan', 'run'):
            output = scan_input(args.nup, args.output, args.resume, args.checkpoint_every,
                                args.workers, args.export_native)
            if args.command == 'scan':
                value = json.loads((output / 'summary.json').read_text(encoding='utf-8'))
                return 2 if value['issue_count'] or value['unclaimed_control_candidates'] else 0
        elif args.command == 'audit':
            output = args.output
        elif args.command == 'task':
            create_task(args.location, args.group_id, args.samples)
            return 0
        elif args.command == 'report':
            report = load_report(args.location)
            print(f"{report['total']} tested: {report['counts'].get('accepted', 0)} accepted; {report['counts'].get('rejected', 0)} rejected")
            print(f"Emulator: {report['build']['git_head']} ({report['build']['fingerprint'][:12]})")
            print(f"No recognized-format extraction gaps: {report['coverage_complete_for_recognized_formats']}")
            for group in report['groups']:
                print(f"{group['id']}  {len(group['files']):5} programs  {group['opcode']:>6}  {group['reason']}")
            if 'comparison' in report:
                comparison = report['comparison']
                print(f"Baseline: {len(comparison['newly_accepted'])} new passes; {len(comparison['regressions'])} regressions; {len(comparison['changed_first_failures'])} changed first failures")
            return 0
        report, _ = audit(output, args.emulator or default_emulator(),
                          getattr(args, 'baseline', None), args.allow_incomplete)
        return 1 if report['counts'].get('rejected', 0) or report.get('comparison', {}).get('regressions') else 0
    except KeyboardInterrupt:
        print('Stopped. Committed scan checkpoints can be continued with --resume.', file=sys.stderr)
        return 130
    except (ValueError, OSError, NupError, sqlite3.Error, struct.error, RuntimeError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 2
