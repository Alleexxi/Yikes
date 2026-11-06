"""Exercise real container traversal, integrity checks and translator audit handoffs."""

import hashlib
import json
import os
import sqlite3
import struct
import tempfile
import unittest
import zipfile
from contextlib import closing
from unittest.mock import patch
from pathlib import Path

import zstandard

from nup_shader_audit.audit import audit, compare_reports, load_report, verify_manifest
from nup_shader_audit.binary import LIMIT, decompress, walk
from nup_shader_audit.cli import main, run_batch, scan_input
from nup_shader_audit.container import format as F
from nup_shader_audit.container.read import NupReader
from nup_shader_audit.scanner import Scanner, yaz0
from nup_shader_audit.tasks import create_task

EXIT = struct.pack('<4I', 0x794d, 0, 0x03800000, 0)
UNKNOWN = struct.pack('<4I', 0x7fff, 0, 0, 0)


def shader(instructions=EXIT, stage='vs'):
    """Make a synthetic adjacent-control native shader with consistent declared bounds."""
    header = bytearray(0 if stage == 'cs' else 128)
    if header:
        struct.pack_into('<I', header, 0, (1 if stage == 'vs' else 5) << 10)
    code = bytes(header) + instructions
    control = bytearray(0xd8)
    control[:8] = bytes.fromhex('34127698c9000000')
    struct.pack_into('<I', control, 0x30, len(control))
    struct.pack_into('<I', control, 0x38, len(code))
    struct.pack_into('<I', control, 0x44, len(code))
    control[0x56] = 5 if stage == 'cs' else 0
    return bytes(control) + code


def archive(members):
    """Build a small anonymous SARC for nested-container tests."""
    begin = (20 + 12 + 16 * len(members) + 8 + 15) & ~15
    size = begin + sum(map(len, members))
    result = bytearray(size)
    struct.pack_into('<4sHHIII', result, 0, b'SARC', 20, 0xfeff, size, begin, 0x100)
    struct.pack_into('<4sHHI', result, 20, b'SFAT', 12, len(members), 0x65)
    offset = 0
    for i, value in enumerate(members):
        struct.pack_into('<4I', result, 32 + i * 16, 0, 0, offset, offset + len(value))
        result[begin + offset:begin + offset + len(value)] = value
        offset += len(value)
    struct.pack_into('<4sHH', result, 32 + len(members) * 16, b'SFNT', 8, 0)
    return bytes(result)


def make_nup(path, members, compress_extents=False, bad_hash=False):
    """Write a deterministic synthetic NUP using the documented local binary layout."""
    pool = b''.join(name.encode() for name, _ in members)
    pool_offset = 48 + 64 + 24 + 80 * len(members) + 4 * len(members)
    toc_size = pool_offset + len(pool)
    begin = (128 + toc_size + 15) & ~15
    toc = bytearray(toc_size)
    F._toc_head_s.pack_into(toc, 0, F.TOC_MAGIC, 1, 1, len(members), pool_offset, len(pool), 0)
    toc[48:112] = F.pack_pkg(F.Package(title_id=1, root_dir=0))
    F._dir_s.pack_into(toc, 112, 0, 0, 0, len(members), 0)
    payload = bytearray()
    name_offset = 0
    for i, (name, value) in enumerate(members):
        encoded = name.encode()
        pad = (-(begin + len(payload))) % 16
        payload.extend(b'\0' * pad)
        extent = zstandard.ZstdCompressor().compress(value) if compress_extents else value
        digest = b'\0' * 32 if bad_hash else hashlib.sha256(value).digest()
        F._file_s.pack_into(toc, 136 + 80 * i, name_offset, len(encoded), len(value),
                           begin + len(payload) if value else 0, len(extent) if value else 0,
                           digest, 1 if compress_extents and value else 0, 0, 0)
        if value:
            payload.extend(extent)
        name_offset += len(encoded)
        struct.pack_into('<I', toc, 136 + 80 * len(members) + i * 4, i + 1)
    toc[pool_offset:] = pool
    header = F.pack_super(F.MAGIC, 128, 1, 128, len(toc), hashlib.sha256(toc).digest(),
                          begin, begin + len(payload), 1, 0, b'\0' * 16)
    path.write_bytes(header + toc + b'\0' * (begin - 128 - len(toc)) + payload)


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='nup-shader-audit-test-')
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.assertTrue(self.root.resolve().is_relative_to(Path(tempfile.gettempdir()).resolve()))
        self.assertTrue(self.root.name.startswith('nup-shader-audit-test-'))
        self.temporary.cleanup()

    def test_nested_dedup_compute_and_read_only_input(self):
        source = self.root / 'game.nup'
        raw = archive([shader(), shader(), shader(stage='cs'), shader(UNKNOWN + EXIT)])
        make_nup(source, [('nested.bin', b'prefix!' + zstandard.ZstdCompressor().compress(raw))], True)
        before = source.read_bytes()
        output = scan_input(source, self.root / 'output', False)
        summary = json.loads((output / 'summary.json').read_text())
        self.assertEqual(summary['root_status_counts'], {'ok': 1})
        self.assertEqual(summary['native_instruction_stage_blobs'], 3)
        self.assertEqual(summary['issue_count'], 0)
        self.assertEqual(summary['unclaimed_control_candidates'], 0)
        self.assertEqual(verify_manifest(output)[0], 3)
        self.assertEqual(source.read_bytes(), before)
        scan_input(source, output, True)
        self.assertEqual(verify_manifest(output)[0], 3)
        self.assertEqual(json.loads((output / 'summary.json').read_text())['stats']['root_files_attempted'], 1)

    def test_resume_rejects_changed_nup(self):
        source = self.root / 'game.nup'
        make_nup(source, [('one', shader())])
        output = scan_input(source, self.root / 'output', False)
        source.write_bytes(source.read_bytes() + b'changed')
        with self.assertRaisesRegex(ValueError, 'changed'):
            scan_input(source, output, True)

    def test_interrupted_batch_resumes_without_missing_or_extra_programs(self):
        source = self.root / 'game.nup'
        members = [('p' + str(i), shader(EXIT + struct.pack('<4I', 0x7918, i, 0, 0))) for i in range(5)]
        make_nup(source, members)
        original = Scanner.scan

        def interrupted(scanner, data, label, depth=0, **kwargs):
            if label.endswith('/p3'):
                raise KeyboardInterrupt()
            return original(scanner, data, label, depth, **kwargs)

        with patch.object(Scanner, 'scan', interrupted):
            with self.assertRaises(KeyboardInterrupt):
                scan_input(source, self.root / 'output', False, checkpoint_every=2)
        output = self.root / 'output'
        incomplete = json.loads((output / 'summary.json').read_text())
        self.assertFalse(incomplete['finished'])
        self.assertEqual(incomplete['stats']['root_files_attempted'], 2)
        scan_input(source, output, True, checkpoint_every=2)
        self.assertEqual(verify_manifest(output)[0], 5)
        self.assertEqual(json.loads((output / 'summary.json').read_text())['root_status_counts'], {'ok': 5})

    def test_corrupt_root_is_reported_and_retry_does_not_duplicate_issues(self):
        source = self.root / 'bad.nup'
        make_nup(source, [('one', shader())], bad_hash=True)
        output = scan_input(source, self.root / 'output', False)
        scan_input(source, output, True)
        summary = json.loads((output / 'summary.json').read_text())
        self.assertEqual(summary['root_status_counts'], {'failed': 1})
        self.assertEqual(summary['issue_count'], 1)

    def test_nested_parser_failure_marks_root_failed(self):
        source = self.root / 'bad.nup'
        make_nup(source, [('one', archive([b'SARCbroken']))])
        output = scan_input(source, self.root / 'output', False)
        summary = json.loads((output / 'summary.json').read_text())
        self.assertEqual(summary['root_status_counts'], {'failed': 1})
        self.assertGreater(summary['issue_count'], 0)
        with self.assertRaisesRegex(ValueError, 'Extraction has gaps'):
            audit(output, self.root / 'not-an-emulator')

    def test_corrupt_toc_is_rejected_and_file_handles_close(self):
        source = self.root / 'bad.nup'
        make_nup(source, [('one', b'abc')])
        raw = bytearray(source.read_bytes())
        raw[130] ^= 1
        source.write_bytes(raw)
        with self.assertRaisesRegex(F.NupError, 'TOC SHA'):
            NupReader(str(source))
        source.unlink()  # Windows rejects this if the mmap/file handle leaked.

    def test_changed_export_is_rejected(self):
        source = self.root / 'game.nup'
        make_nup(source, [('one', shader())])
        output = scan_input(source, self.root / 'output', False)
        next((output / 'native').glob('*.bin')).write_bytes(UNKNOWN)
        with self.assertRaisesRegex(ValueError, 'changed'):
            verify_manifest(output)

    def test_large_corpus_hash_checks_detect_corruption(self):
        source = self.root / 'game.nup'
        programs = [shader(EXIT + struct.pack('<4I', 0x7918, i, 0, 0)) for i in range(80)]
        make_nup(source, [('many', archive(programs))])
        output = scan_input(source, self.root / 'output', False)
        self.assertEqual(verify_manifest(output)[0], 80)
        file = next((output / 'native').glob('*.bin'))
        file.write_bytes(b'\0' * file.stat().st_size)
        with self.assertRaisesRegex(ValueError, 'changed'):
            verify_manifest(output)

    def test_manifest_cannot_escape_export_directory(self):
        source = self.root / 'game.nup'
        make_nup(source, [('one', shader())])
        output = scan_input(source, self.root / 'output', False)
        (output / 'native-audit.tsv').write_text('../outside.bin\tvs\n')
        with self.assertRaisesRegex(ValueError, 'Invalid'):
            verify_manifest(output)

    def test_cycle_and_unbounded_decompression_are_rejected(self):
        class Cyclic:
            dirs = [(b'', 0, 1)]
            children = [0]
            dir_count = 1
        with self.assertRaisesRegex(ValueError, 'cycle'):
            list(walk(Cyclic(), 0))
        frame = zstandard.ZstdCompressor().compress(b'x' * 1024)
        self.assertGreater(LIMIT, 1024)
        oversized = bytes.fromhex('28b52ffd') + b'\xa0' + struct.pack('<I', LIMIT + 1) + b'\x01\0\0'
        with self.assertRaisesRegex(ValueError, 'exceeds limit'):
            decompress(oversized, {})
        with self.assertRaises(ValueError):
            yaz0(b'Yaz0' + struct.pack('>I', LIMIT + 1) + bytes(8))
        self.assertEqual(decompress(bytes(frame), {}), b'x' * 1024)

    def test_comparison_distinguishes_passes_regressions_and_changed_failures(self):
        def row(name, status, offset=0):
            return {'file': name, 'status': status, 'error_offset': offset, 'reason': 'test'}
        old = {'corpus_sha256': 'same', 'cases': [row('a', 'accepted'), row('b', 'rejected'), row('c', 'rejected')]}
        new = {'corpus_sha256': 'same', 'cases': [row('a', 'rejected'), row('b', 'accepted'), row('c', 'rejected', 16)]}
        result = compare_reports(old, new)
        self.assertEqual(result, {'newly_accepted': ['b'], 'regressions': ['a'], 'changed_first_failures': ['c']})
        new['corpus_sha256'] = 'different'
        with self.assertRaisesRegex(ValueError, 'different shader corpus'):
            compare_reports(old, new)

    def test_cli_bad_input_returns_tool_error(self):
        source = self.root / 'invalid.nup'
        source.write_bytes(b'bad')
        self.assertEqual(main(['scan', str(source), '--output', str(self.root / 'output')]), 2)

    def test_finished_resume_reuses_extraction_but_still_checks_program_hashes(self):
        source = self.root / 'game.nup'
        make_nup(source, [('one', shader())])
        output = scan_input(source, self.root / 'output', False)
        with patch('nup_shader_audit.cli.Scanner') as scanner:
            self.assertEqual(scan_input(source, output, True), output)
            scanner.assert_not_called()
        program = next((output / 'native').glob('*.bin'))
        program.write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError, 'changed or is incomplete'):
            verify_manifest(output)

    def test_threaded_scan_preserves_serial_extraction(self):
        source = self.root / 'game.nup'
        make_nup(source, [(f'p{i}', archive([shader(), shader(stage='cs')])) for i in range(12)], True)
        serial = scan_input(source, self.root / 'serial', False, workers=1)
        parallel = scan_input(source, self.root / 'parallel', False, workers=4)
        self.assertEqual((serial / 'native-audit.tsv').read_bytes(), (parallel / 'native-audit.tsv').read_bytes())
        for name in ('issues.json', 'unclaimed-controls.json'):
            self.assertEqual((serial / name).read_bytes(), (parallel / name).read_bytes())
        self.assertEqual(verify_manifest(serial), verify_manifest(parallel))

    def test_bahs_control_fields_are_not_mistaken_for_table_entries(self):
        record = shader()
        control, code = record[:0xd8], record[0xd8:]
        region, control_offset, entry_offset = 0x400, 0x100, 0x40
        data = bytearray(region + len(code))
        data[:4] = b'BAHS'
        struct.pack_into('<II', data, 0x18, len(code), region)
        struct.pack_into('<IIIi', data, entry_offset, 0, 0, len(control), control_offset - entry_offset)
        data[control_offset:control_offset + len(control)] = control
        data[region:] = code
        # This valid-looking descriptor is inside a control range and must be rejected.
        false_entry = control_offset + 0x10
        struct.pack_into('<IIIi', data, false_entry, 0, 0, len(control), control_offset - false_entry)
        source = self.root / 'game.nup'
        make_nup(source, [('pack', bytes(data))])
        output = scan_input(source, self.root / 'output', False)
        summary = json.loads((output / 'summary.json').read_text())
        self.assertEqual(summary['stats']['BAHS_control_field_false_entries'], 1)
        self.assertEqual(summary['native_instruction_stage_blobs'], 1)
        self.assertEqual(summary['issue_count'], 0)

    def test_cancelled_batch_still_writes_a_result_zip(self):
        folder = self.root / 'games'
        folder.mkdir()
        (folder / 'game.nup').touch()
        with patch('nup_shader_audit.cli.scan_input', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                run_batch(folder, self.root / 'results', 'fake-emulator')
        with zipfile.ZipFile(next((self.root / 'results').glob('batch-results-*.zip'))) as archive:
            self.assertIsNone(archive.testzip())
            manifest = json.loads(archive.read('batch.json'))
            self.assertEqual(manifest['entries'][0]['status'], 'cancelled')

    def test_batch_finds_nested_nups_and_reports_rejections(self):
        folder = self.root / 'games'
        (folder / 'nested').mkdir(parents=True)
        (folder / 'a.NUP').touch()
        (folder / 'nested' / 'b.nup').touch()
        with (patch('nup_shader_audit.cli.scan_input', side_effect=lambda source, output, **kwargs: output),
              patch('nup_shader_audit.cli.audit', return_value=({'total': 4, 'counts': {'rejected': 1}, 'cases': []}, self.root)) as audit_call,
              patch('nup_shader_audit.cli.write_batch_bundle', return_value=self.root / 'results.zip')):
            result = run_batch(folder, self.root / 'results', 'fake-emulator')
        self.assertEqual(result, 1)
        self.assertEqual(audit_call.call_count, 2)

    @unittest.skipUnless(Path(os.environ.get('NUP_SHADER_EMULATOR', 'C:/dev/eglantine')).is_dir(), 'Emulator checkout needed')
    def test_real_batch_zip_has_portable_regression_corpora_and_no_nups(self):
        folder = self.root / 'games'
        (folder / 'nested').mkdir(parents=True)
        make_nup(folder / 'one.nup', [('shader', archive([shader(), shader(stage='cs')]))])
        make_nup(folder / 'nested' / 'one.NUP', [('shader', shader(UNKNOWN + EXIT))])
        (folder / 'bad.nup').write_bytes(b'bad')
        emulator = os.environ.get('NUP_SHADER_EMULATOR', 'C:/dev/eglantine')
        output = self.root / 'results'
        self.assertEqual(run_batch(folder, output, emulator), 2)
        with zipfile.ZipFile(next(output.glob('batch-results-*.zip'))) as package:
            self.assertIsNone(package.testzip())
            manifest = json.loads(package.read('batch.json'))
            self.assertEqual(len(manifest['entries']), 3)
            self.assertEqual([row['status'] for row in manifest['entries']].count('error'), 1)
            self.assertEqual(sum(name.endswith('/audit/report.json') for name in package.namelist()), 2)
            self.assertEqual(sum(name.endswith('/corpus.sqlite') for name in package.namelist()), 2)
            self.assertFalse(any(name.endswith('.bin') for name in package.namelist()))
            self.assertFalse(any(name.lower().endswith('.nup') for name in package.namelist()))
            self.assertFalse(any(name.endswith('/shaders.sqlite') for name in package.namelist()))
            extracted = self.root / 'unpacked'
            package.extractall(extracted)
        portable = extracted / 'games/one.nup'
        self.assertEqual(verify_manifest(portable)[0], 2)
        repeated, _ = audit(portable, emulator)
        self.assertEqual(repeated['counts'], {'accepted': 2})
        self.assertEqual(repeated['comparison']['regressions'], [])
        self.assertFalse((portable / 'shaders.sqlite').exists())
        self.assertFalse((portable / 'native').exists())
        # Model an older translator that accepted the currently rejected program.
        rejected = extracted / 'games/nested/one.NUP'
        baseline_path = rejected / 'audit/report.json'
        baseline = json.loads(baseline_path.read_text())
        baseline['cases'][0]['status'] = 'accepted'
        baseline_path.write_text(json.dumps(baseline))
        regressed, _ = audit(rejected, emulator)
        self.assertEqual(regressed['comparison']['regressions'], [baseline['cases'][0]['file']])
        with closing(sqlite3.connect(portable / 'corpus.sqlite')) as db:
            db.execute("UPDATE programs SET code=?", (b'corrupt',))
            db.commit()
        with self.assertRaisesRegex(ValueError, 'changed or is incomplete'):
            verify_manifest(portable)

    @unittest.skipUnless(Path(os.environ.get('NUP_SHADER_EMULATOR', 'C:/dev/eglantine')).is_dir(), 'Emulator checkout needed')
    def test_real_translator_and_agent_packet(self):
        source = self.root / 'game.nup'
        make_nup(source, [('one', archive([shader(), shader(stage='cs'), shader(UNKNOWN + EXIT)]))])
        output = scan_input(source, self.root / 'output', False)
        emulator = os.environ.get('NUP_SHADER_EMULATOR', 'C:/dev/eglantine')
        report, directory = audit(output, emulator)
        self.assertEqual(report['counts'], {'accepted': 2, 'rejected': 1})
        self.assertEqual(report['groups'][0]['opcode'], '0xfff')
        self.assertEqual(load_report(output)['corpus_sha256'], report['corpus_sha256'])
        packet = create_task(output, samples=1)
        self.assertTrue((packet / 'TASK.md').is_file())
        self.assertEqual(len(list((packet / 'native').glob('*.bin'))), 1)
        repeated, _ = audit(output, emulator, baseline=directory / 'report.json')
        self.assertEqual(repeated['comparison']['regressions'], [])
        self.assertEqual(repeated['comparison']['newly_accepted'], [])
        self.assertEqual(main(['audit', str(output), '--emulator', emulator]), 1)


if __name__ == '__main__':
    unittest.main()
