"""Exercise complete archive traversal and streamed decoding with a small memory threshold."""

import hashlib
import json
import os
import sqlite3
import struct
import tempfile
import unittest
import zipfile
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import lz4.frame
import zstandard

from nup_shader_audit.audit import audit, verify_manifest
from nup_shader_audit.cli import run_batch, scan_input
from nup_shader_audit.codecs import NativeDecoder
from nup_shader_audit.corpus import extraction_programs
from nup_shader_audit.large import Window, decoded_lz4, decoded_yaz0, decoded_zstd, digest
from nup_shader_audit.scanner import Scanner, yaz0
from nup_shader_audit.tasks import create_task
from test_pipeline import EXIT, UNKNOWN, archive, make_nup, shader


def onepack(payload, compression=0, size=None):
    """Build a single-file ONEPACK using explicit FlatBuffers table/vector offsets."""
    pack = bytearray(116 + len(payload))
    struct.pack_into('<I', pack, 0, 16)
    struct.pack_into('<4H', pack, 8, 8, 12, 4, 8)
    struct.pack_into('<3I', pack, 16, 8, 12, 24)
    struct.pack_into('<IQ', pack, 32, 1, 123)
    struct.pack_into('<II', pack, 48, 1, 28)
    struct.pack_into('<7H', pack, 64, 14, 20, 0, 4, 5, 8, 16)
    struct.pack_into('<I', pack, 80, 16)
    struct.pack_into('<b', pack, 84, compression)
    struct.pack_into('<Q', pack, 88, len(payload) if size is None else size)
    struct.pack_into('<I', pack, 96, 16)
    struct.pack_into('<I', pack, 112, len(payload))
    pack[116:] = payload
    metadata = bytearray(64)
    struct.pack_into('<I', metadata, 0, 16)
    struct.pack_into('<4H', metadata, 8, 8, 12, 4, 8)
    struct.pack_into('<3I', metadata, 16, 8, 12, 24)
    struct.pack_into('<IQ', metadata, 32, 1, 456)
    struct.pack_into('<IQ', metadata, 48, 1, 16)
    return b'ONEPACK\0' + struct.pack('<Q', 16 + len(pack)) + pack + metadata


def bea(payload, unpacked):
    """Build an inline Bezel ASST entry with a declared packed/unpacked length."""
    data = bytearray(0x100 + len(payload))
    data[:4] = b'SCNE'
    struct.pack_into('<QQ', data, 0x20, 1, 0x40)
    data[0x40:0x44] = b'ASST'
    struct.pack_into('<I', data, 0x44, 0x48)
    struct.pack_into('<II', data, 0x54, len(payload), unpacked)
    struct.pack_into('<QQ', data, 0x78, 0x100, 0x90)
    struct.pack_into('<H', data, 0x90, 4)
    data[0x92:0x96] = b'test'
    data[0x100:] = payload
    return bytes(data)


def ray_bnsh(declared_size=16):
    """Build a stage-8 module with a one-function table; code must not be read as compute."""
    data = bytearray(0x410)
    data[:8] = b'BNSH\0\0\0\0'
    struct.pack_into('<I', data, 0x1c, len(data))
    data[0x60:0x64] = b'grsc'
    struct.pack_into('<IQ', data, 0x7c, 1, 0x100)
    struct.pack_into('<Q', data, 0x110, 0x140)
    struct.pack_into('<Q', data, 0x178, 0x1a0)
    struct.pack_into('<QQII', data, 0x1a8, 0x220, 0x400, 16, 0x120)
    control = bytearray(0x120)
    control[:8] = bytes.fromhex('34127698c9000000')
    struct.pack_into('<I', control, 0x30, len(control))
    struct.pack_into('<I', control, 0x44, len(EXIT))
    control[0x56] = 8
    # Function table: base pointer at 0xd8; one function at 0 with its declared size, no relocations.
    struct.pack_into('<Q', control, 0xd8, 0xe0)
    struct.pack_into('<III', control, 0xf0, 1, 0x38, 0x3c)
    struct.pack_into('<II', control, 0x118, 0, declared_size)
    data[0x220:0x340] = control
    data[0x400:] = EXIT
    return bytes(data)


class LargeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='yikes-large-test-')
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_large_raw_and_zstd_roots_are_hash_checked_and_fully_scanned(self):
        raw = archive([bytes(4096), shader(), shader(stage='cs')])
        for compressed in (False, True):
            source = self.root / f'{compressed}.nup'
            make_nup(source, [('large', raw)], compressed)
            with (patch('nup_shader_audit.large.LIMIT', 512),
                  patch('nup_shader_audit.scanner.LIMIT', 512),
                  patch('nup_shader_audit.container.read.LIMIT', 512)):
                output = scan_input(source, self.root / str(compressed), False)
            self.assertEqual(verify_manifest(output)[0], 2)
            summary = json.loads((output / 'summary.json').read_text())
            self.assertEqual(summary['root_status_counts'], {'ok': 1})
            self.assertEqual(summary['issue_count'], 0)
        source = self.root / 'bad.nup'
        make_nup(source, [('large', raw)], True, bad_hash=True)
        with (patch('nup_shader_audit.large.LIMIT', 512), patch('nup_shader_audit.scanner.LIMIT', 512),
              patch('nup_shader_audit.container.read.LIMIT', 512)):
            output = scan_input(source, self.root / 'bad', False)
        self.assertEqual(verify_manifest(output)[0], 0)
        self.assertIn('SHA-256 mismatch', (output / 'issues.json').read_text())

    def test_streamed_codecs_match_and_reject_truncation(self):
        raw = b'!' * 4096
        for known in (False, True):
            packed = zstandard.ZstdCompressor(write_content_size=known, write_checksum=True).compress(raw)
            with patch('nup_shader_audit.large.LIMIT', 512):
                with decoded_zstd(packed) as decoded:
                    self.assertIsInstance(decoded, Window)
                    self.assertEqual(decoded[:], raw)
                    self.assertEqual(digest(decoded), hashlib.sha256(raw).hexdigest())
                with self.assertRaises(ValueError):
                    with decoded_zstd(packed[:-1]):
                        pass
        packed = lz4.frame.compress(raw)
        with patch('nup_shader_audit.large.LIMIT', 512):
            with decoded_lz4(packed) as decoded:
                self.assertIsInstance(decoded, Window)
                self.assertEqual(decoded[:], raw)
            with self.assertRaises(ValueError):
                with decoded_lz4(packed[:-1]):
                    pass
        # Literal-only Yaz0 exercises output spill without relying on another codec.
        packed = b'Yaz0' + struct.pack('>I', len(raw)) + bytes(8)
        packed += b''.join(b'\xff' + raw[i:i + 8] for i in range(0, len(raw), 8))
        with patch('nup_shader_audit.large.LIMIT', 512):
            with decoded_yaz0(packed, yaz0) as decoded:
                self.assertEqual(decoded[:], raw)

    def test_onepack_bea_and_ndve_traverse_declared_members(self):
        source = self.root / 'formats.nup'
        raw = shader()
        compressed = zstandard.ZstdCompressor().compress(raw)
        pack = bytearray(0x120 + len(raw) - 0xd8)
        pack[:4] = b'NDSR'
        struct.pack_into('<4I', pack, 0x10, 0x40, 0xd86, 0x120, (len(raw) - 0xd8) << 4 | 7)
        pack[0x40:0x118] = raw[:0xd8]
        pack[0x120:] = raw[0xd8:]
        ndve = bytearray(0x18)
        ndve[:4] = b'NDVE'
        struct.pack_into('<I', ndve, 0x0c, len(pack))
        make_nup(source, [('trinity', onepack(raw)), ('bea', bea(compressed, len(raw))),
                          ('ndve', bytes(ndve + pack))])
        output = scan_input(source, self.root / 'output', False)
        summary = json.loads((output / 'summary.json').read_text())
        self.assertEqual(summary['stats']['trinity_files'], 1)
        self.assertEqual(summary['stats']['bea_files'], 1)
        self.assertEqual(summary['stats']['ndve_archives'], 1)
        self.assertEqual(summary['issue_count'], 0)
        self.assertEqual(verify_manifest(output)[0], 1)
        with closing(sqlite3.connect(output / 'shaders.sqlite')) as db:
            self.assertTrue(any('/test' in row[0] for row in db.execute('SELECT path FROM paths')))

    def test_bahs_record_array_rejects_fake_entries_without_hiding_real_ones(self):
        data = bytearray(0x600)
        data[:4] = b'BAHS'
        struct.pack_into('<II', data, 0x18, 0x200, 0x400)
        struct.pack_into('<II', data, 0x40, 0x208, 2)
        for i, instructions in enumerate((EXIT, UNKNOWN + EXIT)):
            record, control, code = 0x48 + i * 0x100, 0x88 + i * 0x100, 0x400 + i * 0x100
            struct.pack_into('<II', data, record, 0x100, 3)
            entry = record + 0x10
            struct.pack_into('<IIIi', data, entry, i * 0x100, 0, 0x80, control - entry)
            raw = shader(instructions, stage='cs')
            data[control:control + 0x80] = raw[:0x80]
            data[code:code + len(instructions)] = instructions
        # This descriptor is in record padding and names real control/code bytes,
        # but it is not one of the array's declared entries.
        fake = 0x128
        struct.pack_into('<IIIi', data, fake, 0x100, 0, 0x100, 0x188 - fake)
        source = self.root / 'bahs.nup'
        make_nup(source, [('pack', bytes(data))])
        output = scan_input(source, self.root / 'bahs', False)
        summary = json.loads((output / 'summary.json').read_text())
        self.assertEqual(summary['stats']['sm86_unique_records'], 2)
        self.assertEqual(summary['stats']['BAHS_control_field_false_entries'], 1)
        self.assertEqual(summary['unclaimed_control_candidates'], 0)
        # Model an older checkpoint containing a false heuristic match. A resume
        # must remove its provenance and orphaned binary, not just append new ones.
        bogus = shader(EXIT * 3, stage='cs')
        bogus_hash = hashlib.sha256(EXIT * 3).hexdigest()
        with closing(sqlite3.connect(output / 'shaders.sqlite')) as db:
            blob = db.execute('SELECT hash FROM blobs').fetchone()[0]
            db.execute('INSERT INTO shaders VALUES (?,?,?,?,?,?,?)',
                       ('f' * 64, 'sm86', 'cs', bogus[:0xd8], bogus[0xd8:], bogus_hash, 48))
            db.execute('INSERT INTO origins VALUES (?,?,?,?,?,?)',
                       ('f' * 64, blob, 'BAHS', 0x188, 0x500, '0x128'))
            previous = json.loads(db.execute("SELECT value FROM state WHERE key='checkpoint'").fetchone()[0])
            previous['scanner_revision'] = 5
            db.execute("UPDATE state SET value=? WHERE key='checkpoint'", (json.dumps(previous),))
            db.commit()
        with patch.object(Scanner, 'scan', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                scan_input(source, output, True)
        with closing(sqlite3.connect(output / 'shaders.sqlite')) as db:
            self.assertEqual(db.execute('SELECT status FROM roots').fetchone()[0], 'retry')
        scan_input(source, output, True)
        self.assertEqual(verify_manifest(output)[0], 2)
        with closing(sqlite3.connect(output / 'shaders.sqlite')) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM shaders WHERE key=?", ('f' * 64,)).fetchone()[0], 0)
        self.assertNotIn(bogus_hash, (output / 'native-audit.tsv').read_text())

    @unittest.skipUnless(os.name == 'nt', 'Native codec helper requires Windows MSVC')
    def test_native_codec_ipc_decodes_both_formats_and_recovers_from_errors(self):
        decoder = NativeDecoder()
        try:
            raw = b'hello'
            self.assertEqual(decoder.decode('oodle', b'\xcc\x0a' + raw, len(raw)), raw)
            zbic = b'ZBIC\x20\x05' + struct.pack('<I', (5 << 3) | 1)[:3] + raw
            self.assertEqual(decoder.decode('zbic', zbic, len(raw)), raw)
            with self.assertRaises(ValueError):
                decoder.decode('oodle', b'bad', 5)
            self.assertEqual(decoder.decode('oodle', b'\xcc\x0a' + raw, len(raw)), raw)
        finally:
            decoder.close()

    @unittest.skipUnless(Path(os.environ.get('NUP_SHADER_EMULATOR', 'C:/dev/eglantine')).is_dir(), 'Emulator checkout needed')
    def test_ray_module_function_tables_are_validated_and_lowered(self):
        source = self.root / 'ray.nup'
        make_nup(source, [('ray', ray_bnsh())])
        output = scan_input(source, self.root / 'ray', False)
        self.assertEqual(verify_manifest(output)[0], 1)
        raw = list(extraction_programs(output))[0][3]
        self.assertEqual(raw[:4], b'NRTM')
        self.assertEqual(struct.unpack_from('<3I', raw, 4), (1, 0x120, 16))
        self.assertEqual(raw[16 + 0x120:16 + 0x120 + 16], EXIT)
        report, _ = audit(output, os.environ.get('NUP_SHADER_EMULATOR', 'C:/dev/eglantine'))
        self.assertEqual(report['counts'], {'accepted': 1})
        self.assertEqual(report['cases'][0]['stage'], 'rt')
        broken = self.root / 'broken.nup'
        make_nup(broken, [('ray', ray_bnsh(declared_size=32))])
        output = scan_input(broken, self.root / 'broken', False)
        report, _ = audit(output, os.environ.get('NUP_SHADER_EMULATOR', 'C:/dev/eglantine'))
        self.assertEqual(report['counts'], {'rejected': 1})
        case = report['cases'][0]
        self.assertIsNone(case['error_offset'])
        self.assertEqual(case['opcode'], '')
        self.assertIn('functions do not cover the code', case['reason'])
        packet = create_task(output, samples=1)
        self.assertIn('NRTM', (packet / 'TASK.md').read_text())
        games = self.root / 'games'
        games.mkdir()
        make_nup(games / 'ray.nup', [('ray', ray_bnsh(declared_size=32))])
        bundled = self.root / 'bundled'
        emulator = os.environ.get('NUP_SHADER_EMULATOR', 'C:/dev/eglantine')
        self.assertEqual(run_batch(games, bundled, emulator), 1)
        with zipfile.ZipFile(next(bundled.glob('batch-results-*.zip'))) as package:
            package.extractall(self.root / 'unpacked')
        portable = self.root / 'unpacked/games/ray.nup'
        replay, _ = audit(portable, emulator)
        self.assertEqual(replay['comparison']['regressions'], [])
        self.assertEqual(replay['cases'][0]['reason'], case['reason'])


if __name__ == '__main__':
    unittest.main()
