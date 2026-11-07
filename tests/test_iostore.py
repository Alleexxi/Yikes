"""Synthetic IoStore assets and both generations of primitive/shader records."""

import json
import hashlib
import sqlite3
import struct
import tempfile
import unittest
import zlib
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from nup_shader_audit.cli import scan_input
from nup_shader_audit.audit import audit
from nup_shader_audit.iostore import MAGIC, IoStore
from nup_shader_audit.scanner import Scanner
from nup_shader_audit.unreal_pak import Pak
from test_pipeline import shader, make_nup


def unreal_shader():
    """Serialize native code before its length-delimited control section."""
    raw = shader()
    control, code = raw[:0xd8], raw[0xd8:]
    return b'Global/Test\0' + struct.pack('<I', len(code)) + code + struct.pack('<I', len(control)) + control + bytes(12)


def inline_table(raw):
    """Use a stand-in Oodle stream; tests inject a decoder instead of shipping game bytes."""
    packed = b'\x8c\x0b' + zlib.compress(raw)
    return struct.pack('<I', 1) + bytes(20) + struct.pack('<II', 1, len(packed)) + packed + struct.pack('<IB', len(raw), 0)


def iostore(raw, split=False, method='Zlib'):
    """Build 128-byte blocks, optionally crossing physical partitions within a chunk."""
    block_size, partition_size = 128, 4096
    blocks, parts = bytearray(), [bytearray(), bytearray()]
    for i in range(0, len(raw), block_size):
        value = raw[i:i + block_size]
        packed = zlib.compress(value) if method != 'None' else value
        part = int(split and i >= block_size)
        offset = len(parts[part]) + part * partition_size
        blocks += offset.to_bytes(5, 'little') + len(packed).to_bytes(3, 'little')
        blocks += len(value).to_bytes(3, 'little') + bytes([int(method != 'None')])
        parts[part] += packed
    header = bytearray(144)
    header[:16] = MAGIC
    header[16] = 6
    struct.pack_into('<9I', header, 20, 144, 1, len(blocks) // 12, 12, int(method != 'None'), 32,
                     block_size, 0, 2 if split else 1)
    struct.pack_into('<Q', header, 88, partition_size)
    chunk_id = bytes(11) + b'\x01'
    ranges = bytes(5) + len(raw).to_bytes(5, 'big')
    names = method.encode().ljust(32, b'\0') if method != 'None' else b''
    return bytes(header) + chunk_id + ranges + blocks + names, [bytes(p) for p in parts]


def pak(raw, version=11, compressed=False):
    """Make one stored/compressed PAK member with hashed primary/directory indexes."""
    def string(value):
        return struct.pack('<i', len(value) + 1) + value + b'\0'
    pieces = [zlib.compress(raw[i:i + 128]) for i in range(0, len(raw), 128)] if compressed else []
    packed = sum(map(len, pieces)) if compressed else len(raw)
    header_size = 57 + 16 * len(pieces) if compressed else 53
    body = bytes(header_size) + (b''.join(pieces) if compressed else raw)
    if version == 11:
        directory = struct.pack('<i', 1) + string(b'Engine/') + struct.pack('<i', 1)
        directory += string(b'GlobalShaderCache.bin') + struct.pack('<i', 0)
        if compressed:
            bits = 0xe0000000 | 0x3f | len(pieces) << 6 | 1 << 23
            encoded = struct.pack('<IIIII', bits, 128, 0, len(raw), packed)
            if len(pieces) > 1:
                encoded += struct.pack('<' + 'I' * len(pieces), *map(len, pieces))
        else:
            encoded = struct.pack('<III', 0xc0000000, 0, len(raw))
        index = string(b'../../../') + struct.pack('<iQiiQQ', 1, 0, 0, 1, len(body), len(directory))
        index += hashlib.sha1(directory).digest() + struct.pack('<i', len(encoded)) + encoded + bytes(4)
    else:
        directory = b''
        index = string(b'../../../') + struct.pack('<i', 1) + string(b'Engine/GlobalShaderCache.bin')
        index += struct.pack('<QQQI', 0, packed, len(raw), int(compressed)) + bytes(20)
        if compressed:
            index += struct.pack('<I', len(pieces))
            offset = header_size
            for piece in pieces:
                index += struct.pack('<QQ', offset, offset + len(piece))
                offset += len(piece)
        index += struct.pack('<BI', 0, 128 if compressed else 0)
    footer = (bytes(17) if version in (8, 11) else bytes(1)) + bytes.fromhex('e1126f5a')
    footer += struct.pack('<IQQ', version, len(body) + len(directory), len(index)) + hashlib.sha1(index).digest()
    if version in (8, 11):
        footer += b'Zlib'.ljust(160, b'\0')
    return body + directory + index + footer


class IoStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='yikes-iostore-')
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_cross_partition_chunk_spills_and_checks_block_sizes(self):
        raw = unreal_shader()
        toc, parts = iostore(raw, split=True)
        reader = IoStore(toc)
        self.assertEqual(len(list(reader.entries(0))), 1)
        self.assertEqual(list(reader.entries(1)), [])
        with patch('nup_shader_audit.iostore.LIMIT', 128):
            with reader.read(0, lambda p, o, n: parts[p][o:o + n], None) as result:
                self.assertEqual(result[:], raw)
        with self.assertRaises(ValueError):
            with reader.read(0, lambda p, o, n: parts[p][o:o + n - 1], None):
                pass
        broken = bytearray(toc)
        broken[144 + 22 + 11] = 2
        with self.assertRaises(ValueError):
            list(IoStore(broken).entries(0))
        broken = bytearray(toc)
        broken[80] = 2
        with self.assertRaisesRegex(ValueError, 'Encrypted'):
            IoStore(broken)

    def test_nup_pairing_and_nested_shader_table(self):
        raw = unreal_shader()
        toc, parts = iostore(inline_table(raw), split=True)
        source = self.root / 'game.nup'
        make_nup(source, [('game-Sage.ucas', parts[0]), ('game_s1-Sage.ucas', parts[1]),
                          ('game-Sage.utoc', toc)])
        decode = lambda _, kind, data, size: zlib.decompress(data[2:])
        with patch.object(Scanner, 'decode_native', decode):
            output = scan_input(source, self.root / 'scan', False)
        summary = json.loads((output / 'summary.json').read_text())
        self.assertEqual(summary['issue_count'], 0)
        self.assertEqual(summary['unclaimed_control_candidates'], 0)
        self.assertEqual(summary['native_instruction_stage_blobs'], 1)
        with closing(sqlite3.connect(output / 'shaders.sqlite')) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM origins WHERE format='UNREAL_NVN2'").fetchone()[0], 1)

    def test_numbered_container_with_own_toc_is_not_a_partition(self):
        toc, parts = iostore(unreal_shader())
        source = self.root / 'separate.nup'
        make_nup(source, [('chunk_s1-Switch2.ucas', parts[0]), ('chunk_s1-Switch2.utoc', toc)])
        output = scan_input(source, self.root / 'separate', False)
        self.assertEqual(json.loads((output / 'summary.json').read_text())['native_instruction_stage_blobs'], 1)

    def test_missing_partition_is_an_explicit_gap(self):
        toc, parts = iostore(unreal_shader(), split=True)
        source = self.root / 'missing.nup'
        make_nup(source, [('chunk.ucas', parts[0]), ('chunk.utoc', toc)])
        output = scan_input(source, self.root / 'missing', False)
        self.assertIn('Missing IoStore partition', (output / 'issues.json').read_text())

    def test_legacy_primitive_pair_is_preserved_separately(self):
        control_size, code_size = 0x880, 0x100
        data = bytearray(16 + 2 * control_size + 2 * code_size)
        cv, cp, kv, kp = 16, 16 + control_size, 16 + 2 * control_size, 16 + 2 * control_size + code_size
        struct.pack_into('<4I', data, 0, cv, cp, kv, kp)
        for c, k, stage in ((cv, kv, 1), (cp, kp, 5)):
            data[c:c + 8] = bytes.fromhex('3412769801000000')
            struct.pack_into('<I', data, c + 0x20, control_size)
            struct.pack_into('<I', data, c + 0x704, code_size)
            data[k:k + 4] = bytes.fromhex('78563412')
            struct.pack_into('<I', data, k + 0x30, stage << 10)
        source = self.root / 'legacy.nup'
        make_nup(source, [('primitive.bin', bytes(data))])
        output = scan_input(source, self.root / 'legacy', False)
        with closing(sqlite3.connect(output / 'shaders.sqlite')) as db:
            self.assertEqual(db.execute('SELECT arch,stage FROM shaders ORDER BY stage').fetchall(),
                             [('maxwell', 'ps'), ('maxwell', 'vs')])
        self.assertEqual(json.loads((output / 'summary.json').read_text())['unclaimed_control_candidates'], 0)

    def test_legacy_and_modern_paks_scan_and_reject_bad_indexes(self):
        for version in (4, 8, 11):
            raw = pak(unreal_shader(), version)
            source = self.root / f'pak-{version}.nup'
            make_nup(source, [('chunk.pak', raw)])
            output = scan_input(source, self.root / f'pak-{version}', False)
            summary = json.loads((output / 'summary.json').read_text())
            self.assertEqual(summary['native_instruction_stage_blobs'], 1)
            self.assertEqual(summary['issue_count'], 0)
            broken = bytearray(raw)
            broken[-1 if version == 4 else -161] ^= 1
            with self.assertRaisesRegex(ValueError, 'SHA-1'):
                Pak(broken)
            archive = Pak(pak(unreal_shader(), version, compressed=True))
            with patch('nup_shader_audit.unreal_pak.LIMIT', 128):
                with archive.read(next(iter(archive.files)), None) as value:
                    self.assertEqual(value[:], unreal_shader())

    def test_zero_native_shaders_is_not_a_compatibility_pass(self):
        source = self.root / 'unrecognized.nup'
        make_nup(source, [('data', b'not a shader')])
        output = scan_input(source, self.root / 'unrecognized', False)
        with patch('nup_shader_audit.audit.build_adapter') as build:
            with self.assertRaisesRegex(ValueError, 'No native shaders'):
                audit(output, 'unused-emulator')
            build.assert_not_called()

    def test_zero_shader_checkpoint_revisits_previously_opaque_ucas(self):
        toc, parts = iostore(unreal_shader())
        source = self.root / 'upgrade.nup'
        make_nup(source, [('chunk.ucas', parts[0]), ('chunk.utoc', toc)])
        scan = Scanner.scan

        def old_scan(scanner, data, label, *args, **kwargs):
            kwargs.pop('iostore', None)
            return scan(scanner, data, label, *args, **kwargs)

        with patch.object(Scanner, 'scan', old_scan), patch('nup_shader_audit.scanner.SCANNER_REVISION', 6):
            output = scan_input(source, self.root / 'upgrade', False)
        self.assertEqual(json.loads((output / 'summary.json').read_text())['native_instruction_stage_blobs'], 0)
        scan_input(source, output, True)
        self.assertEqual(json.loads((output / 'summary.json').read_text())['native_instruction_stage_blobs'], 1)

    def test_unsupported_libraries_and_malformed_bundles_remain_explicit_gaps(self):
        toc, parts = iostore(unreal_shader())
        toc = bytearray(toc)
        toc[144 + 11] = 8
        source = self.root / 'unknown.nup'
        make_nup(source, [('chunk.ucas', parts[0]), ('chunk.utoc', bytes(toc)),
                          ('asset.bundle', b'UnityFS\0' + bytes(128)),
                          ('archive.ushaderbytecode', bytes(128))])
        output = scan_input(source, self.root / 'unknown', False)
        summary = json.loads((output / 'summary.json').read_text())
        self.assertEqual(summary['issue_count'], 3)
        self.assertEqual(summary['native_instruction_stage_blobs'], 1)

    def test_same_ucas_with_different_toc_is_not_skipped(self):
        toc, parts = iostore(unreal_shader())
        empty = bytearray(toc)
        empty[144 + 12:144 + 22] = bytes(10)
        scanner = Scanner(self.root / 'contexts')
        try:
            read = lambda p, offset, size: parts[p][offset:offset + size]
            scanner.scan(parts[0], 'old', iostore=(IoStore(empty), 0, read))
            self.assertEqual(len(scanner.written_native), 0)
            scanner.scan(parts[0], 'new', iostore=(IoStore(toc), 0, read))
            self.assertEqual(len(scanner.written_native), 1)
        finally:
            scanner.close()


if __name__ == '__main__':
    unittest.main()
