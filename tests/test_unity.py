"""Synthetic UnityFS/serialized assets exercise code, parameter and kernel boundaries."""

import hashlib
import json
import lzma
import sqlite3
import struct
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import lz4.block
from UnityPy.helpers.TypeTreeHelper import write_typetree
from UnityPy.helpers.TypeTreeNode import TypeTreeNode
from UnityPy.streams import EndianBinaryWriter

from nup_shader_audit.cli import scan_input
from nup_shader_audit.scanner import Scanner
from nup_shader_audit.unity import (AssetStream, bundle_members, compute_programs, decode, graphics_programs,
                                    is_serialized, program_ranges)
from test_pipeline import shader, make_nup


def program(stage='vs', count=9):
    """Serialize a synthetic shader into the native Unity stage-array layout."""
    raw = shader(stage=stage)
    index = 5 if stage == 'cs' else 0
    header = [0] * count + [-1] * count + [-1] * count + [-1] * count
    header[count + index], header[2 * count + index], header[3 * count + index] = 0, 0xd8, len(raw) - 0xd8
    return struct.pack('<' + 'i' * len(header), *header) + (bytes(4) if count == 9 else b'') + raw


def subprogram(code):
    """Make a modern code entry whose keywords and byte-array bounds are explicit."""
    return struct.pack('<2I', 202012090, 26) + bytes(16) + struct.pack('<2I', 0, len(code)) + code


def shader_dict(code):
    """Build a single-platform, single-segment shader object."""
    raw = subprogram(code)
    segment = struct.pack('<4I', 1, 16, len(raw), 0) + raw
    packed = lz4.block.compress(segment, store_size=False)
    return {'platforms': [27], 'offsets': [[0]], 'compressedLengths': [[len(packed)]],
            'decompressedLengths': [[len(segment)]], 'compressedBlob': packed}


def tree(fields):
    """Construct a minimal explicit type tree, independent of Unity's built-in class database."""
    nodes = []

    def add(kind, name, level, size=-1, flags=0):
        nodes.append(dict(m_Version=1, m_Level=level, m_TypeFlags=0, m_Type=kind, m_Name=name,
                          m_ByteSize=size, m_Index=len(nodes), m_MetaFlag=flags, m_RefTypeHash=0))

    def field(kind, name, level):
        if isinstance(kind, list):
            add('vector', name, level)
            add('Array', 'Array', level + 1, flags=0x4000)
            add('int', 'size', level + 2, 4)
            field(kind[0], 'data', level + 2)
        elif isinstance(kind, dict):
            add('Entry', name, level)
            for child, value in kind.items():
                field(value, child, level + 1)
        elif kind == 'bytes':
            add('TypelessData', name, level, flags=0x4000)
        else:
            add('int', name, level, 4)

    add('Shader', 'Base', 0)
    for name, kind in fields.items():
        field(kind, name, 1)
    return TypeTreeNode.from_list(nodes)


def asset(entries, stripped=False, engine='6000.3.0f1'):
    """Write a Unity v22 asset containing original synthetic shader/compute object bytes."""
    graphics = {'platforms': ['int'], 'offsets': [['int']], 'compressedLengths': [['int']],
                'decompressedLengths': [['int']], 'compressedBlob': 'bytes'}
    compute = {'variants': [{'kernels': [{'uniqueVariants': [{'code': 'bytes'}]}]}]}
    layouts = {48: graphics, 72: compute, 49: {'m_Name': 'bytes', 'm_Script': 'bytes'}}
    types, payloads, descriptions = [], bytearray(), []
    for path_id, (class_id, data) in enumerate(entries, 1):
        node = tree(layouts[class_id])
        object_writer = EndianBinaryWriter(endian='<')
        write_typetree(data, node, object_writer)
        raw = object_writer.bytes
        descriptions.append((path_id, len(payloads), len(raw), len(types)))
        payloads += raw + bytes(-len(raw) % 8)
        types.append((class_id, node))
    metadata = EndianBinaryWriter(endian='<')
    metadata.write_string_to_null(engine)
    metadata.write_int(48)
    metadata.write_boolean(not stripped)
    metadata.write_int(len(types))
    for class_id, node in types:
        metadata.write(struct.pack('<iBh', class_id, 0, -1))
        metadata.write(hashlib.md5(str(layouts[class_id]).encode()).digest())
        if not stripped:
            node.dump_blob(metadata, 22)
            metadata.write_int(0)
    metadata.write_int(len(entries))
    for description in descriptions:
        metadata.align_stream(4)
        metadata.write(struct.pack('<qqIi', *description))
    metadata.write(bytes(12) + b'\0')
    start = (48 + len(metadata.bytes) + 15) & ~15
    total = start + len(payloads)
    header = struct.pack('>4I', 0, 0, 22, 0) + bytes(4) + struct.pack('>IQQQ', len(metadata.bytes), total, start, 0)
    return header + metadata.bytes + bytes(start - 48 - len(metadata.bytes)) + payloads


def bundle(payload, at_end=False, kind=2):
    """Build a UnityFS v7 bundle with a compressed metadata table and payload block."""
    packed = lz4.block.compress(payload, store_size=False) if kind else payload
    info = bytes(16) + struct.pack('>iIIHiQQI', 1, len(payload), len(packed), kind, 1, 0, len(payload), 0)
    info += b'CAB-test\0'
    packed_info = lz4.block.compress(info, store_size=False)
    header = b'UnityFS\0' + struct.pack('>I', 7) + b'5.x.x\0' + b'6000.3.0f1\0'
    dimensions = len(header)
    header += struct.pack('>QIII', 0, len(packed_info), len(info), 0x42 | (0x80 if at_end else 0))
    header += bytes(-len(header) % 16)
    data = bytearray(header + (packed + packed_info if at_end else packed_info + packed))
    struct.pack_into('>Q', data, dimensions, len(data))
    return bytes(data)


class UnityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='yikes-unity-')
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_serialized_graphics_and_compute_inside_streamed_bundles(self):
        raw = asset([(48, shader_dict(program())), (72, {'variants': [{'kernels': [
            {'uniqueVariants': [{'code': program('cs')}, {'code': b''}]}]}]}),
                     (49, {'m_Name': b'binary', 'm_Script': shader(stage='ps')})])
        self.assertTrue(is_serialized(raw))
        for at_end in (False, True):
            source = self.root / f'{at_end}.nup'
            make_nup(source, [('Data/file.bundle', bundle(raw, at_end))])
            with patch('nup_shader_audit.unity.LIMIT', 128):
                output = scan_input(source, self.root / str(at_end), False)
            summary = json.loads((output / 'summary.json').read_text())
            self.assertEqual(summary['native_instruction_stage_blobs'], 3)
            self.assertEqual(summary['issue_count'], 0)
            self.assertEqual(summary['unclaimed_control_candidates'], 0)
            self.assertEqual(summary['stats']['unity_shader_objects'], 1)
            self.assertEqual(summary['stats']['unity_compute_objects'], 1)
            self.assertEqual(summary['stats']['unity_text_assets'], 1)
            with closing(sqlite3.connect(output / 'shaders.sqlite')) as db:
                self.assertEqual(db.execute("SELECT count(*) FROM origins WHERE format='UNITY'").fetchone()[0], 2)

    def test_parameter_entries_and_multiple_segments(self):
        code = subprogram(program())
        params = bytes(32)
        segment0 = struct.pack('<7I', 2, 28, len(params), 0, 0, len(code), 1) + params
        packed = [lz4.block.compress(d, store_size=False) for d in (segment0, code)]
        d = {'platforms': [27], 'offsets': [[0, len(packed[0])]],
             'compressedLengths': [[len(p) for p in packed]], 'decompressedLengths': [[len(segment0), len(code)]],
             'compressedBlob': b''.join(packed), 'm_ParsedForm': {'m_SubShaders': [{'m_Passes': [{
                 'progVertex': {'m_ParameterBlobIndices': [[0]], 'm_PlayerSubPrograms': [[{'m_BlobIndex': 1}]]}}]}]}}
        result = list(graphics_programs(d))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][1], program())
        d['decompressedLengths'][0].pop()
        with self.assertRaisesRegex(ValueError, 'dimensions'):
            list(graphics_programs(d))

    def test_both_stage_array_sizes_reject_truncated_code(self):
        for count in (6, 9):
            raw = program(count=count)
            self.assertEqual(program_ranges(raw)[0][0], 'vs')
            with self.assertRaises(ValueError):
                program_ranges(raw[:-1])
        raw = shader()
        legacy = bytes(8) + struct.pack('<2I', 0xd8, len(raw) - 0xd8) + raw
        self.assertEqual(program_ranges(legacy, 'vs')[0], ('vs', 16, 0xd8, 16 + 0xd8, len(raw) - 0xd8))

    def test_reader_and_compression_fail_with_explicit_bounds(self):
        stream = AssetStream(b'abcd')
        self.assertEqual(stream.read(2), b'ab')
        self.assertEqual(stream.seek(-1, 2), 3)
        with self.assertRaises(ValueError):
            stream.read(2)
        packed = bundle(asset([(48, shader_dict(program()))]))
        with self.assertRaises(ValueError):
            with bundle_members(packed[:-1]):
                pass
        with self.assertRaises(ValueError):
            decode(b'bad', 4000, 2)
        raw = b'Unity LZMA data' * 100
        filters = [{'id': lzma.FILTER_LZMA1, 'dict_size': 65536, 'lc': 3, 'lp': 0, 'pb': 2}]
        packed = bytes([93]) + struct.pack('<I', 65536) + lzma.compress(raw, format=lzma.FORMAT_RAW, filters=filters)
        self.assertEqual(decode(packed, len(raw), 1), raw)

    def test_compute_legacy_maps_direct_kernels_and_empty_variants(self):
        for kernel in ({'code': program('cs')}, {'variantMap': [{'second': {'code': program('cs')}}]},
                       {'uniqueVariants': [{'code': b''}, {'code': program('cs')}]}):
            result = list(compute_programs({'variants': [{'kernels': [kernel]}]}))
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0][1], program('cs'))

    def test_strictly_validated_schema_cache_survives_resume(self):
        raw = asset([(48, shader_dict(program()))])
        stripped = asset([(48, shader_dict(program('cs')))], stripped=True, engine='6000.3.0b4')
        source = self.root / 'schemas.nup'
        make_nup(source, [('Data/globalgamemanagers.assets', raw), ('Data/sharedassets0.assets', stripped)])
        output = self.root / 'schemas'

        def interrupt(current, total):
            if current == 1:
                raise KeyboardInterrupt

        scanner = Scanner(output, checkpoint_every=1, progress=interrupt)
        try:
            with self.assertRaises(KeyboardInterrupt):
                scanner.run(source)
        finally:
            scanner.close()
        with closing(sqlite3.connect(output / 'shaders.sqlite')) as db:
            state = json.loads(db.execute("SELECT value FROM state WHERE key='checkpoint'").fetchone()[0])
        self.assertTrue(state['unity_schemas'])
        scan_input(source, output, True)
        summary = json.loads((output / 'summary.json').read_text())
        self.assertEqual(summary['native_instruction_stage_blobs'], 2)
        self.assertEqual(summary['issue_count'], 0)


if __name__ == '__main__':
    unittest.main()
