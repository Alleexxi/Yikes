"""Synthetic encrypted Unreal, chained VZIP, shader-group and SDF boundaries."""

import hashlib
import io
import json
import struct
import tempfile
import unittest
import zipfile
import zlib
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import lz4.block
from Crypto.Cipher import AES

from nup_shader_audit.iostore import IoStore
from nup_shader_audit.scanner import Scanner
from nup_shader_audit.large import decoded_zlib
from nup_shader_audit.snowdrop import Snowdrop, decode_page
from nup_shader_audit.unreal_crypto import KeyProbe, find_key
from nup_shader_audit.unreal_archive import looks_like as shader_archive_like, parse as shader_archive, program as archive_program
from nup_shader_audit.unreal_library import library, group_programs
from nup_shader_audit.unreal_pak import Pak
from nup_shader_audit.zip_archive import ZipArchive
from test_iostore import iostore, unreal_shader
from test_pipeline import shader

KEY = bytes(range(32))  # Synthetic fixture, never a game key.


def encrypted(raw):
    """Use deliberately nonzero alignment padding to exercise UE's actual padding rule."""
    return AES.new(KEY, AES.MODE_ECB).encrypt(raw + b'\x0a' * (-len(raw) % 16))


def string(raw):
    return struct.pack('<i', len(raw) + 1) + raw + b'\0'


def encrypted_pak(raw, compressed, version=11):
    packed = zlib.compress(raw) if compressed else raw
    body = bytes(73 if compressed else 53) + encrypted(packed)
    directory = struct.pack('<i', 1) + string(b'Engine/') + struct.pack('<i', 1)
    # Version 12 stores directory file names without the terminator.
    directory += (struct.pack('<i', 10) + b'shader.bin' if version >= 12 else string(b'shader.bin')) + bytes(4)
    if compressed:
        bits = 0xe0000000 | 0x3f | 1 << 6 | 1 << 22 | 1 << 23
        entry = struct.pack('<6I', bits, len(raw), 0, len(raw), len(encrypted(packed)), len(packed))
    else:
        entry = struct.pack('<3I', 0xc0400000, 0, len(raw))
    index = string(b'../../../') + struct.pack('<iQiiQQ', 1, 0, 0, 1, len(body), len(directory))
    index += hashlib.sha1(directory).digest() + struct.pack('<i', len(entry)) + entry + bytes(4)
    offset = len(body) + len(encrypted(directory))
    footer = bytes(16) + b'\1' + bytes.fromhex('e1126f5a')
    footer += struct.pack('<IQQ', version, offset, len(index)) + hashlib.sha1(index).digest()
    footer += b'Zlib'.ljust(160, b'\0')
    return body + encrypted(directory) + encrypted(index) + footer


def shader_library(raw, hash_size=20):
    """Make a version-one library whose group precedes it in the owning TOC."""
    gid = bytes(11) + b'\x09'
    data = struct.pack('<III', 1, 0, 1) + bytes(hash_size)
    data += struct.pack('<I', 1) + gid + struct.pack('<I', 0)
    data += struct.pack('<IQ', 1, 0)  # One shader, frequency zero, offset/group zero.
    data += struct.pack('<I4I', 1, 0, 1, len(raw), len(raw))
    data += struct.pack('<II', 1, 0)
    return gid, data


class ArchiveExtensionTests(unittest.TestCase):
    def test_encrypted_pak_indexes_and_payloads(self):
        for compressed, version in ((False, 11), (True, 11), (False, 12), (True, 12)):
            raw = shader()
            data = encrypted_pak(raw, compressed, version)
            archive = Pak(data, lambda probe: KEY)
            self.assertEqual(list(archive.files), ['Engine/shader.bin'])
            with patch('nup_shader_audit.unreal_pak.LIMIT', 32):
                with archive.read('Engine/shader.bin', None) as result:
                    self.assertEqual(result[:], raw)
            with self.assertRaisesRegex(ValueError, 'SHA-1'):
                Pak(data, lambda probe: bytes(32))
            corrupted = bytearray(data)
            corrupted[-204 + 24] ^= 1
            with self.assertRaises(ValueError):
                Pak(bytes(corrupted), lambda probe: KEY)

    def test_encrypted_iostore_padding_directory_and_payload(self):
        raw = unreal_shader()
        toc, parts = iostore(raw)
        original = IoStore(toc)
        fixed, body = bytearray(toc), bytearray()
        fixed[80] = 2
        for i in range(original.block_count):
            _, at, size, _, _ = original.block(i)
            fixed[original.blocks + i * 12:original.blocks + i * 12 + 5] = len(body).to_bytes(5, 'little')
            body += encrypted(parts[0][at:at + size])
        directory = string(b'../../../')
        directory += struct.pack('<I4I', 1, 0xffffffff, 0xffffffff, 0xffffffff, 0)
        directory += struct.pack('<I3I', 1, 0, 0xffffffff, 0)
        directory += struct.pack('<I', 1) + string(b'shader.bin')
        cipher = encrypted(directory)
        struct.pack_into('<I', fixed, 48, len(cipher))
        reader = IoStore(bytes(fixed) + cipher, lambda probe: KEY)
        with reader.read(0, lambda p, o, n: body[o:o + n], None) as result:
            self.assertEqual(result[:], raw)
        with self.assertRaises(ValueError):
            reader.validate_directory(directory + bytes(16))
        with self.assertRaises(ValueError):
            IoStore(bytes(fixed) + cipher, lambda probe: bytes(32))

    def test_key_recovery_requires_full_hash(self):
        raw = string(b'../../../') + b'index contents'
        probe = KeyProbe(encrypted(raw), len(raw), hashlib.sha1(raw).digest())
        self.assertTrue(probe.accepts(KEY))
        bad = KeyProbe(encrypted(raw), len(raw), bytes(20))
        self.assertFalse(bad.accepts(KEY))
        image = bytearray(8192)
        # ADRP x1,+0x1000; LDR q0,[x1]; LDR q1,[x1,#32]; STP q0,q1,[x0].
        struct.pack_into('<4I', image, 0, 0xb0000001, 0x3dc00020, 0x3dc00821, 0xad000400)
        image[4096:4112], image[4128:4144] = KEY[:16], KEY[16:]
        self.assertEqual(find_key(bytes(image), 16, 4096, len(image), probe), KEY)

    def test_zip_and_vzip_decode_crc_dictionary_and_spill(self):
        raw = b'previous block dictionary\0' * 6000
        source = io.BytesIO()
        with zipfile.ZipFile(source, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('../metadata-only.bin', raw)
        with closing(ZipArchive(source.getvalue())) as archive:
            with archive.read(archive.archive.infolist()[0]) as result:
                self.assertEqual(result[:], raw)
        chunks, previous = [], b''
        for at in range(0, len(raw), 65536):
            value = raw[at:at + 65536]
            packed = lz4.block.compress(value, store_size=False, dict=previous)
            chunks.append(struct.pack('<I', len(packed)) + packed)
            previous = value
        payload = b''.join(chunks)
        name = b'member'
        local = struct.pack('<4s5H3I2H', b'PK\x03\x04', 20, 0, 0, 0, 0,
                            zlib.crc32(raw), len(payload), len(raw), len(name), 0) + name + payload
        central = struct.pack('<4s6H3I5H2I', b'PK\x01\x02', 20, 20, 0, 0, 0, 0,
                              zlib.crc32(raw), len(payload), len(raw), len(name), 0, 0, 0, 0, 0, 0) + name
        end = struct.pack('<4s4H2IH', b'PK\x05\x06', 0, 0, 1, 1, len(central), len(local), 0)
        data = b'VZIP' + local + central + end
        with closing(ZipArchive(data)) as archive, patch('nup_shader_audit.zip_archive.LIMIT', 32):
            info = archive.archive.infolist()[0]
            with archive.read(info) as result:
                self.assertEqual(result[:], raw)
            info.CRC ^= 1
            with self.assertRaisesRegex(ValueError, 'CRC'):
                with archive.read(info):
                    pass

    def test_shader_group_ranges_and_compression(self):
        raw = unreal_shader()
        gid, header = shader_library(raw)
        groups = library(header)
        self.assertEqual(list(group_programs(raw, groups[gid], None))[0][2], raw)
        # Newer engine versions store 8-byte hashes; the same arrays otherwise.
        short_gid, short = shader_library(raw, 8)
        self.assertEqual(list(group_programs(raw, library(short)[short_gid], None))[0][2], raw)
        with self.assertRaises(ValueError):
            library(shader_library(raw, 12)[1])
        packed = zlib.compress(raw)
        descriptor = (len(raw), len(packed), groups[gid][2])
        self.assertEqual(list(group_programs(packed, descriptor, None))[0][2], raw)
        with self.assertRaises(ValueError):
            library(header[:-1])
        with self.assertRaises(ValueError):
            list(group_programs(packed[:-1], descriptor, None))

    def test_serialized_shader_archive_decodes_every_declared_shader(self):
        raw = b'LSLG' + unreal_shader()
        packed = lz4.block.compress(raw, store_size=False)
        other = b'LSLG' + bytes(64)  # A second, stored shader with no native control record.

        def archive(entries, maps=((0, 2, 0, 0),), indices=(0, 1), trailer=b''):
            code, shaders = b'', []
            for body, size, frequency in entries:
                shaders.append(struct.pack('<QIIB', len(code), len(body), size, frequency))
                code += body
            data = struct.pack('<I', 2) + struct.pack('<I', len(maps)) + bytes(20 * len(maps))
            data += struct.pack('<I', len(entries)) + bytes(20 * len(entries))
            data += struct.pack('<I', len(maps)) + b''.join(struct.pack('<4I', *m) for m in maps)
            data += struct.pack('<I', len(shaders)) + b''.join(shaders)
            data += struct.pack('<I', 1) + bytes(16)  # One preload range.
            data += struct.pack('<I', len(indices)) + b''.join(struct.pack('<I', i) for i in indices)
            return data + code + trailer

        entries = [(packed, len(raw), 1), (other, len(other), 2)]
        data = archive(entries)
        shaders, code = shader_archive(data)
        self.assertEqual([s[:4] for s in shaders][0], (0, len(packed), len(raw), 1))
        self.assertEqual(archive_program(data, shaders[0], code, None), raw)
        self.assertEqual(archive_program(data, shaders[1], code, None), other)
        with tempfile.TemporaryDirectory() as directory:
            with closing(Scanner(Path(directory))) as scanner:
                scanner.scan(data, 'ShaderArchive-Test-SF_GLSL_SAGE.ushaderbytecode', unreal=True)
                self.assertEqual(scanner.stats['unreal_shader_archives'], 1)
                self.assertEqual(len(scanner.written_native), 1)  # The stored one holds no shader record.
                self.assertEqual([i['kind'] for i in scanner.issues], ['unsupported_shader_record'])
        # An IoStore chunk carries no name: the layout alone identifies the archive.
        with tempfile.TemporaryDirectory() as directory:
            with closing(Scanner(Path(directory))) as scanner:
                scanner.scan(data, 'Game-Switch2.ucas#io-abcdef0000000009', unreal=True)
                self.assertEqual(scanner.stats['unreal_shader_archives'], 1)
                self.assertEqual(len(scanner.written_native), 1)
            with closing(Scanner(Path(directory) / 'plain')) as scanner:
                scanner.scan(data, 'not-unreal.bin')
                self.assertEqual(scanner.stats['unreal_shader_archives'], 0)
        for noise in (struct.pack('<I', 2) + bytes([255]) * 100, struct.pack('<I', 2) + bytes(100)):
            self.assertFalse(shader_archive_like(noise))
        # A corrupt compressed shader is one issue; the archive's other shader still scans.
        bad = archive([(b'bad', len(raw), 1), (packed, len(raw), 1)])
        with tempfile.TemporaryDirectory() as directory:
            with closing(Scanner(Path(directory))) as scanner:
                scanner.scan(bad, 'bad.ushaderbytecode', unreal=True)
                self.assertEqual(len(scanner.written_native), 1)
                self.assertEqual([i['kind'] for i in scanner.issues], ['unreal_shader'])
        for broken in (data[:-1], b'' + data[1:], archive(entries, indices=(0, 5)),
                       archive(entries, indices=(0, 0)), archive(entries, maps=((0, 3, 0, 0),)),
                       archive([(packed, len(packed) - 1, 1), (other, len(other), 2)])):
            with self.assertRaises(ValueError):
                shader_archive(broken)

    def test_headed_oodle_streams_count_only_when_they_decode_to_records(self):
        record = unreal_shader()
        packed = len(record) // 2
        stream = bytes([0x8c, 0x0a]) + bytes(range(packed - 2))
        good = struct.pack('<4I', len(record), 3, packed, 0) + stream
        # Same magic, but the header is wrong (nonzero last word), and a valid header whose
        # stream decodes to something that is not a shader record.
        wrong = struct.pack('<4I', len(record), 3, packed, 7) + stream
        junk = struct.pack('<4I', 2000, 0, 900, 0) + bytes([0x8c, 0x0a]) + bytes(898)
        data = bytes(64) + good + bytes(32) + wrong + bytes(32) + junk + bytes(16)
        calls = []

        def decode(kind, raw, size):
            calls.append((kind, size))
            if size == len(record):
                return record
            return bytes(size)

        with tempfile.TemporaryDirectory() as directory:
            with closing(Scanner(Path(directory))) as scanner:
                with patch.object(Scanner, 'decode_native', side_effect=decode):
                    scanner.scan(data, 'Game.ucas#io-aa', unreal=True)
                self.assertEqual(scanner.stats['unreal_streams'], 1)
                self.assertEqual(scanner.stats['unreal_stream_nonrecords'], 1)
                self.assertEqual(len(scanner.written_native), 1)
                self.assertEqual(scanner.issues, [])
                self.assertEqual(set(calls), {('oodle', 2000), ('oodle', len(record))})

    def test_headed_zlib_streams_in_a_global_cache_decode_to_records(self):
        record = unreal_shader()
        packed = zlib.compress(record, 9)
        self.assertLess(len(packed), len(record))
        # UE 4.26 layout: 20-byte shader hash, then (0, frequency, raw size, 0, packed size).
        good = bytes(20) + struct.pack('<5I', 0, 5, len(record), 0, len(packed)) + packed
        bad_header = bytes(20) + struct.pack('<5I', 1, 5, len(record), 0, len(packed)) + packed
        # A valid header over a stream that inflates fine but is not a shader record.
        other = zlib.compress(bytes(len(record)), 9)
        notshader = bytes(20) + struct.pack('<5I', 0, 5, len(record), 0, len(other)) + other
        data = b'BMSG' + bytes(40) + good + bytes(24) + bad_header + bytes(24) + notshader + bytes(16)
        with tempfile.TemporaryDirectory() as directory:
            with closing(Scanner(Path(directory))) as scanner:
                scanner.scan(data, 'GlobalShaderCache-SF_GLSL_SWITCH2.bin', unreal=True)
                self.assertEqual(scanner.stats['unreal_streams'], 1)
                self.assertEqual(len(scanner.written_native), 1)
                self.assertEqual(scanner.issues, [])

    def test_fna_effects_are_counted_not_reported_as_gaps(self):
        effect = bytes.fromhex('0109fffe') + bytes(60)
        with tempfile.TemporaryDirectory() as directory:
            with closing(Scanner(Path(directory))) as scanner:
                scanner.scan(effect, 'Content/Shaders/Outline.fxb')
                scanner.scan(effect, 'Content/Shaders/NotAnEffect.bin')
                self.assertEqual(scanner.stats['fna_effects'], 1)
                self.assertEqual((scanner.issues, scanner.unclaimed, len(scanner.written_native)), ([], [], 0))

    def test_snowdrop_page_streams_longer_than_declared_decode_to_the_declared_length(self):
        expected = bytes(range(200)) * 8

        def decode(kind, raw, size):
            # A stream whose real output is 40 bytes longer than the table declares.
            if size < len(expected) + 40:
                raise ValueError('oodle decompression failed')
            return expected + bytes(size - len(expected))

        value = decode_page(decode, b'x' * 700, len(expected))
        self.assertEqual(value, expected)
        with self.assertRaises(ValueError):
            decode_page(lambda *a: (_ for _ in ()).throw(ValueError('bad')), b'x', 10)
        with Snowdrop.read(b'x' * 700, 0, len(expected), [700], decode) as asset:
            self.assertEqual(asset[:], expected)

    def test_snowdrop_independent_width_and_multipage(self):
        raw = shader()
        packed = zlib.compress(raw)
        name = b'shader.cache'
        # A one-extent leaf: raw size width 2, compressed size width 1, offset width 1.
        tree = bytes([len(name)]) + name + b'B' + bytes(4) + b'\0'
        tree += b'\x25' + struct.pack('<H', len(raw)) + bytes([2, 1, len(packed), 8]) + struct.pack('<H', 10)
        stored = zlib.compress(tree)
        header = bytearray(98)
        struct.pack_into('<4sIII', header, 0, b'WEST', 43, len(tree), len(stored))
        footer = b'massive\0' + bytes(32) + b'ubisoft\0'
        with closing(Snowdrop(bytes(header) + stored + footer)) as archive:
            row, = list(archive.partition(10))
            self.assertEqual(row[:3], ('shader.cache', 8, len(raw)))
            with archive.read(bytes(8) + packed, row[1], row[2], row[3],
                              lambda kind, value, size: zlib.decompress(value)) as value:
                self.assertEqual(value[:], raw)
        with closing(Snowdrop(bytes(header) + stored + footer)) as archive:
            archive.tree = b'\x60' + bytes(4) + b'A'  # Branch back to itself.
            with self.assertRaisesRegex(ValueError, 'cyclic'):
                list(archive.entries())
        large = b'synthetic pages' * 9000
        parts = [zlib.compress(large[i:i + 65536]) for i in range(0, len(large), 65536)]
        with patch('nup_shader_audit.snowdrop.LIMIT', 32):
            with Snowdrop.read(b''.join(parts), 0, len(large), list(map(len, parts)),
                               lambda kind, value, size: zlib.decompress(value)) as value:
                self.assertEqual(value[:], large)

    def test_lz4_inline_table_and_failed_later_program_remain_explicit(self):
        raw = b'LSLG' + unreal_shader()
        packed = lz4.block.compress(raw, store_size=False)
        row = struct.pack('<I', len(packed)) + packed + struct.pack('<IB', len(raw), 0)
        table = struct.pack('<I', 2) + bytes(40) + struct.pack('<I', 2) + row
        table += struct.pack('<I', 3) + b'bad' + struct.pack('<IB', len(raw), 0)
        with tempfile.TemporaryDirectory() as directory:
            with closing(Scanner(Path(directory))) as scanner:
                scanner.scan(table, 'inline', unreal=True)
                self.assertEqual(len(scanner.written_native), 1)
                self.assertEqual(scanner.unclaimed, [])
                self.assertEqual(scanner.issues[0]['kind'], 'unreal_shader')

    def test_snowdrop_cache_wrapper_and_zlib_spill_checks(self):
        raw = shader()
        # An inner cache has decoded-size zero; its next word is reflection metadata.
        inner = bytes.fromhex('ef02bcda') + bytes(12) + struct.pack('<I', 4) + raw
        packed = zlib.compress(inner)
        wrapper = bytes.fromhex('ef02bcda') + bytes(8) + struct.pack('<II', len(inner), len(packed))
        with tempfile.TemporaryDirectory() as directory:
            with closing(Scanner(Path(directory))) as scanner:
                scanner.scan(wrapper + packed, 'cache')
                self.assertEqual(len(scanner.written_native), 1)
                self.assertEqual(scanner.issues, [])
        with patch('nup_shader_audit.large.LIMIT', 32):
            with decoded_zlib(packed, len(inner)) as value:
                self.assertEqual(value[:], inner)
        for value in (packed[:-1], packed + b'trailing'):
            with self.assertRaises(ValueError):
                with decoded_zlib(value, len(inner)):
                    pass

    def test_viper_wrapper_and_embedded_ndsr_keep_original_bytes(self):
        raw = shader()
        control, code = raw[:0xd8], raw[0xd8:]
        wrapper = bytes.fromhex('91688619') + struct.pack('<IIIQ', len(code), len(control), 0, 0)
        with tempfile.TemporaryDirectory() as directory:
            with closing(Scanner(Path(directory))) as scanner:
                scanner.scan(wrapper + code + control, 'viper')
                self.assertEqual(len(scanner.written_native), 1)
                self.assertEqual(scanner.unclaimed, [])
                ndsr = bytearray(48)
                ndsr[:6] = b'NDSR\0\x01'
                struct.pack_into('<4I', ndsr, 16, 48, len(control) << 4, 48 + len(control), len(code))
                scanner.scan(b'VIPR' + bytes(13) + bytes(ndsr) + control + code, 'resource')
                self.assertEqual(scanner.unclaimed, [])
                self.assertEqual(scanner.stats['NDSR_references'], 1)
