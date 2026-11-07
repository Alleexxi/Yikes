"""Scan NUP members and nested archives, preserving shader bytes and provenance."""

import hashlib
import json
import sqlite3
import struct
import time
import mmap
import tempfile
import re
import zlib
from bisect import bisect_right
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager, nullcontext
from pathlib import Path

import lz4.block
import lz4.frame
import zstandard

from .binary import LIMIT, check_range, decompress, ray_module, span, unpack, walk
from .container.read import NupReader
from .markers import MarkerFinder
from .large import Window, decoded_lz4, decoded_yaz0, decoded_zstd, decoded_zlib, digest, window
from .codecs import NativeDecoder
from .trinity import entries as trinity_entries
from .bea import members as bea_members
from .iostore import MAGIC as IOSTORE, IoStore, decode_block
from .unreal import OODLE, ZLIB, adjacent as unreal_adjacent, record as unreal_record, shader_tables
from .unreal_pak import MAGIC as PAK_MAGIC, Pak
from .zip_archive import ZipArchive
from .unreal_crypto import find_key
from .snowdrop import Snowdrop
from .unreal_library import library as shader_library, group_programs
from .unreal_archive import looks_like as shader_archive_like, parse as shader_archive, program as archive_program
from .unity import (bundle_members as unity_bundle, is_serialized as is_unity_asset,
                    objects as unity_objects, graphics_programs, compute_programs,
                    program_ranges as unity_program_ranges, text_asset, read_shader)
from .storage import atomic_json, source_identity

CONTROL = bytes.fromhex("34127698")
ZSTD = bytes.fromhex("28b52ffd")
LZ4 = bytes.fromhex("04224d18")
NATIVE = CONTROL + bytes.fromhex("c9000000")
SHORT = ("vs", "hs", "ds", "gs", "ps", "cs", "ts", "ms", "rt")
SCANNER_REVISION = 10


def plausible_control_header(header):
    """Require a control structure, rather than a coincidental magic word in asset data."""
    if header[:8] == NATIVE:
        return True
    if len(header) < 0x24 or header[:4] != CONTROL:
        return False
    own, = unpack(header, '<I', 0x20)
    return 0x760 <= own < 0x10000


def sarc(data):
    endian = "<" if span(data, 6, 2) == b"\xff\xfe" else ">"
    header, = unpack(data, endian + "H", 4)
    file_size, start = unpack(data, endian + "II", 8)
    if file_size != len(data) or span(data, header, 4) != b"SFAT":
        raise ValueError("SARC header/size mismatch")
    table_size, count = unpack(data, endian + "HH", header + 4)
    nodes = header + table_size
    names = nodes + count * 16
    if span(data, names, 4) != b"SFNT" or names + 8 > start:
        raise ValueError("SARC name table mismatch")
    total = 0
    for i in range(count):
        _, attribute, lo, hi = unpack(data, endian + "IIII", nodes + 16 * i)
        if lo > hi or start + lo < start:
            raise ValueError("SARC member range")
        member = window(data, start + lo, hi - lo)
        total += len(member)
        if total > len(data) * 16:
            raise ValueError("overlapping SARC member budget")
        name = f"#{i}"
        if attribute >> 24:
            offset = names + 8 + (attribute & 0xffffff) * 4
            end = data.find(b"\0", offset, start)
            if end < 0:
                raise ValueError("unterminated SARC name")
            name = data[offset:end].decode("utf-8", "replace")
        yield name, member


def yaz0(data):
    size, = unpack(data, ">I", 4)
    if size > LIMIT:
        raise ValueError("Yaz0 output exceeds limit")
    output = bytearray()
    pos = 16
    mask = flags = 0
    while len(output) < size:
        if not mask:
            flags = span(data, pos, 1)[0]
            pos += 1
            mask = 128
        if flags & mask:
            output.append(span(data, pos, 1)[0])
            pos += 1
        else:
            a, b = span(data, pos, 2)
            pos += 2
            length = a >> 4
            distance = ((a & 15) << 8 | b) + 1
            if not length:
                length = span(data, pos, 1)[0] + 18
                pos += 1
            else:
                length += 2
            if distance > len(output) or len(output) + length > size:
                raise ValueError("invalid Yaz0 backreference")
            for _ in range(length):
                output.append(output[-distance])
        mask >>= 1
    return bytes(output)


@contextmanager
def nso_image(data, decode_native):
    flags, = unpack(data, "<I", 12)
    segments = []
    for i in range(3):
        offset, address, size, _ = unpack(data, "<4I", 0x10 + 16 * i)
        compressed_size, = unpack(data, "<I", 0x60 + 4 * i)
        segments.append((offset, address, size, compressed_size, bool(flags & (1 << i))))
    total = max(address + size for _, address, size, _, _ in segments)
    with tempfile.SpooledTemporaryFile(max_size=LIMIT) as image:
        image.truncate(total)
        for offset, address, size, compressed_size, compressed in segments:
            raw = span(data, offset, compressed_size if compressed else size)
            if compressed:
                decoded = (decode_native('zbic', raw, size) if raw[:4] == b'ZBIC'
                           else lz4.block.decompress(raw, uncompressed_size=size))
            else:
                decoded = raw
            if len(decoded) != size:
                raise ValueError("NSO segment length mismatch")
            image.seek(address)
            image.write(decoded)
        if total <= LIMIT:
            image.seek(0)
            yield image.read()
        else:
            image.flush()
            with mmap.mmap(image.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                yield Window(mapped)


class Scanner:
    def __init__(self, output, resume=False, checkpoint_every=5000, progress=None, workers=4,
                 export_native=False):
        if checkpoint_every < 1:
            raise ValueError('checkpoint interval must be positive')
        self.checkpoint_every = checkpoint_every
        if workers < 1:
            raise ValueError('worker count must be positive')
        self.workers = workers
        self.marker_finder = MarkerFinder()
        self.progress = progress
        self.output = output
        output.mkdir(parents=True, exist_ok=True)
        self.native_dir = output / "native"
        self.db = sqlite3.connect(output / "shaders.sqlite")
        self.db.executescript("""
          PRAGMA journal_mode=WAL;
          CREATE TABLE IF NOT EXISTS blobs(hash TEXT PRIMARY KEY, size INTEGER, magic TEXT);
          CREATE TABLE IF NOT EXISTS paths(path TEXT PRIMARY KEY, hash TEXT);
          CREATE TABLE IF NOT EXISTS shaders(key TEXT PRIMARY KEY, arch TEXT, stage TEXT,
            control BLOB, code BLOB, instruction_hash TEXT, instruction_bytes INTEGER);
          CREATE TABLE IF NOT EXISTS origins(shader TEXT, blob TEXT, format TEXT,
            control_offset INTEGER, code_offset INTEGER, variant TEXT,
            UNIQUE(shader,blob,format,control_offset,code_offset,variant));
          CREATE TABLE IF NOT EXISTS roots(file_index INTEGER PRIMARY KEY, path TEXT, size INTEGER,
            expected_hash TEXT, actual_hash TEXT, status TEXT);
          CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY, value TEXT);
          CREATE INDEX IF NOT EXISTS paths_by_hash ON paths(hash);
          CREATE INDEX IF NOT EXISTS shader_instructions ON shaders(instruction_hash,stage);
        """)
        storage = self.db.execute("SELECT value FROM state WHERE key='native_storage'").fetchone()
        if storage is not None and storage[0] not in ('files', 'sqlite'):
            self.db.close()
            raise ValueError('Unsupported native shader storage mode')
        self.export_native = (storage is None or storage[0] == 'files') if resume else export_native
        if resume and export_native and not self.export_native:
            self.db.close()
            raise ValueError('Cannot add --export-native on resume; choose a fresh output directory')
        if self.export_native:
            self.native_dir.mkdir(exist_ok=True)
        if not resume:
            self.db.execute("INSERT INTO state VALUES ('native_storage',?)",
                            ('files' if export_native else 'sqlite',))
        self.seen = set()
        self.keys = set()
        self.written_native = set()
        self.issues = []
        self.unclaimed = []
        self.stats = Counter()
        self.magics = Counter()
        self.extensions = Counter()
        self.dictionaries = {}
        self.key_provider = None
        self.snowdrop_archives = {}
        self.started = time.monotonic()
        self.elapsed_before_resume = 0
        self.existing_roots = {}
        self.recovered = []
        self.identity = None
        self.native_decoder = None
        self.unreal_decoded = {}
        self.iostore_seen = set()
        self.unity_schemas = {}
        if resume:
            saved = self.db.execute("SELECT value FROM state WHERE key='checkpoint'").fetchone()
            if saved is None:
                raise ValueError("No compatible checkpoint; choose a fresh output directory")
            previous = json.loads(saved[0])
            self.stats.update(previous["stats"])
            self.magics.update(previous.get('all_magics', dict(previous["top_decoded_magics"])))
            self.extensions.update(previous.get('all_extensions', dict(previous["top_extensions"])))
            self.issues = previous["issues"]
            self.unclaimed = previous["unclaimed"]
            # Saved candidate headers contain the fields needed to reject old magic-only
            # false positives; shader bytes and their provenance remain unchanged.
            self.unclaimed = [row for row in self.unclaimed
                              if plausible_control_header(bytes.fromhex(row['header_hex']))]
            self.recovered = previous["recovered"]
            self.unity_schemas = previous.get('unity_schemas', {})
            self.identity = previous["identity"]
            self.elapsed_before_resume = previous["elapsed_seconds"]
            self.seen = {row[0] for row in self.db.execute("SELECT hash FROM blobs")}
            self.keys = {row[0] for row in self.db.execute("SELECT key FROM shaders")}
            self.written_native = {sha + '.' + stage for stage, sha in self.db.execute("SELECT DISTINCT stage,instruction_hash FROM shaders WHERE arch='sm86'")}
            self.existing_roots = dict(self.db.execute("SELECT file_index,status FROM roots"))
            if previous.get('scanner_revision') != SCANNER_REVISION:
                roots = {path: index for index, path in self.db.execute('SELECT file_index,path FROM roots')}
                revisit = {row['path'] for row in self.unclaimed}
                # Earlier heuristic BAHS scans can have stored false records even when
                # their controls were subsequently claimed. Reparse those blobs too.
                revisit.update(row[0] for row in self.db.execute(
                    "SELECT DISTINCT p.path FROM origins o JOIN paths p ON p.hash=o.blob WHERE o.format='BAHS'"))
                revisit.update(path for path in roots if path.endswith(
                    ('.ucas', '.utoc', '.pak', '.bundle', '.unity3d', '.ushaderbytecode', '.zip', '.sdfdata', '.sdftoc')))
                unity_roots = {path.rsplit('/', 1)[0] + '/' for path in roots
                               if path.endswith(('/globalgamemanagers', '/globalgamemanagers.assets'))}
                revisit.update(path for path in roots if any(path.startswith(prefix) for prefix in unity_roots))
                for path in revisit:
                    prefix = path
                    while prefix:
                        if prefix in roots:
                            index = roots[prefix]
                            self.existing_roots[index] = 'retry'
                            self.db.execute("UPDATE roots SET status='retry' WHERE file_index=?", (index,))
                            break
                        end = max(prefix.rfind('/'), prefix.rfind('#'))
                        prefix = prefix[:end] if end >= 0 else ''

    def decode_native(self, kind, raw, size):
        """Start native archive codecs only when a member actually requires them."""
        if self.native_decoder is None:
            self.native_decoder = NativeDecoder()
        return self.native_decoder.decode(kind, raw, size)

    def issue(self, label, kind, reason):
        self.issues.append({"path": label, "kind": kind, "reason": str(reason)})

    def stage(self, control, code):
        if control.startswith(NATIVE):
            kind = control[0x56] if len(control) > 0x56 else -1
            if kind in (5, 6, 7, 8):
                return SHORT[kind]
            word, = unpack(code, "<I", 0)
        else:
            if code[:4] == bytes.fromhex("79563412"):
                return "cs"
            if code[:4] != bytes.fromhex("78563412"):
                return "cs" if len(control) >= 0x754 and all(unpack(control, "<3I", 0x748)) else None
            word, = unpack(code, "<I", 0x30)
        return {0: "vs", 1: "vs", 2: "hs", 3: "ds", 4: "gs", 5: "ps"}.get((word >> 10) & 15)

    def add(self, data, blob, label, fmt, stage, control_offset, control_size, code_offset, code_size, variant=""):
        control = span(data, control_offset, control_size)
        code = span(data, code_offset, code_size)
        if not control.startswith(CONTROL):
            raise ValueError("missing shader control magic")
        native = control.startswith(NATIVE)
        length_offset = 0x44 if native else 0x704
        declared, = unpack(control, "<I", length_offset)
        if declared != len(code) or not declared:
            raise ValueError("shader control/code length mismatch")
        actual_stage = self.stage(control, code)
        if stage is None:
            stage = actual_stage
        if stage not in SHORT or (actual_stage is not None and stage != actual_stage):
            raise ValueError(f"shader stage mismatch: table {stage}, header {actual_stage}")
        arch = "sm86" if native else "maxwell"
        key = hashlib.sha256(arch.encode() + stage.encode() + control + code).hexdigest()
        instruction_hash = None
        instruction_size = 0
        if native:
            if stage == 'rt':
                instructions = ray_module(control, code)
            else:
                size, = unpack(control, "<I", 0x38)
                begin = 0 if stage == "cs" else 0x80
                if not begin < size <= len(code) or (size - begin) % 16:
                    raise ValueError(f"invalid native instruction range {begin:#x}..{size:#x} of {len(code):#x}")
                instructions = code[begin:size]
            instruction_hash = hashlib.sha256(instructions).hexdigest()
            instruction_size = len(instructions)
            native_key = instruction_hash + "." + stage
            if native_key not in self.written_native:
                if self.export_native:
                    (self.native_dir / (native_key + ".bin")).write_bytes(instructions)
                self.written_native.add(native_key)
        if key not in self.keys:
            self.db.execute("INSERT OR IGNORE INTO shaders VALUES (?,?,?,?,?,?,?)",
                            (key, arch, stage, control, code, instruction_hash, instruction_size))
            self.keys.add(key)
            self.stats[arch + "_unique_records"] += 1
            self.stats[arch + "_" + stage] += 1
        self.db.execute("INSERT OR IGNORE INTO origins VALUES (?,?,?,?,?,?)",
                        (key, blob, fmt, control_offset, code_offset, str(variant)))
        self.stats[fmt + "_references"] += 1
        return control_offset

    def bnsh(self, data, blob, label, base, claimed):
        if span(data, base + 0x60, 4) != b"grsc":
            return False
        size, = unpack(data, "<I", base + 0x1c)
        check_range(data, base, size)
        count, table = unpack(data, "<IQ", base + 0x7c)
        check_range(data, base + table, count * 0x40)
        for i in range(count):
            program, = unpack(data, "<Q", base + table + i * 0x40 + 0x10)
            if not program:
                continue
            for si, stage in enumerate(SHORT):
                slot = (8, 16, 24, 32, 40, 48, 64, 72, 56)[si]
                if base + program + slot + 8 > len(data):
                    continue
                descriptor, = unpack(data, "<Q", base + program + slot)
                if not descriptor:
                    continue
                if si >= 6:
                    if base + descriptor + 32 > len(data):
                        continue
                    c, k, nk, nc = unpack(data, "<QQII", base + descriptor + 8)
                    if not (0x58 <= nc < 0x10000 and base + c + nc <= len(data)):
                        continue
                    control = data[base + c:base + c + nc]
                    if not control.startswith(NATIVE) or control[0x56] != si:
                        continue
                else:
                    c, k, nk, nc = unpack(data, "<QQII", base + descriptor + 8)
                claimed.add(self.add(data, blob, label, "BNSH", stage, base + c, nc, base + k, nk, i))
        self.stats["BNSH_containers"] += 1
        return True

    def bahs(self, data, blob, label, claimed):
        region_size, region = unpack(data, "<II", 0x18)
        check_range(data, region, region_size)
        candidates = []
        for a in range(0, region - 15, 4):
            off, zero, size, rel = unpack(data, "<IIIi", a)
            c = a + rel
            if zero or off % 0x100 or not (0x48 <= size < 0x10000 and 0 <= c <= region - size):
                continue
            control = data[c:c + size]
            if not control.startswith(CONTROL):
                continue
            native = control.startswith(NATIVE)
            if not native and not (0x760 <= size <= 0x900):
                continue
            n, = unpack(control, "<I", 0x44 if native else 0x704)
            if not 0 < n <= region_size - off:
                continue
            code = data[region + off:region + off + n]
            stage = self.stage(control, code)
            if stage:
                candidates.append((a, c, size, region + off, n, stage))
        # The supported BAHS binary array has length-prefixed records whose
        # descriptors start at +0x10. Prefer its exact boundaries over heuristics.
        array_entries = None
        if candidates:
            array = min(row[0] for row in candidates) - 0x18
            if 0x20 <= array <= region - 8:
                array_size, count = unpack(data, '<II', array)
                if 8 <= array_size <= region - array and 0 < count <= (array_size - 8) // 0x20:
                    at, entries = array + 8, set()
                    for _ in range(count):
                        if at + 0x20 > array + array_size:
                            break
                        size, = unpack(data, '<I', at)
                        if size < 0x20 or at + size > array + array_size:
                            break
                        entries.add(at + 0x10)
                        at += size
                    else:
                        if at == array + array_size:
                            array_entries = entries
        if array_entries is not None:
            valid = {hex(row[0]) for row in candidates if row[0] in array_entries}
            old = self.db.execute("SELECT DISTINCT variant FROM origins WHERE blob=? AND format='BAHS'", (blob,)).fetchall()
            self.db.executemany("DELETE FROM origins WHERE blob=? AND format='BAHS' AND variant=?",
                                ((blob, variant) for variant, in old if variant not in valid))
            for a, c, nc, k, nk, stage in candidates:
                if a in array_entries:
                    claimed.add(self.add(data, blob, label, 'BAHS', stage, c, nc, k, nk, hex(a)))
                else:
                    self.stats['BAHS_control_field_false_entries'] += 1
            self.stats['BAHS_containers'] += 1
            return
        # Discard descriptors embedded in control headers before trusting their lengths:
        # +0x38..+0x47 can imitate a descriptor with a much larger control range.
        headers = []
        for _, c, nc, _, _, _ in candidates:
            if data[c:c + 8] == NATIVE:
                own, = unpack(data, '<I', c + 0x30)
                length = own if 0x58 <= own <= nc else 0x58
            else:
                own, = unpack(data, '<I', c + 0x20)
                length = own if 0x760 <= own <= nc else min(nc, 0x880)
            headers.append((c, c + length))

        def outside_ranges(entries, ranges):
            starts, ends = [], []
            highest = 0
            for start, end in sorted(ranges):
                starts.append(start)
                highest = max(highest, end)
                ends.append(highest)
            for entry in entries:
                previous = bisect_right(starts, entry[0]) - 1
                if previous >= 0 and entry[0] < ends[previous]:
                    self.stats['BAHS_control_field_false_entries'] += 1
                else:
                    yield entry

        candidates = list(outside_ranges(candidates, headers))
        control_ranges = [(c, c + n) for _, c, n, _, _, _ in candidates]
        for a, c, nc, k, nk, stage in outside_ranges(candidates, control_ranges):
            claimed.add(self.add(data, blob, label, "BAHS", stage, c, nc, k, nk, hex(a)))
        self.stats["BAHS_containers"] += 1

    def ndsr(self, data, blob, label, claimed, base=0):
        def score(start):
            result = 0
            for at in range(start, min(start + 256, len(data) - 15), 16):
                c, _, _, _ = unpack(data, "<4I", base + at)
                result += data[base + c:base + c + 8] == NATIVE
            return result
        offset = max((0x10, 0x14), key=score)
        while base + offset + 16 <= len(data):
            c, nc, k, nk = unpack(data, "<4I", base + offset)
            if not (c or nc or k or nk):
                break
            c, k = base + c, base + k
            if data[c:c + 8] != NATIVE:
                offset += 8
                continue
            control = span(data, c, max(nc >> 4, 0x48))
            length, = unpack(control, "<I", 0x44)
            claimed.add(self.add(data, blob, label, "NDSR", None, c, len(control), k, length, hex(offset)))
            offset += 16
        self.stats["NDSR_containers"] += 1

    def glslc(self, data, blob, label, claimed, offsets):
        for base in offsets:
            try:
                version, = unpack(data, "<I", base + 0x30)
                native = version == 0xc9
                size, = unpack(data, "<I", base + (0x5c if native else 0x44))
                count, = unpack(data, "<I", base + (0x64 if native else 0x4c))
                check_range(data, base, size)
                if not 0 < count <= 16:
                    continue
                first, stride = (0xa8, 0x98) if native else (0x90, 0x90)
                check_range(data, base + first, count * stride)
                for i in range(count):
                    at = base + first + i * stride
                    section_size, section, kind = unpack(data, "<3I", at)
                    if kind:
                        continue
                    co, ko, kn, cn = unpack(data, "<4I", at + 0x30)
                    if section + section_size > size or co + cn > section_size or ko + kn > section_size:
                        raise ValueError("GLSLC section bounds")
                    c, k = base + section + co, base + section + ko
                    claimed.add(self.add(data, blob, label, "GLSLC", None, c, cn, k, kn, hex(base)))
            except (ValueError, struct.error):
                # Executables may contain the four-byte magic as an ordinary literal.
                self.stats["GLSLC_magic_nonrecords"] += 1

    def unreal_shaders(self, data, label, depth):
        """Decode proven inline shader tables and exclude their packed bytes from matching."""
        ranges, end = [], 0
        for rows in shader_tables(data):
            if rows[0][0] < end:
                continue
            valid = False
            for at, packed, size, frequency in rows:
                name = label + f'#ue-shader@{at:x}'
                try:
                    raw = span(data, at, packed)
                    key = (hashlib.sha256(raw).digest(), size)
                    cached = self.unreal_decoded.get(key)
                    if cached is not None:
                        self.db.execute('INSERT OR IGNORE INTO paths VALUES (?,?)', (name, cached))
                        self.stats['duplicate_blobs'] += 1
                    else:
                        if packed == size:
                            decoded = raw
                        elif raw[:1] == b'\x8c':
                            decoded = self.decode_native('oodle', raw, size)
                        else:
                            # LZ4's bound also prevents a corrupt size from causing an
                            # arbitrary allocation before the native record is proved.
                            if size > 255 * packed:
                                raise ValueError('Impossible Unreal LZ4 expansion ratio')
                            decoded = None
                            if (len(raw) >= 2 and raw[0] & 15 == 8 and raw[0] >> 4 <= 7
                                    and int.from_bytes(raw[:2], 'big') % 31 == 0):
                                # A zlib stream (Unreal 4.26's default); an LZ4 token can look
                                # like its header, so a failure falls through to LZ4.
                                try:
                                    decoded = decode_block(raw, size, 'zlib', None)
                                except (ValueError, zlib.error):
                                    decoded = None
                            if decoded is None:
                                decoded = lz4.block.decompress(raw, uncompressed_size=size)
                        c = decoded.find(NATIVE)
                        try:
                            unreal_record(decoded, c)
                        except ValueError:
                            unreal_adjacent(decoded, c)  # Ray-tracing modules: code follows control.
                        self.scan(decoded, name, depth + 1)
                        self.unreal_decoded[key] = digest(decoded)
                    valid = True
                    self.stats['unreal_inline_shaders'] += 1
                    ranges.append((at, at + packed))
                except (ValueError, OSError, RuntimeError, lz4.block.LZ4BlockError) as exc:
                    if not valid and raw[:1] != b'\x8c':
                        self.stats['unreal_table_nonrecords'] += 1
                        break
                    self.issue(name, 'unreal_shader', exc)
            if valid:
                end = rows[-1][0] + rows[-1][1] + 5
        ranges.extend(self.unreal_streams(data, label, depth, ranges))
        return sorted(ranges)

    def unreal_streams(self, data, label, depth, taken):
        """Decode headed compressed streams that hold shader records, outside counted tables.

        Some builds store each shader in a cooked package or global cache as one stream with its
        own small header: Oodle behind (raw size, flags, packed size, 0), zlib behind
        (0, frequency, raw size, 0, packed size). The header only nominates a stream: it counts
        when it decodes to exactly its declared size and the result is a valid length-checked
        record, so ordinary data that happens to contain a codec's magic is ignored.
        """
        ranges, positions = [], set()
        for magic in OODLE + ZLIB:
            at = data.find(magic, 20)
            while at >= 0:
                positions.add(at)
                at = data.find(magic, at + 2)
        for start in sorted(positions):
            if any(low <= start < high for low, high in taken):
                continue
            oodle = data[start] == 0x8c
            if oodle:
                raw_size, flags, packed, zero = unpack(data, '<4I', start - 16)
                header = start - 16
                valid = not zero and flags <= 0xff
            else:
                zero_a, frequency, raw_size, zero_b, packed = unpack(data, '<5I', start - 20)
                header = start - 20
                valid = not zero_a and not zero_b and frequency <= 15
            if (not valid or not 16 <= packed < raw_size <= 0x1000000 or raw_size > 32 * packed
                    or start + packed > len(data)):
                continue
            stream = span(data, start, packed)
            key = (hashlib.sha256(stream).digest(), raw_size)
            name = label + f'#ue-stream@{start:x}'
            try:
                cached = self.unreal_decoded.get(key)
                if cached is not None:
                    self.db.execute('INSERT OR IGNORE INTO paths VALUES (?,?)', (name, cached))
                    self.stats['duplicate_blobs'] += 1
                else:
                    if oodle:
                        decoded = self.decode_native('oodle', stream, raw_size)
                    else:
                        decoded = decode_block(stream, raw_size, 'zlib', None)
                    control = decoded.find(NATIVE)
                    try:
                        unreal_record(decoded, control)
                    except ValueError:
                        unreal_adjacent(decoded, control)
                    self.scan(decoded, name, depth + 1)
                    self.unreal_decoded[key] = digest(decoded)
                self.stats['unreal_streams'] += 1
                ranges.append((header, start + packed))
            except (ValueError, OSError, RuntimeError, struct.error, zlib.error):
                self.stats['unreal_stream_nonrecords'] += 1
        return ranges

    def unreal_program(self, program, name, depth, frequency):
        """Scan one declared Unreal shader; a shader without a native control is a gap, not a skip."""
        before = self.stats['UNREAL_NVN2_references']
        self.scan(program, name, depth + 1, unreal=True)
        # Duplicate program blobs are already covered by their original parse.
        if (self.stats['UNREAL_NVN2_references'] == before
                and not any(program[c:c + 8] == NATIVE for c in self.marker_finder.find(program)[CONTROL])):
            self.issue(name, 'unsupported_shader_record',
                       f'No native control found in declared shader (frequency {frequency})')

    def unity_asset(self, data, label, depth):
        """Extract typed shader objects without matching compressed asset bytes as controls."""
        self.stats['unity_serialized_assets'] += 1
        for obj in unity_objects(data):
            name = label + f'#unity-{obj.class_id}/{obj.path_id}'
            try:
                if obj.class_id == 49:
                    self.scan(text_asset(obj), name + '/script', depth + 1)
                    self.stats['unity_text_assets'] += 1
                    continue
                shader = read_shader(obj, self.unity_schemas)
                programs = graphics_programs(shader) if obj.class_id == 48 else compute_programs(shader)
                self.stats['unity_shader_objects' if obj.class_id == 48 else 'unity_compute_objects'] += 1
                for variant, code, stage in programs:
                    try:
                        self.scan(code, name + '/' + variant, depth + 1,
                                  unity_program=True, stage_hint=stage)
                        self.stats['unity_program_entries'] += 1
                    except (ValueError, RuntimeError, struct.error) as exc:
                        self.issue(name + '/' + variant, 'unity_program', exc)
            except Exception as exc:
                self.issue(name, 'unity_object', exc)

    def leaf(self, data, blob, label, depth=0, unreal=False):
        claimed = set()
        packed_ranges = self.unreal_shaders(data, label, depth) if unreal else []
        packed_index = 0
        markers = self.marker_finder.find(data)
        if data[:4] == b"BAHS":
            self.bahs(data, blob, label, claimed)
        elif data[:4] == b"NDSR":
            self.ndsr(data, blob, label, claimed)
        elif data[:4] == b'VIPR':
            offset = 0
            while (offset := data.find(b'NDSR\0\x01', offset)) >= 0:
                self.ndsr(data, blob, label, claimed, offset)
                offset += 6
        for base in markers[b"BNSH\0\0\0\0"]:
            try:
                if not self.bnsh(data, blob, label, base, claimed):
                    self.stats["BNSH_magic_nonrecords"] += 1
            except (ValueError, struct.error) as exc:
                self.issue(label + f"#BNSH@{base:x}", "shader_parser", exc)
        self.glslc(data, blob, label, claimed, markers[bytes.fromhex("91688619")])
        # Viper stores one code area before its control section, with explicit lengths.
        if data[:4] == bytes.fromhex('91688619') and len(data) >= 24:
            code_size, control_size, reserved = unpack(data, '<3I', 4)
            c = 24 + code_size
            if (not reserved and c + control_size == len(data) and data[c:c + 8] == NATIVE):
                claimed.add(self.add(data, blob, label, 'VIPER_NVN2', None,
                                     c, control_size, 24, code_size))
        # sead primitive drawer: four absolute file offsets in the first sixteen bytes.
        if len(data) >= 16:
            cv, cp, kv, kp = unpack(data, "<4I", 0)
            if data[cv:cv + 4] == CONTROL and data[cp:cp + 4] == CONTROL:
                for c, k, stage in ((cv, kv, "vs"), (cp, kp, "ps")):
                    native = data[c:c + 8] == NATIVE
                    size, = unpack(data, "<I", c + (0x30 if native else 0x20))
                    length, = unpack(data, "<I", c + (0x44 if native else 0x704))
                    claimed.add(self.add(data, blob, label, "SEAD", stage, c,
                                         max(size, 0x48 if native else 0x708), k, length))
        # Some runtime libraries store a complete NVN2 control followed by its code directly.
        # Recover such records only when all declared bounds, stage and instruction ranges agree.
        for c in markers[CONTROL]:
            if c in claimed:
                continue
            while packed_index < len(packed_ranges) and packed_ranges[packed_index][1] <= c:
                packed_index += 1
            if packed_index < len(packed_ranges) and packed_ranges[packed_index][0] <= c:
                continue
            if not plausible_control_header(data[c:c + 0x58]):
                self.stats['control_magic_nonrecords'] += 1
                continue
            native = data[c:c + 8] == NATIVE
            if native:
                try:
                    nc, k, nk = unreal_record(data, c)
                    claimed.add(self.add(data, blob, label, 'UNREAL_NVN2', None, c, nc, k, nk, hex(c)))
                    continue
                except (ValueError, struct.error):
                    pass
                try:
                    own, = unpack(data, "<I", c + 0x30)
                    length, = unpack(data, "<I", c + 0x44)
                    if 0x58 <= own <= 0x1000000:
                        claimed.add(self.add(data, blob, label, "ADJACENT_NVN2", None,
                                             c, own, c + own, length, hex(c)))
                        continue
                except (ValueError, struct.error):
                    pass
            try:
                size, = unpack(data, "<I", c + (0x44 if native else 0x704))
                plausible = 0 < size <= LIMIT and size % (16 if native else 8) == 0
            except ValueError:
                plausible = False
            if native or plausible:
                self.unclaimed.append({"path": label, "blob": blob, "offset": c,
                                       "native": native, "plausible_code_size": plausible,
                                       "header_hex": data[c:c + 0x58].hex()})
        # Also look inside embedded compressed frames, e.g. a size/hash prefix before zstd.
        for magic in (ZSTD, LZ4):
            for pos in markers[magic]:
                if pos == 0:
                    continue
                with ExitStack() as stack:
                    try:
                        if magic == ZSTD:
                            frame = Window(data, pos)
                            params = zstandard.get_frame_parameters(frame[:18])
                            dictionary = self.dictionaries.get(params.dict_id)
                            if params.dict_id and dictionary is None:
                                raise ValueError("missing embedded zstd dictionary")
                            value = stack.enter_context(decoded_zstd(frame, dictionary))
                        else:
                            value = stack.enter_context(decoded_lz4(Window(data, pos)))
                    except (ValueError, RuntimeError, zstandard.ZstdError):
                        self.stats["embedded_frame_nonrecords"] += 1
                        continue
                    self.scan(value, label + f"#frame@{pos:x}", depth + 1)
                    self.stats["embedded_frames_decoded"] += 1

    def scan(self, data, label, depth=0, *, verified_hash=None, iostore=None, unreal=False,
             unity_program=False, stage_hint=None, sdf=None):
        if depth > 16:
            raise ValueError("nesting limit")
        blob = verified_hash if verified_hash is not None else digest(data)
        self.db.execute("INSERT OR IGNORE INTO paths VALUES (?,?)", (label, blob))
        # The same UCAS payload can have a different TOC in another package.
        # Its logical chunk ranges must be interpreted using that package's metadata.
        context = ((blob, digest(iostore[0].data), iostore[1]) if iostore is not None else
                   (blob, sdf[2], sdf[1]) if sdf is not None else None)
        duplicate = context in self.iostore_seen if context is not None else blob in self.seen
        if duplicate:
            self.stats["duplicate_blobs"] += 1
            return
        if context is not None:
            self.iostore_seen.add(context)
        self.seen.add(blob)
        self.db.execute("INSERT OR IGNORE INTO blobs VALUES (?,?,?)", (blob, len(data), data[:8].hex()))
        self.stats["unique_decoded_blobs"] += 1
        self.magics[data[:4].hex()] += 1
        if unity_program:
            for stage, c, nc, k, nk in unity_program_ranges(data, stage_hint):
                self.add(data, blob, label, 'UNITY', stage, c, nc, k, nk)
        elif sdf is not None:
            archive, part, _ = sdf
            for ordinal, (asset, offset, size, pages, extent) in enumerate(archive.partition(part), 1):
                name = label + '/' + asset + f'#extent-{extent}'
                try:
                    with archive.read(data, offset, size, pages, self.decode_native) as value:
                        self.scan(value, name, depth + 1)
                    self.stats['snowdrop_extents'] += 1
                except Exception as exc:
                    self.issue(name, 'snowdrop_asset', exc)
                if ordinal % 10000 == 0:
                    print(f'SDF: {ordinal} assets; {len(self.written_native)} native programs; '
                          f'{len(self.issues)} issues', flush=True)
        elif data[:4] == b'WEST' and label.endswith('.sdftoc'):
            if blob not in self.snowdrop_archives:
                self.snowdrop_archives[blob] = Snowdrop(data)
                self.snowdrop_archives[blob].index()
        elif label.endswith('.sdfdata'):
            raise ValueError('SDFDATA requires its matching SDFTOC file index')
        elif iostore is not None:
            toc, partition, read_partition = iostore
            self.stats['iostore_partitions'] += 1
            shader_groups = {}
            valid_libraries = set()
            # Libraries may follow their groups in the TOC and may live in another
            # physical partition. Resolve their descriptors before walking this slice.
            if toc.version >= 4:
                for index in range(toc.count):
                    chunk_id = span(toc.data, toc.header + index * 12, 12)
                    if chunk_id[-1] != 8:
                        continue
                    name = label + '#io-' + chunk_id.hex()
                    try:
                        with toc.read(index, read_partition, self.decode_native) as value:
                            groups = shader_library(value)
                        for key, descriptor in groups.items():
                            if key in shader_groups and shader_groups[key] != descriptor:
                                raise ValueError('Conflicting IoStore shader-library group descriptors')
                            shader_groups[key] = descriptor
                        self.stats['iostore_shader_libraries'] += 1
                        valid_libraries.add(index)
                    except Exception as exc:
                        self.issue(name, 'unsupported_shader_library', exc)
            for ordinal, (index, chunk_id, size) in enumerate(toc.entries(partition), 1):
                name = label + '#io-' + chunk_id.hex()
                try:
                    with toc.read(index, read_partition, self.decode_native) as value:
                        if toc.version >= 4 and chunk_id[-1] == 8:
                            if index not in valid_libraries:
                                self.scan(value, name, depth + 1, unreal=True)
                            continue  # Validated in the metadata pass above.
                        if toc.version >= 4 and chunk_id[-1] == 9:
                            if chunk_id not in shader_groups:
                                self.scan(value, name, depth + 1, unreal=True)
                                raise ValueError('IoStore shader group has no validated library descriptor')
                            for shader_index, frequency, program in group_programs(
                                    value, shader_groups[chunk_id], self.decode_native):
                                self.unreal_program(program, name + f'#shader-{shader_index}',
                                                    depth, frequency)
                            self.stats['iostore_shader_groups'] += 1
                        else:
                            self.scan(value, name, depth + 1, unreal=True)
                    self.stats['iostore_chunks'] += 1
                except (ValueError, OSError, RuntimeError, zlib.error, zstandard.ZstdError) as exc:
                    self.issue(name, 'iostore_chunk', exc)
                if ordinal % 5000 == 0:
                    print(f'IoStore: {ordinal}/{toc.count} chunks; {len(self.written_native)} native programs; '
                          f'{len(self.issues)} issues', flush=True)
        elif data[:16] == IOSTORE:
            IoStore(data, self.key_provider)  # Raw TOC bytes are not shader records.
        elif data[:4] in (b'VZIP', b'PK\x03\x04', b'PK\x05\x06'):
            archive = ZipArchive(data)
            try:
                self.stats['zip_archives'] += 1
                for ordinal, info in enumerate(archive.archive.infolist(), 1):
                    if info.is_dir():
                        continue
                    name = label + f'#zip-{ordinal}/' + info.filename
                    try:
                        with archive.read(info) as member:
                            self.scan(member, name, depth + 1)
                        self.stats['zip_members'] += 1
                    except Exception as exc:
                        self.issue(name, 'zip_member', exc)
                    if ordinal % 5000 == 0:
                        print(f'ZIP: {ordinal}/{len(archive.archive.infolist())} members; '
                              f'{len(self.written_native)} native programs; {len(self.issues)} issues', flush=True)
            finally:
                archive.close()
        elif data[:4] == bytes.fromhex('ef02bcda'):
            size, packed = unpack(data, '<II', 12)
            # Lookup indexes share the magic but begin with a counted hexadecimal
            # name, rather than the shader cache's reserved word and size pair.
            name_length, = unpack(data, '<I', 8)
            first_name = data[12:12 + name_length] if 0 < name_length <= len(data) - 12 else b''
            lookup = bool(first_name) and all(c in b'0123456789abcdefABCDEF' for c in first_name)
            if not size or lookup:
                self.leaf(data, blob, label, depth)
            elif len(data) != 20 + packed:
                raise ValueError('Snowdrop shader-cache wrapper length mismatch')
            else:
                with decoded_zlib(Window(data, 20, packed), size) as value:
                    self.scan(value, label + '#snowdrop-cache', depth + 1)
            self.stats['snowdrop_shader_caches'] += 1
        elif data[:4] == ZSTD:
            self.stats["zstd_layers"] += 1
            params = zstandard.get_frame_parameters(data[:18])
            dictionary = self.dictionaries.get(params.dict_id)
            if params.dict_id and dictionary is None:
                raise ValueError('missing zstd dictionary')
            with decoded_zstd(data, dictionary) as decoded:
                self.scan(decoded, label + "#zstd", depth + 1)
        elif data[:4] == b"Yaz0":
            self.stats["yaz0_layers"] += 1
            with decoded_yaz0(data, yaz0) as decoded:
                self.scan(decoded, label + "#yaz0", depth + 1)
        elif data[:4] == LZ4:
            self.stats["lz4_layers"] += 1
            with decoded_lz4(data) as value:
                self.scan(value, label + "#lz4", depth + 1)
        elif data[:4] == b"NSO0":
            self.stats["nso_modules"] += 1
            with nso_image(data, self.decode_native) as image:
                self.scan(image, label + "#nso-image", depth + 1)
        elif data[:4] == b'NDVE':
            pack_length, = unpack(data, '<I', 0x0c)
            models, = unpack(data, '<I', 0x14)
            pack = 0x18 + models * 8
            if data[pack:pack + 4] != b'NDSR':
                raise ValueError('NDVE is missing its declared NDSR pack')
            self.scan(window(data, pack, pack_length), label + '#ndsr', depth + 1)
            if pack + pack_length < len(data):
                self.scan(window(data, pack + pack_length, len(data) - pack - pack_length),
                          label + '#networks', depth + 1)
            self.stats['ndve_archives'] += 1
        elif data[:4] == b'SCNE':
            self.stats['bea_archives'] += 1
            for name, packed, size in bea_members(data):
                with ExitStack() as stack:
                    if packed[:4] == ZSTD:
                        params = zstandard.get_frame_parameters(packed[:18])
                        dictionary = self.dictionaries.get(params.dict_id)
                        if params.dict_id and dictionary is None:
                            raise ValueError('Missing BEA zstd dictionary')
                        value = stack.enter_context(decoded_zstd(packed, dictionary, expected_size=size))
                    elif len(packed) == size:
                        value = packed
                    else:
                        raise ValueError(f'Unsupported BEA compression: {len(packed)} -> {size}')
                    self.scan(value, label + '/' + name, depth + 1)
                    self.stats['bea_files'] += 1
        elif data[:8] == b'ONEPACK\0':
            self.stats['trinity_archives'] += 1
            for ordinal, (pack_hash, file_hash, compression, size, packed) in enumerate(trinity_entries(data), 1):
                name = label + f'#pack-{pack_hash:016x}/file-{file_hash:016x}'
                try:
                    if compression == 3:
                        value = self.decode_native('oodle', packed, size)
                    elif len(packed) == size:
                        value = packed
                    else:
                        raise ValueError(f'Unsupported Trinity codec {compression}: {len(packed)} -> {size}')
                    self.scan(value, name, depth + 1)
                    self.stats['trinity_files'] += 1
                except (ValueError, OSError, RuntimeError) as exc:
                    self.issue(name, 'trinity_member', exc)
                if ordinal % 5000 == 0:
                    print(f'Trinity: {ordinal} files scanned; {len(self.written_native)} native programs; '
                          f'{len(self.issues)} issues', flush=True)
        elif data[:4] == b"SARC":
            self.stats["sarc_archives"] += 1
            for name, member in sarc(data):
                self.stats["sarc_members"] += 1
                try:
                    self.scan(member, label + "/" + name, depth + 1)
                except Exception as exc:
                    self.issue(label + "/" + name, "nested_member", exc)
        elif label.endswith('.fxb') and data[:4] == bytes.fromhex('0109fffe'):
            # XNA/FNA Direct3D 9 effect: shader model 2/3 bytecode the game translates at runtime.
            self.stats['fna_effects'] += 1
        elif label.endswith('.ushaderbytecode') or (unreal and shader_archive_like(data)):
            shaders, code = shader_archive(data)
            self.stats['unreal_shader_archives'] += 1
            for index, shader in enumerate(shaders):
                name = label + f'#shader-{index}'
                try:
                    program = archive_program(data, shader, code, self.decode_native)
                    self.unreal_program(program, name, depth, shader[3])
                except (ValueError, OSError, RuntimeError, zlib.error, zstandard.ZstdError) as exc:
                    self.issue(name, 'unreal_shader', exc)
        elif data[:8] == b'UnityFS\0':
            self.stats['unity_bundles'] += 1
            with unity_bundle(data) as members:
                for name, member in members:
                    try:
                        self.scan(member, label + '/' + name, depth + 1)
                    except Exception as exc:
                        self.issue(label + '/' + name, 'unity_bundle_member', exc)
        elif any(data[:len(magic)] == magic for magic in (b'UnityWeb\0', b'UnityRaw\0', b'UnityArchive\0')):
            self.issue(label, 'unsupported_container', 'Legacy Unity bundle format is not supported')
        elif is_unity_asset(data):
            self.unity_asset(data, label, depth)
        elif (label.endswith('.pak') or any(data[len(data) - back:len(data) - back + 4] == PAK_MAGIC
                                           for back in (0xcc, 0xc8, 0x2c) if len(data) >= back + 1)):
            archive = Pak(data, self.key_provider)
            self.stats['unreal_paks'] += 1
            for ordinal, name in enumerate(archive.files, 1):
                try:
                    with archive.read(name, self.decode_native) as value:
                        self.scan(value, label + '/' + name, depth + 1, unreal=True)
                    self.stats['unreal_pak_files'] += 1
                except (ValueError, OSError, RuntimeError, zlib.error, zstandard.ZstdError) as exc:
                    self.issue(label + '/' + name, 'unreal_pak_member', exc)
                if ordinal % 1000 == 0:
                    print(f'PAK: {ordinal}/{len(archive.files)} files; {len(self.written_native)} native programs; '
                          f'{len(self.issues)} issues', flush=True)
        else:
            self.leaf(data, blob, label, depth, unreal=unreal)

    @contextmanager
    def snowdrop_root(self, reader, members, label):
        """Pair SDF slices with verified sibling metadata and a reusable temporary index."""
        if not label.endswith('.sdfdata'):
            yield None
            return
        match = re.search(r'sdf-([A-Z])-([0-9]+)(?:-[^/]+)?\.sdfdata$', label)
        toc_name = label.rsplit('/', 1)[0] + '/sdf.sdftoc'
        if match is None or toc_name not in members:
            raise ValueError('SDFDATA has no supported name/matching SDFTOC')
        index = members[toc_name]
        expected = reader.files[index][2].hex()
        if expected not in self.snowdrop_archives:
            with reader.open_file(index) as data:
                if digest(data) != expected:
                    raise ValueError('SDFTOC NUP member SHA-256 mismatch')
                archive = Snowdrop(data)
                self.snowdrop_archives[expected] = archive
                archive.index()
        archive = self.snowdrop_archives[expected]
        available = {int(found[1]) for name in members
                     if name.rsplit('/', 1)[0] == label.rsplit('/', 1)[0]
                     and (found := re.search(r'sdf-[A-Z]-([0-9]+)(?:-[^/]+)?\.sdfdata$', name))}
        missing = {row[0] for row in archive.db.execute('SELECT DISTINCT part FROM ranges')} - available
        if missing:
            raise ValueError('Missing SDFDATA slices referenced by the index: '
                             + ', '.join(map(str, sorted(missing))))
        yield archive, int(match[2]), expected

    @contextmanager
    def iostore_root(self, reader, members, label, data):
        """Pair UCAS roots with verified TOCs and lazily open verified sibling partitions."""
        if not label.endswith('.ucas'):
            yield None
            return
        stem = label[:-5]
        match = re.search(r'_s([0-9]+)(?=-|$)', stem) if stem + '.utoc' not in members else None
        partition = int(match[1]) if match else 0
        base = stem[:match.start()] + stem[match.end():] if match else stem
        toc_name = base + '.utoc'
        if toc_name not in members:
            raise ValueError('UCAS member has no matching IoStore TOC')
        with ExitStack() as stack:
            index = members[toc_name]
            metadata = stack.enter_context(reader.open_file(index))
            if digest(metadata) != reader.files[index][2].hex():
                raise ValueError('IoStore TOC NUP member SHA-256 mismatch')
            toc = IoStore(metadata, self.key_provider)
            if partition >= toc.parts:
                raise ValueError('UCAS partition exceeds TOC partition count')
            opened = {partition: data}

            def read_partition(part, offset, size):
                if part not in opened:
                    names = ([base + '.ucas'] if not part else
                             [base + f'_s{part}.ucas',
                              re.sub(r'(-[^/]+)$', lambda m: f'_s{part}' + m[0], base) + '.ucas'])
                    if part:
                        names = [name for name in names if name != base + '.ucas']
                    name = next((name for name in names if name in members), names[0])
                    if name not in members:
                        raise ValueError(f'Missing IoStore partition {part}')
                    index = members[name]
                    value = stack.enter_context(reader.open_file(index))
                    if digest(value) != reader.files[index][2].hex():
                        raise ValueError('IoStore partition NUP member SHA-256 mismatch')
                    opened[part] = value
                return span(opened[part], offset, size)

            yield toc, partition, read_partition

    @staticmethod
    def read_root(reader, index):
        """Read/decompress one root and hash it, without touching scanner state or SQLite."""
        if reader.files[index][1] > LIMIT:
            raise ValueError('Large members must use the streaming reader')
        value = reader.read_file(index)
        return value, hashlib.sha256(value).hexdigest()

    @contextmanager
    def root_data(self, reader, index, future):
        """Keep large mapped/decompressed members alive only while their root is scanned."""
        if reader.files[index][1] > LIMIT:
            print(f'\nStreaming large member ({reader.files[index][1] / 1024**3:.2f} GiB): '
                  + reader.files[index][0].decode('utf-8', 'replace'), flush=True)
            with reader.open_file(index) as value:
                yield value, digest(value)
        else:
            yield future.result() if future else self.read_root(reader, index)

    def prefetch_roots(self, reader, members, executor):
        """Overlap root reads with parsing, retaining order and a 128 MiB queue budget."""
        pending = deque()
        position = queued_bytes = 0
        while position < len(members) or pending:
            while position < len(members) and len(pending) < self.workers:
                name, index = members[position]
                node = reader.files[index]
                skip = self.existing_roots.get(index) == 'ok'
                cost = node[1] + node[4] if not skip else 0
                # One large root is allowed alone; several large roots cannot fill memory.
                if pending and queued_bytes + cost > 128 * 1024 * 1024:
                    break
                future = (executor.submit(self.read_root, reader, index)
                          if executor and not skip and node[1] <= LIMIT else None)
                pending.append((position + 1, name, index, future, cost))
                queued_bytes += cost
                position += 1
            ordinal, name, index, future, cost = pending.popleft()
            yield ordinal, name, index, future
            queued_bytes -= cost

    def run(self, source):
        """Verify every member, checkpoint traversal, and export the audit manifest."""
        identity = source_identity(source)
        if self.identity is not None and identity != self.identity:
            raise ValueError("NUP changed since the checkpoint; choose a fresh output directory")
        self.identity = identity
        with NupReader(str(source)) as reader, (
                ThreadPoolExecutor(max_workers=self.workers) if self.workers > 1 else nullcontext(None)) as executor:
            all_members = []
            for package in reader.packages:
                all_members.extend((f"pkg{package.index}" + name, index)
                                   for name, index in walk(reader, package.root_dir))
            if len(all_members) != reader.file_count or len({index for _, index in all_members}) != reader.file_count:
                raise ValueError("NUP roots do not form a complete tree of distinct file nodes")
            member_indices = dict(all_members)
            package_keys = {}

            def recover_key(package, probe):
                """Keep validated keys in memory and recover only from this package's verified main."""
                for key in package_keys.get(package, []):
                    if probe.accepts(key):
                        return key
                main = package + '/exefs/main'
                if main not in member_indices:
                    raise ValueError('Encrypted Unreal archive has no package main for local key recovery')
                index = member_indices[main]
                with reader.open_file(index) as module:
                    if digest(module) != reader.files[index][2].hex():
                        raise ValueError('Unreal key-source NSO SHA-256 mismatch')
                    if module[:4] != b'NSO0':
                        raise ValueError('Unreal key source is not an NSO')
                    text_size, = unpack(module, '<I', 0x18)
                    data_start, = unpack(module, '<I', 0x24)
                    address, size = unpack(module, '<II', 0x34)
                    print('Validating local Unreal archive key from package main...', flush=True)
                    with nso_image(module, self.decode_native) as image:
                        check_range(image, data_start, address + size - data_start)
                        key = find_key(image, text_size, data_start, address + size, probe)
                package_keys.setdefault(package, []).append(key)
                return key
            package_dictionaries = {package.index: {} for package in reader.packages}
            for name, index in all_members:
                if name.endswith("/Pack/ZsDic.pack.zs"):
                    if reader.files[index][1] > LIMIT:
                        raise ValueError("dictionary pack exceeds member limit")
                    dictionary_raw = reader.read_file(index)
                    if hashlib.sha256(dictionary_raw).digest() != reader.files[index][2]:
                        raise ValueError("dictionary pack SHA-256 mismatch")
                    value = decompress(dictionary_raw, {})
                    for _, raw in sarc(value):
                        if raw[:4] == bytes.fromhex("37a430ec"):
                            dictionary = zstandard.ZstdCompressionDict(raw)
                            target = package_dictionaries[int(name.split('/')[0][3:])]
                            if dictionary.dict_id() in target and target[dictionary.dict_id()].as_bytes() != raw:
                                raise ValueError("conflicting dictionary IDs within one package")
                            target[dictionary.dict_id()] = dictionary
            self.package_info = [{'index': p.index, 'title_id': f'{p.title_id:016X}',
                                  'version': p.version, 'kind': p.kind_name} for p in reader.packages]
            self.dictionary_ids = sorted({key for dictionaries in package_dictionaries.values() for key in dictionaries})
            self.write_summary(source, len(all_members), final=False)
            for ordinal, name, index, future in self.prefetch_roots(reader, all_members, executor):
                previous_status = self.existing_roots.get(index)
                if previous_status == "ok":
                    if self.progress:
                        self.progress(ordinal, len(all_members))
                    continue
                self.dictionaries = package_dictionaries[int(name.split('/')[0][3:])]
                node = reader.files[index]
                if previous_status is None:
                    self.extensions[Path(name).suffix.lower()] += 1
                actual = ""
                status = "ok"
                old_issues = [issue for issue in self.issues if issue['path'] == name or issue['path'].startswith(name + '#') or issue['path'].startswith(name + '/')]
                self.issues = [issue for issue in self.issues if issue not in old_issues]
                self.unclaimed = [row for row in self.unclaimed if not (row['path'] == name or row['path'].startswith(name + '#') or row['path'].startswith(name + '/'))]
                # Interrupted and failed roots may have partial descendants in the checkpoint.
                if previous_status is not None:
                    for path, blob_hash in self.db.execute("SELECT path,hash FROM paths WHERE path>=? AND path<?", (name, name+'\uffff')):
                        if path == name or path.startswith(name+'#') or path.startswith(name+'/'):
                            self.seen.discard(blob_hash)
                try:
                    self.key_provider = lambda probe, package=name.split('/')[0]: recover_key(package, probe)
                    with self.root_data(reader, index, future) as (value, actual):
                        if actual != node[2].hex():
                            raise ValueError("NUP member SHA-256 mismatch")
                        issues_before = len(self.issues)
                        with (self.iostore_root(reader, member_indices, name, value) as iostore,
                              self.snowdrop_root(reader, member_indices, name) as sdf):
                            self.scan(value, name, verified_hash=actual, iostore=iostore, sdf=sdf)
                    if len(self.issues) != issues_before:
                        status = 'failed'
                    else:
                        self.recovered.extend(old_issues)
                except Exception as exc:
                    status = "failed"
                    self.issue(name, "root_member", exc)
                self.db.execute("INSERT OR REPLACE INTO roots VALUES (?,?,?,?,?,?)",
                                (index, name, node[1], node[2].hex(), actual, status))
                if ordinal % self.checkpoint_every == 0:
                    self.write_summary(source, len(all_members), final=False)
                if self.progress:
                    self.progress(ordinal, len(all_members))
                elif ordinal % 1000 == 0:
                    print(f"{ordinal}/{len(all_members)} files; {len(self.keys)} records; "
                          f"{len(self.issues)} issues; {time.monotonic()-self.started:.1f}s since resume", flush=True)
            self.stats["nup_file_table_count"] = reader.file_count
        if source_identity(source) != identity:
            raise ValueError("NUP changed while it was being scanned")
        # A newer parser may invalidate old provenance; do not retain orphaned
        # heuristic records or include their binaries in the new audit manifest.
        self.db.execute('DELETE FROM shaders WHERE NOT EXISTS (SELECT 1 FROM origins o WHERE o.shader=shaders.key)')
        self.keys = {row[0] for row in self.db.execute('SELECT key FROM shaders')}
        self.written_native = {sha + '.' + stage for stage, sha in self.db.execute(
            "SELECT DISTINCT stage,instruction_hash FROM shaders WHERE arch='sm86'")}
        manifest = self.output / 'native-audit.tsv'
        temporary_manifest = manifest.with_suffix('.tsv.tmp')
        with temporary_manifest.open("w", encoding="utf-8", newline="") as stream:
            for stage, sha in self.db.execute("SELECT DISTINCT stage,instruction_hash FROM shaders WHERE arch='sm86' ORDER BY stage,instruction_hash"):
                stream.write(f"{sha}.{stage}.bin\t{stage}\n")
        temporary_manifest.replace(manifest)
        self.write_summary(source, len(all_members), final=True)
        self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        print(f"Scan complete: {len(self.written_native)} native programs; {len(self.issues)} issues; {len(self.unclaimed)} unclaimed controls", flush=True)
        return self.summary

    def close(self):
        """Close the checkpoint database, rolling back an interrupted uncommitted batch."""
        self.db.close()
        if self.native_decoder is not None:
            self.native_decoder.close()
        for archive in self.snowdrop_archives.values():
            archive.close()

    def write_summary(self, source, count, final):
        """Commit authoritative progress before publishing readable status files."""
        self.stats['root_files_attempted'] = self.db.execute('SELECT count(*) FROM roots').fetchone()[0]
        self.stats['root_bytes_verified'] = self.db.execute("SELECT coalesce(sum(size),0) FROM roots WHERE actual_hash=expected_hash").fetchone()[0]
        self.stats['unique_decoded_blobs'] = self.db.execute('SELECT count(*) FROM blobs').fetchone()[0]
        # Counts of unique records are authoritative even after an interrupted/retried member.
        record_stats = {arch + '_' + stage for arch in ('maxwell', 'sm86')
                        for stage in (*SHORT, 'unique_records')}
        for key in list(self.stats):
            if key.endswith('_references') or key in record_stats:
                self.stats[key] = 0
        for arch, stage, total in self.db.execute('SELECT arch,stage,count(*) FROM shaders GROUP BY arch,stage'):
            self.stats[arch + '_' + stage] = total
        for arch, total in self.db.execute('SELECT arch,count(*) FROM shaders GROUP BY arch'):
            self.stats[arch + '_unique_records'] = total
        for fmt, total in self.db.execute('SELECT format,count(*) FROM origins GROUP BY format'):
            self.stats[fmt + '_references'] = total
        self.issues = list({json.dumps(row, sort_keys=True): row for row in self.issues}.values())
        self.unclaimed = list({json.dumps(row, sort_keys=True): row for row in self.unclaimed}.values())
        self.summary = {"source": str(source), "source_size": source.stat().st_size,
                        "scanner_revision": SCANNER_REVISION,
                        "finished": final, "expected_root_paths": count, "stats": dict(self.stats),
                        "elapsed_seconds": round(self.elapsed_before_resume + time.monotonic() - self.started, 1),
                        "native_instruction_stage_blobs": len(self.written_native),
                        "issue_count": len(self.issues), "unclaimed_control_candidates": len(self.unclaimed),
                        "dictionaries": getattr(self, 'dictionary_ids', []),
                        "packages": getattr(self, 'package_info', []),
                        "top_extensions": self.extensions.most_common(35),
                        "top_decoded_magics": self.magics.most_common(40),
                        "complete_runtime_coverage_proven": False}
        self.summary["root_status_counts"] = dict(self.db.execute("SELECT status,count(*) FROM roots GROUP BY status"))
        self.summary["recovered_parser_limit_issues"] = len(self.recovered)
        checkpoint = {**self.summary, 'identity': self.identity, 'issues': self.issues,
                      'all_magics': dict(self.magics), 'all_extensions': dict(self.extensions),
                      'unclaimed': self.unclaimed, 'recovered': self.recovered,
                      'unity_schemas': self.unity_schemas}
        self.db.execute("INSERT OR REPLACE INTO state VALUES ('checkpoint',?)", (json.dumps(checkpoint),))
        self.db.commit()
        atomic_json(self.output / 'summary.json', self.summary)
        atomic_json(self.output / 'issues.json', self.issues)
        atomic_json(self.output / 'unclaimed-controls.json', self.unclaimed)
        atomic_json(self.output / 'recovered-issues.json', self.recovered)
