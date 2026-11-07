"""Scan NUP members and nested archives, preserving shader bytes and provenance."""

import hashlib
import json
import sqlite3
import struct
import time
from bisect import bisect_right
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from pathlib import Path

import lz4.block
import lz4.frame
import zstandard

from .binary import LIMIT, decompress, span, unpack, walk
from .container.read import NupReader
from .markers import MarkerFinder
from .storage import atomic_json, source_identity

CONTROL = bytes.fromhex("34127698")
ZSTD = bytes.fromhex("28b52ffd")
LZ4 = bytes.fromhex("04224d18")
NATIVE = CONTROL + bytes.fromhex("c9000000")
SHORT = ("vs", "hs", "ds", "gs", "ps", "cs", "ts", "ms")


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
        member = span(data, start + lo, hi - lo)
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


def nso_image(data):
    flags, = unpack(data, "<I", 12)
    segments = []
    for i in range(3):
        offset, address, size, _ = unpack(data, "<4I", 0x10 + 16 * i)
        compressed_size, = unpack(data, "<I", 0x60 + 4 * i)
        if address + size > LIMIT:
            raise ValueError("NSO segment exceeds limit")
        raw = span(data, offset, compressed_size if flags & (1 << i) else size)
        decoded = lz4.block.decompress(raw, uncompressed_size=size) if flags & (1 << i) else raw
        if len(decoded) != size:
            raise ValueError("NSO segment length mismatch")
        segments.append((address, decoded))
    image = bytearray(max(address + len(value) for address, value in segments))
    for address, value in segments:
        image[address:address + len(value)] = value
    return bytes(image)


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
        self.started = time.monotonic()
        self.elapsed_before_resume = 0
        self.existing_roots = {}
        self.recovered = []
        self.identity = None
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
            self.recovered = previous["recovered"]
            self.identity = previous["identity"]
            self.elapsed_before_resume = previous["elapsed_seconds"]
            self.seen = {row[0] for row in self.db.execute("SELECT hash FROM blobs")}
            self.keys = {row[0] for row in self.db.execute("SELECT key FROM shaders")}
            self.written_native = {sha + '.' + stage for stage, sha in self.db.execute("SELECT DISTINCT stage,instruction_hash FROM shaders WHERE arch='sm86'")}
            self.existing_roots = dict(self.db.execute("SELECT file_index,status FROM roots"))

    def issue(self, label, kind, reason):
        self.issues.append({"path": label, "kind": kind, "reason": str(reason)})

    def stage(self, control, code):
        if control.startswith(NATIVE):
            kind = control[0x56] if len(control) > 0x56 else -1
            if kind in (5, 6, 7):
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
        span(data, base, size)
        count, table = unpack(data, "<IQ", base + 0x7c)
        span(data, base + table, count * 0x40)
        for i in range(count):
            program, = unpack(data, "<Q", base + table + i * 0x40 + 0x10)
            if not program:
                continue
            for si, stage in enumerate(SHORT):
                slot = 8 + si * 8 if si < 6 else (0x40 if si == 6 else 0x48)
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
        span(data, region, region_size)
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
        control_ranges = sorted((c, c + n) for _, c, n, _, _, _ in candidates)
        control_starts = []
        control_ends = []
        highest_end = 0
        for start, end in control_ranges:
            control_starts.append(start)
            highest_end = max(highest_end, end)
            control_ends.append(highest_end)
        for a, c, nc, k, nk, stage in candidates:
            # Prefix maxima preserve membership for nested and overlapping control ranges.
            previous = bisect_right(control_starts, a) - 1
            if previous >= 0 and a < control_ends[previous]:
                self.stats["BAHS_control_field_false_entries"] += 1
                continue
            claimed.add(self.add(data, blob, label, "BAHS", stage, c, nc, k, nk, hex(a)))
        self.stats["BAHS_containers"] += 1

    def ndsr(self, data, blob, label, claimed):
        def score(start):
            result = 0
            for at in range(start, min(start + 256, len(data) - 15), 16):
                c, _, _, _ = unpack(data, "<4I", at)
                result += data[c:c + 8] == NATIVE
            return result
        offset = max((0x10, 0x14), key=score)
        while offset + 16 <= len(data):
            c, nc, k, nk = unpack(data, "<4I", offset)
            if not (c or nc or k or nk):
                break
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
                span(data, base, size)
                if not 0 < count <= 16:
                    continue
                first, stride = (0xa8, 0x98) if native else (0x90, 0x90)
                span(data, base + first, count * stride)
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

    def leaf(self, data, blob, label, depth=0):
        claimed = set()
        markers = self.marker_finder.find(data)
        if data[:4] == b"BAHS":
            self.bahs(data, blob, label, claimed)
        elif data[:4] == b"NDSR":
            self.ndsr(data, blob, label, claimed)
        for base in markers[b"BNSH\0\0\0\0"]:
            try:
                if not self.bnsh(data, blob, label, base, claimed):
                    self.stats["BNSH_magic_nonrecords"] += 1
            except (ValueError, struct.error) as exc:
                self.issue(label + f"#BNSH@{base:x}", "shader_parser", exc)
        self.glslc(data, blob, label, claimed, markers[bytes.fromhex("91688619")])
        # sead primitive drawer: four absolute file offsets in the first sixteen bytes.
        if len(data) >= 16:
            cv, cp, kv, kp = unpack(data, "<4I", 0)
            if data[cv:cv + 8] == NATIVE and data[cp:cp + 8] == NATIVE:
                for c, k, stage in ((cv, kv, "vs"), (cp, kp, "ps")):
                    size, = unpack(data, "<I", c + 0x30)
                    length, = unpack(data, "<I", c + 0x44)
                    claimed.add(self.add(data, blob, label, "SEAD", stage, c, max(size, 0x48), k, length))
        # Some runtime libraries store a complete NVN2 control followed by its code directly.
        # Recover such records only when all declared bounds, stage and instruction ranges agree.
        for c in markers[CONTROL]:
            if c in claimed:
                continue
            native = data[c:c + 8] == NATIVE
            if native:
                try:
                    own, = unpack(data, "<I", c + 0x30)
                    length, = unpack(data, "<I", c + 0x44)
                    if 0x58 <= own < 0x10000:
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
                try:
                    if magic == ZSTD:
                        frame = memoryview(data)[pos:]
                        params = zstandard.get_frame_parameters(frame)
                        if params.content_size not in (zstandard.CONTENTSIZE_UNKNOWN, zstandard.CONTENTSIZE_ERROR) and params.content_size > LIMIT:
                            raise ValueError("embedded zstd exceeds limit")
                        dictionary = self.dictionaries.get(params.dict_id)
                        if params.dict_id and dictionary is None:
                            raise ValueError("missing embedded zstd dictionary")
                        # Decode just this frame, not all subsequent array/mipmap frames again.
                        value = zstandard.ZstdDecompressor(dict_data=dictionary).decompress(frame, max_output_size=LIMIT)
                    else:
                        info = lz4.frame.get_frame_info(data[pos:])
                        if info["content_size"] > LIMIT:
                            raise ValueError("embedded LZ4 exceeds limit")
                        dec = lz4.frame.LZ4FrameDecompressor()
                        value = dec.decompress(data[pos:], max_length=LIMIT + 1)
                        if not dec.eof or len(value) > LIMIT:
                            raise ValueError("embedded LZ4 truncated or exceeds limit")
                except (ValueError, RuntimeError, zstandard.ZstdError):
                    self.stats["embedded_frame_nonrecords"] += 1
                    continue
                self.scan(value, label + f"#frame@{pos:x}", depth + 1)
                self.stats["embedded_frames_decoded"] += 1

    def scan(self, data, label, depth=0, *, verified_hash=None):
        if depth > 16 or len(data) > LIMIT:
            raise ValueError("decoded size or nesting limit")
        blob = verified_hash if verified_hash is not None else hashlib.sha256(data).hexdigest()
        self.db.execute("INSERT OR IGNORE INTO paths VALUES (?,?)", (label, blob))
        if blob in self.seen:
            self.stats["duplicate_blobs"] += 1
            return
        self.seen.add(blob)
        self.db.execute("INSERT OR IGNORE INTO blobs VALUES (?,?,?)", (blob, len(data), data[:8].hex()))
        self.stats["unique_decoded_blobs"] += 1
        self.magics[data[:4].hex()] += 1
        if data[:4] == ZSTD:
            self.stats["zstd_layers"] += 1
            self.scan(decompress(data, self.dictionaries), label + "#zstd", depth + 1)
        elif data[:4] == b"Yaz0":
            self.stats["yaz0_layers"] += 1
            self.scan(yaz0(data), label + "#yaz0", depth + 1)
        elif data[:4] == LZ4:
            dec = lz4.frame.LZ4FrameDecompressor()
            value = dec.decompress(data, max_length=LIMIT + 1)
            if not dec.eof:
                raise ValueError("LZ4 truncated or decoded limit exceeded")
            self.stats["lz4_layers"] += 1
            self.scan(value, label + "#lz4", depth + 1)
        elif data[:4] == b"NSO0":
            self.stats["nso_modules"] += 1
            self.scan(nso_image(data), label + "#nso-image", depth + 1)
        elif data[:4] == b"SARC":
            self.stats["sarc_archives"] += 1
            for name, member in sarc(data):
                self.stats["sarc_members"] += 1
                try:
                    self.scan(member, label + "/" + name, depth + 1)
                except Exception as exc:
                    self.issue(label + "/" + name, "nested_member", exc)
        else:
            self.leaf(data, blob, label, depth)

    @staticmethod
    def read_root(reader, index):
        """Read/decompress one root and hash it, without touching scanner state or SQLite."""
        if reader.files[index][1] > LIMIT:
            raise ValueError('NUP member exceeds limit')
        value = reader.read_file(index)
        return value, hashlib.sha256(value).hexdigest()

    def prefetch_roots(self, reader, members, executor):
        """Overlap root reads with parsing, retaining order and a 128 MiB queue budget."""
        pending = deque()
        position = queued_bytes = 0
        while position < len(members) or pending:
            while position < len(members) and len(pending) < self.workers:
                name, index = members[position]
                node = reader.files[index]
                skip = self.existing_roots.get(index) == 'ok'
                cost = node[1] + node[4] if not skip and node[1] <= LIMIT else 0
                # One large root is allowed alone; several large roots cannot fill memory.
                if pending and queued_bytes + cost > 128 * 1024 * 1024:
                    break
                future = executor.submit(self.read_root, reader, index) if executor and not skip else None
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
                    for path, digest in self.db.execute("SELECT path,hash FROM paths WHERE path>=? AND path<?", (name, name+'\uffff')):
                        if path == name or path.startswith(name+'#') or path.startswith(name+'/'):
                            self.seen.discard(digest)
                try:
                    value, actual = future.result() if future else self.read_root(reader, index)
                    if actual != node[2].hex():
                        raise ValueError("NUP member SHA-256 mismatch")
                    issues_before = len(self.issues)
                    self.scan(value, name, verified_hash=actual)
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

    def write_summary(self, source, count, final):
        """Commit authoritative progress before publishing readable status files."""
        self.stats['root_files_attempted'] = self.db.execute('SELECT count(*) FROM roots').fetchone()[0]
        self.stats['root_bytes_verified'] = self.db.execute("SELECT coalesce(sum(size),0) FROM roots WHERE actual_hash=expected_hash").fetchone()[0]
        self.stats['unique_decoded_blobs'] = self.db.execute('SELECT count(*) FROM blobs').fetchone()[0]
        # Counts of unique records are authoritative even after an interrupted/retried member.
        for arch, stage, total in self.db.execute('SELECT arch,stage,count(*) FROM shaders GROUP BY arch,stage'):
            self.stats[arch + '_' + stage] = total
        for arch, total in self.db.execute('SELECT arch,count(*) FROM shaders GROUP BY arch'):
            self.stats[arch + '_unique_records'] = total
        for fmt, total in self.db.execute('SELECT format,count(*) FROM origins GROUP BY format'):
            self.stats[fmt + '_references'] = total
        self.issues = list({json.dumps(row, sort_keys=True): row for row in self.issues}.values())
        self.unclaimed = list({json.dumps(row, sort_keys=True): row for row in self.unclaimed}.values())
        self.summary = {"source": str(source), "source_size": source.stat().st_size,
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
                      'unclaimed': self.unclaimed, 'recovered': self.recovered}
        self.db.execute("INSERT OR REPLACE INTO state VALUES ('checkpoint',?)", (json.dumps(checkpoint),))
        self.db.commit()
        atomic_json(self.output / 'summary.json', self.summary)
        atomic_json(self.output / 'issues.json', self.issues)
        atomic_json(self.output / 'unclaimed-controls.json', self.unclaimed)
        atomic_json(self.output / 'recovered-issues.json', self.recovered)
