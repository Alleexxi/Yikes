"""Snowdrop v43 file-tree ranges and independently compressed asset pages.

The radix-tree layout was cross-checked against SnowplowCLI's SDFS.cs. Version
43 adds a codec byte and an independent compressed-size width before that size.
Only the locally verified v43 layout is accepted here.
"""

import mmap
import sqlite3
import struct
import tempfile
import zlib
from contextlib import contextmanager

from .binary import LIMIT, span, unpack
from .large import Window, window


def decode_page(decode_native, raw, expected):
    """Decode an Oodle page to its declared length.

    Some pages hold a stream that produces a few more bytes than the table declares (16 to 112
    in Star Wars Outlaws), which the exact-size decoder rejects although it consumes the whole
    stream. A larger request succeeds with identical leading bytes, so retry with growing slack
    and keep exactly the declared bytes; every shader record is still checked downstream.
    """
    try:
        return decode_native('oodle', raw, expected)
    except ValueError as first:
        for slack in (16, 64, 256, 1024, 4096, 65536):
            try:
                value = decode_native('oodle', raw, expected + slack)
            except ValueError:
                continue
            return value[:expected]
        raise first


class Snowdrop:
    """Validate an SDF index and stream its entries without retaining every asset name."""

    def __init__(self, data):
        if data[:4] != b'WEST' or unpack(data, '<I', 4)[0] != 43:
            raise ValueError('Unsupported Snowdrop SDF index version')
        size, packed = unpack(data, '<II', 8)
        if data[96:98] != b'\0\0':
            raise ValueError('Unsupported/encrypted Snowdrop SDF index flags')
        if not (data[-48:-40] == b'massive\0' and data[-8:] == b'ubisoft\0'):
            raise ValueError('Invalid Snowdrop SDF index footer')
        offset = len(data) - 48 - packed
        raw = span(data, offset, packed)
        decoder = zlib.decompressobj()
        self.tree = decoder.decompress(raw, size + 1)
        if (len(self.tree) != size or not decoder.eof or decoder.unused_data
                or decoder.unconsumed_tail):
            raise ValueError('Snowdrop SDF index decoded length/stream mismatch')
        self.directory = None
        self.db = None
        self.indexed = False

    def close(self):
        """Delete the temporary range index after closing its SQLite connection."""
        if self.db is not None:
            self.db.close()
        if self.directory is not None:
            self.directory.cleanup()

    def index(self):
        """Index metadata on temporary disk instead of retaining millions of Python names."""
        if self.indexed:
            return
        if self.db is not None:
            self.close()
        from pathlib import Path
        self.directory = tempfile.TemporaryDirectory(prefix='yikes-sdf-')
        self.db = sqlite3.connect(Path(self.directory.name) / 'ranges.sqlite')
        self.db.execute('CREATE TABLE ranges(part, name, offset, size, pages, extent)')
        rows = []
        for name, part, offset, size, pages, extent in self.entries():
            rows.append((part, name, offset, size, struct.pack('<' + 'I' * len(pages), *pages), extent))
            if len(rows) == 10000:
                self.db.executemany('INSERT INTO ranges VALUES (?,?,?,?,?,?)', rows)
                rows.clear()
        self.db.executemany('INSERT INTO ranges VALUES (?,?,?,?,?,?)', rows)
        self.db.execute('CREATE INDEX by_part ON ranges(part)')
        self.db.commit()
        self.tree = b''
        self.indexed = True

    def partition(self, part):
        """Yield only the current SDFDATA member's validated file extents."""
        self.index()
        for name, offset, size, raw, extent in self.db.execute(
                'SELECT name,offset,size,pages,extent FROM ranges WHERE part=?', (part,)):
            pages = list(struct.unpack('<' + 'I' * (len(raw) // 4), raw))
            yield name, offset, size, pages, extent

    def entries(self):
        """Walk bounded radix branches, yielding every asset extent and its page sizes."""
        data, pending, visited = self.tree, [(0, b'')], set()
        while pending:
            at, name = pending.pop()
            def take(size):
                nonlocal at
                value = span(data, at, size)
                at += size
                return value
            def number(size):
                return int.from_bytes(take(size), 'little')
            while True:
                if at in visited:
                    raise ValueError('Repeated/cyclic Snowdrop radix node')
                visited.add(at)
                kind = number(1)
                if 1 <= kind <= 31:
                    name += take(kind)
                    if len(name) > 32768:
                        raise ValueError('Snowdrop asset name exceeds path budget')
                elif 65 <= kind <= 90:
                    flags = kind - 65
                    count = flags & 7
                    if count:
                        number(4)  # Stable asset identifier, not a payload offset.
                        texture = number(1)
                        number(texture & 3)  # Optional texture-header index.
                        if texture & 3:
                            take(8)  # Inline texture metadata in the v43 index.
                        for extent in range(count):
                            bits = number(1)
                            size = number((bits & 3) + 1)
                            codec, packed = 0, 0
                            if bits & 32:
                                codec, width = number(1), number(1)
                                if codec != 2 or not 1 <= width <= 4:
                                    raise ValueError(f'Unsupported Snowdrop codec {codec}/size width {width} at {at:#x}')
                                packed = number(width)
                            offset = number(bits >> 2 & 7)
                            part = number(2)
                            pages = ([number(2) for _ in range((size + 65535) // 65536)]
                                     if codec and size > 65536 else [packed] if codec else [])
                            yield name.decode('utf-8'), part, offset, size, pages, extent
                    if flags & 8:
                        take(number(1) * 2)
                    break
                elif kind:
                    destination = number(4)
                    if destination >= len(data):
                        raise ValueError('Snowdrop radix branch exceeds file table')
                    pending.append((destination, name))
                else:
                    raise ValueError('Invalid Snowdrop radix node')

    @staticmethod
    @contextmanager
    def read(data, offset, size, pages, decode_native):
        """Read an exact asset extent; Oodle pages spill to disk for large assets."""
        if not pages:
            yield window(data, offset, size)
            return
        with tempfile.SpooledTemporaryFile(max_size=LIMIT) as output:
            for packed in pages:
                expected = min(65536, size - output.tell())
                if expected <= 0:
                    raise ValueError('Snowdrop page count exceeds asset size')
                stored = packed or expected
                raw = span(data, offset, stored)
                value = raw if stored == expected else decode_page(decode_native, raw, expected)
                if len(value) != expected:
                    raise ValueError('Snowdrop decoded page length mismatch')
                output.write(value)
                offset += stored
            if output.tell() != size:
                raise ValueError('Snowdrop asset page count/size mismatch')
            if size <= LIMIT:
                output.seek(0)
                yield output.read()
            else:
                output.flush()
                with mmap.mmap(output.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                    yield Window(mapped)
