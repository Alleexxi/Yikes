"""Unencrypted version-11 Unreal PAK indexes and block-compressed members.

Encoded-entry dimensions were cross-checked against CUE4Parse and nxnative's
dm/gfx/tools/uepak.py. Encrypted or unsupported variants remain explicit gaps.
"""

import hashlib
import mmap
import tempfile
from contextlib import contextmanager

from .binary import LIMIT, span, unpack
from .iostore import decode_block
from .large import Window, window

MAGIC = bytes.fromhex('e1126f5a')


class Cursor:
    """Advance through bounded little-endian index tables and FString values."""

    def __init__(self, data, offset=0):
        self.data, self.offset = data, offset

    def read(self, size):
        value = span(self.data, self.offset, size)
        self.offset += size
        return value

    def take(self, fmt):
        import struct
        values = struct.unpack(fmt, self.read(struct.calcsize(fmt)))
        return values[0] if len(values) == 1 else values

    def string(self):
        size = self.take('<i')
        raw = self.read(abs(size) * (2 if size < 0 else 1))
        if raw and not raw.endswith(bytes(2 if size < 0 else 1)):
            raise ValueError('Unterminated Unreal FString')
        return raw.decode('utf-16-le' if size < 0 else 'utf-8').rstrip('\0')

    def count(self, minimum):
        """Reject negative counts or arrays that cannot fit even their smallest records."""
        count = self.take('<i')
        if not 0 <= count <= (len(self.data) - self.offset) // minimum:
            raise ValueError('Unreal index array count exceeds bounds')
        return count


class Pak:
    """Resolve filenames from the full directory index, preserving every member."""

    def __init__(self, data):
        self.data = data
        footer = next((len(data) - back for back in (0xcc, 0xc8, 0x2c)
                       if len(data) >= back + 1 and data[len(data) - back:len(data) - back + 4] == MAGIC), None)
        if footer is None:
            raise ValueError('Unrecognized Unreal PAK footer')
        version, offset, size = unpack(data, '<IQQ', footer + 4)
        self.version, self.legacy = version, {}
        if version not in (4, 8, 11):
            raise ValueError(f'Unsupported Unreal PAK version {version}')
        if data[footer - 1]:
            raise ValueError('Encrypted Unreal PAK indexes are not supported')
        self.methods = (['none', 'zlib', 'gzip', 'lz5', 'custom'] if version == 4 else
                        ['none'] + [data[footer + 44 + i * 32:footer + 76 + i * 32]
                                    .rstrip(b'\0').decode('ascii').lower() for i in range(5)])
        index = self.verified(offset, size, span(data, footer + 24, 20))
        r = Cursor(index)
        self.mount, self.total = r.string(), r.count(1)
        self.files, self.encoded = {}, b''
        if not self.total:
            return
        if version in (4, 8):
            for _ in range(self.total):
                name = r.string()
                offset, packed, size, method = r.take('<QQQI')
                r.read(20)
                blocks = [r.take('<QQ') for _ in range(r.count(16))] if method else []
                encrypted, block_size = r.take('<BI')
                if name in self.files or method >= len(self.methods):
                    raise ValueError('Invalid legacy Unreal PAK entry')
                self.files[name] = None
                blocks = [(start + (offset if version >= 5 else 0), end - start) for start, end in blocks]
                self.legacy[name] = offset, size, packed, method, block_size, blocks, encrypted
            return
        r.take('<Q')
        if r.take('<i'):
            r.read(36)  # Optional path-hash index; full directory index follows.
        if not r.take('<i'):
            raise ValueError('Unreal PAK has no full directory index')
        directory_offset, directory_size = r.take('<QQ')
        directory_hash = r.read(20)
        self.encoded = r.read(r.count(1))
        if r.take('<i'):
            raise ValueError('Unencoded Unreal PAK entries are not supported')
        directory = Cursor(self.verified(directory_offset, directory_size, directory_hash))
        for _ in range(directory.count(8)):
            folder = directory.string()
            for _ in range(directory.count(8)):
                name, entry = folder + directory.string(), directory.take('<i')
                if entry == -1:  # Tombstone, not a file.
                    continue
                if name in self.files or not 0 <= entry < len(self.encoded):
                    raise ValueError('Duplicate/out-of-bounds Unreal PAK directory entry')
                self.files[name] = entry
        if len(self.files) != self.total:
            raise ValueError('Unreal PAK directory/file count mismatch')

    def verified(self, offset, size, expected):
        """Validate the primary/directory index SHA-1 before trusting entry offsets."""
        raw = span(self.data, offset, size)
        if hashlib.sha1(raw).digest() != expected:
            raise ValueError('Unreal PAK index SHA-1 mismatch')
        return raw

    @contextmanager
    def read(self, name, decode_native):
        """Decode one file block by block, spilling large output into temporary storage."""
        if self.version in (4, 8):
            offset, size, packed, method, block_size, ranges, encrypted = self.legacy[name]
            blocks = len(ranges)
        else:
            r = Cursor(self.encoded, self.files[name])
            bits = r.take('<I')
            block_size = r.take('<I') if bits & 0x3f == 0x3f else (bits & 0x3f) << 11
            blocks, encrypted, method = (bits >> 6) & 0xffff, (bits >> 22) & 1, (bits >> 23) & 0x3f
            offset = r.take('<I' if bits >> 31 else '<Q')
            size = r.take('<I' if bits >> 30 & 1 else '<Q')
            packed = r.take('<I' if bits >> 29 & 1 else '<Q') if method else size
            at, ranges = offset + 57 + 16 * blocks, []
            for _ in range(blocks):
                length = packed if blocks == 1 and not encrypted else r.take('<I')
                ranges.append((at, length))
                at += (length + 15) & ~15 if encrypted else length
        if encrypted:
            raise ValueError('Encrypted Unreal PAK members are not supported')
        if method >= len(self.methods) or not self.methods[method]:
            raise ValueError('Invalid Unreal PAK compression method')
        if not method:
            yield window(self.data, offset + 53, size)
            return
        if not blocks:
            raise ValueError('Compressed Unreal PAK member has no blocks')
        block_size = block_size or (size if blocks == 1 else 0)
        if not block_size or (size + block_size - 1) // block_size != blocks:
            raise ValueError('Unreal PAK block count/size mismatch')
        consumed = 0
        with tempfile.SpooledTemporaryFile(max_size=LIMIT) as output:
            for at, length in ranges:
                raw = span(self.data, at, length)
                expected = min(block_size, size - output.tell())
                output.write(decode_block(raw, expected, self.methods[method], decode_native))
                consumed += length
            if consumed != packed or output.tell() != size:
                raise ValueError('Unreal PAK member size mismatch')
            if size <= LIMIT:
                output.seek(0)
                yield output.read()
            else:
                output.flush()
                with mmap.mmap(output.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                    yield Window(mapped)
