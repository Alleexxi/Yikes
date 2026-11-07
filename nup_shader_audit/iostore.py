"""Bounded Unreal IoStore chunk reads using the NUP's matching UTOC/UCAS members.

Layout references: CUE4Parse's UE4/IO/Objects/FIoStoreToc{Header,Resource}.cs
and FIoStoreTocCompressedBlockEntry.cs. No external parser is executed.
"""

import mmap
import tempfile
import zlib
from contextlib import contextmanager

import lz4.block
import zstandard

from .binary import LIMIT, check_range, span, unpack
from .large import Window
from .unreal_crypto import KeyProbe, decrypt

MAGIC = b'-==--==--==--==-'


def decode_block(raw, decoded, method, decode_native):
    """Decode a declared Unreal archive block and reject expansion/length mismatches."""
    if method == 'none':
        value = raw
    elif method == 'oodle' or (method == 'custom' and len(raw) >= 2
                               and raw[0] & 0x3f == 0x0c and raw[1] in (6, 10, 11, 12)):
        value = decode_native('oodle', raw, decoded)
    elif method == 'lz4':
        try:
            value = lz4.block.decompress(raw, uncompressed_size=decoded)
        except lz4.block.LZ4BlockError as exc:
            raise ValueError(f'Invalid Unreal LZ4 block: {exc}') from exc
    elif method in ('zlib', 'gzip'):
        decoder = zlib.decompressobj(31 if method == 'gzip' else 15)
        value = decoder.decompress(raw, decoded + 1)
        if not decoder.eof or decoder.unused_data:
            raise ValueError('Invalid Unreal zlib/gzip block')
    elif method == 'zstd':
        params = zstandard.get_frame_parameters(raw)
        if params.content_size not in (zstandard.CONTENTSIZE_UNKNOWN, decoded):
            raise ValueError('Unreal zstd block length mismatch')
        value = zstandard.ZstdDecompressor().decompress(raw, max_output_size=decoded)
    else:
        raise ValueError(f'Unsupported Unreal compression method {method}')
    if len(value) != decoded:
        raise ValueError('Unreal decoded block length mismatch')
    return value


class IoStore:
    """Read logical chunks through explicit compression blocks, never magic guesses."""

    def __init__(self, data, key_provider=None):
        if data[:16] != MAGIC:
            raise ValueError('Invalid IoStore TOC magic')
        check_range(data, 0, 144)
        self.data, self.version = data, data[16]
        if not 1 <= self.version <= 8:
            raise ValueError(f'Unsupported IoStore TOC version {self.version}')
        (self.header, self.count, self.block_count, self.stride, method_count,
         method_length, self.block_size, directory_size, self.parts) = unpack(data, '<9I', 20)
        if self.header < 144 or self.stride != 12 or not self.block_size:
            raise ValueError('Invalid IoStore header/block dimensions')
        self.key = None
        seeds = unpack(data, '<I', 84)[0] if self.version >= 4 else 0
        overflow = unpack(data, '<I', 96)[0] if self.version >= 5 else 0
        self.parts = max(self.parts, 1) if self.version >= 3 else 1
        self.partition_size = unpack(data, '<Q', 88)[0] if self.version >= 3 else (1 << 64) - 1
        if not self.partition_size:
            raise ValueError('Invalid IoStore partition size')
        self.offsets = self.header + 12 * self.count
        self.blocks = self.offsets + 10 * self.count + 4 * (seeds + overflow)
        methods = self.blocks + self.stride * self.block_count
        check_range(data, self.header, methods - self.header + method_count * method_length)
        if method_count and not method_length:
            raise ValueError('Invalid IoStore compression name size')
        self.methods = ['none'] + [span(data, methods + i * method_length, method_length)
                                  .rstrip(b'\0').decode('ascii').lower() for i in range(method_count)]
        if data[80] & 2:
            if key_provider is None or not directory_size:
                raise ValueError('Encrypted IoStore needs a validated directory-index key')
            directory = methods + method_count * method_length
            if data[80] & 4:
                hash_size, = unpack(data, '<I', directory)
                directory += 4 + 2 * hash_size + 20 * self.block_count
            encrypted = span(data, directory, (directory_size + 15) & ~15)
            probe = KeyProbe(encrypted, directory_size, validator=self.validate_directory)
            self.key = key_provider(probe)
            if not probe.accepts(self.key):
                raise ValueError('IoStore key did not validate its directory index')

    def validate_directory(self, raw):
        """Validate every decrypted FString, array range and directory/file reference."""
        # Imported lazily because the PAK reader shares this module's block decoder.
        from .unreal_pak import Cursor
        r = Cursor(raw)
        mount = r.string()
        if not (mount.startswith('../') or mount == '/'):
            raise ValueError('Invalid IoStore mount point')
        directories = [r.take('<4I') for _ in range(r.count(16))]
        files = [r.take('<3I') for _ in range(r.count(12))]
        strings = [r.string() for _ in range(r.count(4))]
        # UE pads the encrypted buffer to 16 bytes; the padding need not be zero.
        if len(raw) - r.offset > 15:
            raise ValueError('Unexpected IoStore directory-index trailing bytes')
        invalid = 0xffffffff
        def reference(value, count):
            return value == invalid or value < count
        for name, child, sibling, first in directories:
            if not (reference(name, len(strings)) and reference(child, len(directories))
                    and reference(sibling, len(directories)) and reference(first, len(files))):
                raise ValueError('Invalid IoStore directory reference')
        for name, next_file, chunk in files:
            if not (name < len(strings) and reference(next_file, len(files)) and chunk < self.count):
                raise ValueError('Invalid IoStore file reference')
        visited, pending, claimed = set(), ([0] if directories else []), set()
        while pending:
            index = pending.pop()
            if index in visited:
                raise ValueError('Repeated/cyclic IoStore directory')
            visited.add(index)
            _, child, sibling, first = directories[index]
            pending.extend(x for x in (child, sibling) if x != invalid)
            while first != invalid:
                if first in claimed:
                    raise ValueError('Repeated/cyclic IoStore file')
                claimed.add(first)
                first = files[first][1]
        if len(visited) != len(directories) or len(claimed) != len(files):
            raise ValueError('Unreachable IoStore directory/file entries')

    def chunk(self, index):
        """Return one big-endian 40-bit logical offset/length pair."""
        if not 0 <= index < self.count:
            raise ValueError('IoStore chunk index out of bounds')
        raw = span(self.data, self.offsets + index * 10, 10)
        offset, size = int.from_bytes(raw[:5], 'big'), int.from_bytes(raw[5:], 'big')
        if size and (offset + size - 1) // self.block_size >= self.block_count:
            raise ValueError('IoStore chunk exceeds compression block table')
        return offset, size

    def block(self, index):
        """Validate a packed 40/24/24/8-bit block entry before reading its payload."""
        if not 0 <= index < self.block_count:
            raise ValueError('IoStore block index out of bounds')
        raw = span(self.data, self.blocks + index * self.stride, 12)
        offset = int.from_bytes(raw[:5], 'little')
        size, decoded = int.from_bytes(raw[5:8], 'little'), int.from_bytes(raw[8:11], 'little')
        partition, local = divmod(offset, self.partition_size)
        physical = (size + 15) & ~15 if self.key else size
        if (partition >= self.parts or not size or not 0 < decoded <= self.block_size
                or raw[11] >= len(self.methods) or local + physical > self.partition_size):
            raise ValueError('Invalid IoStore compression block range/method')
        return partition, local, size, decoded, self.methods[raw[11]]

    def entries(self, partition):
        """Assign each chunk to its first physical partition, retaining all chunk types."""
        for index in range(self.count):
            offset, size = self.chunk(index)
            owner = self.block(offset // self.block_size)[0] if size else 0
            if owner == partition:
                yield index, span(self.data, self.header + index * 12, 12), size

    @contextmanager
    def read(self, index, read_partition, decode_native):
        """Reassemble one chunk in bounded memory; large chunks spill and are deleted."""
        offset, size = self.chunk(index)
        with tempfile.SpooledTemporaryFile(max_size=LIMIT) as output:
            end = offset + size
            for block in range(offset // self.block_size, (end - 1) // self.block_size + 1 if size else 0):
                partition, local, packed, decoded, method = self.block(block)
                stored = (packed + 15) & ~15 if self.key else packed
                raw = read_partition(partition, local, stored)
                if len(raw) != stored:
                    raise ValueError('Truncated IoStore compression block')
                if self.key:
                    raw = decrypt(raw, self.key)[:packed]
                value = decode_block(raw, decoded, method, decode_native)
                start = max(offset - block * self.block_size, 0)
                stop = min(end - block * self.block_size, decoded)
                if not 0 <= start < stop <= decoded:
                    raise ValueError('IoStore chunk slice exceeds its block')
                output.write(value[start:stop])
            if output.tell() != size:
                raise ValueError('IoStore chunk length mismatch')
            if size <= LIMIT:
                output.seek(0)
                yield output.read()
            else:
                output.flush()
                with mmap.mmap(output.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                    yield Window(mapped)
