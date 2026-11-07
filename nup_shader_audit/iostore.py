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

MAGIC = b'-==--==--==--==-'


def decode_block(raw, decoded, method, decode_native):
    """Decode a declared Unreal archive block and reject expansion/length mismatches."""
    if method == 'none':
        value = raw
    elif method == 'oodle' or (method == 'custom' and len(raw) >= 2
                               and raw[0] & 0x3f == 0x0c and raw[1] in (6, 10, 11, 12)):
        value = decode_native('oodle', raw, decoded)
    elif method == 'lz4':
        value = lz4.block.decompress(raw, uncompressed_size=decoded)
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

    def __init__(self, data):
        if data[:16] != MAGIC:
            raise ValueError('Invalid IoStore TOC magic')
        check_range(data, 0, 144)
        self.data, self.version = data, data[16]
        if not 1 <= self.version <= 8:
            raise ValueError(f'Unsupported IoStore TOC version {self.version}')
        (self.header, self.count, self.block_count, self.stride, method_count,
         method_length, self.block_size, _, self.parts) = unpack(data, '<9I', 20)
        if self.header < 144 or self.stride != 12 or not self.block_size:
            raise ValueError('Invalid IoStore header/block dimensions')
        if data[80] & 2:
            raise ValueError('Encrypted IoStore containers are not supported')
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
        if (partition >= self.parts or not size or not 0 < decoded <= self.block_size
                or raw[11] >= len(self.methods) or local + size > self.partition_size):
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
                raw = read_partition(partition, local, packed)
                if len(raw) != packed:
                    raise ValueError('Truncated IoStore compression block')
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
