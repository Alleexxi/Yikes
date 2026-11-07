"""Bounded ZIP/VZIP reads with CRC verification and temporary large-member storage.

VZIP's chained LZ4 layout was cross-checked against nxnative's shader_split.py.
Archive names remain provenance labels; no member is extracted to a filesystem path.
"""

import io
import mmap
import tempfile
import zipfile
import zlib
from contextlib import contextmanager

import lz4.block

from .binary import LIMIT, check_range, span, unpack
from .large import Window


class ArchiveStream(io.RawIOBase):
    """Expose a bounded asset with standard file seek and short-read behavior."""

    def __init__(self, data):
        self.data, self.position = data, 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=0):
        base = {0: 0, 1: self.position, 2: len(self.data)}.get(whence)
        if base is None or base + offset < 0:
            raise ValueError('Invalid ZIP seek')
        self.position = base + offset
        return self.position

    def read(self, size=-1):
        end = len(self.data) if size is None or size < 0 else min(len(self.data), self.position + size)
        value = self.data[self.position:max(self.position, end)]
        self.position += len(value)
        return value


class ZipArchive:
    """Keep the central directory open while decoding one CRC-checked member at a time."""

    def __init__(self, data):
        self.data = data
        self.archive = zipfile.ZipFile(ArchiveStream(data))
        self.viper = data[:4] == b'VZIP'

    def close(self):
        self.archive.close()

    @contextmanager
    def read(self, info):
        """Decode ordinary ZIP members or VZIP's dictionary-linked 64 KiB LZ4 chunks."""
        if info.flag_bits & 1:
            raise ValueError('Encrypted ZIP members are not supported')
        with tempfile.SpooledTemporaryFile(max_size=LIMIT) as output:
            if self.viper and info.compress_type == 0 and info.compress_size != info.file_size:
                header = span(self.data, info.header_offset, 30)
                if header[:4] != b'PK\x03\x04':
                    raise ValueError('Invalid VZIP local header')
                names, extra = unpack(header, '<HH', 26)
                at = info.header_offset + 30 + names + extra
                check_range(self.data, at, info.compress_size)
                end, previous, crc = at + info.compress_size, b'', 0
                while output.tell() < info.file_size:
                    length, = unpack(self.data, '<I', at)
                    at += 4
                    want = min(65536, info.file_size - output.tell())
                    if not 0 < length <= end - at:
                        raise ValueError('VZIP LZ4 chunk exceeds member bounds')
                    packed = span(self.data, at, length)
                    value = (packed if length == want else
                             lz4.block.decompress(packed, uncompressed_size=want, dict=previous))
                    if len(value) != want:
                        raise ValueError('VZIP decoded chunk length mismatch')
                    output.write(value)
                    previous, at = value, at + length
                    crc = zlib.crc32(value, crc)
                if at != end or crc & 0xffffffff != info.CRC:
                    raise ValueError('VZIP member length/CRC mismatch')
            else:
                with self.archive.open(info) as member:
                    while True:
                        value = member.read(1024 * 1024)
                        if not value:
                            break
                        if output.tell() + len(value) > info.file_size:
                            raise ValueError('ZIP member exceeds its declared size')
                        output.write(value)
            if output.tell() != info.file_size:
                raise ValueError('ZIP decoded member length mismatch')
            if info.file_size <= LIMIT:
                output.seek(0)
                yield output.read()
            else:
                output.flush()
                with mmap.mmap(output.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                    yield Window(mapped)
