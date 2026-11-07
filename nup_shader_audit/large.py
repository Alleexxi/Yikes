"""Scan large assets through bounded views and temporary mapped decompression output."""

import hashlib
import mmap
import tempfile
import zlib
from contextlib import contextmanager

import zstandard
import lz4.frame

from .binary import LIMIT, span, unpack

CHUNK = 1024 * 1024


class Window:
    """A read-only range of bytes or a mapping, without copying the entire member."""

    def __init__(self, data, offset=0, size=None):
        size = len(data) - offset if size is None else size
        if offset < 0 or size < 0 or offset > len(data) - size:
            raise ValueError('Mapped member range exceeds its container')
        if isinstance(data, Window):
            offset += data.offset
            data = data.data
        self.data, self.offset, self.size = data, offset, size

    def __len__(self):
        return self.size

    def __getitem__(self, key):
        if isinstance(key, slice):
            start, stop, step = key.indices(self.size)
            if step != 1:
                raise ValueError('Strided asset views are unsupported')
            return self.data[self.offset + start:self.offset + max(start, stop)]
        if key < 0:
            key += self.size
        if not 0 <= key < self.size:
            raise IndexError(key)
        return self.data[self.offset + key]

    def find(self, pattern, start=0, end=None):
        start, end, _ = slice(start, end).indices(self.size)
        at = self.data.find(pattern, self.offset + start, self.offset + end)
        return at - self.offset if at >= 0 else -1


def window(data, offset, size):
    """Copy small members for speed and retain a bounded view for large members."""
    view = Window(data, offset, size)
    return view[:] if size <= LIMIT else view


def digest(data):
    """Hash mapped members incrementally, retaining the existing bytes fast path."""
    if isinstance(data, bytes):
        return hashlib.sha256(data).hexdigest()
    if getattr(data, 'decoded_hash', None) is not None:
        return data.decoded_hash
    value = hashlib.sha256()
    for at in range(0, len(data), CHUNK):
        value.update(data[at:at + CHUNK])
    return value.hexdigest()


class WindowReader:
    """Expose a bounded mapped range as a streaming decompressor input."""

    def __init__(self, data):
        self.data, self.position = data, 0

    def read(self, size):
        value = self.data[self.position:self.position + size]
        self.position += len(value)
        return value


def frame_size(data):
    """Find a complete zstd frame structurally, including its optional checksum."""
    params = zstandard.get_frame_parameters(data[:18])
    at = zstandard.frame_header_size(data[:18])
    while True:
        if at + 3 > len(data):
            raise ValueError('Truncated zstd block header')
        header = int.from_bytes(data[at:at + 3], 'little')
        kind, size = (header >> 1) & 3, header >> 3
        if kind == 3:
            raise ValueError('Reserved zstd block type')
        at += 3 + (1 if kind == 1 else size)
        if at > len(data):
            raise ValueError('Truncated zstd block')
        if header & 1:
            break
    at += 4 if params.has_checksum else 0
    if at > len(data):
        raise ValueError('Truncated zstd checksum')
    return at


@contextmanager
def decoded_zstd(data, dictionary=None, expected_size=None):
    """Decode one complete frame; large output lives in a deleted-on-close temp file."""
    params = zstandard.get_frame_parameters(data[:18])
    declared = params.content_size
    known = declared not in (zstandard.CONTENTSIZE_UNKNOWN, zstandard.CONTENTSIZE_ERROR)
    if expected_size is not None and known and declared != expected_size:
        raise ValueError('zstd content size disagrees with container member')
    expected = expected_size if expected_size is not None else declared if known else None
    decoder = zstandard.ZstdDecompressor(dict_data=dictionary)
    if expected is not None and expected <= LIMIT:
        packed = data if isinstance(data, bytes) else Window(data, 0, frame_size(data))[:]
        raw = decoder.decompress(packed, max_output_size=expected)
        if len(raw) != expected:
            raise ValueError('Decoded zstd size mismatch')
        yield raw
        return
    # Explicit frame bounds preserve truncated-frame detection with the streaming API.
    source = WindowReader(Window(data, 0, frame_size(data)))
    with tempfile.TemporaryFile() as temporary:
        total = 0
        decoded_hash = hashlib.sha256()
        with decoder.stream_reader(source) as reader:
            while True:
                block = reader.read(CHUNK)
                if not block:
                    break
                total += len(block)
                if expected is not None and total > expected:
                    raise ValueError('Decoded zstd exceeds declared member size')
                temporary.write(block)
                decoded_hash.update(block)
        if expected is not None and total != expected:
            raise ValueError('Decoded zstd size mismatch')
        if not total:
            yield b''
        elif total <= LIMIT:
            temporary.seek(0)
            yield temporary.read()
        else:
            temporary.flush()
            with mmap.mmap(temporary.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                value = Window(mapped)
                value.decoded_hash = decoded_hash.hexdigest()
                yield value


@contextmanager
def decoded_zlib(data, expected):
    """Decode a complete length-delimited zlib stream with bounded output chunks."""
    decoder = zlib.decompressobj()
    with tempfile.SpooledTemporaryFile(max_size=LIMIT) as output:
        at, pending = 0, b''
        while not decoder.eof:
            if not pending:
                pending = data[at:at + CHUNK]
                at += len(pending)
                if not pending:
                    raise ValueError('Truncated zlib stream')
            value = decoder.decompress(pending, CHUNK)
            pending = decoder.unconsumed_tail
            if output.tell() + len(value) > expected:
                raise ValueError('Zlib output exceeds declared size')
            output.write(value)
        if at != len(data) or decoder.unused_data or output.tell() != expected:
            raise ValueError('Zlib stream length/decoded size mismatch')
        if expected <= LIMIT:
            output.seek(0)
            yield output.read()
        else:
            output.flush()
            with mmap.mmap(output.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                yield Window(mapped)


@contextmanager
def decoded_lz4(data):
    """Decode one LZ4 frame in bounded chunks, spilling large results to a mapping."""
    info = lz4.frame.get_frame_info(data[:19])
    expected = info['content_size'] or None
    decoder = lz4.frame.LZ4FrameDecompressor()
    with tempfile.SpooledTemporaryFile(max_size=LIMIT) as temporary:
        total, position = 0, 0
        hashed = hashlib.sha256()
        while not decoder.eof:
            if decoder.needs_input:
                packed = data[position:position + CHUNK]
                if not packed:
                    raise ValueError('Truncated LZ4 frame')
                position += len(packed)
            else:
                packed = b''
            block = decoder.decompress(packed, max_length=CHUNK)
            total += len(block)
            if expected is not None and total > expected:
                raise ValueError('LZ4 output exceeds declared size')
            hashed.update(block)
            temporary.write(block)
        if expected is not None and total != expected:
            raise ValueError('LZ4 output size mismatch')
        if total <= LIMIT:
            temporary.seek(0)
            yield temporary.read()
        else:
            temporary.flush()
            with mmap.mmap(temporary.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                value = Window(mapped)
                value.decoded_hash = hashed.hexdigest()
                yield value


@contextmanager
def decoded_yaz0(data, small_decoder):
    """Retain the fast small Yaz0 decoder; large output needs only a 4 KiB history."""
    size, = unpack(data, '>I', 4)
    if size <= LIMIT:
        yield small_decoder(data)
        return
    ring, block = bytearray(4096), bytearray()
    produced, position, mask, flags = 0, 16, 0, 0
    with tempfile.TemporaryFile() as temporary:
        while produced < size:
            if not mask:
                flags = span(data, position, 1)[0]
                position += 1
                mask = 128
            if flags & mask:
                values = span(data, position, 1)
                position += 1
                length, distance = 1, 0
            else:
                a, b = span(data, position, 2)
                position += 2
                length, distance = a >> 4, ((a & 15) << 8 | b) + 1
                if not length:
                    length = span(data, position, 1)[0] + 18
                    position += 1
                else:
                    length += 2
                if distance > produced or produced + length > size:
                    raise ValueError('Invalid Yaz0 backreference')
            for _ in range(length):
                value = ring[(produced - distance) & 4095] if distance else values[0]
                ring[produced & 4095] = value
                block.append(value)
                produced += 1
                if len(block) >= CHUNK:
                    temporary.write(block)
                    block.clear()
            mask >>= 1
        temporary.write(block)
        temporary.flush()
        with mmap.mmap(temporary.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
            yield Window(mapped)
