"""Serialized Unreal shader-code archives (`.ushaderbytecode`, FSerializedShaderArchive v2).

The table layout follows nxnative's uepak.py `archive()` (UE 4.26 and later without IoStore):
version, shader-map hashes, shader hashes, shader-map entries, shader entries, preload entries,
shader indices, then the code those entries point into. Every table is bounds-checked and every
shader must be referenced by a map, lie inside the code and not overlap another one.
"""

import struct

from .binary import span
from .iostore import decode_block
from .unreal_pak import Cursor

VERSION = 2


def parse(data):
    """Return (shaders, code_start): shaders are (offset, packed, raw size, frequency, hash)."""
    r = Cursor(data)
    if r.take('<I') != VERSION:
        raise ValueError('Unsupported serialized shader-code archive version')
    map_hashes = r.count(20)
    r.read(20 * map_hashes)
    shader_count = r.count(20)
    hashes = [r.read(20) for _ in range(shader_count)]
    maps = [r.take('<4I') for _ in range(r.count(16))]
    shaders = [r.take('<QIIB') for _ in range(r.count(17))]
    r.read(16 * r.count(16))  # Preload ranges only serve the engine's file cache.
    indices = [r.take('<I') for _ in range(r.count(4))]
    code = r.offset
    if len(maps) != map_hashes or len(shaders) != shader_count:
        raise ValueError('Shader-code archive table counts disagree')
    if any(index >= shader_count for index in indices):
        raise ValueError('Shader-code archive index exceeds shader table')
    referenced = set()
    for first, count, _, _ in maps:
        if first + count > len(indices):
            raise ValueError('Shader-code archive map indices exceed table')
        referenced.update(indices[first:first + count])
    if len(referenced) != shader_count:
        raise ValueError('Shader-code archive has shaders no shader map uses')
    end = 0
    for offset, packed, raw, frequency in sorted(shaders):
        if not packed or not raw or packed > raw or frequency > 15 or offset < end:
            raise ValueError('Invalid or overlapping shader-code archive entry')
        end = offset + packed
    if end > len(data) - code:
        raise ValueError('Shader-code archive entry exceeds the file')
    return [(offset, packed, raw, frequency, hashes[i])
            for i, (offset, packed, raw, frequency) in enumerate(shaders)], code


def looks_like(data):
    """Recognize an anonymous archive (an IoStore chunk has no name) by a fully valid layout."""
    if len(data) < 64 or data[:4] != VERSION.to_bytes(4, 'little'):
        return False
    count = int.from_bytes(data[4:8], 'little')
    if count > (len(data) - 8) // 20:
        return False
    try:
        shaders, _ = parse(data)
    except (ValueError, struct.error):
        return False
    return bool(shaders)  # An empty layout is just zeros that happen to start with a two.


def program(data, shader, code, decode_native):
    """Decode one shader entry to its exact declared raw size."""
    offset, packed, raw, _, _ = shader
    value = span(data, code + offset, packed)
    if packed == raw:
        return value
    if value[:1] == bytes([0x8c]):
        method = 'oodle'
    elif value[:4] == bytes.fromhex('28b52ffd'):
        method = 'zstd'
    elif len(value) >= 2 and value[0] & 15 == 8 and int.from_bytes(value[:2], 'big') % 31 == 0:
        method = 'zlib'
    else:
        method = 'lz4'
    return decode_block(value[:], raw, method, decode_native)
