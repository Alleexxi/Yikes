"""Unreal IoStore shader libraries and size-delimited shader groups.

The version-one header and packed shader descriptor were cross-checked against
retoc/src/shader_library.rs and Epic's ShaderCodeArchive.h API documentation.
"""

from .binary import span, unpack
from .iostore import decode_block
from .unreal_pak import Cursor


def library(data):
    """Parse with the 20-byte (SHA-1) hash tables, then the 8-byte ones of newer engine versions."""
    try:
        return _library(data, 20)
    except ValueError as exc:
        try:
            return _library(data, 8)
        except ValueError:
            raise exc from None


def _library(data, hash_size):
    """Resolve every shader to one declared group and a nonoverlapping byte range."""
    r = Cursor(data)
    if r.take('<I') != 1:
        raise ValueError('Unsupported IoStore shader-library version')
    def array(fmt, width):
        return [r.take(fmt) for _ in range(r.count(width))]
    maps = [r.read(hash_size) for _ in range(r.count(hash_size))]
    hashes = [r.read(hash_size) for _ in range(r.count(hash_size))]
    groups = [r.read(12) for _ in range(r.count(12))]
    map_entries = array('<II', 8)
    entries = array('<Q', 8)
    descriptors = array('<4I', 16)
    indices = array('<I', 4)
    if (r.offset != len(data) or len(maps) != len(map_entries) or len(hashes) != len(entries)
            or len(groups) != len(descriptors) or len(set(groups)) != len(groups)):
        raise ValueError('IoStore shader-library array counts/trailing bytes mismatch')
    if any(index >= len(entries) for index in indices):
        raise ValueError('IoStore shader index exceeds shader table')
    for first, count in map_entries:
        if first + count > len(indices):
            raise ValueError('IoStore shader-map indices exceed table')
    result, claimed = {}, set()
    for group, (first, count, size, packed) in enumerate(descriptors):
        if (not count or not size or not 0 < packed <= size or first + count > len(indices)
                or groups[group][-1] != 9):
            raise ValueError('Invalid IoStore shader-group descriptor')
        rows = []
        for index in indices[first:first + count]:
            entry = entries[index]
            frequency, owner, offset = entry & 15, entry >> 4 & 0x3fffffff, entry >> 34
            if owner != group or index in claimed or offset >= size:
                raise ValueError('Conflicting IoStore shader group/offset')
            claimed.add(index)
            rows.append((offset, frequency, index))
        rows.sort()
        if rows[0][0] != 0 or any(a[0] >= b[0] for a, b in zip(rows, rows[1:])):
            raise ValueError('Overlapping/gapped IoStore shader-group starts')
        ranges = [(offset, (rows[i + 1][0] if i + 1 < len(rows) else size) - offset,
                   frequency, index) for i, (offset, frequency, index) in enumerate(rows)]
        result[groups[group]] = size, packed, ranges
    if len(claimed) != len(entries):
        raise ValueError('IoStore library has shaders without a group')
    return result


def group_programs(data, descriptor, decode_native):
    """Decode the group's second compression layer and yield exact individual programs."""
    size, packed, ranges = descriptor
    if len(data) != packed:
        raise ValueError('IoStore shader-group packed length mismatch')
    if packed != size:
        if data[:1] == b'\x8c':
            method = 'oodle'
        elif data[:4] == bytes.fromhex('28b52ffd'):
            method = 'zstd'
        elif len(data) >= 2 and data[0] & 15 == 8 and int.from_bytes(data[:2], 'big') % 31 == 0:
            method = 'zlib'
        else:
            method = 'lz4'
        data = decode_block(data[:], size, method, decode_native)
    for offset, length, frequency, index in ranges:
        yield index, frequency, span(data, offset, length)
