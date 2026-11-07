"""Traverse Game Freak ONEPACK archives and their FlatBuffers file records."""

from .binary import span, unpack
from .large import Window, window


def root(data, at=0):
    """Read a bounded FlatBuffers root offset."""
    relative, = unpack(data, '<I', at)
    table = at + relative
    span(data, table, 4)
    return table


def field(data, table, index):
    """Find an optional field through its validated vtable, including shared vtables."""
    distance, = unpack(data, '<i', table)
    vtable = table - distance
    length, object_size = unpack(data, '<HH', vtable)
    if length < 4 or length % 2 or object_size < 4:
        raise ValueError('Invalid FlatBuffers vtable')
    span(data, vtable, length)
    span(data, table, object_size)
    if 4 + 2 * index + 2 > length:
        return None
    offset, = unpack(data, '<H', vtable + 4 + 2 * index)
    if not offset:
        return None
    if not 4 <= offset < object_size:
        raise ValueError('FlatBuffers field exceeds table')
    return table + offset


def vector(data, table, index, stride):
    """Validate a vector before iterating its members; missing vectors are empty."""
    pointer = field(data, table, index)
    if pointer is None:
        return 0, 0
    relative, = unpack(data, '<I', pointer)
    start = pointer + relative
    count, = unpack(data, '<I', start)
    start += 4
    if start > len(data) or count > (len(data) - start) // stride:
        raise ValueError('FlatBuffers vector exceeds archive')
    return start, count


def entries(data):
    """Yield every declared pack file, without requiring filenames or copying the archive."""
    if data[:8] != b'ONEPACK\0':
        raise ValueError('Missing ONEPACK signature')
    metadata, = unpack(data, '<Q', 8)
    table = root(data, metadata)
    hashes, count = vector(data, table, 0, 8)
    offsets, offset_count = vector(data, table, 1, 8)
    if count != offset_count:
        raise ValueError('ONEPACK hash/offset count mismatch')
    packs = []
    for i in range(count):
        offset, = unpack(data, '<Q', offsets + 8 * i)
        hash_value, = unpack(data, '<Q', hashes + 8 * i)
        if not 16 <= offset < metadata:
            raise ValueError('ONEPACK pack offset exceeds data region')
        packs.append((offset, hash_value))
    packs.sort()
    if len({offset for offset, _ in packs}) != count:
        raise ValueError('Duplicate ONEPACK pack offset')
    for index, (offset, pack_hash) in enumerate(packs):
        end = packs[index + 1][0] if index + 1 < count else metadata
        pack = Window(data, offset, end - offset)
        table = root(pack)
        file_hashes, file_count = vector(pack, table, 0, 8)
        files, record_count = vector(pack, table, 1, 4)
        if file_count != record_count:
            raise ValueError('Trinity pack hash/file count mismatch')
        for i in range(file_count):
            entry = root(pack, files + 4 * i)
            comp_at, size_at = field(pack, entry, 1), field(pack, entry, 3)
            compression = unpack(pack, '<b', comp_at)[0] if comp_at is not None else 0
            size = unpack(pack, '<Q', size_at)[0] if size_at is not None else 0
            start, stored = vector(pack, entry, 4, 1)
            file_hash, = unpack(pack, '<Q', file_hashes + 8 * i)
            yield pack_hash, file_hash, compression, size, window(pack, start, stored)
