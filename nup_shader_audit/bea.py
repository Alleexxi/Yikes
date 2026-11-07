"""Read NintendoWare Bezel Engine archive entries without scanning compressed bytes."""

from .binary import check_range, span, unpack
from .large import window


def members(data):
    """Yield names, packed data and declared lengths from pointer and inline ASST tables."""
    count, array = unpack(data, '<QQ', 0x20)
    if array > len(data) or count > len(data) // 8:
        raise ValueError('BEA entry array exceeds archive')
    inline = data[array:array + 4] == b'ASST'
    if not inline:
        check_range(data, array, count * 8)
    at = array
    for i in range(count):
        if not inline:
            at, = unpack(data, '<Q', array + i * 8)
        if data[at:at + 4] != b'ASST':
            raise ValueError('Missing BEA ASST entry signature')
        size = unpack(data, '<I', at + 4)[0] if inline else 0x30
        if size < 0x30 or size > len(data) - at:
            raise ValueError('Invalid BEA ASST entry size')
        stored, length = unpack(data, '<II', at + 0x14)
        offset, name_offset = unpack(data, '<QQ', at + size - 16)
        name_size, = unpack(data, '<H', name_offset)
        name = span(data, name_offset + 2, name_size).decode('utf-8', 'replace')
        yield name, window(data, offset, stored), length
        if inline:
            at += size
