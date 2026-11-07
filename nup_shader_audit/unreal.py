"""Length-delimited Unreal native records and inline FShaderMapResourceCode tables.

The code/control ordering and paired shader-table counts were cross-checked against
nxnative's dm/gfx/tools/uepak.py (sage_record and shader_map_entries).
"""

from .binary import check_range, unpack

CONTROL = bytes.fromhex('34127698c9000000')
OODLE = (b'\x8c\x06', b'\x8c\x0a', b'\x8c\x0b', b'\x8c\x0c')


def record(data, control):
    """Validate the two length prefixes and the native header's matching code size."""
    if control < 8 or data[control:control + 8] != CONTROL:
        raise ValueError('Missing Unreal native control record')
    control_size, = unpack(data, '<I', control - 4)
    code_size, = unpack(data, '<I', control + 0x44)
    code = control - 4 - code_size
    if code < 4 or not 0x58 <= control_size < 0x10000:
        raise ValueError('Invalid Unreal native record sizes')
    check_range(data, control, control_size)
    if unpack(data, '<I', code - 4)[0] != code_size:
        raise ValueError('Unreal native code length prefixes disagree')
    return control_size, code, code_size


def shader_tables(data):
    """Yield complete tables whose repeated count, hash array and entry bounds agree."""
    offsets = set()
    for magic in OODLE:
        at = data.find(magic)
        while at >= 0:
            offsets.add(at)
            at = data.find(magic, at + 2)
    for start in sorted(offsets):
        if start < 12:
            continue
        count, = unpack(data, '<I', start - 8)
        hashes = start - 8 - count * 20
        if not count or hashes < 4 or unpack(data, '<I', hashes - 4)[0] != count:
            continue
        rows, at = [], start - 4
        for _ in range(count):
            if at + 4 > len(data):
                break
            packed, = unpack(data, '<I', at)
            tail = at + 4 + packed
            if not packed or tail + 5 > len(data):
                break
            size, frequency = unpack(data, '<IB', tail)
            if not packed <= size <= 0x7fffffff or frequency > 15:
                break
            rows.append((at + 4, packed, size, frequency))
            at = tail + 5
        if len(rows) == count:
            # A failed candidate must not hide another table inside it. The caller
            # validates decoded shader structure before consuming these ranges.
            yield rows
