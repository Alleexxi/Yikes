"""Length-delimited Unreal native records and inline FShaderMapResourceCode tables.

The code/control ordering and paired shader-table counts were cross-checked against
nxnative's dm/gfx/tools/uepak.py (sage_record and shader_map_entries).
"""

from .binary import check_range, unpack

CONTROL = bytes.fromhex('34127698c9000000')
OODLE = (b'\x8c\x06', b'\x8c\x0a', b'\x8c\x0b', b'\x8c\x0c')
# A zlib stream's two header bytes (default, best, no and fast compression levels). Candidates
# only: a table still needs its counts, hashes and every row to fit before it is used.
ZLIB = tuple(bytes((0x78, level)) for level in (0x01, 0x5e, 0x9c, 0xda))


def record(data, control):
    """Validate the two length prefixes and the native header's matching code size."""
    if control < 8 or data[control:control + 8] != CONTROL:
        raise ValueError('Missing Unreal native control record')
    control_size, = unpack(data, '<I', control - 4)
    code_size, = unpack(data, '<I', control + 0x44)
    code = control - 4 - code_size
    # Control records run to over 100 KiB for large compute shaders; both length prefixes and the
    # code length must still agree and fit.
    if code < 4 or not 0x58 <= control_size <= 0x1000000:
        raise ValueError('Invalid Unreal native record sizes')
    check_range(data, control, control_size)
    if unpack(data, '<I', code - 4)[0] != code_size:
        raise ValueError('Unreal native code length prefixes disagree')
    return control_size, code, code_size


def adjacent(data, control):
    """Validate a native control record followed directly by its code (ray-tracing modules)."""
    if control < 0 or data[control:control + 8] != CONTROL:
        raise ValueError('Missing Unreal native control record')
    own, = unpack(data, '<I', control + 0x30)
    length, = unpack(data, '<I', control + 0x44)
    if not 0x58 <= own <= 0x1000000 or not length or length % 16:
        raise ValueError('Invalid adjacent Unreal native record sizes')
    check_range(data, control, own + length)
    return own, control + own, length


def shader_tables(data):
    """Yield complete tables whose repeated count, hash array and entry bounds agree."""
    offsets = set()
    for magic in OODLE + ZLIB:
        at = data.find(magic)
        while at >= 0:
            offsets.add(at)
            at = data.find(magic, at + 2)
    # UE's LSLG shader records retain their magic in LZ4's initial literal run.
    # Use that declared format instead of treating arbitrary integers in every
    # export as potential table counts. Both counts and all rows still must fit.
    at = data.find(b'LSLG')
    while at >= 0:
        offsets.add(at)  # A stored, uncompressed first record.
        if at and 4 <= data[at - 1] >> 4 < 15:
            offsets.add(at - 1)
        if at >= 2 and data[at - 1] < 255:
            # The literal length is 15 plus extension bytes (255s then one smaller byte), after
            # the token. A token can itself be 0xff (15 literals, 19+ match), so every byte of
            # the run is a candidate; each still has to fit a whole table.
            token = at - 2
            for _ in range(16384):
                if token < 0:
                    break
                if data[token] >> 4 == 15:
                    offsets.add(token)
                if data[token] != 255:
                    break
                token -= 1
        at = data.find(b'LSLG', at + 4)
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
        if len(rows) == count and count == 1:
            # Two coincidental integers in a package's export list read as a one-row table, and
            # nothing else cross-checks a single row. A compressed stream shorter than a codec
            # header or expanding a thousandfold is not a shader.
            _, packed, size, _ = rows[0]
            if packed != size and (packed < 16 or size > 1024 * packed):
                continue
        if len(rows) == count:
            # A failed candidate must not hide another table inside it. The caller
            # validates decoded shader structure before consuming these ranges.
            yield rows
