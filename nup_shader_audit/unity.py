"""UnityFS members, serialized shader objects and NVN/NVN2 stage records.

UnityPy 1.25.4 supplies serialized-file metadata and versioned type trees. Bundle,
subprogram and stage boundaries are checked here before original bytes are stored.
Layout references: UnityPy's BundleFile/ShaderConverter and nxnative's unityfs.py.
"""

import io
import lzma
import mmap
import re
import struct
import tempfile
from contextlib import contextmanager

import lz4.block

from .binary import LIMIT, check_range, span, unpack
from .large import Window, window

CONTROL = bytes.fromhex('34127698')
STAGES = ('vs', 'ps', 'gs', 'hs', 'ds', 'cs', 'ts', 'ms', 'rt')
PASS_STAGES = {'progVertex': 'vs', 'progFragment': 'ps', 'progGeometry': 'gs',
               'progHull': 'hs', 'progDomain': 'ds', 'progRayTracing': 'rt'}


class AssetStream(io.RawIOBase):
    """Give UnityPy seekable access to a bounded asset/object without copying it."""

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
        if base is None or not 0 <= base + offset <= len(self.data):
            raise ValueError('Unity reader seek exceeds asset bounds')
        self.position = base + offset
        return self.position

    def read(self, size=-1):
        if size is None or size < 0:
            size = len(self.data) - self.position
        value = span(self.data, self.position, size)
        self.position += size
        return value


class Cursor:
    """Read explicitly bounded Unity binary tables in either byte order."""

    def __init__(self, data, endian='>', offset=0):
        self.data, self.endian, self.offset = data, endian, offset

    def read(self, size):
        result = span(self.data, self.offset, size)
        self.offset += size
        return result

    def take(self, fmt):
        values = struct.unpack(self.endian + fmt, self.read(struct.calcsize(self.endian + fmt)))
        return values[0] if len(values) == 1 else values

    def align(self, amount=4):
        self.read(-self.offset % amount)

    def count(self, minimum=4):
        count = self.take('i')
        if not 0 <= count <= (len(self.data) - self.offset) // minimum:
            raise ValueError('Unity array count exceeds its containing record')
        return count

    def cstring(self):
        end = self.data.find(b'\0', self.offset)
        if end < 0:
            raise ValueError('Unterminated Unity string')
        value = self.read(end - self.offset + 1)
        return value[:-1].decode('utf-8', 'replace')

    def strings(self):
        for _ in range(self.count()):
            self.read(self.count(1))
            self.align()


def decode(raw, size, kind):
    """Decode a bounded Unity block and require its exact declared output length."""
    if kind == 0:
        value = raw
    elif kind in (2, 3):
        if size > 255 * len(raw):
            raise ValueError('Unity LZ4 declared output exceeds the block expansion bound')
        value = lz4.block.decompress(raw, uncompressed_size=size)
    elif kind == 1:
        properties = span(raw, 0, 5)
        lc, lp, pb = properties[0] % 9, properties[0] // 9 % 5, properties[0] // 45
        dictionary, = unpack(properties, '<I', 1)
        decoder = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[{
            'id': lzma.FILTER_LZMA1, 'dict_size': dictionary, 'lc': lc, 'lp': lp, 'pb': pb}])
        value = decoder.decompress(raw[5:], max_length=size + 1)
        if decoder.unused_data:
            raise ValueError('Unity LZMA block has trailing data')
    else:
        raise ValueError(f'Unsupported Unity compression {kind}')
    if len(value) != size:
        raise ValueError('Unity decoded block length mismatch')
    return value


@contextmanager
def bundle_members(data):
    """Reassemble UnityFS blocks in temporary storage and yield bounded file views."""
    r = Cursor(data)
    if r.read(8) != b'UnityFS\0':
        raise ValueError('Invalid UnityFS signature')
    format_version = r.take('I')
    if not 6 <= format_version <= 8:
        raise ValueError(f'Unsupported UnityFS version {format_version}')
    r.cstring()
    engine = r.cstring()
    size, packed_size, info_size, flags = r.take('QIII')
    if size != len(data) or flags & ~0x3ff:
        raise ValueError('Invalid/encrypted UnityFS bundle header')
    version = tuple(int(v) for v in re.findall(r'\d+', engine)[:3])
    old_flags = (version < (2020,) or (version[0] == 2020 and version < (2020, 3, 34))
                 or (version[0] == 2021 and version < (2021, 3, 2))
                 or (version[0] == 2022 and version < (2022, 1, 1)))
    if old_flags and flags & 0x200:
        raise ValueError('Encrypted UnityFS bundle is not supported')
    if format_version >= 7 or (version[:2] == (2019, 4) and version >= (2019, 4, 15)):
        r.align(16)
    payload_end = len(data) - packed_size if flags & 0x80 else len(data)
    packed = span(data, payload_end, packed_size) if flags & 0x80 else r.read(packed_size)
    info = Cursor(decode(packed, info_size, flags & 0x3f), offset=16)
    blocks = [info.take('IIH') for _ in range(info.count(10))]
    nodes = []
    names = set()
    for _ in range(info.count(21)):
        offset, length, node_flags = info.take('QQI')
        name = info.cstring()
        if name in names:
            raise ValueError('Duplicate UnityFS node name')
        names.add(name)
        nodes.append((name, offset, length))
    if not old_flags and flags & 0x200:
        r.align(16)
    with tempfile.SpooledTemporaryFile(max_size=LIMIT) as output:
        for unpacked, packed, block_flags in blocks:
            if r.offset + packed > payload_end or block_flags & ~0x7f:
                raise ValueError('UnityFS block range/flags exceeds bundle payload')
            output.write(decode(r.read(packed), unpacked, block_flags & 0x3f))
        total = output.tell()
        for _, offset, length in nodes:
            if offset > total or length > total - offset:
                raise ValueError('UnityFS file range exceeds decoded blocks')
        if total <= LIMIT:
            output.seek(0)
            raw = output.read()
            yield ((name, window(raw, offset, length)) for name, offset, length in nodes)
        else:
            output.flush()
            with mmap.mmap(output.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                yield ((name, window(mapped, offset, length)) for name, offset, length in nodes)


def is_serialized(data):
    """Recognize a complete Unity serialized-file header independently of its filename."""
    if len(data) < 48 or data[16] not in (0, 1):
        return False
    metadata, size, version, offset = unpack(data, '>4I', 0)
    if not 9 <= version <= 23:
        return False
    header_size = 48 if version >= 22 else 20
    if version >= 22:
        metadata, size, offset = unpack(data, '>IQQ', 20)
    return size == len(data) and 0 < metadata < size and header_size <= offset <= size


def objects(data):
    """Parse only shader, compute and TextAsset objects, bounded to each object's bytes."""
    try:
        from UnityPy.files.SerializedFile import SerializedFile
        from UnityPy.helpers import TypeTreeHelper
        from UnityPy.streams import EndianBinaryReader
    except ImportError as exc:
        raise ValueError('Unity extraction needs UnityPy 1.25.4; rerun setup.ps1') from exc
    # Use the checked Python type-tree reader; errors remain catchable in the scanner.
    TypeTreeHelper.read_typetree_boost = False
    asset = SerializedFile(EndianBinaryReader(AssetStream(data)))
    for obj in asset.objects.values():
        check_range(data, obj.byte_start, obj.byte_size)
        if obj.class_id not in (48, 49, 72):
            continue
        raw = Window(data, obj.byte_start, obj.byte_size)
        obj.reader = EndianBinaryReader(AssetStream(raw), endian=asset.reader.endian)
        obj.byte_start = 0
        yield obj


def read_shader(obj, schemas):
    """Reuse strictly validated type trees by Unity's exact serialized-layout hash."""
    from UnityPy.helpers.TypeTreeNode import TypeTreeNode
    type_hash = obj.serialized_type.old_type_hash if obj.serialized_type is not None else None
    key = f'{obj.class_id}/{type_hash.hex()}' if type_hash is not None else None
    node = obj.serialized_type.node if obj.serialized_type is not None else None
    if node is None and key in schemas:
        node = TypeTreeNode.from_list(schemas[key])
    value = obj.read_typetree(nodes=node)
    if key is not None:
        schemas[key] = [{key: value for key, value in row.items() if key != 'm_Children'}
                        for row in (node or obj._get_typetree_node()).to_dict_list()]
    return value


def text_asset(obj):
    """Return TextAsset script bytes directly, preserving binary data without text decoding."""
    r = Cursor(obj.get_raw_data(), obj.reader.endian)
    r.read(r.count(1))
    r.align()
    return r.read(r.count(1))


def references(shader):
    """Find executable blob indices separately from parameter blobs in modern Unity."""
    modern, indices, hints = False, set(), {}
    for sub in shader.get('m_ParsedForm', {}).get('m_SubShaders', []):
        for shader_pass in sub.get('m_Passes', []):
            for field, stage in PASS_STAGES.items():
                program = shader_pass.get(field) or {}
                modern |= 'm_ParameterBlobIndices' in program
                programs = list(program.get('m_SubPrograms', []))
                programs.extend(p for group in program.get('m_PlayerSubPrograms', []) for p in group)
                for item in programs:
                    index = item['m_BlobIndex']
                    indices.add(index)
                    hints.setdefault(index, stage)
    return (indices if modern else None), hints


def subprogram_code(data):
    """Read versioned keyword lists and the exact program-code byte array."""
    r = Cursor(data, '<')
    version, program_type = r.take('ii')
    r.read(12 + (4 if version >= 201608170 else 0))
    r.strings()
    if 201806140 <= version < 202012090:
        r.strings()
    return r.read(r.count(1))


def graphics_programs(shader):
    """Yield every code entry across every compressed platform/segment, excluding parameters."""
    blob = bytes(shader.get('compressedBlob', b''))
    if not blob:
        raise ValueError('Unsupported Unity shader without a serialized compressed program blob')
    platforms = shader['platforms']
    if any(len(shader[field]) != len(platforms) for field in ('offsets', 'compressedLengths', 'decompressedLengths')):
        raise ValueError('Unity shader platform/segment arrays disagree')
    indices, hints = references(shader)
    for platform_index, platform in enumerate(platforms):
        offsets, packed, sizes = (shader[field][platform_index]
                                  for field in ('offsets', 'compressedLengths', 'decompressedLengths'))
        modern = isinstance(offsets, list)
        if not modern:
            offsets, packed, sizes = [offsets], [packed], [sizes]
        if not len(offsets) == len(packed) == len(sizes):
            raise ValueError('Unity shader segment dimensions disagree')
        segments = [decode(span(blob, start, length), size, 2)
                    for start, length, size in zip(offsets, packed, sizes)]
        if not segments:
            if indices:
                raise ValueError('Unity shader references code but has no compressed segments')
            continue
        table = Cursor(segments[0], '<')
        count = table.count(12 if modern else 8)
        if indices is not None and any(not 0 <= index < count for index in indices):
            raise ValueError('Unity shader references a missing blob entry')
        for index in range(count):
            offset, length = table.take('II')
            segment = table.take('I') if modern else 0
            if segment >= len(segments):
                raise ValueError('Unity shader blob segment index out of bounds')
            raw = window(segments[segment], offset, length)
            if indices is None or index in indices:
                code = subprogram_code(raw)
                if not code:
                    raise ValueError('Unity shader code entry contains no program bytes')
                yield f'platform-{platform}/blob-{index}', code, hints.get(index)


def compute_programs(shader):
    """Yield kernel code from current uniqueVariants and earlier variantMap/direct layouts."""
    for variant_index, variant in enumerate(shader['variants']):
        for kernel_index, kernel in enumerate(variant['kernels']):
            if 'uniqueVariants' in kernel:
                variants = kernel['uniqueVariants']
            elif 'variantMap' in kernel:
                variants = [item['second'] for item in kernel['variantMap']]
            else:
                variants = [kernel]
            for index, item in enumerate(variants):
                code = bytes(item['code'])
                if code:  # Unity legitimately includes empty kernels with no GPU program.
                    yield f'variant-{variant_index}/kernel-{kernel_index}/{index}', code, 'cs'


def program_ranges(data, stage_hint=None):
    """Validate six-stage NVN, nine-stage NVN2 or older single-stage program descriptors."""
    if data[0x10:0x14] == CONTROL:
        control_size, code_size = unpack(data, '<ii', 8)
        check_range(data, 0x10, control_size + code_size)
        if control_size <= 0 or code_size <= 0 or 0x10 + control_size + code_size != len(data):
            raise ValueError('Invalid legacy Unity program length')
        return [(stage_hint, 0x10, control_size, 0x10 + control_size, code_size)]
    for count, base in ((9, 0x94), (9, 0x90), (6, 0x60)):
        if len(data) < base:
            continue
        header = unpack(data, '<' + 'i' * (count * 4), 0)
        rows, ranges = [], []
        for index, stage in enumerate(STAGES[:count]):
            offset, control_size, code_size = (header[count * column + index] for column in (1, 2, 3))
            if offset == -1:
                continue
            control, end = base + offset, base + offset + control_size + code_size
            if (offset < 0 or control_size < 0x48 or code_size <= 0 or end > len(data)
                    or data[control:control + 4] != CONTROL):
                break
            native = data[control + 4:control + 8] == b'\xc9\0\0\0'
            length_offset = 0x44 if native else 0x704
            if length_offset + 4 > control_size or unpack(data, '<I', control + length_offset)[0] != code_size:
                break
            rows.append((stage, control, control_size, control + control_size, code_size))
            ranges.append((control, end))
        else:
            ordered = sorted(ranges)
            if (ordered and ordered[0][0] == base and ordered[-1][1] == len(data)
                    and all(a[1] == b[0] for a, b in zip(ordered, ordered[1:]))):
                return rows
    raise ValueError('Unsupported or malformed Unity NVN/NVN2 program descriptor')
