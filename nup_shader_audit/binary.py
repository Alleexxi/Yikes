"""Bounded binary access and archive traversal shared by the shader readers."""

import struct

import zstandard

LIMIT = 256 * 1024 * 1024


def span(data, offset, size):
    """Return a bounded range; reject negative or truncated offsets."""
    if offset < 0 or size < 0 or offset > len(data) - size:
        raise ValueError(f"range {offset:#x}+{size:#x} exceeds {len(data):#x}")
    return data[offset:offset + size]


def unpack(data, fmt, offset):
    """Decode one explicitly bounded binary structure."""
    return struct.unpack(fmt, span(data, offset, struct.calcsize(fmt)))


def decompress(data, dictionaries):
    """Decode a single bounded zstd frame using its declared dictionary."""
    params = zstandard.get_frame_parameters(data)
    if params.content_size not in (zstandard.CONTENTSIZE_UNKNOWN, zstandard.CONTENTSIZE_ERROR):
        if params.content_size > LIMIT:
            raise ValueError("decoded zstd frame exceeds limit")
    dictionary = dictionaries.get(params.dict_id)
    if params.dict_id and dictionary is None:
        raise ValueError(f"missing zstd dictionary {params.dict_id}")
    return zstandard.ZstdDecompressor(dict_data=dictionary).decompress(data, max_output_size=LIMIT)


def walk(reader, directory):
    """Walk a package tree without following repeated directories or cycles."""
    stack = [(directory, "")]
    visited = set()
    while stack:
        index, prefix = stack.pop()
        if index in visited:
            raise ValueError("repeated directory or cycle in NUP tree")
        visited.add(index)
        _, first, count = reader.dirs[index]
        for slot in range(first, first + count):
            child = reader.children[slot]
            is_dir = child < reader.dir_count
            at = child if is_dir else child - reader.dir_count
            table = reader.dirs if is_dir else reader.files
            if not 0 <= at < len(table):
                raise ValueError("NUP child reference outside node table")
            name = prefix + "/" + table[at][0].decode("utf-8", "backslashreplace")
            if is_dir:
                stack.append((at, name))
            else:
                yield name, at
