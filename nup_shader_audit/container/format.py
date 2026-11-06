"""NUP (NX Package) format constants and binary layout.

Implements SPEC.md v1 exactly. All integers little-endian. All reserved
fields must be zero on write and are validated on read.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

MAGIC = b"NUP\x01"  # 'N','U','P', format major version 1
TOC_MAGIC = b"TOC\x01"
HEADER_SIZE = 0x80
PKG_SIZE = 0x40
DIR_SIZE = 0x18
FILE_SIZE = 0x50
EXTENT_ALIGN = 16
NO_DIR = 0xFFFFFFFF

CODEC_RAW = 0
CODEC_ZSTD = 1

KIND_BASE = 0
KIND_UPDATE = 1
KIND_ADDON = 2
KIND_ADDON_UPDATE = 3
KIND_SYSTEM = 4

KIND_NAMES = {
    KIND_BASE: "base",
    KIND_UPDATE: "update",
    KIND_ADDON: "addon",
    KIND_ADDON_UPDATE: "addon_update",
    KIND_SYSTEM: "system",
}

# Meta TLV types (SPEC §5)
TLV_NPDM = 0x0001
TLV_NACP = 0x0002
TLV_ICON = 0x0003
TLV_DISPLAY_VERSION = 0x0004
TLV_TITLE_NAME = 0x0005
TLV_PUBLISHER = 0x0006
TLV_BUILD_ID = 0x0007
TLV_SOURCE_DUMP = 0x0008
TLV_LOCALIZED_TITLES = 0x0009
TLV_LOCALIZED_ICONS = 0x000A

PKG_FLAG_STANDALONE_UPDATE = 0x01

_super_s = struct.Struct("<4sHHQQ32sQQII16s32s")  # 128
_pkg_s = struct.Struct("<QIIIIBBHIQI20x")  # 64
_dir_s = struct.Struct("<IIIIQ")  # 24
_file_s = struct.Struct("<IIQQQ32sBBH12x")  # 80
_toc_head_s = struct.Struct("<4sIQQQQQ")  # 48
_tlv_s = struct.Struct("<HHI")  # 8

# struct sizes must match the documented record sizes exactly (SPEC §8);
assert _super_s.size == HEADER_SIZE
assert _pkg_s.size == PKG_SIZE
assert _dir_s.size == DIR_SIZE
assert _file_s.size == FILE_SIZE


class NupError(Exception):
    """Malformed or nonconforming NUP data (fail closed)."""


@dataclass
class Package:
    title_id: int = 0
    root_dir: int = 0
    exefs_dir: int = NO_DIR
    romfs_dir: int = NO_DIR
    version: int = 0
    kind: int = KIND_BASE
    flags: int = 0
    meta_offset: int = 0
    meta_size: int = 0


@dataclass
class DirNode:
    name: bytes
    first_child: int = 0
    child_count: int = 0


@dataclass
class FileNode:
    name: bytes
    size: int = 0
    sha256: bytes = b"\0" * 32
    extent_offset: int = 0
    extent_size: int = 0
    codec: int = CODEC_RAW
    codec_flags: int = 0
    # pack-time only (not serialized)
    src_path: str | None = field(default=None, repr=False)


def pack_super(magic: bytes, header_size: int, header_version: int, toc_offset: int,
               toc_size: int, toc_sha256: bytes, blob_offset: int, file_size: int,
               package_count: int, flags: int, uuid: bytes) -> bytes:
    assert len(toc_sha256) == 32 and len(uuid) == 16
    return _super_s.pack(magic, header_size, header_version, toc_offset, toc_size,
                         toc_sha256, blob_offset, file_size, package_count, flags, uuid,
                         b"\0" * 32)


def pack_pkg(p: Package) -> bytes:
    return _pkg_s.pack(p.title_id, p.root_dir, p.exefs_dir, p.romfs_dir, p.version,
                       p.kind, p.flags, 0, 0, p.meta_offset, p.meta_size)


def pack_dir(d: DirNode) -> bytes:
    return _dir_s.pack(0, 0, d.first_child, d.child_count, 0)  # name off/len patched at write


def pack_file(f: FileNode) -> bytes:
    return _file_s.pack(0, 0, f.size, f.extent_offset, f.extent_size, f.sha256,
                        f.codec, f.codec_flags, 0)


def parse_super(buf: bytes) -> dict:
    if len(buf) < HEADER_SIZE:
        raise NupError(f"superblock truncated: {len(buf)} < {HEADER_SIZE}")
    (magic, header_size, header_version, toc_offset, toc_size, toc_sha256,
     blob_offset, file_size, package_count, flags, uuid, reserved) = _super_s.unpack_from(buf, 0)
    if magic[0:3] != MAGIC[0:3]:
        raise NupError(f"bad magic {magic!r}, expected {MAGIC[0:3]!r}")
    if magic[3] != 1:
        raise NupError(f"unsupported format major version {magic[3]}")
    if header_size < HEADER_SIZE:
        raise NupError(f"header_size {header_size:#x} < {HEADER_SIZE:#x}")
    if reserved != b"\0" * 32:
        raise NupError("superblock reserved bytes not zero")
    if flags != 0:
        raise NupError(f"unknown superblock flags {flags:#x}")
    return dict(header_size=header_size, header_version=header_version,
                toc_offset=toc_offset, toc_size=toc_size, toc_sha256=toc_sha256,
                blob_offset=blob_offset, file_size=file_size,
                package_count=package_count, flags=flags, uuid=uuid)


def parse_pkg(buf: bytes, off: int) -> Package:
    (title_id, root, exefs, romfs, version, kind, flags, _r, _r2,
     meta_offset, meta_size) = _pkg_s.unpack_from(buf, off)
    if kind >= len(KIND_NAMES):
        raise NupError(f"unknown package kind {kind}")
    if _r != 0 or _r2 != 0:
        raise NupError("package reserved bytes not zero")
    return Package(title_id=title_id, root_dir=root, exefs_dir=exefs, romfs_dir=romfs,
                   version=version, kind=kind, flags=flags,
                   meta_offset=meta_offset, meta_size=meta_size)
