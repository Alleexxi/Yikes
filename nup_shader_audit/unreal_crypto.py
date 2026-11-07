"""Local Unreal AES decoding and validated key recovery from a NUP's own NSO image.

No key bytes are logged, serialized, exported, or fetched from external key lists.
The bounded AArch64 literal pattern follows the load/store sequence documented by
nxnative's uepak.py; a key is accepted only by a complete archive-index validator.
"""

import hashlib
import re
import struct

from .binary import span, unpack


def decrypt(raw, key):
    """Decode an aligned Unreal AES-256-ECB encryption unit."""
    if len(key) != 32 or len(raw) % 16:
        raise ValueError('Invalid Unreal AES key length or encrypted block alignment')
    try:
        from Crypto.Cipher import AES
    except ImportError as exc:
        raise ValueError('Unreal AES extraction needs PyCryptodome; rerun setup.ps1') from exc
    return AES.new(key, AES.MODE_ECB).decrypt(raw)


def mount_prefix(raw):
    """Quickly reject unrelated literals before decrypting and validating a full index."""
    length, = unpack(raw, '<i', 0)
    return ((4 <= length <= 4096 and raw[4:7] == b'../')
            or (length == 2 and raw[4:6] == b'/\0')
            or (-4096 <= length <= -4 and raw[4:10] == b'.\0.\0/\0')
            or (length == -2 and raw[4:8] == b'/\0\0\0'))


class KeyProbe:
    """Validate a candidate against the complete index, not only recognizable plaintext."""

    def __init__(self, encrypted, size, expected_hash=None, validator=None):
        if not encrypted or len(encrypted) % 16 or not 0 < size <= len(encrypted):
            raise ValueError('Invalid Unreal encrypted-index range')
        self.encrypted, self.size = encrypted, size
        self.expected_hash, self.validator = expected_hash, validator

    def accepts(self, key):
        """Require a valid mount point and either its recorded hash or full directory structure."""
        if not mount_prefix(decrypt(self.encrypted[:16], key)):
            return False
        plain = decrypt(self.encrypted, key)[:self.size]
        if self.expected_hash is not None:
            return hashlib.sha1(plain).digest() == self.expected_hash
        if self.validator is None:
            raise ValueError('Unreal key probe has no complete index validator')
        try:
            self.validator(plain)
        except (ValueError, UnicodeError, struct.error):
            return False
        return True


def literal_keys(image, text_size):
    """Recover two SIMD literals copied by ADRP/LDR Q/STP Q into a key output buffer."""
    for offset in range(0, min(text_size, len(image)) - 3, 4):
        instruction, = unpack(image, '<I', offset)
        if instruction & 0xffff83e0 != 0xad000000:  # STP Qn,Qm,[X0,#0]
            continue
        pages, vectors = {}, {}
        for at in range(max(0, offset - 32), offset, 4):
            word, = unpack(image, '<I', at)
            target = word & 31
            if word & 0x9f000000 == 0x90000000:  # ADRP Xd, signed page displacement
                immediate = (word >> 29 & 3) | (word >> 5 & 0x7ffff) << 2
                if immediate & (1 << 20):
                    immediate -= 1 << 21
                pages[target] = (at & ~4095) + (immediate << 12)
            elif word & 0xffc00000 == 0x3dc00000 and (word >> 5 & 31) in pages:
                vectors[target] = pages[word >> 5 & 31] + (word >> 10 & 0xfff) * 16
            else:
                # Conservative invalidation: an unrecognized instruction cannot extend
                # the lifetime of the address/vector value used by this pattern.
                pages.pop(target, None)
                vectors.pop(target, None)
        first, second = vectors.get(instruction & 31), vectors.get(instruction >> 10 & 31)
        if (first is not None and second is not None
                and 0 <= first <= len(image) - 16 and 0 <= second <= len(image) - 16):
            yield span(image, first, 16) + span(image, second, 16)


def find_key(image, text_size, data_start, data_end, probe, progress=None):
    """Try executable literals; archive hashes/structure decide whether a candidate is valid."""
    tried = set()
    for candidate in literal_keys(image, text_size):
        if candidate not in tried:
            tried.add(candidate)
            if probe.accepts(candidate):
                return candidate
    # Some builds embed a printable hexadecimal key rather than SIMD constants.
    raw = span(image, data_start, data_end - data_start)
    for match in re.finditer(rb'(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])', raw):
        candidate = bytes.fromhex(match[0].decode('ascii'))
        if candidate not in tried:
            tried.add(candidate)
            if probe.accepts(candidate):
                return candidate
    for offset in range(data_start, data_end - 31, 4):
        candidate = span(image, offset, 32)
        # This is an optimization for the literal search, not key validation. Low
        # entropy keys referenced by actual code are tested in the first pass too.
        if len(set(candidate)) < 20:
            continue
        if probe.accepts(candidate):
            return candidate
        if progress is not None and (offset - data_start) % (4 * 1024 * 1024) == 0:
            progress()
    raise ValueError('No embedded Unreal AES key validated against this archive index')
