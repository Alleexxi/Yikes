"""Search all leaf markers in one native pass, with an identical Python fallback."""

import ctypes
import hashlib
import os
import subprocess

from .adapter import ROOT, find_vcvars

PATTERNS = (b'BNSH\0\0\0\0', bytes.fromhex('91688619'), bytes.fromhex('34127698'),
            bytes.fromhex('28b52ffd'), bytes.fromhex('04224d18'))


def find_offsets(data, pattern):
    """Yield matches without allocating an unbounded list for marker-dense input."""
    at = data.find(pattern)
    while at >= 0:
        yield at
        at = data.find(pattern, at + len(pattern))


def python_markers(data):
    """Return lazy ascending offsets using the original exhaustive byte searches."""
    return {pattern: find_offsets(data, pattern) for pattern in PATTERNS}


def build_finder():
    """Cache the optional self-contained Windows x64 helper; scanning works without MSVC."""
    if os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8:
        return None
    try:
        vcvars = find_vcvars()
    except ValueError:
        return None
    source = ROOT / 'native/markers.cpp'
    signature = source.read_bytes() + str(vcvars).encode() + str(vcvars.stat().st_mtime_ns).encode()
    directory = ROOT / '.cache/markers' / hashlib.sha256(signature).hexdigest()
    directory.mkdir(parents=True, exist_ok=True)
    library = directory / 'markers.dll'
    if not library.is_file():
        if any(character in str(vcvars) for character in '%\r\n"'):
            return None
        arguments = ['/nologo', '/utf-8', '/std:c++20', '/EHsc', '/MT', '/O2', '/LD',
                     f'"{source}"', '/Fe:markers.dll', '/Fo:markers.obj']
        (directory / 'compile.rsp').write_text('\n'.join(arguments), encoding='utf-8')
        build = directory / 'build.cmd'
        build.write_text(f'@echo off\ncall "{vcvars}" >nul 2>&1\nif errorlevel 1 exit /b 2\n'
                         'cl @compile.rsp\nexit /b %ERRORLEVEL%\n', encoding='utf-8')
        result = subprocess.run(['cmd.exe', '/d', '/c', str(build)], cwd=directory,
                                capture_output=True, text=True, errors='replace')
        (directory / 'build.log').write_text(result.stdout + result.stderr, encoding='utf-8')
        if result.returncode or not library.is_file():
            library.unlink(missing_ok=True)
            return None
    return library


class MarkerFinder:
    """Reuse a bounded result buffer; overflow falls back without dropping any matches.

    One finder belongs to one scanner and is called only by its parsing thread.
    """

    def __init__(self, capacity=131072, native=True):
        self.capacity = capacity
        self.function = None
        self.buffer = None
        try:
            library = build_finder() if native else None
        except OSError:
            # The accelerator is optional, including when its cache cannot be written.
            library = None
        if library:
            try:
                self.library = ctypes.CDLL(str(library))
                self.function = self.library.find_markers
                self.function.argtypes = (ctypes.c_char_p, ctypes.c_size_t,
                                          ctypes.POINTER(ctypes.c_uint64), ctypes.c_size_t)
                self.function.restype = ctypes.c_size_t
                self.buffer = (ctypes.c_uint64 * capacity)()
            except OSError:
                self.function = None

    def find(self, data):
        """Search bytes without copying them or retaining pointers beyond the native call."""
        if self.function is None or not isinstance(data, bytes) or len(data) < 1024:
            return python_markers(data)
        count = self.function(data, len(data), self.buffer, self.capacity)
        if count > self.capacity:
            return python_markers(data)
        result = {pattern: [] for pattern in PATTERNS}
        for i in range(count):
            value = self.buffer[i]
            result[PATTERNS[value & 7]].append(value >> 3)
        return result
