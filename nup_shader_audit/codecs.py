"""Pinned native archive codecs, isolated from the scanner in a local child process."""

import hashlib
import json
import os
import struct
import subprocess
import urllib.request
from pathlib import Path

from .adapter import ROOT, find_vcvars

DEPENDENCIES = {
    'ooz': ('powzix/ooz', '05038060aa68f9187ae9923b2388ca8db40e58d1', {
        'kraken.cpp': '20c48a30db54efa7681f8c9c674f2a16f081373872d033885a6fdf244b9cff01',
        'lzna.cpp': '8fc3fa71d814918f4a286d076c38a155ae8d93375281d796e2feba8ab866c712',
        'bitknit.cpp': '6e448d52fe485032e8b7aaf3efff2f0efd6394c776d0c6b14f91d2e1d286ed73',
        'stdafx.h': '92b798615ee1ac90ed53a2685fc62dfbe7133d5ba69e567733d8081d420cf701',
        'targetver.h': '7f988ed4cd4fe1acdede1f014931a08c508cc82f9407bc2b869ec2195c10c9c9'}),
    'zbic': ('kinnay/zbic', '11b08f2712264bbed731545085cbd9702096ceb7', {
        'src/zstd.c': '6f8e89a93f760ab2e9e48f8bbac766e254aa748a343e495eaa896ac441772e1f',
        'src/zstd.h': '787f615a8d12e62811dc198c3003bccf035756da1a953ee5d182ca92849b276a',
        'src/zstd_errors.h': '8336c9edf7c11fa7e3730efb05895d4619148f215849a820705e2e3819238cb2',
        'LICENSE': '8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643'})}


def codec_sources():
    """Download only required source files, validating pinned hashes on every build."""
    directories = {}
    for name, (repo, commit, files) in DEPENDENCIES.items():
        directory = ROOT / '.cache/dependencies' / name / commit
        directories[name] = directory
        for relative, sha in files.items():
            target = directory / relative
            if target.is_file() and hashlib.sha256(target.read_bytes()).hexdigest() == sha:
                continue
            print(f'Fetching {repo} codec source: {relative}', flush=True)
            with urllib.request.urlopen(f'https://raw.githubusercontent.com/{repo}/{commit}/{relative}', timeout=60) as response:
                raw = response.read()
            if hashlib.sha256(raw).hexdigest() != sha:
                raise ValueError(f'Codec source hash mismatch: {name}/{relative}')
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = target.with_suffix(target.suffix + '.tmp')
            temporary.write_bytes(raw)
            temporary.replace(target)
    return directories


def build_decoder():
    """Build just the pinned Oodle/ZBIC codecs and IPC wrapper, never the emulator."""
    if os.name != 'nt':
        raise ValueError('Native Oodle/ZBIC extraction currently requires Windows x64')
    vcvars = find_vcvars()
    directories = codec_sources()
    source = ROOT / 'native/decode.cpp'
    signature = json.dumps(DEPENDENCIES, sort_keys=True).encode() + source.read_bytes() + Path(__file__).read_bytes()
    signature += str(vcvars).encode() + str(vcvars.stat().st_mtime_ns).encode()
    directory = ROOT / '.cache/codecs' / hashlib.sha256(signature).hexdigest()
    directory.mkdir(parents=True, exist_ok=True)
    executable = directory / 'decode.exe'
    if not executable.is_file():
        if any(c in str(vcvars) for c in '%\r\n"'):
            raise ValueError('Unsupported compiler environment path')
        ooz, zbic = directories['ooz'], directories['zbic'] / 'src'
        # Compile only the decoder, excluding the upstream command-line frontend.
        separator = '// The decompressor will write outside of the target buffer.'
        core = (ooz / 'kraken.cpp').read_text(encoding='utf-8').split(separator)
        if len(core) != 2:
            raise ValueError('Unexpected pinned ooz decoder source layout')
        (directory / 'kraken_core.cpp').write_text(core[0], encoding='utf-8')
        (directory / 'ooz.rsp').write_text('\n'.join([
            '/nologo', '/O2', '/MT', '/EHsc', '/std:c++20', '/c', f'/I"{ooz}"',
            'kraken_core.cpp', *(f'"{ooz / name}"' for name in ('lzna.cpp', 'bitknit.cpp'))]), encoding='utf-8')
        (directory / 'zbic.rsp').write_text('\n'.join([
            '/nologo', '/O2', '/MT', '/DZSTD_ZBIC_SUPPORT=1', '/c', f'"{zbic / "zstd.c"}"']), encoding='utf-8')
        (directory / 'link.rsp').write_text('\n'.join([
            '/nologo', '/O2', '/MT', '/EHsc', '/std:c++20', '/DZSTD_ZBIC_SUPPORT=1',
            f'/I"{zbic}"', f'"{source}"', 'kraken_core.obj', 'lzna.obj', 'bitknit.obj', 'zstd.obj',
            '/Fe:decode.exe', '/Fo:decode.obj']), encoding='utf-8')
        build = directory / 'build.cmd'
        build.write_text(f'@echo off\ncall "{vcvars}" >nul 2>&1\nif errorlevel 1 exit /b 2\n'
                         'cl @ooz.rsp\nif errorlevel 1 exit /b 2\n'
                         'cl @zbic.rsp\nif errorlevel 1 exit /b 2\n'
                         'cl @link.rsp\nexit /b %ERRORLEVEL%\n', encoding='utf-8')
        print('Building archive codecs (Oodle and ZBIC)...', flush=True)
        result = subprocess.run(['cmd.exe', '/d', '/c', str(build)], cwd=directory,
                                capture_output=True, text=True, errors='replace')
        (directory / 'build.log').write_text(result.stdout + result.stderr, encoding='utf-8')
        if result.returncode or not executable.is_file():
            executable.unlink(missing_ok=True)
            raise ValueError(f'Archive codec build failed; see {directory / "build.log"}')
    return executable


class NativeDecoder:
    """Reuse a codec process; crashes cannot take down the Python scanner."""

    def __init__(self):
        self.executable = build_decoder()
        self.process = None

    def decode(self, kind, raw, size):
        """Decode a declared archive entry and require exactly its expected output size."""
        if kind not in ('oodle', 'zbic') or not 0 < size <= 0x7fffffff or not 0 < len(raw) <= 0x7fffffff:
            raise ValueError('Invalid or unsupported native codec entry size')
        if self.process is None or self.process.poll() is not None:
            self.close()
            self.process = subprocess.Popen([str(self.executable)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            creationflags=subprocess.CREATE_NO_WINDOW)
        process = self.process
        try:
            process.stdin.write(f'{kind}\t{len(raw)}\t{size}\n'.encode('ascii'))
            process.stdin.write(raw)
            process.stdin.flush()
            header = process.stdout.read(8)
            if len(header) != 8:
                raise ValueError('Archive codec process exited before returning a result')
            length, = struct.unpack('<Q', header)
            if length != size:
                raise ValueError(f'{kind} decompression failed')
            decoded = process.stdout.read(size)
            if len(decoded) != size:
                raise ValueError('Archive codec returned truncated output')
            return decoded
        except (OSError, ValueError):
            self.close()
            raise

    def close(self):
        """Release the scanner-owned child, including on interrupted extraction."""
        if self.process is not None:
            process, self.process = self.process, None
            if process.poll() is None:
                process.kill()
            process.communicate()
