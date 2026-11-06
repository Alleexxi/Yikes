"""Build a small audit executable against the selected emulator's current source."""

import hashlib
import json
import os
import subprocess
from pathlib import Path

from .storage import atomic_json

ROOT = Path(__file__).resolve().parent.parent


def git_value(emulator, *arguments):
    """Read optional Git provenance without requiring a clean checkout."""
    result = subprocess.run(['git', '-C', str(emulator), *arguments], capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else None


def find_vcvars():
    """Locate the installed x64 MSVC development environment."""
    choices = []
    for name in ('ProgramFiles', 'ProgramFiles(x86)'):
        location = os.environ.get(name)
        if location:
            choices.extend(Path(location).glob('Microsoft Visual Studio/*/*/VC/Auxiliary/Build/vcvars64.bat'))
    if not choices:
        raise ValueError('MSVC x64 C++ tools are required; vcvars64.bat was not found')
    return sorted(choices)[-1]


def fmt_include(emulator):
    """Locate fmt headers already present in the emulator checkout/build."""
    choices = [emulator / 'externals/fmt/include', emulator / 'build/_deps/fmt-src/include']
    choices.extend(sorted((ROOT / '.cache/dependencies/fmt').glob('*/include'), reverse=True))
    choices.extend(sorted(emulator.glob('.cache/cpm/fmt/*/include'), reverse=True))
    for choice in choices:
        if (choice / 'fmt/format.h').is_file():
            return choice
    raise ValueError('fmt headers not found; run shader-audit.cmd update or configure the emulator build')


def build_adapter(emulator):
    """Rebuild when the lowering source, adapter, dependencies, or compiler environment changes."""
    emulator = Path(emulator).resolve()
    header = emulator / 'src/shader_recompiler/frontend/ampere/lower_to_maxwell.h'
    if not header.is_file():
        raise ValueError(f'Native Ampere translator not found: {header}')
    include = fmt_include(emulator)
    vcvars = find_vcvars()
    source = header.read_text(encoding='utf-8')
    owned = source
    if 'std::string_view error;' in source:
        owned = source.replace('std::string_view error;', 'std::string error;')
        owned = '#include <string>\n' + owned
    elif 'std::string error;' not in source:
        raise ValueError('Translator diagnostic layout changed; the audit adapter needs updating')
    dependencies = [header, ROOT / 'native/audit.cpp', emulator / 'src/common/common_types.h']
    dependencies.extend(sorted((include / 'fmt').glob('*.h')))
    hashes = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in dependencies}
    signature = {'files': hashes, 'vcvars': str(vcvars), 'vcvars_mtime_ns': vcvars.stat().st_mtime_ns,
                 'tensor': True, 'native_address': 0, 'build_flags': '/std:c++20 /MD /O2 /DFMT_HEADER_ONLY'}
    fingerprint = hashlib.sha256(json.dumps(signature, sort_keys=True).encode()).hexdigest()
    directory = ROOT / '.cache/adapters' / fingerprint
    directory.mkdir(parents=True, exist_ok=True)
    executable = directory / 'audit.exe'
    if not executable.is_file():
        (directory / 'lowering_owned_error.h').write_text(owned, encoding='utf-8')
        # The response file keeps compiler arguments out of shell command interpolation.
        arguments = ['/nologo', '/utf-8', '/std:c++20', '/EHsc', '/MD', '/O2', '/DFMT_HEADER_ONLY',
                     f'/I"{directory}"', f'/I"{emulator / "src"}"', f'/I"{include}"',
                     f'"{ROOT / "native/audit.cpp"}"', '/Fe:audit.exe', '/Fo:audit.obj']
        (directory / 'compile.rsp').write_text('\n'.join(arguments), encoding='utf-8')
        if any(character in str(vcvars) for character in '%\r\n"'):
            raise ValueError('Unsupported characters in compiler environment path')
        build = directory / 'build.cmd'
        build.write_text(f'@echo off\ncall "{vcvars}" >nul 2>&1\nif errorlevel 1 exit /b 2\ncl @compile.rsp\nexit /b %ERRORLEVEL%\n', encoding='utf-8')
        print('Building audit adapter against current emulator source...', flush=True)
        result = subprocess.run(['cmd.exe', '/d', '/c', str(build)], cwd=directory,
                                capture_output=True, text=True, errors='replace')
        (directory / 'build.log').write_text(result.stdout + result.stderr, encoding='utf-8')
        if result.returncode or not executable.is_file():
            executable.unlink(missing_ok=True)
            raise ValueError(f'Audit adapter build failed; see {directory / "build.log"}')
    metadata = {**signature, 'fingerprint': fingerprint, 'emulator': str(emulator),
                'git_head': git_value(emulator, 'rev-parse', 'HEAD'),
                'git_dirty': bool(git_value(emulator, 'status', '--porcelain')),
                'diagnostic_change': 'Own error text as std::string; lowering algorithm unchanged',
                'scope': 'Native Ampere to Maxwell lowering; tensor enabled; address zero; no host pipeline compilation'}
    atomic_json(directory / 'build-metadata.json', metadata)
    return executable, metadata
