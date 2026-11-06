"""Maintain the private, automatically updated nx2-experimental source checkout."""

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPOSITORY = 'https://github.com/Djihads80/Eglantine.git'
BRANCH = 'nx2-experimental'


def git(*arguments, cwd=None):
    """Run Git and report its useful diagnostics on failure."""
    result = subprocess.run(['git', *map(str, arguments)], cwd=cwd,
                            capture_output=True, text=True, errors='replace')
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise ValueError(f"Git {' '.join(map(str, arguments))} failed: {detail}")
    return result.stdout.strip()


def ensure_fmt(emulator):
    """Fetch the exact fmt version pinned by this Eglantine revision when needed."""
    manifest = json.loads((emulator / 'cpmfile.json').read_text(encoding='utf-8'))
    package = manifest.get('packages', manifest).get('fmt')
    if not package or not package.get('version'):
        raise ValueError('Could not find the pinned fmt version in Eglantine cpmfile.json')
    version = package['version']
    destination = ROOT / '.cache/dependencies/fmt' / version
    if not (destination / 'include/fmt/format.h').is_file():
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise ValueError(f'Incomplete fmt checkout at {destination}; remove it and retry')
        git('clone', '--depth', '1', '--single-branch', '--branch', version,
            f"https://github.com/{package['repo']}.git", destination)
    return destination / 'include'


def sync_emulator():
    """Clone once, then fast-forward the managed checkout before every default audit."""
    checkout = ROOT / '.cache/emulator-nx2-experimental'
    if not (checkout / '.git').exists():
        checkout.parent.mkdir(parents=True, exist_ok=True)
        git('clone', '--depth', '1', '--single-branch', '--branch', BRANCH,
            REPOSITORY, checkout)
    remote = git('-C', checkout, 'remote', 'get-url', 'origin')
    if remote.rstrip('/').removesuffix('.git').lower() != REPOSITORY.removesuffix('.git').lower():
        raise ValueError(f'Managed checkout has unexpected origin: {remote}')
    branch = git('-C', checkout, 'branch', '--show-current')
    if branch != BRANCH:
        raise ValueError(f'Managed checkout is on {branch!r}, expected {BRANCH!r}')
    if git('-C', checkout, 'status', '--porcelain'):
        raise ValueError(f'Managed checkout has local changes: {checkout}')
    git('-C', checkout, 'pull', '--ff-only', 'origin', BRANCH)
    ensure_fmt(checkout)
    return checkout
