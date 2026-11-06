"""Atomic local metadata and fingerprints for reproducible runs."""

import hashlib
import json
import os
import uuid
from pathlib import Path


def atomic_json(path, value):
    """Replace a JSON file only after its complete payload has been written."""
    path = Path(path)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        temporary.write_text(json.dumps(value, indent=2, ensure_ascii=True), encoding='utf-8')
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def source_identity(source):
    """Bind a resumable scan to its input path, size, modification time and header."""
    source = Path(source).resolve()
    stat = source.stat()
    with source.open('rb') as stream:
        header_hash = hashlib.sha256(stream.read(128)).hexdigest()
    return {'path': str(source), 'size': stat.st_size, 'mtime_ns': stat.st_mtime_ns,
            'header_sha256': header_hash}
