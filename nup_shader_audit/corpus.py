"""Store portable native programs together and read them sequentially for regression audits."""

import hashlib
import sqlite3
from contextlib import closing
from pathlib import Path


def compact_programs(output):
    """Stream a versioned corpus DB read-only; no separate shader files are needed."""
    path = (Path(output).resolve() / 'corpus.sqlite').as_uri() + '?mode=ro'
    with closing(sqlite3.connect(path, uri=True)) as db:
        if db.execute('PRAGMA user_version').fetchone()[0] != 1:
            raise ValueError('Unsupported shader corpus database version')
        for filename, stage, size, raw in db.execute('SELECT filename,stage,bytes,code FROM programs'):
            if not isinstance(filename, str) or not isinstance(stage, str) or not isinstance(raw, bytes):
                raise ValueError('Invalid shader corpus database record')
            yield filename, stage, size, raw


def extraction_programs(output):
    """Read only deduplicated native instruction streams from the full extraction cache."""
    path = (Path(output).resolve() / 'shaders.sqlite').as_uri() + '?mode=ro'
    with closing(sqlite3.connect(path, uri=True)) as db:
        rows = db.execute("SELECT instruction_hash,stage,instruction_bytes,"
                          "substr(code,CASE WHEN stage='cs' THEN 1 ELSE 129 END,instruction_bytes) "
                          "FROM shaders WHERE arch='sm86' GROUP BY instruction_hash,stage")
        for sha, stage, size, raw in rows:
            yield f'{sha}.{stage}.bin', stage, size, raw


def write_compact_corpus(output, destination, cases, progress=None):
    """Copy the audited native corpus into one temporary SQLite file, checking every hash."""
    output = Path(output)
    expected = {case['file']: case for case in cases}
    if len(expected) != len(cases):
        raise ValueError('Duplicate shader case in audit report')
    if (output / 'shaders.sqlite').is_file():
        programs = extraction_programs(output)
    elif (output / 'corpus.sqlite').is_file():
        programs = compact_programs(output)
    else:
        programs = ((case['file'], case['stage'], case['input_bytes'],
                     (output / 'native' / case['file']).read_bytes()) for case in cases)
    seen = set()
    with closing(programs) as programs, closing(sqlite3.connect(destination)) as target:
        # This disposable file is published only after a successful ZIP; the source DB is read-only.
        target.executescript('PRAGMA page_size=65536; PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; '
                             'PRAGMA user_version=1; '
                             'CREATE TABLE programs(filename TEXT PRIMARY KEY,stage TEXT,bytes INTEGER,code BLOB);')
        for filename, stage, size, raw in programs:
            case = expected.get(filename)
            if (case is None or filename in seen or stage != case['stage'] or size != case['input_bytes']
                    or len(raw) != size or hashlib.sha256(raw).hexdigest() != filename.split('.')[0]):
                raise ValueError('Shader database content disagrees with the audited corpus')
            target.execute('INSERT INTO programs VALUES (?,?,?,?)', (filename, stage, size, raw))
            seen.add(filename)
            if progress:
                progress(len(seen))
        if seen != expected.keys():
            raise ValueError('Shader database does not cover the audited corpus')
        target.commit()
