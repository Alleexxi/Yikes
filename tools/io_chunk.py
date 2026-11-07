"""List or extract chunks of an Unreal IoStore container inside a NUP, for format research.

usage: io_chunk.py <nup> <container stem substring> [--type N] [--id HEX] [--out PATH] [--limit N]
The container is the .utoc/.ucas pair whose path contains the substring (single partition only).
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from nup_shader_audit.binary import span, walk  # noqa: E402
from nup_shader_audit.codecs import NativeDecoder  # noqa: E402
from nup_shader_audit.container.read import NupReader  # noqa: E402
from nup_shader_audit.iostore import IoStore  # noqa: E402


def main():
    p = argparse.ArgumentParser()
    p.add_argument('nup')
    p.add_argument('stem')
    p.add_argument('--type', type=int)
    p.add_argument('--id')
    p.add_argument('--out')
    p.add_argument('--limit', type=int, default=20)
    args = p.parse_args()
    decoder = None
    with NupReader(args.nup) as reader:
        members = {}
        for pkg in reader.packages:
            for name, index in walk(reader, pkg.root_dir):
                members[f'pkg{pkg.index}{name}'] = index
        tocs = [n for n in members if n.endswith('.utoc') and args.stem in n]
        if not tocs:
            raise SystemExit('no matching .utoc')
        toc_name = tocs[0]
        ucas_name = toc_name[:-5] + '.ucas'
        print('container', toc_name)
        with reader.open_file(members[toc_name]) as meta, reader.open_file(members[ucas_name]) as ucas:
            toc = IoStore(meta, None)
            print('toc version', toc.version, 'chunks', toc.count, 'partitions', toc.parts)

            def read_partition(part, offset, size):
                return span(ucas, offset, size)

            def decode_native(kind, raw, size):
                nonlocal decoder
                decoder = decoder or NativeDecoder()
                return decoder.decode(kind, raw, size)

            shown = 0
            for index, chunk_id, size in toc.entries(0):
                if args.type is not None and chunk_id[-1] != args.type:
                    continue
                if args.id and chunk_id.hex() != args.id:
                    continue
                print(chunk_id.hex(), 'type', chunk_id[-1], 'size', size)
                if args.out:
                    with toc.read(index, read_partition, decode_native) as value:
                        Path(args.out).write_bytes(bytes(value[:]))
                    return
                shown += 1
                if shown >= args.limit:
                    break


if __name__ == '__main__':
    main()
