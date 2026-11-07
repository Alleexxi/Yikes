"""Copy one file out of a NUP, optionally from inside an Unreal PAK, for format research.

usage: extract_member.py <nup> <path substring> <output> [--in-pak <pak path substring>] [--list]
Paths are the ones the scanner reports (e.g. pkg0/romfs/SB/Content/Paks/x.pak/SB/Content/y.bin).
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from nup_shader_audit.binary import walk  # noqa: E402
from nup_shader_audit.codecs import NativeDecoder  # noqa: E402
from nup_shader_audit.container.read import NupReader  # noqa: E402
from nup_shader_audit.unreal_pak import Pak  # noqa: E402


def main():
    p = argparse.ArgumentParser()
    p.add_argument('nup')
    p.add_argument('needle')
    p.add_argument('output', nargs='?')
    p.add_argument('--in-pak')
    p.add_argument('--list', action='store_true')
    args = p.parse_args()
    decoder = NativeDecoder()
    with NupReader(args.nup) as reader:
        for pkg in reader.packages:
            for name, entry in walk(reader, pkg.root_dir):
                path = f'pkg{pkg.index}{name}'
                target = args.in_pak or args.needle
                if target not in path:
                    continue
                if not args.in_pak:
                    print('match', path)
                    if args.list or not args.output:
                        continue
                    with reader.open_file(entry) as data:
                        Path(args.output).write_bytes(bytes(data[:]))
                    return
                with reader.open_file(entry) as data:
                    pak = Pak(data, None)
                    for member in pak.files:
                        if args.needle in member:
                            print('match', path, member)
                            if args.list or not args.output:
                                continue
                            with pak.read(member, decoder.decode) as value:
                                Path(args.output).write_bytes(bytes(value[:]))
                            return


if __name__ == '__main__':
    main()
