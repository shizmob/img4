#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Greetings to:
# - hexdump tool of choice

import restruct


def escape_nvram_value(v: bytes) -> bytes:
    res = bytearray()

    i = 0
    while i < len(v):
        if v[i] in (0, 0xff):
            nzeros = len(v[i:]) - len(v[i:].lstrip(b'\x00'))
            nmax = len(v[i:]) - len(v[i:].lstrip(b'\xff'))
            i += nzeros + nmax

            while nzeros > 0:
                res.append(0xff)
                res.append(nzeros % 0x80)
                nzeros -= 0x7F
            while nmax > 0:
                res.append(0xff)
                res.append(0x80 + nmax % 0x80)
                nmax -= 0x7F
        else:
            res.append(v[i])
            i += 1

    return res

def unescape_nvram_value(v: bytes) -> bytes:
    res = bytearray()

    i = 0
    while i < len(v):
        if v[i] == 0xff:
            i += 1
            l = v[i]
            if l < 0x80:
                res.extend(b'\x00' * l)
            else:
                l -= 0x80
                res.extend(b'\xFF' * l)
        else:
            res.append(v[i])
        i += 1

    return res


class NVRAMKeyValue(restruct.Struct):
    key:   Str(terminator=b'=')
    value: Processed(Data(), parse=unescape_nvram_value, emit=escape_nvram_value)

NVRAMKeyValues = restruct.Arr(NVRAMKeyValue, separator=b'\x00')

class NVRAMHeader(restruct.Struct):
    unk1:  Data(4)
    name:  Str(type='raw', length=12, exact=True)

class NVRAMSection(restruct.Struct):
    header: NVRAMHeader
    values: NVRAMKeyValues

class NVRAM(restruct.Struct):
    header: NVRAMHeader
    unk1:   NVRAMHeader
    sections: Arr(AlignTo(NVRAMSection, 0x4000))  # total guess


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='work with raw NVRAM data')
    parser.set_defaults(func=None)
    subparsers = parser.add_subparsers(help='subcommand')

    def do_dump(args):
        nvram = restruct.parse(NVRAM, args.infile)

        for section in nvram.sections:
            name = section.header.name.rstrip('\x00')
            if not name:
                continue
            print(name + ':')
            for val in section.values:
                print('  ' + val.key + ': ' + restruct.format_value(val.value, str))
    dump_parser = subparsers.add_parser('dump', help='show all data')
    dump_parser.add_argument('infile', type=argparse.FileType('rb'), help='input file')
    dump_parser.set_defaults(func=do_dump)

    args = parser.parse_args()
    if not args.func:
        parser.error('a subcommand must be provided')
    args.func(args)
