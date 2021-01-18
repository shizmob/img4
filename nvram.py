import restruct


def escape_nvram_value(v: bytes) -> bytes:
    res = bytearray()

    i = 0
    while i < len(v):
        nzeros = 0
        while i < len(v) and v[i] == 0:
            nzeros += 1
            i += 1

        nmax = 0
        while i < len(v) and v[i] == 0xff:
            nmax += 1
            i += 1

        if nzeros == 0 and nmax == 0:
            res.append(v[i])
            i += 1

        while nzeros > 0:
            res.append(0xff)
            res.append(nzeros % 0x80)
            nzeros -= 0x7F
        while nmax > 0:
            res.append(0xff)
            res.append(0x80 + nmax % 0x80)
            nmax -= 0x7F
        
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

RawNVRAMKeyValues = restruct.Arr(restruct.Data(), separator=b'\x00', stop_value=b'')

class NVRAMKeyValues(restruct.Type):
    def parse(self, io, context):
        values = restruct.parse(RawNVRAMKeyValues, io, context)
        res = {}
        for value in values:
            key, value = value.split(b'=', maxsplit=1)
            res[key.decode('ascii')] = unescape_nvram_value(value)
        return res

    def emit(self, value, io, context):
        value = [k.encode('ascii') + b'=' + escape_nvram_value(v) for k, v in value.items()]
        return restruct.emit(RawNVRAMKeyValues, value, io, context)

    def sizeof(self, value, context):
        if value is not None:
            value = [k.encode('ascii') + b'=' + escape_nvram_value(v) for k, v in value.items()]
        return restruct._sizeof(spec, value, context)

    def default(self, context):
        return {}


class NVRAMHeader(restruct.Struct):
    unk1:  Data(4)
    name:  Str(type='raw', length=12, exact=True)

class NVRAMSection(restruct.Struct):
    header: NVRAMHeader
    values: NVRAMKeyValues()

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
            for k, v in section.values.items():
                print('  ' + k + ': ' + restruct.format_value(v, str))
    dump_parser = subparsers.add_parser('dump', help='show all data')
    dump_parser.add_argument('infile', type=argparse.FileType('rb'), help='input file')
    dump_parser.set_defaults(func=do_dump)

    args = parser.parse_args()
    if not args.func:
        parser.error('a subcommand must be provided')
    args.func(args)
