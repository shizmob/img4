#!/usr/bin/env python3
import enum
import restruct


class DeviceTreeType(enum.Enum):
    Empty = enum.auto()
    U32 = enum.auto()
    U64 = enum.auto()
    Handle = enum.auto()
    String = enum.auto()
    StringList = enum.auto()
    Opaque = enum.auto()

PROPERTY_TYPES = {
    'compatible': DeviceTreeType.StringList,
    'model': DeviceTreeType.String,
    'phandle': DeviceTreeType.Handle,
    'AAPL,phandle': DeviceTreeType.Handle,
    'linux,phandle': DeviceTreeType.Handle,
    'status': DeviceTreeType.String,
    '#size-cells': DeviceTreeType.U32,
    '#address-cells': DeviceTreeType.U32,

    'name': DeviceTreeType.String,
}

def isprint(x):
    return all(0x7E >= b >= 0x20 for b in x)

def determine_type(k, v):
    if k in PROPERTY_TYPES:
        return PROPERTY_TYPES[k]
    if v and v[-1] == 0 and isprint(v[:-1]):
        return DeviceTreeType.String
    if len(v) == 4:
        # not a fan of this heuristic
        return DeviceTreeType.U32
    return DeviceTreeType.Opaque

def determine_reverse_type(k, v):
    if k in PROPERTY_TYPES:
        return PROPERTY_TYPES[k]
    return {
        type(None): DeviceTreeType.Empty,
        int:   DeviceTreeType.U32,
        str:   DeviceTreeType.String,
        list:  DeviceTreeType.StringList,
        bytes: DeviceTreeType.Opaque,
    }[type(v)]


FDT_PROPERTY_TYPES = {
    DeviceTreeType.Empty:      restruct.Nothing(),
    DeviceTreeType.U32:        restruct.UInt(32, order='be'),
    DeviceTreeType.U64:        restruct.UInt(64, order='be'),
    DeviceTreeType.Handle:     restruct.UInt(32, order='be'),
    DeviceTreeType.String:     restruct.Str(),
    DeviceTreeType.StringList: restruct.Arr(restruct.Str(type='c')),
    DeviceTreeType.Opaque:     restruct.Data(),
}

class FDTMemoryReservation(restruct.Struct):
    address: UInt(64, order='be')
    size:    UInt(64, order='be')

FDTMemoryArray = restruct.Arr(restruct.AlignedTo(FDTMemoryReservation, 8))

class FDTToken(enum.Enum):
    NodeBegin = 1
    NodeEnd   = 2
    Property  = 3
    Ignore    = 4
    End       = 9

class FDTProperty(restruct.Struct, partials={'DataSize'}):
    size:        UInt(32, order='be') @ DataSize.limit
    name_offset: UInt(32, order='be')
    name:        Ref(Str())
    data:        Sized(Data()) @ DataSize

    def on_parse_name_offset(self, spec, context):
        spec.name.point = context.user.strings_offset + self.name_offset

    def on_parse_data(self, spec, context):
        self.data = restruct.parse(FDT_PROPERTY_TYPES[determine_type(self.name, self.data)], self.data)

class FDTNode(restruct.Struct, partials={'DataType'}):
    token: Enum(FDTToken, UInt(32, order='be')) @ DataType.selector
    data:  Switch(fallback=Nothing(), options={
        FDTToken.NodeBegin: Str(),
        FDTToken.Property: FDTProperty,
    }) @ DataType

FDTNodeArray = restruct.Arr(restruct.AlignedTo(FDTNode, 4), stop_value=FDTNode(token=FDTToken.End, data=None))

class FlattenedDeviceTree(restruct.Struct, partials={'MemOff', 'StruOff', 'StruSize', 'StriOff', 'StriSize'}):
    magic:          Fixed(b'\xd0\x0d\xfe\xed')
    size:           UInt(32, order='be')
    structs_offset: UInt(32, order='be') @ StruOff.point
    strings_offset: UInt(32, order='be') @ StriOff.point
    mem_offset:     UInt(32, order='be') @ MemOff.point
    version:        UInt(32, order='be')
    compat_version: UInt(32, order='be')
    boot_cpu_id:    UInt(32, order='be')
    strings_size:   UInt(32, order='be') @ StriSize.limit
    structs_size:   UInt(32, order='be') @ StruSize.limit

    strings: Ref(Sized(Data()) @ StriSize) @ StriOff
    structs: Ref(Sized(FDTNodeArray) @ StruSize) @ StruOff
    memory:  Ref(Sized(FDTMemoryArray)) @ MemOff

    def on_parse_structs_size(self, spec, context):
        spec.memory.type.limit = self.size - self.structs_size - self.strings_size - 40

    def on_parse_strings(self, spec, context):
        context.user.strings_offset = self.strings_offset



ADT_PROPERTY_TYPES = {
    DeviceTreeType.Empty:      restruct.Nothing(),
    DeviceTreeType.U32:        restruct.UInt(32, order='le'),
    DeviceTreeType.U64:        restruct.UInt(64, order='le'),
    DeviceTreeType.Handle:     restruct.UInt(32, order='le'),
    DeviceTreeType.String:     restruct.Str(),
    DeviceTreeType.StringList: restruct.Arr(restruct.Str(type='c')),
    DeviceTreeType.Opaque:     restruct.Data(),
}

class ADTProperty(restruct.Struct, partials={'DataSize'}):
    name:     Str(length=32, exact=True)
    size:     Bits(31, byteswap=True) @ DataSize.limit
    template: Bool(Bits(1))
    value:    Sized(Data()) @ DataSize

    def on_parse_value(self, spec, context):
        self.value = restruct.parse(ADT_PROPERTY_TYPES[determine_type(self.name, self.value)], self.value)

    def on_emit_value(self, spec, context):
        self.value = restruct.emit(ADT_PROPERTY_TYPES[determine_reverse_type(self.name, self.value)], self.value).getvalue()

class ADTNode(restruct.Struct, recursive=True, partials={'PropArr', 'ChildArr'}):
    property_count: UInt(32) @ PropArr.count
    child_count:    UInt(32) @ ChildArr.count
    properties:     Arr(AlignTo(ADTProperty, 4)) @ PropArr
    children:       Arr(Self) @ ChildArr

AppleDeviceTree = ADTNode



class DeviceTreeRange(restruct.Struct, generics={'ChildAddrSize', 'ParentAddrSize', 'LengthSize'}):
    child_address:  UInt(ChildAddrSize)
    parent_address: UInt(ParentAddrSize)
    length:         UInt(LengthSize)

class DeviceTreeRegister(restruct.Struct, generics={'AddrSize', 'LengthSize'}):
    address:  UInt(AddrSize)
    length:   UInt(LengthSize)



def dump_value(n, v):
    return restruct.format_value(v, str)

def dump(node, depth=0, last=True):
    space = ' ' * (depth * 2)
    if last and not node.children:
        leader = '    '
    else:
        leader = '|   '

    props = {p.name: p.value for p in node.properties}

    name = props.get('name', '<unnamed>')
    s = space + '+- [' + name + ']\n'

    for k, v in props.items():
        s += space + leader + ' ' + k + ': ' + dump_value(k, v) + '\n'

    if node.children:
        s += space + '\\_,\n'
        for i, child in enumerate(node.children, start=1):
            s += dump(child, depth=depth + 1, last=i == len(node.children))

    return s


def to_adt(nodes, depth=0):
    node = ADTNode(property_count=0, properties=[], child_count=0, children=[])

    assert nodes[0].token == FDTToken.NodeBegin
    if depth == 0 and not nodes[0].data:
        name = 'device-tree'
    else:
        name = nodes[0].data
    node.properties.append(ADTProperty(name='name', template=False, value=name))

    i = 1
    while True:
        if nodes[i].token == FDTToken.NodeEnd:
            break
        elif nodes[i].token == FDTToken.NodeBegin:
            n, child = to_adt(nodes[i:], depth=depth + 1)
            i += n
            node.children.append(child)
        elif nodes[i].token == FDTToken.Property:
            k = nodes[i].data.name
            v = nodes[i].data.data
            node.properties.append(ADTProperty(name=k, template=False, value=v))
        i += 1

    node.property_count = len(node.properties)
    node.child_count = len(node.children)
    return i, node


def to_fdt(node, depth=0):
    raise NotImplementedError


def value_to_dts(val):
    if val is None:
        return None
    if isinstance(val, int):
        return '<' + hex(val) + '>'
    if isinstance(val, str):
        return '"' + val.replace('"', '\\"') + '"'
    if isinstance(val, list):
        return ','.join(value_to_dts(x) for x in val)
    if isinstance(val, bytes):
        return '[' + val.hex() + ']'

def to_dts(node, depth=0):
    s = ''
    props = {p.name: p.value for p in node.properties}
    spacing = ' ' * (depth * 2)

    if not depth:
        s += '/dts-v1/;\n\n'

    name = props.pop('name')
    if not depth:
        name = '/'
    s += spacing + name + ' {\n'

    for k, v in props.items():
        p = k
        sv = value_to_dts(v)
        if sv is not None:
            p += ' = ' + sv
        s += restruct.indent(p + ';', count=(depth + 1) * 2, start=True) + '\n'

    for c in node.children:
        s += '\n' + to_dts(c, depth=depth + 1)

    s += spacing + '};\n'

    return s


def diff(a, b, path=[]):
    a_props = {p.name: p.value for p in a.properties}
    b_props = {p.name: p.value for p in b.properties}

    for k in a_props:
        p = '/' + '/'.join(path + [k])
        if k not in b_props:
            print('--- ' + p)
            print(dump_value(k, a_props[k]))
        else:
            if a_props[k] != b_props[k]:
                print('--- ' + p)
                print(dump_value(k, a_props[k]))
                print('+++ ' + p)
                print(dump_value(k, b_props[k]))
            del b_props[k]

    for k in b_props:
        p = '/' + '/'.join(path + [k])
        print('+++ ' + p)
        print(dump_value(k, b_props[k]))

    b_children = {}
    for c in b.children:
        name = next(p.value for p in c.properties if p.name == 'name')
        b_children.setdefault(name, []).append(c)
    for c in a.children:
        name = next(p.value for p in c.properties if p.name == 'name')
        p = '/' + '/'.join(path + [name])
        if name not in b_children:
            print('--- ' + p)
            print(dump(c))
        else:
            diff(c, b_children[name].pop(0), path + [name])

    for name, cs in b_children.items():
        for c in cs:
            p = '/' + '/'.join(path + [name])
            print('+++' + p)
            print(dump(c))


def regs(node, path):
    path = path[:]
    addrspaces = []
    last_addr_size = None
    last_size_size = None

    while True:
        props = {p.name: p.value for p in node.properties}

        if '#address-cells' in props and '#size-cells' in props:
            this_addr_size = props['#address-cells']
            this_size_size = props['#size-cells']
            if 'ranges' in props:
                range_spec = DeviceTreeRange[this_addr_size * 32, last_addr_size * 32, this_size_size * 32]
                ranges = restruct.parse(restruct.Arr(range_spec), props['ranges'])
                addrspaces.append(ranges)
            last_addr_size = this_addr_size
            last_size_size = this_size_size

        if not path:
            if 'reg' in props:
                reg_spec = DeviceTreeRegister[last_addr_size * 32, last_size_size * 32]
                regs = restruct.parse(restruct.Arr(reg_spec), props['reg'])
            else:
                regs = []
            break

        for child in node.children:
            cprops = {p.name: p.value for p in child.properties}
            cname = cprops['name']
            if cname == path[0]:
                path.pop(0)
                node = child
                break
        else:
            raise ValueError('404')

    for reg in regs:
        addr = reg.address

        for addrspace in reversed(addrspaces):
            for r in addrspace:
                if addr >= r.child_address and addr + reg.length <= r.child_address + r.length:
                    addr = r.parent_address + (addr - r.child_address)
                    break
            else:
                if addrspace:
                    raise ValueError('could not map child to parent address space')

        print(hex(addr), reg.length)


if __name__ == '__main__':
    def get_adt(infile):
        try:
            fdt = restruct.parse(FlattenedDeviceTree, infile)
            _, adt = to_adt(fdt.structs)
            return adt
        except:
            infile.seek(0)
            return restruct.parse(AppleDeviceTree, infile)

    import sys
    import argparse

    parser = argparse.ArgumentParser(description='process Apple (ADT) and Flattened (FDT) device tree files')
    parser.set_defaults(func=None)
    subparsers = parser.add_subparsers(help='subcommand')

    def do_dump(args):
        dt = get_adt(args.infile)
        args.outfile.write(dump(dt))
    dump_parser = subparsers.add_parser('dump', help='visually show device tree')
    dump_parser.add_argument('infile', type=argparse.FileType('rb'), help='input file')
    dump_parser.add_argument('outfile', type=argparse.FileType('w'), nargs='?', default=sys.stdout, help='output file')
    dump_parser.set_defaults(func=do_dump)

    def do_conv_fdt(args):
        adt = restruct.parse(AppleDeviceTree, args.infile)
        n, dt = to_fdt(adt)
        restruct.emit(FlattenedDeviceTree, dt, args.outfile)
    conv_fdt_parser = subparsers.add_parser('to-fdt', help='convert to flattened device tree')
    conv_fdt_parser.add_argument('infile', type=argparse.FileType('rb'), help='input file')
    conv_fdt_parser.add_argument('outfile', type=argparse.FileType('w+b'), nargs='?', default=sys.stdout.buffer, help='output file')
    conv_fdt_parser.set_defaults(func=do_conv_fdt)

    def do_conv_adt(args):
        dt = get_adt(args.infile)
        restruct.emit(AppleDeviceTree, dt, args.outfile)
    conv_adt_parser = subparsers.add_parser('to-adt', help='convert to Apple device tree')
    conv_adt_parser.add_argument('infile', type=argparse.FileType('rb'), help='input file')
    conv_adt_parser.add_argument('outfile', type=argparse.FileType('w+b'), nargs='?', default=sys.stdout.buffer, help='output file')
    conv_adt_parser.set_defaults(func=do_conv_adt)

    def do_conv_src(args):
        dt = get_adt(args.infile)
        dts = to_dts(dt)
        args.outfile.write(dts)
    conv_src_parser = subparsers.add_parser('to-src', help='convert to device tree source')
    conv_src_parser.add_argument('infile', type=argparse.FileType('rb'), help='input file')
    conv_src_parser.add_argument('outfile', type=argparse.FileType('w'), nargs='?', default=sys.stdout, help='output file')
    conv_src_parser.set_defaults(func=do_conv_src)

    def do_diff(args):
        a = get_adt(args.a)
        b = get_adt(args.b)
        diff(a, b)
    diff_parser = subparsers.add_parser('diff', help='visually show the difference between two device trees')
    diff_parser.add_argument('a', type=argparse.FileType('rb'), help='first file')
    diff_parser.add_argument('b', type=argparse.FileType('rb'), help='second file')
    diff_parser.set_defaults(func=do_diff)

    def do_regs(args):
        dt = get_adt(args.infile)
        path = args.path.lstrip('/').split('/')
        regs(dt, path)
    regs_parser = subparsers.add_parser('regs', help='show calculated register ranges for given path')
    regs_parser.add_argument('infile', type=argparse.FileType('rb'), help='input file')
    regs_parser.add_argument('path', help='path to the device node, nodes separated by \'/\' (example: arm-io/i2c2/audio-codec-output)')
    regs_parser.set_defaults(func=do_regs)

    args = parser.parse_args()
    if not args.func:
        parser.error('a subcommand must be provided')
    args.func(args)
