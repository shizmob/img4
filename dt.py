import restruct


def Mask(p, m):
    return restruct.Processed(p, parse=lambda x: x & m, emit=lambda x: x)

class Property(restruct.Struct, partials={'D'}):
    name:  Str(length=32, exact=True)
    size:  Mask(UInt(32), 0x7FFFFFFF) @ D.limit
    value: WithSize(Data()) @ D

class Node(restruct.Struct, partials={'P', 'C'}):
    property_count: UInt(32) @ P.count
    child_count:    UInt(32) @ C.count
    properties:     Arr(AlignTo(Property, 4)) @ P
    children:       Arr(...) @ C

# recursionnn
restruct.to_type(Node).fields['children'].type = Node


if __name__ == '__main__':
    import sys

    formats = {
        'compatible': restruct.Arr(restruct.Str(), stop_value=''),
        'platform-name': restruct.Str(),
        'name': restruct.Str(),
        '#size-cells': restruct.UInt(32),
        '#address-cells': restruct.UInt(32),
        'AAPL,phandle': restruct.UInt(32),
    }

    def isprint(x):
        return all(0x7E >= b >= 0x20 for b in x)

    def to_nice(k, v):
        if k in formats:
            return restruct.format_value(restruct.parse(formats[k], v), str)
        if v and v[-1] == 0 and isprint(v[:-1]):
            return v[:-1].decode('ascii')
        return restruct.format_bytes(v)

    def print_node(n, depth=0, last=False):
        space = ' ' * (depth * 2)
        if last and not n.children:
            leader = '    '
        else:
            leader = '|   '

        props = {x.name: x.value for x in n.properties}
        name = props.pop('name')
        print(space + '+-', '[' + to_nice('name', name) + ']')

        for k, v in props.items():
            print(space + leader, k + ':', to_nice(k, v))

        if n.children:
            print(space + '\\_,')
            for i, c in enumerate(n.children, start=1):
                print_node(c, depth=depth + 1, last=i == len(n.children))

    dt = restruct.parse(Node, open(sys.argv[1], 'rb'))
    print_node(dt)
