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
    properties:      Arr(AlignTo(Property, 4)) @ P
    children:        Arr(...) @ C

# recursionnn
restruct.to_type(Node).fields['children'].type = Node


if __name__ == '__main__':
    import sys

    def isprint(x):
        return all(0x7E >= b >= 0x20 for b in x)

    def print_nice(v):
        stripped = v.rstrip(b'\x00')
        if stripped and isprint(stripped):
            return stripped.decode('ascii')
        return restruct.format_bytes(v)

    def print_node(n, depth=0):
        space = ' ' * (depth * 2)
        props = {x.name: x.value for x in n.properties}
        name = props.pop('name')
        print(space + '+-', print_nice(name))
        for k, v in props.items():
            print(space + '|   ', k + ':', print_nice(v))
        if n.children:
            print(space + '\\_,')
            for c in n.children:
                print_node(c, depth=depth + 1)
    dt = restruct.parse(Node, open(sys.argv[1], 'rb'))
    print_node(dt)
