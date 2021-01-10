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
    print(restruct.parse(Node, open(sys.argv[1], 'rb')))
