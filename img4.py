# SPDX-License-Identifier: MIT
# Greetings to:
# - https://www.theiphonewiki.com/wiki/IMG4_File_Format
# - https://github.com/tihmstar/img4tool/
# - https://lapo.it/asn1js/
# - hexdump tool of choice

import functools
from asn1crypto.core import (
    Enumerated, Choice, Sequence, SequenceOf, SetOf,
    Integer, IA5String, OctetString, ParsableOctetString, Integer,
    Any
)
from asn1crypto.x509 import Certificate
import restruct


def ascii2int(s):
    return int.from_bytes(s.encode('ascii'), byteorder='big')

class any_tag(tuple):
    """ highly cursed tuple subtype to bully asn1crypto into accepting any tag """
    def __contains__(self, o):
        return True


class IMG4KeyBag(Sequence):
    _fields = [
        ('id',  Integer),
        ('iv',  OctetString),
        ('key', OctetString),
    ]

class IMG4KeyBagSequence(SequenceOf):
    _child_spec = IMG4KeyBag

class IMG4CompressionAlgorithm(Integer):
    _map = {
        1: 'lzfse',
    }

class IMG4Compression(Sequence):
    _fields = [
        ('algorithm', IMG4CompressionAlgorithm),
        ('original_size', Integer),
    ]

class IMG4Payload(Sequence):
    _fields = [
        ('magic',       IA5String), # "IM4P"
        ('type',        IA5String),
        ('description', IA5String),
        ('data',        OctetString,         {'optional': True}),
        ('keybags',     ParsableOctetString, {'optional': True}),
        ('compression', IMG4Compression,     {'optional': True}),
    ]


class AnyValueInner(Sequence):
    _fields = [
        ('key',   IA5String),
        ('value', Any, {'optional': True}),
    ]

class AnyValue(Sequence):
    _fields = [
        ('value', AnyValueInner),
    ]
    class_ = 3
    _bad_tag = any_tag()

class AnySet(SetOf):
    _child_spec = AnyValue

class IMG4ManifestProperties(Sequence):
    _fields = [
        ('type',   IA5String), # "MANP",
        ('values', AnySet)
    ]

class IMG4ManifestCategory(Sequence):
    _fields = [
        ('category', IMG4ManifestProperties)
    ]
    class_ = 3
    _bad_tag = any_tag()

class IMG4ManifestCategorySet(SetOf):
    _child_spec = IMG4ManifestCategory

class IMG4ManifestBody(Sequence):
    _fields = [
        ('type',       IA5String), # "MANB"
        ('categories', IMG4ManifestCategorySet),
    ]

class IMG4ManifestContent(Choice):
    _alternatives = [
        ('category', IMG4ManifestBody, {'explicit': ('private', ascii2int('MANB'))}),
    ]

class IMG4ManifestContentSet(SetOf):
    _child_spec = IMG4ManifestContent

class IMG4CertificateSequence(SequenceOf):
    _child_spec = Certificate

class IMG4Manifest(Sequence):
    _fields = [
        ('magic',        IA5String), # "IM4M"
        ('version',      Integer),
        ('contents',     IMG4ManifestContentSet),
        ('signature',    OctetString),
        ('certificates', IMG4CertificateSequence),
    ]


class IMG4(Sequence):
    _fields = [
        ('magic',    IA5String), # "IMG4",
        ('payload',  IMG4Payload),
        ('manifest', IMG4Manifest, {'explicit': 0}),
    ]


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--raw', action='store_true', help='print raw parsed data')
    parser.add_argument('infile', type=argparse.FileType('rb'), help='input .img4/.im4m/.im4p file')
    parser.add_argument('outfile', type=argparse.FileType('wb'), nargs='?', help='output data file for payload')
    args = parser.parse_args()

    contents = args.infile.read()
    errors = {}
    for p in (IMG4, IMG4Manifest, IMG4Payload):
        try:
            img4 = p.load(contents)
            img4.native  # trigger parsing
            break
        except Exception as e:
            errors[p] = e
    else:
        print('Could not parse file {}:'.format(args.infile.name))
        for (p, e) in errors.items():
            print(' - As {}: {}'.format(p.__name__, e))
        sys.exit(1)
    
    if isinstance(img4, IMG4):
        payload = img4['payload']
        manifest = img4['manifest']
    elif isinstance(img4, IMG4Manifest):
        payload = None
        manifest = img4
    elif isinstance(img4, IMG4Payload):
        payload = img4
        manifest = None

    if payload:
        p = payload.native
        if args.raw:
            print(restruct.format_value(p, str))
        else:
            print('payload:')
            print('  type:', p['type'])
            print('  desc:', p['description'])
            if p['keybags']:
                print('  keybags:')
                keybags = payload['keybags'].parse(IMG4KeyBagSequence).native
                for kb in keybags:
                    print('    id: ', kb['id'])
                    print('    iv: ', restruct.format_value(kb['iv'], str))
                    print('    key:', restruct.format_value(kb['key'], str))
                    print()
            if p['compression']:
                print('  compression:')
                print('    algo:', p['compression']['algorithm'])
                print('    size:', p['compression']['original_size'])
                algo = p['compression']['algorithm']
            else:
                algo = None
            print()

        if args.outfile:
            if algo == 'lzfse':
                import lzfse
                data = lzfse.decompress(p['data'])
            elif algo:
                raise ValueError('unknown algorithm: {}'.format(algo))
            else:
                data = p['data']
            args.outfile.write(data)
    if manifest:
        m = manifest.native
        if args.raw:
            print(restruct.format_value(m, str))
        else:
            print('manifest:')
            for p in m['contents']:
                print('  body:')
                if p['type'] == 'MANB':
                    for c in p['categories']:
                        cname = c['category']['type']
                        for v in c['category']['values']:
                            print('    {}.{}: {}'.format(cname, v['value']['key'], restruct.format_value(v['value']['value'], str)))
                        print()
