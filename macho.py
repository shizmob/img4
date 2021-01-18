#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Greetings to: XNU source code

import enum
import uuid
import restruct
from restruct import Processed, Type, Struct, Data, Arr, Generic


# Forward declaration
MachO_ = Generic()


class ULEB128(Type):
    def parse(self, io, context):
        value = 0
        n = 0
        while True:
            v = io.read(1)[0]
            value |= (v & 0b1111111) << n
            if not (v & 0b10000000):
                break
            n += 7
        return value


class Protection(enum.Flag):
    Read  = 1
    Write = 2
    Exec  = 4


class CPUType(enum.Enum):
    VAX     = 1
    MC68k   = 6
    X86     = 7
    MIPS    = 8
    MC98k   = 10
    HPPA    = 11
    ARM     = 12
    MC88k   = 13
    SPARC   = 14
    I860    = 15
    Alpha   = 16
    PowerPC = 18

class LoadCommandType(enum.Enum):
    Segment = 1
    SymbolTable = 2
    SymbolDebugInfo = 3
    Thread = 4
    UnixThread = 5
    LoadFixedLibrary = 6
    FixedLibraryID = 7
    ID = 8
    IncludeFixed = 9
    Prepage = 10
    DynamicSymbolTable = 11
    LoadDynamicLibrary = 12
    DynamicLibraryID = 13
    LoadDynamicLinker = 14
    DynamicLinkerID = 15
    PreboundDynamicLibrary = 16
    Routines = 17
    SubFramework = 18
    SubUmbrella = 19
    SubClient = 20
    SubLibrary = 21
    TwoLevelHints = 22
    PreboundChecksum = 23
    LoadWeakDynamicLibrary = 24
    Segment64 = 25
    Routines64 = 26
    UUID = 27
    RunPath = 28
    CodeSignature = 29
    SegmentSplitInfo = 30
    ReExportDynamicLibrary = 31
    LazyLoadDynamicLibrary = 32
    EncryptionInfo = 33
    DynamicLinkerInfo = 34
    LoadUpwardDynamicLibrary = 35
    MinMacOSVersion = 36
    MinIPhoneOSVersion = 37
    FunctionStartAddresses = 38
    DynamicLinkerEnvironment = 39
    Main = 40
    DataInCode = 41
    SourceVersion = 42
    DynamicLibraryCodeSignatureDR = 43
    EncryptionInfo64 = 44
    LinkerOption = 45
    LinkerOptimizationHint = 46
    MinTVOSVersion = 47
    MinWatchOSVersion = 48
    Note = 49
    BuildVersion = 50
    DynamicLibraryExportsTrie = 51
    ChainedFixups = 52
    FileSetEntry = 53


LOAD_COMMANDS = {}

def lc(i):
    def inner(v):
        LOAD_COMMANDS[i] = v
        return v
    return inner


lc(LoadCommandType.UUID)(
    Processed(Data(16), lambda x: uuid.UUID(bytes=x), lambda x: x.bytes)
)

class Version(Struct):
    patch: UInt(8)
    minor: UInt(8)
    major: UInt(16)

class BuildTool(enum.Enum):
    Clang = 1
    Swift = 2
    LD  = 3

class BuildToolVersion(Struct):
    tool:    Enum(BuildTool, UInt(32))
    version: Version

class Platform(enum.Enum):
    Unknown = 0
    macOS = 1
    iOS = 2
    tvOS = 3
    watchOS = 4
    bridgeOS = 5
    Catalyst = 6
    iOSSimulator = 7
    tvOSSimulator = 8
    watchOSSimulator = 9
    DriverKit = 10

@lc(LoadCommandType.BuildVersion)
class BuildVersion(Struct, partials={'C'}):
    platform:   Enum(Platform, UInt(32))
    min_os:     Version
    sdk:        Version
    tool_count: UInt(32) @ C.count
    tools:      Arr(BuildToolVersion) @ C


class ThreadFlavor(enum.Enum):
    Thread = 1
    FloatingPoint = 2
    Exception = 3
    Debug = 4
    No = 5
    Thread64 = 6
    Exception64 = 7
    Thread32 = 9

THREAD_TYPES = {}

def thread(cpu, id):
    def inner(v):
        THREAD_TYPES[cpu, id] = v
        return v
    return inner


@thread(CPUType.ARM, ThreadFlavor.Thread)
class ARMThreadState32(Struct):
    gp: Arr(UInt(32), count=13)
    sp: UInt(32)
    lr: UInt(32)
    pc: UInt(32)
    cpsr: UInt(32)

@thread(CPUType.ARM, ThreadFlavor.Thread64)
class ARMThreadState64(Struct):
    gp: Arr(UInt(64), count=29)
    fp: UInt(64)
    lr: UInt(64)
    sp: UInt(64)
    pc: UInt(64)
    cpsr: UInt(32)
    flags: UInt(32)

@thread(CPUType.ARM, ThreadFlavor.FloatingPoint)
class ARMFloatingPointState(Struct):
    fp: Arr(UInt(32), count=64)
    fpscr: UInt(32)

@thread(CPUType.ARM, ThreadFlavor.Exception)
class ARMExceptionState32(Struct):
    id: UInt(32)
    status: UInt(32)
    addr: UInt(32)

@thread(CPUType.ARM, ThreadFlavor.Exception64)
class ARMExceptionState64(Struct):
    addr: UInt(64)
    status: UInt(32)
    id: UInt(32)

@lc(LoadCommandType.Thread)
@lc(LoadCommandType.UnixThread)
class Thread(Struct, partials={'S'}):
    flavor: Enum(ThreadFlavor, UInt(32))
    size:   Processed(UInt(32), lambda x: x * 4, lambda x: x // 4) @ S.limit
    state:  Sized(Switch(fallback=Data(), options=THREAD_TYPES), exact=True) @ S

    def on_parse_flavor(self, spec, context):
        spec.state.type.selector = (context.user.cpu_type, self.flavor)


class LinkEntry(Struct, generics={'T'}, partials={'R', 'S'}):
    offset: UInt(32) @ R.point
    size:   UInt(32) @ S.limit
    data:   Ref(Sized(T) @ S) @ R

lc(LoadCommandType.ChainedFixups)(LinkEntry[Data()])
lc(LoadCommandType.FunctionStartAddresses)(LinkEntry[Arr(ULEB128(), stop_value=0)])


class Section(Struct, generics={'AddrSize'}):
    name: Str(length=16, exact=True)
    segment_name: Str(length=16, exact=True)
    vm_offset:    UInt(AddrSize)
    vm_size:      UInt(AddrSize)
    file_offset:  UInt(32)
    alignment:    UInt(32)
    reloc_offset: UInt(32)
    reloc_count:  UInt(32)
    flags:        UInt(32)
    _reserved:    Data(12)

class Segment(Struct, generics={'AddrSize'}, partials={'C', 'DS', 'DR'}):
    name: Str(length=16, exact=True)
    vm_offset:     UInt(AddrSize) @ DR.point
    vm_size:       UInt(AddrSize) @ DS.size
    file_offset:   UInt(AddrSize)
    file_size:     UInt(AddrSize)
    max_prot:      Enum(Protection, UInt(32))
    init_prot:     Enum(Protection, UInt(32))
    section_count: UInt(32) @ C.count
    flags:         UInt(32)
    sections:      Arr(Section[AddrSize])


lc(LoadCommandType.Segment)(Segment[32])
lc(LoadCommandType.Segment64)(Segment[64])


class SymbolType(enum.Enum):
    Undefined = 0
    Absolute = 1
    Indirect = 5
    Prebound = 6
    InSection = 7

class SymbolEntry(Struct, generics={'AddrSize'}):
    string_index: UInt(32)
    external:     Bool(Bits(1))
    type:         Enum(SymbolType, Bits(3))
    priv_external:Bool(Bits(1))
    stab:         Bits(3)
    section:      UInt(8)
    desc:         UInt(16)
    value:        UInt(AddrSize)

@lc(LoadCommandType.SymbolTable)
class SymbolTable(Struct, partials={'SyR', 'SyA', 'StL', 'StR', 'StC'}):
    symbol_offset: UInt(32) @ SyR.point
    symbol_count:  UInt(32) @ SyA.count
    string_offset: UInt(32) @ StR.point
    string_size:   UInt(32) @ StC.limit @ StL.size
    #symbols:       Ref(Arr(SymbolEntry[64]) @ SyA) @ SyR
    #strings:       Ref(Lazy(Sized(Arr(Str(), stop_value='')) @ StC) @ StL) @ StR

@lc(LoadCommandType.DynamicSymbolTable)
class DynamicSymbolTable(Struct):
    local_index: UInt(32)
    local_count: UInt(32)
    external_index: UInt(32)
    external_count: UInt(32)
    undefined_index: UInt(32)
    undefined_count: UInt(32)
    toc_offset: UInt(32)
    toc_count:  UInt(32)
    module_table_offset: UInt(32)
    module_table_count:  UInt(32)
    external_table_offset: UInt(32)
    external_table_count:  UInt(32)
    indirect_table_offset: UInt(32)
    indirect_table_count:  UInt(32)
    external_reloc_offset: UInt(32)
    external_reloc_count:  UInt(32)
    reloc_offset: UInt(32)
    reloc_count:  UInt(32)

@lc(LoadCommandType.SourceVersion)
class SourceVersion(Struct):
    level:    Bits(10)
    stage:    Bits(10)
    revision: Bits(10)
    minor:    Bits(10)
    major:    UInt(24)

@lc(LoadCommandType.FileSetEntry)
class FileSetEntry(Struct, partials={'R'}):
    vm_offset:   UInt(64)
    file_offset: UInt(64) @ R.point
    entry_id:    UInt(64)
    name:        Str()
    data:        Ref(MachO_) @ R


class CPUTypeFlags(Struct):
    is_64_bit:    Bool(Bits(1))
    is_64_32_bit: Bool(Bits(1))
    _pad2: Bits(6)

class ARMSubType(enum.Enum):
    All    = 0
    V4T    = 5
    V6     = 6
    V5TEJ  = 7
    XScale = 8
    V7     = 9
    V7F    = 10
    V7S    = 11
    V7K    = 12
    V8     = 13
    V6M    = 14
    V7M    = 15
    V7EM   = 16
    V8M    = 17

class ARM64SubType(enum.Enum):
    All = 0
    V8  = 1
    E   = 2

class FileType(enum.Enum):
    Object = 1
    Executable = 2
    FixedLibrary = 3
    CoreDump = 4
    Preloaded = 5
    DynamicLibrary = 6
    DynamicLinker = 7
    Bundle = 8
    DynamicLibraryStub = 9
    DSym = 10
    KernelExtensionBundle = 11
    FileSet = 12

class LoadCommand(Struct, partials={'T', 'S'}):
    type:  Enum(LoadCommandType, Bits(31)) @ T.selector
    vital: Bool(Bits(1))
    size:  Processed(UInt(32), lambda x: x - 8, lambda x: x + 8) @ S.limit
    data:  Sized(Switch(fallback=Data(), options=LOAD_COMMANDS) @ T, exact=True) @ S

class MachO(Struct, partials={'C', 'S'}):
    magic:              UInt(32)
    cpu_type:           Enum(CPUType, UInt(24))
    cpu_type_flags:     CPUTypeFlags
    cpu_sub_type:       Switch(fallback=UInt(24), options={
        (CPUType.ARM, False): Enum(ARMSubType, UInt(24)),
        (CPUType.ARM, True):  Enum(ARM64SubType, UInt(24))
    })
    cpu_sub_type_flags: UInt(8)
    file_type:          Enum(FileType, UInt(32))
    command_count:      UInt(32) @ C.count
    command_size:       UInt(32) @ S.limit
    flags:              UInt(32)
    reserved:           UInt(32)
    commands:           Sized(Arr(LoadCommand) @ C) @ S

    def on_parse_cpu_type_flags(self, spec, context):
        context.user.cpu_type = self.cpu_type
        spec.cpu_sub_type.selector = (self.cpu_type, self.cpu_type_flags.is_64_bit)

MachO_.resolve(MachO)


if __name__ == '__main__':
    import sys, os, os.path
    f = open(sys.argv[1], 'rb')
    m = restruct.parse(MachO, f)
    print(m)
