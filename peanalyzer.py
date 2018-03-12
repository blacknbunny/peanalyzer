import pefile, argparse, os, hashlib
from capstone import *

parser = argparse.ArgumentParser(description='Pe Analyzer')
parser.add_argument('--file', help='FILE NAME')
parser.add_argument('--show', help='all')
parser.add_argument('--disassemble', help='all')

args = parser.parse_args()

def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def sha1(fname):
    hash_sha1 = hashlib.sha1()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha1.update(chunk)
    return hash_sha1.hexdigest()

def replacethehex(hex):
    return hex.replace('0x', '')

def offset_increase(variable, offset):
    return hex(variable + offset).replace('0x', '').upper()

def show():
    PE_FILE                     = pefile.PE(args.file)
    target_file                 = os.path.abspath(args.file)

    # GENERAL
    PATH                        = target_file
    FILE_SIZE                   = str(os.path.getsize(target_file))
    MD5_CHECKSUM                = md5(target_file)
    SHA1_CHECKSUM               = sha1(target_file)
    CHECKSUM                    = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.CheckSum))

    # DOS HEADER
    MAGIC_NUMBER                = replacethehex(hex(PE_FILE.DOS_HEADER.e_magic))
    ADDR_NEW_HEADER             = replacethehex(hex(PE_FILE.DOS_HEADER.e_lfanew))
    BYTES_LAST                  = replacethehex(hex(PE_FILE.DOS_HEADER.e_cblp))
    PAGES_IN_FILE               = replacethehex(hex(PE_FILE.DOS_HEADER.e_cp))
    RELOCATIONS                 = replacethehex(hex(PE_FILE.DOS_HEADER.e_crlc))
    HEADER_IN_PARAGRAPH         = replacethehex(hex(PE_FILE.DOS_HEADER.e_cparhdr))
    MINALLOC                    = replacethehex(hex(PE_FILE.DOS_HEADER.e_minalloc))
    MAXALLOC                    = replacethehex(hex(PE_FILE.DOS_HEADER.e_maxalloc))
    INITIAL_SS                  = replacethehex(hex(PE_FILE.DOS_HEADER.e_ss))
    INITIAL_SP                  = replacethehex(hex(PE_FILE.DOS_HEADER.e_sp))
    INITIAL_IP                  = replacethehex(hex(PE_FILE.DOS_HEADER.e_ip))
    INITIAL_CS                  = replacethehex(hex(PE_FILE.DOS_HEADER.e_cs))
    DOS_CHECKSUM                = replacethehex(hex(PE_FILE.DOS_HEADER.e_csum))
    ADDR_RELOCATION_TABLE       = replacethehex(hex(PE_FILE.DOS_HEADER.e_lfarlc))
    OVERLAY_NUMBER              = replacethehex(hex(PE_FILE.DOS_HEADER.e_ovno))
    OEM_ID                      = replacethehex(hex(PE_FILE.DOS_HEADER.e_oemid))
    OEM_INFORMATION             = replacethehex(hex(PE_FILE.DOS_HEADER.e_oeminfo))

    RESERVED_WORDS              = PE_FILE.DOS_HEADER.e_res
    RESERVED_WORDS_ARRAY        = []
    for i in range(0, len(RESERVED_WORDS)):
        RESERVED_WORDS_ARRAY.append(hex(RESERVED_WORDS[i]))

    RESERVED_WORDS_TWO          = PE_FILE.DOS_HEADER.e_res2
    RESERVED_WORDS_TWO_ARRAY    = []
    for x in range(0, len(RESERVED_WORDS_TWO)):
        RESERVED_WORDS_TWO_ARRAY.append(hex(RESERVED_WORDS_TWO[x]))

    print("\n-------------------------------------------------------------------------\n\t\t\t\tGeneral\n-------------------------------------------------------------------------")

    print("File Info: ")
    print("\t" + "Path: " + PATH)
    print("\t" + "Is truncated?: " + "No") # If expection output is not "Unable to read the DOS Header", file is not truncated.
    print("\t" + "File size: " + FILE_SIZE)
    print("\t" + "MD5 Checksum: " + MD5_CHECKSUM)
    print("\t" + "SHA1 Checksum: " + SHA1_CHECKSUM)
    print("\t" + "Checksum: " + CHECKSUM)

    print("\n-------------------------------------------------------------------------\n\t\t\t\tDos Header\n-------------------------------------------------------------------------")

    OFFSET_VALUE = -0x1
    print("Offset  \t\tName\t\t\t\t        Value\n")
    print(offset_increase(OFFSET_VALUE, 1)  + "\t" + "\t\tMagic Number\t\t\t\t"                           + MAGIC_NUMBER.upper())
    print(offset_increase(OFFSET_VALUE, 2)  + "\t" + "\t\tFile address of new exe header\t\t"             + ADDR_NEW_HEADER.upper())
    print(offset_increase(OFFSET_VALUE, 3)  + "\t" + "\t\tBytes on last page of file\t\t"                 + BYTES_LAST)
    print(offset_increase(OFFSET_VALUE, 4)  + "\t" + "\t\tPages in file\t\t\t\t"                          + PAGES_IN_FILE.upper())
    print(offset_increase(OFFSET_VALUE, 5)  + "\t" + "\t\tRelocations\t\t\t\t"                            + RELOCATIONS.upper())
    print(offset_increase(OFFSET_VALUE, 6)  + "\t" + "\t\tSize of header in paragraphs\t\t"               + HEADER_IN_PARAGRAPH.upper())
    print(offset_increase(OFFSET_VALUE, 7)  + "\t" + "\t\tMinimum extra paragraphs needed\t\t"            + MINALLOC.upper())
    print(offset_increase(OFFSET_VALUE, 8)  + "\t" + "\t\tMaximum extra paragraphs needed\t\t"            + MAXALLOC.upper())
    print(offset_increase(OFFSET_VALUE, 9)  + "\t" + "\t\tInitial (relative) SS value\t\t"                + INITIAL_SS.upper())
    print(offset_increase(OFFSET_VALUE, 10)  + "\t" + "\t\tInitial SP Value\t\t\t"                        + INITIAL_SP.upper())
    print(offset_increase(OFFSET_VALUE, 11)  + "\t" + "\t\tInitial IP Value\t\t\t"                        + INITIAL_IP.upper())
    print(offset_increase(OFFSET_VALUE, 12)  + "\t" + "\t\tChecksum\t\t\t\t"                              + DOS_CHECKSUM.upper())
    print(offset_increase(OFFSET_VALUE, 13)  + "\t" + "\t\tInitial (relative) CS Value\t\t"               + INITIAL_CS.upper())
    print(offset_increase(OFFSET_VALUE, 14)  + "\t" + "\t\tFile address of relocation table\t"            + ADDR_RELOCATION_TABLE.upper())
    print(offset_increase(OFFSET_VALUE, 15)  + "\t" + "\t\tOverlay number\t\t\t\t"                        + OVERLAY_NUMBER.upper())
    print(offset_increase(OFFSET_VALUE, 16)  + "\t" + "\t\tOEM Identifier\t\t\t\t"                        + OEM_ID.upper())
    print(offset_increase(OFFSET_VALUE, 17)  + "\t" + "\t\tInformation for OEM\t\t\t"                     + OEM_INFORMATION.upper())
    print(offset_increase(OFFSET_VALUE, 18)  + "\t" + "\t\tReserved Words\t\t\t\t"                        + ','.join(str(x) for x in RESERVED_WORDS))
    print(offset_increase(OFFSET_VALUE, 19)  + "\t" + "\t\tReserved Words Two\t\t\t"                      + ','.join(str(x) for x in RESERVED_WORDS_TWO))

    print("\n-------------------------------------------------------------------------\n\t\t\t\tFile Header\n-------------------------------------------------------------------------")

    MACHINE                    = replacethehex(hex(PE_FILE.FILE_HEADER.Machine))
    NumberOfSections           = replacethehex(hex(PE_FILE.FILE_HEADER.NumberOfSections))
    NumberOfSymbols            = replacethehex(hex(PE_FILE.FILE_HEADER.NumberOfSymbols))
    TimeDateStamp              = replacethehex(hex(PE_FILE.FILE_HEADER.TimeDateStamp))
    PointerToSymbolTable       = replacethehex(hex(PE_FILE.FILE_HEADER.PointerToSymbolTable))
    SizeOfOptionalHeader       = replacethehex(hex(PE_FILE.FILE_HEADER.SizeOfOptionalHeader))
    Characteristics            = replacethehex(hex(PE_FILE.FILE_HEADER.Characteristics))
    MACHINE_TYPE               = ''
    if MACHINE == '0':
        MACHINE_TYPE = 'UNKNOWN'
    elif MACHINE == '14c':
        MACHINE_TYPE = 'I386'
    elif MACHINE == '162':
        MACHINE_TYPE = 'R3000'
    elif MACHINE == '166':
        MACHINE_TYPE = 'R4000'
    elif MACHINE == '168':
        MACHINE_TYPE = 'R10000'
    elif MACHINE == '169':
        MACHINE_TYPE = 'WCEMIPSV2'
    elif MACHINE == '184':
        MACHINE_TYPE = 'ALPHA'
    elif MACHINE == '1a2':
        MACHINE_TYPE = 'SH3'
    elif MACHINE == '1a3':
        MACHINE_TYPE = 'SH3DSP'
    elif MACHINE == '1a4':
        MACHINE_TYPE = 'SH3E'
    elif MACHINE == '1a6':
        MACHINE_TYPE = 'SH4'
    elif MACHINE == '1a8':
        MACHINE_TYPE = 'SH5'
    elif MACHINE == '1c0':
        MACHINE_TYPE = 'ARM'
    elif MACHINE == '1c2':
        MACHINE_TYPE = 'THUMB'
    elif MACHINE == '1c4':
        MACHINE_TYPE = 'ARMNT'
    elif MACHINE == '1d3':
        MACHINE_TYPE = 'AM33'
    elif MACHINE == '1f0':
        MACHINE_TYPE = 'POWERPC'
    elif MACHINE == '1f1':
        MACHINE_TYPE = 'POWERPCFP'
    elif MACHINE == '200':
        MACHINE_TYPE = 'IA64'
    elif MACHINE == '266':
        MACHINE_TYPE = 'MIPS16'
    elif MACHINE == '284':
        MACHINE_TYPE = 'AXP64'
    elif MACHINE == '366':
        MACHINE_TYPE = 'MIPSFPU'
    elif MACHINE == '466':
        MACHINE_TYPE = 'MIPSFPU16'
    elif MACHINE == '520':
        MACHINE_TYPE = 'TRICORE'
    elif MACHINE == 'cef':
        MACHINE_TYPE = 'CEF'
    elif MACHINE == 'ebc':
        MACHINE_TYPE = 'EBC'
    elif MACHINE == '8664':
        MACHINE_tYPE = 'AMD64'
    elif MACHINE == '9041':
        MACHINE_TYPE = 'M32R'
    elif MACHINE == 'c0ee':
        MACHINE_TYPE = 'CEE'

    print("Offset   \t\tName\t\t\t Value\t\t Type\n")
    print(offset_increase(OFFSET_VALUE, 20) + "\t" + "\t\tMachine\t\t\t " + MACHINE   + "\t\t " + MACHINE_TYPE)
    print(offset_increase(OFFSET_VALUE, 21) + "\t" + "\t\tNumber Of Sections\t "      + NumberOfSections)
    print(offset_increase(OFFSET_VALUE, 22) + "\t" + "\t\tNumber Of Symbols\t "       + NumberOfSymbols)
    print(offset_increase(OFFSET_VALUE, 23) + "\t" + "\t\tTime Date Stamp\t\t "       + TimeDateStamp)
    print(offset_increase(OFFSET_VALUE, 24) + "\t" + "\t\tPointer To Symbol Table\t " + PointerToSymbolTable)
    print(offset_increase(OFFSET_VALUE, 25) + "\t" + "\t\tSize of Optional Header\t " + SizeOfOptionalHeader)
    print(offset_increase(OFFSET_VALUE, 26) + "\t" + "\t\tCharacteristics\t\t "       + Characteristics)

    print("\n-------------------------------------------------------------------------\n\t\t\t\tOptional Header\n-------------------------------------------------------------------------")
    
    MAGIC                                        = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.Magic) if hasattr(PE_FILE.OPTIONAL_HEADER, 'Magic') else '0x0')
    MajorLinkerVersion                           = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.MajorLinkerVersion) if hasattr(PE_FILE.OPTIONAL_HEADER, 'MajorLinkerVersion') else '0x0')
    MinorLinkerVersion                           = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.MinorLinkerVersion) if hasattr(PE_FILE.OPTIONAL_HEADER, 'MinorLinkerVersion') else '0x0')
    SizeOfCode                                   = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.SizeOfCode) if hasattr(PE_FILE.OPTIONAL_HEADER, 'SizeOfCode') else '0x0')
    SizeOfInitializedData                        = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.SizeOfInitializedData) if hasattr(PE_FILE.OPTIONAL_HEADER, 'SizeOfInitializedData') else '0x0')
    SizeOfUninitializedData                      = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.SizeOfUninitializedData) if hasattr(PE_FILE.OPTIONAL_HEADER, 'SizeOfUninitializedData') else '0x0')
    AddressOfEntryPoint                          = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.AddressOfEntryPoint) if hasattr(PE_FILE.OPTIONAL_HEADER, 'AddressOfEntryPoint') else '0x0')
    BaseOfCode                                   = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.BaseOfCode) if hasattr(PE_FILE.OPTIONAL_HEADER, 'BaseOfCode') else '0x0')
    BaseOfData                                   = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.BaseOfData) if hasattr(PE_FILE.OPTIONAL_HEADER, 'BaseOfData') else '0x0')
    ImageBase                                    = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.ImageBase) if hasattr(PE_FILE.OPTIONAL_HEADER, 'ImageBase') else '0x0')
    SectionAlignment                             = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.SectionAlignment) if hasattr(PE_FILE.OPTIONAL_HEADER, 'SectionAlignment') else '0x0')
    FileAlignment                                = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.FileAlignment) if hasattr(PE_FILE.OPTIONAL_HEADER, 'FileAlignment') else '0x0')
    MajorOperatingSystemVersion                  = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.MajorOperatingSystemVersion) if hasattr(PE_FILE.OPTIONAL_HEADER, 'MajorOperatingSystemVersion') else '0x0')
    MinorOperatingSystemVersion                  = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.MinorOperatingSystemVersion) if hasattr(PE_FILE.OPTIONAL_HEADER, 'MinorOperatingSystemVersion') else '0x0')
    MajorImageVersion                            = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.MajorImageVersion) if hasattr(PE_FILE.OPTIONAL_HEADER, 'MajorImageVersion') else '0x0')
    MinorImageVersion                            = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.MinorImageVersion) if hasattr(PE_FILE.OPTIONAL_HEADER, 'MinorImageVersion') else '0x0')
    MajorSubsystemVersion                        = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.MajorSubsystemVersion) if hasattr(PE_FILE.OPTIONAL_HEADER, 'MajorSubsystemVersion') else '0x0')
    MinorSubsystemVersion                        = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.MinorSubsystemVersion) if hasattr(PE_FILE.OPTIONAL_HEADER, 'MinorSubsystemVersion') else '0x0')
    SizeOfImage                                  = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.SizeOfImage) if hasattr(PE_FILE.OPTIONAL_HEADER, 'SizeOfImage') else '0x0')
    SizeOfHeaders                                = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.SizeOfHeaders) if hasattr(PE_FILE.OPTIONAL_HEADER, 'SizeOfHeaders') else '0x0')
    CheckSum                                     = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.CheckSum) if hasattr(PE_FILE.OPTIONAL_HEADER, 'CheckSum') else '0x0')
    Subsystem                                    = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.Subsystem) if hasattr(PE_FILE.OPTIONAL_HEADER, 'Subsystem') else '0x0')
    DllCharacteristics                           = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.DllCharacteristics) if hasattr(PE_FILE.OPTIONAL_HEADER, 'DllCharacteristics') else '0x0')
    SizeOfStackReserve                           = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.SizeOfStackReserve) if hasattr(PE_FILE.OPTIONAL_HEADER, 'SizeOfStackReserve') else '0x0')
    SizeOfStackCommit                            = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.SizeOfStackCommit) if hasattr(PE_FILE.OPTIONAL_HEADER, 'SizeOfStackCommit') else '0x0')
    SizeOfHeapReserve                            = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.SizeOfHeapReserve) if hasattr(PE_FILE.OPTIONAL_HEADER, 'SizeOfHeapReserve') else '0x0')
    SizeOfHeapCommit                             = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.SizeOfHeapCommit) if hasattr(PE_FILE.OPTIONAL_HEADER, 'SizeOfHeapCommit') else '0x0')
    LoaderFlags                                  = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.LoaderFlags) if hasattr(PE_FILE.OPTIONAL_HEADER, 'LoaderFlags') else '0x0')
    NumberOfRvaAndSizes                          = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.NumberOfRvaAndSizes) if hasattr(PE_FILE.OPTIONAL_HEADER, 'NumberOfRvaAndSizes') else '0x0')
    Data_Directory                               = PE_FILE.OPTIONAL_HEADER.DATA_DIRECTORY

    print("Offset   \t\tName\t\t\t\t Value\n")
    print(offset_increase(OFFSET_VALUE, 27) + "\t" + "\t\tMagic\t\t\t\t "                            + MAGIC)
    print(offset_increase(OFFSET_VALUE, 28) + "\t" + "\t\tMajor Linker Version\t\t "                 + MajorLinkerVersion)
    print(offset_increase(OFFSET_VALUE, 29) + "\t" + "\t\tMinor Linker Version\t\t "                 + MinorLinkerVersion)
    print(offset_increase(OFFSET_VALUE, 30) + "\t" + "\t\tSize Of Code\t\t\t "                       + SizeOfCode)
    print(offset_increase(OFFSET_VALUE, 31) + "\t" + "\t\tSize Of Initialized Data\t "               + SizeOfInitializedData)
    print(offset_increase(OFFSET_VALUE, 32) + "\t" + "\t\tSize Of Uninitialized Data\t "             + SizeOfUninitializedData)
    print(offset_increase(OFFSET_VALUE, 33) + "\t" + "\t\tAddress Of Entry Point\t\t "               + AddressOfEntryPoint)
    print(offset_increase(OFFSET_VALUE, 34) + "\t" + "\t\tBase Of Code\t\t\t "                       + BaseOfCode)
    print(offset_increase(OFFSET_VALUE, 35) + "\t" + "\t\tBase Of Data\t\t\t "                       + BaseOfData)
    print(offset_increase(OFFSET_VALUE, 36) + "\t" + "\t\tImage Base\t\t\t "                         + ImageBase)
    print(offset_increase(OFFSET_VALUE, 37) + "\t" + "\t\tSection Alignment\t\t "                    + SectionAlignment)
    print(offset_increase(OFFSET_VALUE, 38) + "\t" + "\t\tFile Alignment\t\t\t "                     + FileAlignment)
    print(offset_increase(OFFSET_VALUE, 39) + "\t" + "\t\tMajor Operating System Version\t "         + MajorOperatingSystemVersion)
    print(offset_increase(OFFSET_VALUE, 40) + "\t" + "\t\tMinor Operating System Version\t "         + MinorOperatingSystemVersion)
    print(offset_increase(OFFSET_VALUE, 41) + "\t" + "\t\tMajor Image Version\t\t "                  + MajorImageVersion)
    print(offset_increase(OFFSET_VALUE, 42) + "\t" + "\t\tMinor Image Version\t\t "                  + MinorImageVersion)
    print(offset_increase(OFFSET_VALUE, 43) + "\t" + "\t\tMajor Subsystem Version\t\t "              + MajorSubsystemVersion)
    print(offset_increase(OFFSET_VALUE, 44) + "\t" + "\t\tMinor Subsystem Version\t\t "              + MinorSubsystemVersion)
    print(offset_increase(OFFSET_VALUE, 45) + "\t" + "\t\tSize Of Image\t\t\t "                      + SizeOfImage)
    print(offset_increase(OFFSET_VALUE, 46) + "\t" + "\t\tSize Of Headers\t\t\t "                    + SizeOfHeaders)
    print(offset_increase(OFFSET_VALUE, 47) + "\t" + "\t\tCheckSum\t\t\t "                           + CheckSum)
    print(offset_increase(OFFSET_VALUE, 48) + "\t" + "\t\tSubsystem\t\t\t "                          + Subsystem)
    print(offset_increase(OFFSET_VALUE, 49) + "\t" + "\t\tDll Characteristics\t\t "                  + DllCharacteristics)
    print(offset_increase(OFFSET_VALUE, 50) + "\t" + "\t\tSize Of Stack Reserve\t\t "                + SizeOfStackReserve)
    print(offset_increase(OFFSET_VALUE, 51) + "\t" + "\t\tSize Of Stack Commit\t\t "                 + SizeOfStackCommit)
    print(offset_increase(OFFSET_VALUE, 52) + "\t" + "\t\tSize Of Heap Reserve\t\t "                 + SizeOfHeapReserve)
    print(offset_increase(OFFSET_VALUE, 53) + "\t" + "\t\tSize Of Heap Commit\t\t "                  + SizeOfHeapCommit)
    print(offset_increase(OFFSET_VALUE, 54) + "\t" + "\t\tLoader Flags\t\t\t "                         + LoaderFlags)
    print(offset_increase(OFFSET_VALUE, 55) + "\t" + "\t\tNumber Of Rva And Sizes\t\t "              + NumberOfRvaAndSizes)
    print("\n-------------------------------------------------------------------------\n\t\t\t\t<-- DATA DIRECTORY\n-------------------------------------------------------------------------")
    print("Name\t\t\t\tVirtual Address\t\tSize\n")
    print("Export Table\t\t\t"                  + replacethehex(hex(Data_Directory[0].VirtualAddress)) + "\t\t\t" + replacethehex(hex(Data_Directory[0].Size)))
    print("Import Table\t\t\t"                  + replacethehex(hex(Data_Directory[1].VirtualAddress)) + "\t\t\t" + replacethehex(hex(Data_Directory[1].Size)))
    print("Resource Table\t\t\t"                + replacethehex(hex(Data_Directory[2].VirtualAddress)) + "\t\t\t" + replacethehex(hex(Data_Directory[2].Size)))
    print("Exception Table\t\t\t"               + replacethehex(hex(Data_Directory[3].VirtualAddress)) + "\t\t\t" + replacethehex(hex(Data_Directory[3].Size)))
    print("Certificate Table\t\t"               + replacethehex(hex(Data_Directory[4].VirtualAddress)) + "\t\t\t" + replacethehex(hex(Data_Directory[4].Size)))
    print("Base Relocation Table\t\t"           + replacethehex(hex(Data_Directory[5].VirtualAddress)) + "\t\t\t" + replacethehex(hex(Data_Directory[5].Size)))
    print("Debugging Information\t\t"           + replacethehex(hex(Data_Directory[6].VirtualAddress)) + "\t\t\t" + replacethehex(hex(Data_Directory[6].Size)))
    print("Architecture-specific\t\t"           + replacethehex(hex(Data_Directory[7].VirtualAddress)) + "\t\t\t" + replacethehex(hex(Data_Directory[7].Size)))
    print("Global Pointer Register\t\t"         + replacethehex(hex(Data_Directory[8].VirtualAddress)) + "\t\t\t" + replacethehex(hex(Data_Directory[8].Size)))
    print("Thread Local Storage\t\t"            + replacethehex(hex(Data_Directory[9].VirtualAddress)) + "\t\t\t" + replacethehex(hex(Data_Directory[9].Size)))
    print("Load Configuration\t\t"              + replacethehex(hex(Data_Directory[10].VirtualAddress)) + "\t\t\t" + replacethehex(hex(Data_Directory[10].Size)))
    print("Bound Import Table\t\t"              + replacethehex(hex(Data_Directory[11].VirtualAddress)) + "\t\t\t" + replacethehex(hex(Data_Directory[11].Size)))
    print("Import Address\t\t\t"                + replacethehex(hex(Data_Directory[12].VirtualAddress)) + "\t\t\t" + replacethehex(hex(Data_Directory[12].Size)))
    print("Delay Import Descriptor\t\t"         + replacethehex(hex(Data_Directory[13].VirtualAddress)) + "\t\t\t" + replacethehex(hex(Data_Directory[13].Size)))
    print("The CLR Header\t\t\t"                + replacethehex(hex(Data_Directory[14].VirtualAddress)) + "\t\t\t" + replacethehex(hex(Data_Directory[14].Size)))
    print("Reserved\t\t\t"                      + replacethehex(hex(Data_Directory[15].VirtualAddress)) + "\t\t\t" + replacethehex(hex(Data_Directory[15].Size)))
    print("\n-------------------------------------------------------------------------\n\t\t\t\tDATA DIRECTORY -->\n-------------------------------------------------------------------------")
    print("\n-------------------------------------------------------------------------\n\t\t\t\tSection Headers\n-------------------------------------------------------------------------")
    print("Name\t\tVirtual Address\t\tVirtual Size\t\tSizeOfRawData\n")
    for section in PE_FILE.sections:
        print (section.Name.decode('utf-8') + "\t\t" +  hex(section.VirtualAddress) + "\t\t\t" + hex(section.Misc_VirtualSize) +  "\t\t\t" + str(section.SizeOfRawData) )
    print("\n-------------------------------------------------------------------------\n\t\t\t\tImports\n-------------------------------------------------------------------------")
    print("Name\t\tAddress\t\tFunction\n")
    for entry in PE_FILE.DIRECTORY_ENTRY_IMPORT:
        print(entry.dll.decode('utf-8'))
        for imps in entry.imports:
            print('\t', hex(imps.address), '\t', (imps.ordinal if (imps.name is None) else imps.name.decode('utf-8')))

def disassemble():
    pe = pefile.PE(args.file)

    eop = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    code_section = pe.get_section_by_rva(eop)

    code_dump = code_section.get_data()
    code_addr = pe.OPTIONAL_HEADER.ImageBase + code_section.VirtualAddress

    md = Cs(CS_ARCH_X86, CS_MODE_64)

    for i in md.disasm(code_dump, code_addr):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
try:
    if args.file != '':
        if args.show == 'all':
            show()
        elif args.disassemble == 'all':
            disassemble();
        else:
            parser.print_help()
    else:
        parser.print_help()
except Exception as err:
    parser.print_help()
    print("\nException: \n", err);
