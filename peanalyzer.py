import pefile, argparse, os, hashlib, re
from capstone import *

parser = argparse.ArgumentParser(description='Pe Analyzer')
parser.add_argument('--file', help='FILE NAME')
parser.add_argument('--show', help='all|file-path|general|dos-header|file-header|optional-header|data-directory|section-headers|imports')
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

def show(scope):
    PE_FILE                     = pefile.PE(args.file)
    target_file                 = os.path.abspath(args.file)

    # GENERAL
    PATH                        = target_file

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

    bNoSectionHeader = ('all' not in scope) and ((len(scope) == 1) or ((len(scope) == 2) and ('file-path' in scope)))
    bGeneralDisplayed = False
    if ('all' in scope) or ('general' in scope):
        bGeneralDisplayed = True
        MD5_CHECKSUM                = md5(target_file)
        SHA1_CHECKSUM               = sha1(target_file)
        CHECKSUM                    = replacethehex(hex(PE_FILE.OPTIONAL_HEADER.CheckSum))
        FILE_SIZE                   = str(os.path.getsize(target_file))
        if(not bNoSectionHeader):
            print("\n-------------------------------------------------------------------------\n\t\t\t\tGeneral\n-------------------------------------------------------------------------")
        fmt = "%-16s\t%s"
        print(fmt % ("File path:",      PATH))
        print(fmt % ("Is truncated?:",  "No")) # If expection output is not "Unable to read the DOS Header", file is not truncated.
        print(fmt % ("File size:",      FILE_SIZE))
        print(fmt % ("MD5 Checksum:",   MD5_CHECKSUM))
        print(fmt % ("SHA1 Checksum:",  SHA1_CHECKSUM))
        print(fmt % ("Checksum:",       CHECKSUM))

    if ('file-path' in scope) and (not bGeneralDisplayed):
        print(PATH)

    OFFSET_VALUE = -0x1

    if ('all' in scope) or ('dos-header' in scope):
        if(not bNoSectionHeader):
            print("\n-------------------------------------------------------------------------\n\t\t\t\tDos Header\n-------------------------------------------------------------------------")
        fmt = "%-6s\t%-40s\t%s"
        print(fmt % ("Offset", "Name", "Value"), end="\n\n")
        print(fmt % (offset_increase(OFFSET_VALUE, 1),  "Magic Number",                           MAGIC_NUMBER.upper()))
        print(fmt % (offset_increase(OFFSET_VALUE, 2),  "File address of new exe header",         ADDR_NEW_HEADER.upper()))
        print(fmt % (offset_increase(OFFSET_VALUE, 3),  "Bytes on last page of file",             BYTES_LAST))
        print(fmt % (offset_increase(OFFSET_VALUE, 4),  "Pages in file",                          PAGES_IN_FILE.upper()))
        print(fmt % (offset_increase(OFFSET_VALUE, 5),  "Relocations",                            RELOCATIONS.upper()))
        print(fmt % (offset_increase(OFFSET_VALUE, 6),  "Size of header in paragraphs",           HEADER_IN_PARAGRAPH.upper()))
        print(fmt % (offset_increase(OFFSET_VALUE, 7),  "Minimum extra paragraphs needed",        MINALLOC.upper()))
        print(fmt % (offset_increase(OFFSET_VALUE, 8),  "Maximum extra paragraphs needed",        MAXALLOC.upper()))
        print(fmt % (offset_increase(OFFSET_VALUE, 9),  "Initial (relative) SS value",            INITIAL_SS.upper()))
        print(fmt % (offset_increase(OFFSET_VALUE, 10), "Initial SP Value",                       INITIAL_SP.upper()))
        print(fmt % (offset_increase(OFFSET_VALUE, 11), "Initial IP Value",                       INITIAL_IP.upper()))
        print(fmt % (offset_increase(OFFSET_VALUE, 12), "Checksum",                               DOS_CHECKSUM.upper()))
        print(fmt % (offset_increase(OFFSET_VALUE, 13), "Initial (relative) CS Value",            INITIAL_CS.upper()))
        print(fmt % (offset_increase(OFFSET_VALUE, 14), "File address of relocation table",       ADDR_RELOCATION_TABLE.upper()))
        print(fmt % (offset_increase(OFFSET_VALUE, 15), "Overlay number",                         OVERLAY_NUMBER.upper()))
        print(fmt % (offset_increase(OFFSET_VALUE, 16), "OEM Identifier",                         OEM_ID.upper()))
        print(fmt % (offset_increase(OFFSET_VALUE, 17), "Information for OEM",                    OEM_INFORMATION.upper()))
        print(fmt % (offset_increase(OFFSET_VALUE, 18), "Reserved Words",                         ','.join(str(x) for x in RESERVED_WORDS)))
        print(fmt % (offset_increase(OFFSET_VALUE, 19), "Reserved Words Two",                     ','.join(str(x) for x in RESERVED_WORDS_TWO)))

    if ('all' in scope) or ('file-header' in scope):
        if(not bNoSectionHeader):
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
       
        fmt = "%-6s\t%-40s\t%-16s\t%s"
        print(fmt % ("Offset", "Name", "Value", "Type"), end="\n\n")
        print(fmt % (offset_increase(OFFSET_VALUE, 20), "Machine", MACHINE, MACHINE_TYPE))
        print(fmt % (offset_increase(OFFSET_VALUE, 21), "Number Of Sections", NumberOfSections, ""))
        print(fmt % (offset_increase(OFFSET_VALUE, 22), "Number Of Symbols", NumberOfSymbols, ""))
        print(fmt % (offset_increase(OFFSET_VALUE, 23), "Time Date Stamp", TimeDateStamp, ""))
        print(fmt % (offset_increase(OFFSET_VALUE, 24), "Pointer To Symbol Table", PointerToSymbolTable, ""))
        print(fmt % (offset_increase(OFFSET_VALUE, 25), "Size of Optional Header", SizeOfOptionalHeader, ""))
        print(fmt % (offset_increase(OFFSET_VALUE, 26), "Characteristics", Characteristics, ""))

    if ('all' in scope) or ('optional-header' in scope):
        if(not bNoSectionHeader):
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
       
        fmt = "%-6s\t%-40s\t%s"
        print(fmt % ("Offset", "Name", "Value"), end="\n\n")
        print(fmt % (offset_increase(OFFSET_VALUE, 27), "Magic", MAGIC))
        print(fmt % (offset_increase(OFFSET_VALUE, 28), "Major Linker Version", MajorLinkerVersion))
        print(fmt % (offset_increase(OFFSET_VALUE, 29), "Minor Linker Version", MinorLinkerVersion))
        print(fmt % (offset_increase(OFFSET_VALUE, 30), "Size Of Code", SizeOfCode))
        print(fmt % (offset_increase(OFFSET_VALUE, 31), "Size Of Initialized Data", SizeOfInitializedData))
        print(fmt % (offset_increase(OFFSET_VALUE, 32), "Size Of Uninitialized Data", SizeOfUninitializedData))
        print(fmt % (offset_increase(OFFSET_VALUE, 33), "Address Of Entry Point", AddressOfEntryPoint))
        print(fmt % (offset_increase(OFFSET_VALUE, 34), "Base Of Code", BaseOfCode))
        print(fmt % (offset_increase(OFFSET_VALUE, 35), "Base Of Data", BaseOfData))
        print(fmt % (offset_increase(OFFSET_VALUE, 36), "Image Base", ImageBase))
        print(fmt % (offset_increase(OFFSET_VALUE, 37), "Section Alignment", SectionAlignment))
        print(fmt % (offset_increase(OFFSET_VALUE, 38), "File Alignment", FileAlignment))
        print(fmt % (offset_increase(OFFSET_VALUE, 39), "Major Operating System Version", MajorOperatingSystemVersion))
        print(fmt % (offset_increase(OFFSET_VALUE, 40), "Minor Operating System Version", MinorOperatingSystemVersion))
        print(fmt % (offset_increase(OFFSET_VALUE, 41), "Major Image Version", MajorImageVersion))
        print(fmt % (offset_increase(OFFSET_VALUE, 42), "Minor Image Version", MinorImageVersion))
        print(fmt % (offset_increase(OFFSET_VALUE, 43), "Major Subsystem Version", MajorSubsystemVersion))
        print(fmt % (offset_increase(OFFSET_VALUE, 44), "Minor Subsystem Version", MinorSubsystemVersion))
        print(fmt % (offset_increase(OFFSET_VALUE, 45), "Size Of Image", SizeOfImage))
        print(fmt % (offset_increase(OFFSET_VALUE, 46), "Size Of Headers", SizeOfHeaders))
        print(fmt % (offset_increase(OFFSET_VALUE, 47), "CheckSum", CheckSum))
        print(fmt % (offset_increase(OFFSET_VALUE, 48), "Subsystem", Subsystem))
        print(fmt % (offset_increase(OFFSET_VALUE, 49), "Dll Characteristics", DllCharacteristics))
        print(fmt % (offset_increase(OFFSET_VALUE, 50), "Size Of Stack Reserve", SizeOfStackReserve))
        print(fmt % (offset_increase(OFFSET_VALUE, 51), "Size Of Stack Commit", SizeOfStackCommit))
        print(fmt % (offset_increase(OFFSET_VALUE, 52), "Size Of Heap Reserve", SizeOfHeapReserve))
        print(fmt % (offset_increase(OFFSET_VALUE, 53), "Size Of Heap Commit", SizeOfHeapCommit))
        print(fmt % (offset_increase(OFFSET_VALUE, 54), "Loader Flags", LoaderFlags))
        print(fmt % (offset_increase(OFFSET_VALUE, 55), "Number Of Rva And Sizes", NumberOfRvaAndSizes))
    if ('all' in scope) or ('data-directory' in scope):
        if(not bNoSectionHeader):
            print("\n-------------------------------------------------------------------------\n\t\t\t\t<-- DATA DIRECTORY\n-------------------------------------------------------------------------")
        Data_Directory                               = PE_FILE.OPTIONAL_HEADER.DATA_DIRECTORY
        fmt = "%-25s\t%-16s\t%s"
        print(fmt % ("Name", "Virtual Address", "Size"), end="\n\n")
        print(fmt % ("Export Table",            replacethehex(hex(Data_Directory[0].VirtualAddress)), replacethehex(hex(Data_Directory[0].Size))))
        print(fmt % ("Import Table",            replacethehex(hex(Data_Directory[1].VirtualAddress)), replacethehex(hex(Data_Directory[1].Size))))
        print(fmt % ("Resource Table",          replacethehex(hex(Data_Directory[2].VirtualAddress)), replacethehex(hex(Data_Directory[2].Size))))
        print(fmt % ("Exception Table",         replacethehex(hex(Data_Directory[3].VirtualAddress)), replacethehex(hex(Data_Directory[3].Size))))
        print(fmt % ("Certificate Table",       replacethehex(hex(Data_Directory[4].VirtualAddress)), replacethehex(hex(Data_Directory[4].Size))))
        print(fmt % ("Base Relocation Table",   replacethehex(hex(Data_Directory[5].VirtualAddress)), replacethehex(hex(Data_Directory[5].Size))))
        print(fmt % ("Debugging Information",   replacethehex(hex(Data_Directory[6].VirtualAddress)), replacethehex(hex(Data_Directory[6].Size))))
        print(fmt % ("Architecture-specific",   replacethehex(hex(Data_Directory[7].VirtualAddress)), replacethehex(hex(Data_Directory[7].Size))))
        print(fmt % ("Global Pointer Register", replacethehex(hex(Data_Directory[8].VirtualAddress)), replacethehex(hex(Data_Directory[8].Size))))
        print(fmt % ("Thread Local Storage",    replacethehex(hex(Data_Directory[9].VirtualAddress)), replacethehex(hex(Data_Directory[9].Size))))
        print(fmt % ("Load Configuration",      replacethehex(hex(Data_Directory[10].VirtualAddress)), replacethehex(hex(Data_Directory[10].Size))))
        print(fmt % ("Bound Import Table",      replacethehex(hex(Data_Directory[11].VirtualAddress)), replacethehex(hex(Data_Directory[11].Size))))
        print(fmt % ("Import Address",          replacethehex(hex(Data_Directory[12].VirtualAddress)), replacethehex(hex(Data_Directory[12].Size))))
        print(fmt % ("Delay Import Descriptor", replacethehex(hex(Data_Directory[13].VirtualAddress)), replacethehex(hex(Data_Directory[13].Size))))
        print(fmt % ("The CLR Header",          replacethehex(hex(Data_Directory[14].VirtualAddress)), replacethehex(hex(Data_Directory[14].Size))))
        print(fmt % ("Reserved",                replacethehex(hex(Data_Directory[15].VirtualAddress)), replacethehex(hex(Data_Directory[15].Size))))
    if ('all' in scope) or ('section-headers' in scope):
        if(not bNoSectionHeader):
            print("\n-------------------------------------------------------------------------\n\t\t\t\tSection Headers\n-------------------------------------------------------------------------")
        fmt = "%-25s\t%-20s\t%-20s\t%s"
        print (fmt % ("Name", "Virtual Address", "Virtual Size", "SizeOfRawData"), end="\n\n")
        for section in PE_FILE.sections:
            print (fmt % (section.Name.decode('utf-8').rstrip("\x00"), hex(section.VirtualAddress), hex(section.Misc_VirtualSize), str(section.SizeOfRawData) ) )
    if ('all' in scope) or ('imports' in scope):
        if(not bNoSectionHeader):
            print("\n-------------------------------------------------------------------------\n\t\t\t\tImports\n-------------------------------------------------------------------------")
        fmt = "\t%-16s\t%s"
        print(("%s" + fmt) % ("Name", "Address", "Function"), end="\n\n")
        for entry in PE_FILE.DIRECTORY_ENTRY_IMPORT:
            print(entry.dll.decode('utf-8'))
            for imps in entry.imports:
                print(fmt % (hex(imps.address), (imps.ordinal if (imps.name is None) else imps.name.decode('utf-8'))))

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
        if args.show is not None:
            show_args = [x.lower() for x in re.split("[^a-zA-Z\-]+", args.show)]
            show(show_args)
        elif args.disassemble == 'all':
            disassemble();
        else:
            parser.print_help()
    else:
        parser.print_help()
except Exception as err:
    parser.print_help()
    print("\nException: \n", err);
