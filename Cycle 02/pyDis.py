
import os, struct, sys, string, getopt, mmap, exceptions, binascii
from capstone import *

IMAGE_DOS_SIGNATURE = 0x5A4D # MZ
IMAGE_NT_SIGNATURE = 0x00004550 # PE00

IMAGE_DOS_HEADER_format = ('IMAGE_DOS_HEADER',
    ('H,e_magic', 'H,e_cblp', 'H,e_cp',
    'H,e_crlc', 'H,e_cparhdr', 'H,e_minalloc',
    'H,e_maxalloc', 'H,e_ss', 'H,e_sp', 'H,e_csum',
    'H,e_ip', 'H,e_cs', 'H,e_lfarlc', 'H,e_ovno', '8s,e_res',
    'H,e_oemid', 'H,e_oeminfo', '20s,e_res2',
    'I,e_lfanew'))

IMAGE_NT_HEADERS_format = ('IMAGE_NT_HEADERS', ('I,Signature',))

IMAGE_FILE_HEADER_format = ('IMAGE_FILE_HEADER',
    ('H,Machine', 'H,NumberOfSections',
    'I,TimeDateStamp', 'I,PointerToSymbolTable',
    'I,NumberOfSymbols', 'H,SizeOfOptionalHeader',
    'H,Characteristics'))

IMAGE_SECTION_HEADER_format = ('IMAGE_SECTION_HEADER',
    ('8s,Name', 'I,Misc,Misc_PhysicalAddress,Misc_VirtualSize',
    'I,VirtualAddress', 'I,SizeOfRawData', 'I,PointerToRawData',
    'I,PointerToRelocations', 'I,PointerToLinenumbers',
    'H,NumberOfRelocations', 'H,NumberOfLinenumbers',
    'I,Characteristics'))

IMAGE_OPTIONAL_HEADER_format = ('IMAGE_OPTIONAL_HEADER',
    ('H,Magic', 'B,MajorLinkerVersion',
    'B,MinorLinkerVersion', 'I,SizeOfCode',
    'I,SizeOfInitializedData', 'I,SizeOfUninitializedData',
    'I,AddressOfEntryPoint', 'I,BaseOfCode', 'I,BaseOfData',
    'I,ImageBase', 'I,SectionAlignment', 'I,FileAlignment',
    'H,MajorOperatingSystemVersion', 'H,MinorOperatingSystemVersion',
    'H,MajorImageVersion', 'H,MinorImageVersion',
    'H,MajorSubsystemVersion', 'H,MinorSubsystemVersion',
    'I,Reserved1', 'I,SizeOfImage', 'I,SizeOfHeaders',
    'I,CheckSum', 'H,Subsystem', 'H,DllCharacteristics',
    'I,SizeOfStackReserve', 'I,SizeOfStackCommit',
    'I,SizeOfHeapReserve', 'I,SizeOfHeapCommit',
    'I,LoaderFlags', 'I,NumberOfRvaAndSizes' ))

STRUCT_SIZEOF_TYPES = {
    'x': 1, 'c': 1, 'b': 1, 'B': 1,
    'h': 2, 'H': 2,
    'i': 4, 'I': 4, 'l': 4, 'L': 4, 'f': 4,
    'q': 8, 'Q': 8, 'd': 8,
    's': 1 }

class Structure:
    """Prepare structure object to extract members from data.

    Format is a list containing definitions for the elements
    of the structure.
    """

    def __init__(self, format, name=None, file_offset=None):
        # Format is forced little endian, for big endian non Intel platforms
        self.__format__ = '<'
        self.__keys__ = []
        #self.values = {}
        self.__format_length__ = 0
        self.__field_offsets__ = dict()
        self.__set_format__(format[1])
        self.__all_zeroes__ = False
        self.__unpacked_data_elms__ = None
        self.__file_offset__ = file_offset
        if name:
            self.name = name
        else:
            self.name = format[0]


    def __get_format__(self):
        return self.__format__

    def get_field_absolute_offset(self, field_name):
        """Return the offset within the field for the requested field in the structure."""
        return self.__file_offset__ + self.__field_offsets__[field_name]

    def get_field_relative_offset(self, field_name):
        """Return the offset within the structure for the requested field."""
        return self.__field_offsets__[field_name]

    def get_file_offset(self):
        return self.__file_offset__

    def set_file_offset(self, offset):
        self.__file_offset__ = offset

    def all_zeroes(self):
        """Returns true is the unpacked data is all zeros."""

        return self.__all_zeroes__

    def sizeof_type(self, t):
        count = 1
        _t = t
        if t[0] in string.digits:
            # extract the count
            count = int( ''.join([d for d in t if d in string.digits]) )
            _t = ''.join([d for d in t if d not in string.digits])
        return STRUCT_SIZEOF_TYPES[_t] * count

    def __set_format__(self, format):

        offset = 0
        for elm in format:
            if ',' in elm:
                elm_type, elm_name = elm.split(',', 1)
                self.__format__ += elm_type

                elm_names = elm_name.split(',')
                names = []
                for elm_name in elm_names:
                    if elm_name in self.__keys__:
                        search_list = [x[:len(elm_name)] for x in self.__keys__]
                        occ_count = search_list.count(elm_name)
                        elm_name = elm_name+'_'+str(occ_count)
                    names.append(elm_name)
                    self.__field_offsets__[elm_name] = offset

                offset += self.sizeof_type(elm_type)

                # Some PE header structures have unions on them, so a certain
                # value might have different names, so each key has a list of
                # all the possible members referring to the data.
                self.__keys__.append(names)

        self.__format_length__ = struct.calcsize(self.__format__)

    def sizeof(self):
        """Return size of the structure."""

        return self.__format_length__

    def __unpack__(self, data):

        if len(data) > self.__format_length__:
            data = data[:self.__format_length__]

        # OC Patch:
        # Some malware have incorrect header lengths.
        # Fail gracefully if this occurs
        # Buggy malware: a29b0118af8b7408444df81701ad5a7f
        #
        elif len(data) < self.__format_length__:
            raise PEFormatError('Data length less than expected header length.')


        if data.count(chr(0)) == len(data):
            self.__all_zeroes__ = True

        self.__unpacked_data_elms__ = struct.unpack(self.__format__, data)
        for i in xrange(len(self.__unpacked_data_elms__)):
            for key in self.__keys__[i]:
                setattr(self, key, self.__unpacked_data_elms__[i])

    def __pack__(self):

        new_values = []

        for i in xrange(len(self.__unpacked_data_elms__)):

            for key in self.__keys__[i]:
                new_val = getattr(self, key)
                old_val = self.__unpacked_data_elms__[i]

                # In the case of Unions, when the first changed value
                # is picked the loop is exited
                if new_val != old_val:
                    break

            new_values.append(new_val)

        return struct.pack(self.__format__, *new_values)

    def __str__(self):
        return '\n'.join( self.dump() )

    def __repr__(self):
        return '<Structure: %s>' % (' '.join( [' '.join(s.split()) for s in self.dump()] ))

    def dump(self, indentation=0):
        """Returns a string representation of the structure."""

        dump = []

        dump.append('[%s]' % self.name)

        # Refer to the __set_format__ method for an explanation
        # of the following construct.
        for keys in self.__keys__:
            for key in keys:

                val = getattr(self, key)
                if isinstance(val, int) or isinstance(val, long):
                    val_str = '0x%-8X' % (val)
                    if key == 'TimeDateStamp' or key == 'dwTimeStamp':
                        try:
                            val_str += ' [%s UTC]' % time.asctime(time.gmtime(val))
                        except exceptions.ValueError, e:
                            val_str += ' [INVALID TIME]'
                else:
                    val_str = ''.join(filter(lambda c:c != '\0', str(val)))

                dump.append('0x%-8X 0x%-3X %-30s %s' % (
                    self.__field_offsets__[key] + self.__file_offset__,
                    self.__field_offsets__[key], key+':', val_str))

        return dump

    def dump_dict(self):
        """Returns a dictionary representation of the structure."""

        dump_dict = dict()

        dump_dict['Structure'] = self.name

        # Refer to the __set_format__ method for an explanation
        # of the following construct.
        for keys in self.__keys__:
            for key in keys:

                val = getattr(self, key)
                if isinstance(val, int) or isinstance(val, long):
                    if key == 'TimeDateStamp' or key == 'dwTimeStamp':
                        try:
                            val = '0x%-8X [%s UTC]' % (val, time.asctime(time.gmtime(val)))
                        except exceptions.ValueError, e:
                            val = '0x%-8X [INVALID TIME]' % val
                else:
                    val = ''.join(filter(lambda c:c != '\0', str(val)))

                dump_dict[key] = {'FileOffset': self.__field_offsets__[key] + self.__file_offset__,
                                  'Offset': self.__field_offsets__[key],
                                  'Value': val}

        return dump_dict

################## END CLASSES #########################

def disassemble(file_name):

	stat = os.stat(file_name)

	if stat.st_size == 0:
		print "[!] File is empty"
		sys.exit()

	file_handle = None
	raw_data = None

	try:
		file_handle = open(file_name, 'rb')

		raw_data = file_handle.read()

	except IOError, exc:
		exception_msg =str(exc)

	finally:
		if file_handle is not None:
			file_handle.close

	print "[*] Received content, disassembling...\n"

	# Access Capstone through the CS class
	# Constructor takes two args: architecture and mode
	md = Cs(CS_ARCH_X86, CS_MODE_32)

	for i in md.disasm(raw_data, 0x0):
	    sys.stdout.write("0x{:08x}\t{:s}\t{:30s}{:s}\n".format(i.address,i.mnemonic,i.op_str, binascii.hexlify(i.bytes)))

	print "\n[*] Finished!"

def search_module(search_opcode, module):

	print "[*] Searching %s for %s...." % (module, search_opcode)

	stat = os.stat(module)
	if stat.st_size == 0:
		print "[!] File is empty"
		sys.exit()

	file_handle = None
	raw_data = None

	try:
		file_handle = open(module, 'rb')

		raw_data = mmap.mmap(file_handle.fileno(), 0, mmap.MAP_PRIVATE)

	except IOError, exc:
		exception_msg =str(exc)

	finally:
		if file_handle is not None:
			file_handle.close

	print "[*] Module loaded..."

	DOS_HEADER = Structure(IMAGE_DOS_HEADER_format, 0)
	DOS_HEADER.__unpack__(raw_data[:64])

	if DOS_HEADER.e_magic != IMAGE_DOS_SIGNATURE:
		print "[!] Unable to locate DOS magic number"

	nt_header_offset = DOS_HEADER.e_lfanew

	NT_HEADERS = Structure(IMAGE_NT_HEADERS_format, nt_header_offset)
	NT_HEADERS.__unpack__(raw_data[nt_header_offset:nt_header_offset+8])

	if(0xFFFF & NT_HEADERS.Signature) != IMAGE_NT_SIGNATURE:
		print "[!] Invalid NT Header Signature"
		sys.exit()

	FILE_HEADER = Structure(IMAGE_FILE_HEADER_format, nt_header_offset+4)
	FILE_HEADER.__unpack__(raw_data[nt_header_offset+4:nt_header_offset+4+32])

	if FILE_HEADER.Characteristics & 0x2000:
		pe_type = "DLL"
	elif FILE_HEADER.Characteristics & 0x2:
		pe_type = "EXE"
	else:
		pe_type = "UNKNOWN"

	if not FILE_HEADER:
		print "[!] No File Header found"
		sys.exit()

	optional_header_offset = nt_header_offset+4+FILE_HEADER.sizeof()

	OPTIONAL_HEADER = Structure(IMAGE_OPTIONAL_HEADER_format, optional_header_offset)
	OPTIONAL_HEADER.__unpack__(raw_data[optional_header_offset:optional_header_offset+224])

	number_of_sections = FILE_HEADER.NumberOfSections

	sections_offset = nt_header_offset + 4 + 20 + FILE_HEADER.SizeOfOptionalHeader

	sections = []

	for section_index in range(number_of_sections):

		section = Structure(IMAGE_SECTION_HEADER_format, sections_offset)
		section.__unpack__(raw_data[sections_offset:sections_offset+40])
		sections_offset += 40 #Section Structs are 40 bytes, no padding

		if '.text' in section.Name:
			break

	instructions = raw_data[section.PointerToRawData+22:section.PointerToRawData+section.SizeOfRawData]

	# Summary Information
	print "[*] Module Information - %s:" % module
	print "\tPE32 Type:\t\t%s" % pe_type
	print "\tSection:\t\t" + section.Name
	print "\tSize of Raw:\t\t" + hex(section.SizeOfRawData)
	print "\tPointer to raw:\t\t" + hex(section.PointerToRawData)
	print ""

	# Access Capstone through the CS class
	# Constructor takes two args: architecture and mode
	md = Cs(CS_ARCH_X86, CS_MODE_32)

	print "[*] Searching..."

	for i in md.disasm(instructions, OPTIONAL_HEADER.ImageBase + section.VirtualAddress + 22):
		test = i.mnemonic + " " + i.op_str

		if search_opcode in test:
			sys.stdout.write("[*]Instruction Found: 0x{:8x} {:s} {:s}\n".format(i.address,i.mnemonic, i.op_str))
	    #sys.stdout.write("0x{:08x}\t{:s}\t{:30s}{:s}\n".format(i.address,i.mnemonic,i.op_str, binascii.hexlify(i.bytes)))


	print "[*] Finished!"


def usage():
	print "[!] You need to provide a file name w/ Shellcode or opcodes and a module to search"


def main(argv):

	file_name = ""
	search_opcode = ""
	module = ""

	try:
		opts, args = getopt.getopt(argv,'hu:f:s:m:')
	except getopt.GetoptError:
		print usage
		sys.exit(2)

	if(len(opts) == 0):
		usage()
		sys.exit()

	for opt, arg in opts:
		if opt == "-h":
			usage()
			sys.exit()
		elif opt == "-f":
			file_name = arg
		elif opt == "-s":
			search_opcode = arg
		elif opt == "-m":
			module = arg
		else:
			usage()
			sys.exit()

	if file_name != "":
		disassemble(file_name)
	elif search_opcode != "":
		search_module(search_opcode, module)

if __name__ == '__main__':
	main(sys.argv[1:])