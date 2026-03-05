import struct

class PEHeader:
    def __init__(self, filename):
        self.filename = filename
        self.file = open(filename, 'rb')
        self.pe_offset = self.get_pe_offset()

    def get_pe_offset(self):
        # Read DOS header and get PE offset
        self.file.seek(60)
        pe_offset = struct.unpack('I', self.file.read(4))[0]
        return pe_offset

    def read_pe_header(self):
        self.file.seek(self.pe_offset)
        pe_signature = self.file.read(4)
        if pe_signature != b'PE\0\0':
            raise ValueError('Not a valid PE file')
        return pe_signature

    def get_architecture(self):
        self.file.seek(self.pe_offset + 4)
        machine = struct.unpack('H', self.file.read(2))[0]
        arch_dict = {
            0x014c: 'x86',
            0x8664: 'x64',
            0x0200: 'IA64',
        }
        return arch_dict.get(machine, 'Unknown Architecture')

    def get_subsystem(self):
        self.file.seek(self.pe_offset + 60)
        subsystem = struct.unpack('H', self.file.read(2))[0]
        subsystem_dict = {
            0x0000: 'Subsystem Unknown',
            0x0001: 'Native',
            0x0002: 'Windows GUI',
            0x0003: 'Windows CUI',
        }
        return subsystem_dict.get(subsystem, 'Unknown Subsystem')

    def get_imports(self):
        # This function would implement more detailed parsing to extract import information
        pass

    def close(self):
        self.file.close()