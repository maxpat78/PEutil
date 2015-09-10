""" Calculates and compares the PE image checksum, finds the Certificate Directory

PE32/PE32+ IMAGE LAYOUT:
MZ Stub
60:        DWORD file offset to the PE signature "PE\0\0"

Coff Header (20 bytes)
0:         WORD Machine Type (0x14C=i386+, 0x8664=x64)

Optional Header
0:         WORD Image Type (0x10B=PE32, 0x20B=PE32+)
64:        DWORD Image Checksum (optional)
92 (108):  NumberOfRvaAndSizes
128 (144): Certificate Directory (2 DWORD, RVA & Size)

Certificate Directory (8 byte aligned)
0:         dwLength
4:         wRevision (0x200)
6:         wCertificateType (0x2=PKCS#7 Signed Data)
8:         bCertificate (Authenticode Signature)"""
import struct, sys
from ctypes import *
from hashlib import sha1

WORD = struct.Struct('<H')
DWORD = struct.Struct('<I')


class BadImage:
    def __init__(p, s):
        print "BAD PE IMAGE:", s
        sys.exit(1)


def validate_pe_header(fp):
    "Validates the PE header and returns the machine and image type, and Optional Header offset"
    pos = fp.tell()
    fp.seek(0) # MZ Header
    if fp.read(2) != 'MZ':
        raise BadImage("MZ stub not found")
    fp.seek(60) # PE offset at 0x3C
    fp.seek(DWORD.unpack(fp.read(4))[0])
    if fp.read(4) != 'PE\0\0':
        raise BadImage("PE signature not found")
    T = WORD.unpack(fp.read(2))[0]
    if T not in (0x14C, 0x8664):
        raise BadImage("Not an x86/x64 image")
    fp.seek(18, 1) # move to COFF
    P = WORD.unpack(fp.read(2))[0]
    if P not in (0x10B, 0x20B):
        raise BadImage("Not a PE32/PE32+ image")
    r = fp.tell() - 2
    fp.seek(pos)
    return T,P,r

def checksum(s, csum):
    for i in xrange(len(s)/2):
        csum += WORD.unpack_from(s, i*2)[0]
        csum = (csum&0xFFFF) + (csum>>16)
    return csum

# 10% slower than xrange
def checksum0(s, csum):
    i=0
    while i < len(s):
        csum += WORD.unpack_from(s, i)[0]
        csum = (csum&0xFFFF) + (csum>>16)
        i+=2
    return csum

# Requires about 20" for a 28 MB FFMPEG.EXE
def pe_calc_checksum(fp, optbase):
    "Calculates the PE image checksum"
    optbase += 64 # checksum base
    pos = fp.tell()
    fp.seek(0)
    s = fp.read(optbase)
    csum = checksum(s, 0)
    fp.seek(4,1)
    while s:
        s = fp.read(32768)
        if not s: break
        csum = checksum(s, csum)
    # Safely adds file size to 16-bit checksum, since it's always < 2 GB
    csum += fp.tell()
    fp.seek(pos)
    return int(csum&0xFFFFFFFF)

def pe_calc_hash(fp, optbase, pe32plus=False):
    "Calculates the image SHA-1 hash according to MS AuthentiCode specs (i.e. omitting checksum and Cert Directory fields)"
    dig = sha1()
    optbase += 64 # checksum base
    pos = fp.tell()
    fp.seek(0)
    # Hash upto checksum field
    s = fp.read(optbase)
    dig.update(s)
    fp.seek(4,1)
    # Hash upto Cert Directory fields
    s = fp.read((60, 76)[pe32plus])
    dig.update(s)
    fp.seek(8,1)
    # Hash the rest
    while s:
        s = fp.read(32768)
        if not s: break
        dig.update(s)
    return dig

# About 2.5x slower than struct.unpack_from version
def pe_calc_checksum_0(fp, optbase):
    "Calculates the PE image checksum"
    optbase += 64 # checksum base
    pos = fp.tell()
    fp.seek(0)
    csum = 0
    while 1:
        if fp.tell() == optbase:
            fp.seek(4, 1)
            continue
        w = fp.read(2)
        if not w: break
        w = WORD.unpack(w)
        csum += w[0]
        csum = (csum&0xFFFF) + (csum>>16)
    csum += fp.tell()
    #~ csum = (csum&0xFFFF) + (csum>>16)
    fp.seek(pos)
    return int(csum&0xFFFFFFFF)

def pe_get_checksum(fp, optbase):
    "Gets the checksum eventually stored in the PE image"
    pos = fp.tell()
    fp.seek(optbase+64)
    r = DWORD.unpack(fp.read(4))[0]
    fp.seek(pos)
    return r

def pe_set_checksum(fp, crcoffs, crc):
    "Sets the checksum in the PE image"
    pos = fp.tell()
    fp.seek(crcoffs)
    fp.write(DWORD.pack(crc))
    fp.seek(pos)

def pe_get_certtable(fp, optbase, pe32plus=False):
    "Returns Certificate Table RVA & size (if present)"
    optbase += (128, 144)[pe32plus]
    pos = fp.tell()
    fp.seek(optbase)
    r1 = DWORD.unpack(fp.read(4))[0]
    r2 = DWORD.unpack(fp.read(4))[0]
    fp.seek(pos)
    return r1, r2
    
if __name__ == '__main__':
    fp = open(sys.argv[1], 'rb')
    arch, typ, offs = validate_pe_header(fp)
    print '%s is an %s %s image' % (fp.name, {0x14C:'x86',0x8664:'x64'}[arch], {0x10B:'PE32',0x20B:'PE32+'}[typ])
    print 'Optional Header @0x%08X' % offs
    c1 = pe_calc_checksum(fp, offs)
    c2 = pe_get_checksum(fp, offs)
    if not c2:
        print 'Calculated checksum: %08X' % c1
    else:
        if c1!=c2:
            print 'Stored checksum %08X != calculated %08X' % (c2,c1)
        else:
            print 'Stored and calculated checksums %08X identical' % c1
    rva, size = pe_get_certtable(fp, offs, typ==0x20B)
    if rva:
        print 'Certificate directory RVA %08X, size %d bytes' % rva, size
    print 'Calculated SHA-1 Hash for the image:', pe_calc_hash(fp, offs, typ==0x20B).hexdigest()
