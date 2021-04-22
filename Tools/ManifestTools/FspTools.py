## @ FspTool.py
#
# Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
##

import os
import sys
import uuid
import hashlib
import operator
import argparse
import subprocess
from   ctypes import *
from functools import reduce

TPM_ALG_SHA1    = 0x4
TPM_ALG_SHA256  = 0xB
TPM_ALG_SM3_256 = 0x12
TPM_ALG_SHA384  = 0xC
TPM_ALG_SHA512  = 0xD

SHA1_DIGEST_SIZE    = 20
SHA256_DIGEST_SIZE  = 32
SM3_256_DIGEST_SIZE = 32
SHA384_DIGEST_SIZE  = 48
SHA512_DIGEST_SIZE  = 64

#
# TCG Algorithm Registry
#

HASH_ALG_SHA1    = 0x00000001
HASH_ALG_SHA256  = 0x00000002
HASH_ALG_SHA384  = 0x00000004
HASH_ALG_SHA512  = 0x00000008
HASH_ALG_SM3_256 = 0x00000010

HashInfo = [[TPM_ALG_SHA1, SHA1_DIGEST_SIZE, HASH_ALG_SHA1],
            [TPM_ALG_SHA256, SHA256_DIGEST_SIZE, HASH_ALG_SHA256],
            [TPM_ALG_SM3_256, SM3_256_DIGEST_SIZE, HASH_ALG_SHA384],
            [TPM_ALG_SHA384, SHA384_DIGEST_SIZE, HASH_ALG_SHA512],
            [TPM_ALG_SHA512, SHA512_DIGEST_SIZE, HASH_ALG_SM3_256]]

#
# EFI specific event types
#
EV_EFI_EVENT_BASE                   = 0x80000000
EV_EFI_VARIABLE_DRIVER_CONFIG       = EV_EFI_EVENT_BASE + 1
EV_EFI_VARIABLE_BOOT                = EV_EFI_EVENT_BASE + 2
EV_EFI_BOOT_SERVICES_APPLICATION    = EV_EFI_EVENT_BASE + 3
EV_EFI_BOOT_SERVICES_DRIVER         = EV_EFI_EVENT_BASE + 4
EV_EFI_RUNTIME_SERVICES_DRIVER      = EV_EFI_EVENT_BASE + 5
EV_EFI_GPT_EVENT                    = EV_EFI_EVENT_BASE + 6
EV_EFI_ACTION                       = EV_EFI_EVENT_BASE + 7
EV_EFI_PLATFORM_FIRMWARE_BLOB       = EV_EFI_EVENT_BASE + 8
EV_EFI_HANDOFF_TABLES               = EV_EFI_EVENT_BASE + 9
EV_EFI_PLATFORM_FIRMWARE_BLOB2      = EV_EFI_EVENT_BASE + 0xA
EV_EFI_HANDOFF_TABLES2              = EV_EFI_EVENT_BASE + 0xB
EV_EFI_HCRTM_EVENT                  = EV_EFI_EVENT_BASE + 0x10
EV_EFI_VARIABLE_AUTHORITY           = EV_EFI_EVENT_BASE + 0xE0
EV_EFI_SPDM_FIRMWARE_BLOB           = EV_EFI_EVENT_BASE + 0xE1
EV_EFI_SPDM_FIRMWARE_CONFIG         = EV_EFI_EVENT_BASE + 0xE2

class c_uint24(Structure):
    """Little-Endian 24-bit Unsigned Integer"""
    _pack_   = 1
    _fields_ = [('Data', (c_uint8 * 3))]

    def __init__(self, val=0):
        self.set_value(val)

    def __str__(self, indent=0):
        return '0x%.6x' % self.value

    def __int__(self):
        return self.get_value()

    def set_value(self, val):
        self.Data[0:3] = Val2Bytes(val, 3)

    def get_value(self):
        return Bytes2Val(self.Data[0:3])

    value = property(get_value, set_value)

class tdTCG_PCR_EVENT_HDR(Structure):
    _fields_ = [
        ('pcrIndex',        c_uint32),
        ('eventType',       c_uint32),
        ('digest',          ARRAY(c_uint8, 20)),
        ('eventDataSize',   c_uint32)
        ]

class TPMU_HA(Union):
    _fields_ = [
        ('sha1',            ARRAY(c_uint8, SHA1_DIGEST_SIZE)),
        ('sha256',          ARRAY(c_uint8, SHA256_DIGEST_SIZE)),
        ('sm3_256',         ARRAY(c_uint8, SM3_256_DIGEST_SIZE)),
        ('sha384',          ARRAY(c_uint8, SHA384_DIGEST_SIZE)),
        ('sha512',          ARRAY(c_uint8, SHA512_DIGEST_SIZE)),
    ]

class TPMT_HA(Structure):
    _fields_ = [
        ('hashAlg',         c_uint16),
        ('digest',          TPMU_HA),
    ]

class TPML_DIGEST_VALUES(Structure):
    _fields_ = [
        ('count',        c_uint32),
        ('digests',      ARRAY(TPMT_HA, 5)),
    ]

class tdTCG_PCR_EVENT2_HDR(Structure):
    _fields_ = [
        ('pcrIndex',        c_uint32),
        ('eventType',       c_uint32),
        ('digests',         TPML_DIGEST_VALUES),
        ('eventDataSize',   c_uint32)
        ]

class EFI_FIRMWARE_VOLUME_HEADER(Structure):
    _fields_ = [
        ('ZeroVector',           ARRAY(c_uint8, 16)),
        ('FileSystemGuid',       ARRAY(c_uint8, 16)),
        ('FvLength',             c_uint64),
        ('Signature',            ARRAY(c_char, 4)),
        ('Attributes',           c_uint32),
        ('HeaderLength',         c_uint16),
        ('Checksum',             c_uint16),
        ('ExtHeaderOffset',      c_uint16),
        ('Reserved',             c_uint8),
        ('Revision',             c_uint8)
        ]

class EFI_FIRMWARE_VOLUME_EXT_HEADER(Structure):
    _fields_ = [
        ('FvName',               ARRAY(c_uint8, 16)),
        ('ExtHeaderSize',        c_uint32)
        ]

class EFI_FFS_INTEGRITY_CHECK(Structure):
    _fields_ = [
        ('Header',               c_uint8),
        ('File',                 c_uint8)
        ]

class EFI_FFS_FILE_HEADER(Structure):
    _fields_ = [
        ('Name',                 ARRAY(c_uint8, 16)),
        ('IntegrityCheck',       EFI_FFS_INTEGRITY_CHECK),
        ('Type',                 c_uint8),
        ('Attributes',           c_uint8),
        ('Size',                 c_uint24),
        ('State',                c_uint8)
        ]

class EFI_COMMON_SECTION_HEADER(Structure):
    _fields_ = [
        ('Size',                 c_uint24),
        ('Type',                 c_uint8)
        ]

class FSP_COMMON_HEADER(Structure):
     _fields_ = [
        ('Signature',            ARRAY(c_char, 4)),
        ('HeaderLength',         c_uint32)
        ]

class FSP_INFORMATION_HEADER(Structure):
     _fields_ = [
        ('Signature',            ARRAY(c_char, 4)),
        ('HeaderLength',         c_uint32),
        ('Reserved1',            c_uint16),
        ('SpecVersion',          c_uint8),
        ('HeaderRevision',       c_uint8),
        ('ImageRevision',        c_uint32),
        ('ImageId',              ARRAY(c_char, 8)),
        ('ImageSize',            c_uint32),
        ('ImageBase',            c_uint32),
        ('ImageAttribute',       c_uint16),
        ('ComponentAttribute',   c_uint16),
        ('CfgRegionOffset',      c_uint32),
        ('CfgRegionSize',        c_uint32),
        ('Reserved2',            c_uint32),
        ('TempRamInitEntryOffset',     c_uint32),
        ('Reserved3',                  c_uint32),
        ('NotifyPhaseEntryOffset',     c_uint32),
        ('FspMemoryInitEntryOffset',   c_uint32),
        ('TempRamExitEntryOffset',     c_uint32),
        ('FspSiliconInitEntryOffset',  c_uint32)
    ]

class FSP_PATCH_TABLE(Structure):
    _fields_ = [
        ('Signature',            ARRAY(c_char, 4)),
        ('HeaderLength',         c_uint16),
        ('HeaderRevision',       c_uint8),
        ('Reserved',             c_uint8),
        ('PatchEntryNum',        c_uint32)
        ]

class EFI_IMAGE_DATA_DIRECTORY(Structure):
    _fields_ = [
        ('VirtualAddress',       c_uint32),
        ('Size',                 c_uint32)
        ]

class EFI_TE_IMAGE_HEADER(Structure):
    _fields_ = [
        ('Signature',            ARRAY(c_char, 2)),
        ('Machine',              c_uint16),
        ('NumberOfSections',     c_uint8),
        ('Subsystem',            c_uint8),
        ('StrippedSize',         c_uint16),
        ('AddressOfEntryPoint',  c_uint32),
        ('BaseOfCode',           c_uint32),
        ('ImageBase',            c_uint64),
        ('DataDirectoryBaseReloc',  EFI_IMAGE_DATA_DIRECTORY),
        ('DataDirectoryDebug',      EFI_IMAGE_DATA_DIRECTORY)
        ]

class EFI_IMAGE_DOS_HEADER(Structure):
    _fields_ = [
        ('e_magic',              c_uint16),
        ('e_cblp',               c_uint16),
        ('e_cp',                 c_uint16),
        ('e_crlc',               c_uint16),
        ('e_cparhdr',            c_uint16),
        ('e_minalloc',           c_uint16),
        ('e_maxalloc',           c_uint16),
        ('e_ss',                 c_uint16),
        ('e_sp',                 c_uint16),
        ('e_csum',               c_uint16),
        ('e_ip',                 c_uint16),
        ('e_cs',                 c_uint16),
        ('e_lfarlc',             c_uint16),
        ('e_ovno',               c_uint16),
        ('e_res',                ARRAY(c_uint16, 4)),
        ('e_oemid',              c_uint16),
        ('e_oeminfo',            c_uint16),
        ('e_res2',               ARRAY(c_uint16, 10)),
        ('e_lfanew',             c_uint16)
        ]

class EFI_IMAGE_FILE_HEADER(Structure):
    _fields_ = [
        ('Machine',               c_uint16),
        ('NumberOfSections',      c_uint16),
        ('TimeDateStamp',         c_uint32),
        ('PointerToSymbolTable',  c_uint32),
        ('NumberOfSymbols',       c_uint32),
        ('SizeOfOptionalHeader',  c_uint16),
        ('Characteristics',       c_uint16)
        ]

class PE_RELOC_BLOCK_HEADER(Structure):
    _fields_ = [
        ('PageRVA',              c_uint32),
        ('BlockSize',            c_uint32)
        ]

class EFI_IMAGE_OPTIONAL_HEADER32(Structure):
    _fields_ = [
        ('Magic',                         c_uint16),
        ('MajorLinkerVersion',            c_uint8),
        ('MinorLinkerVersion',            c_uint8),
        ('SizeOfCode',                    c_uint32),
        ('SizeOfInitializedData',         c_uint32),
        ('SizeOfUninitializedData',       c_uint32),
        ('AddressOfEntryPoint',           c_uint32),
        ('BaseOfCode',                    c_uint32),
        ('BaseOfData',                    c_uint32),
        ('ImageBase',                     c_uint32),
        ('SectionAlignment',              c_uint32),
        ('FileAlignment',                 c_uint32),
        ('MajorOperatingSystemVersion',   c_uint16),
        ('MinorOperatingSystemVersion',   c_uint16),
        ('MajorImageVersion',             c_uint16),
        ('MinorImageVersion',             c_uint16),
        ('MajorSubsystemVersion',         c_uint16),
        ('MinorSubsystemVersion',         c_uint16),
        ('Win32VersionValue',             c_uint32),
        ('SizeOfImage',                   c_uint32),
        ('SizeOfHeaders',                 c_uint32),
        ('CheckSum'     ,                 c_uint32),
        ('Subsystem',                     c_uint16),
        ('DllCharacteristics',            c_uint16),
        ('SizeOfStackReserve',            c_uint32),
        ('SizeOfStackCommit' ,            c_uint32),
        ('SizeOfHeapReserve',             c_uint32),
        ('SizeOfHeapCommit' ,             c_uint32),
        ('LoaderFlags'     ,              c_uint32),
        ('NumberOfRvaAndSizes',           c_uint32),
        ('DataDirectory',                 ARRAY(EFI_IMAGE_DATA_DIRECTORY, 16))
        ]

class EFI_IMAGE_OPTIONAL_HEADER32_PLUS(Structure):
    _fields_ = [
        ('Magic',                         c_uint16),
        ('MajorLinkerVersion',            c_uint8),
        ('MinorLinkerVersion',            c_uint8),
        ('SizeOfCode',                    c_uint32),
        ('SizeOfInitializedData',         c_uint32),
        ('SizeOfUninitializedData',       c_uint32),
        ('AddressOfEntryPoint',           c_uint32),
        ('BaseOfCode',                    c_uint32),
        ('ImageBase',                     c_uint64),
        ('SectionAlignment',              c_uint32),
        ('FileAlignment',                 c_uint32),
        ('MajorOperatingSystemVersion',   c_uint16),
        ('MinorOperatingSystemVersion',   c_uint16),
        ('MajorImageVersion',             c_uint16),
        ('MinorImageVersion',             c_uint16),
        ('MajorSubsystemVersion',         c_uint16),
        ('MinorSubsystemVersion',         c_uint16),
        ('Win32VersionValue',             c_uint32),
        ('SizeOfImage',                   c_uint32),
        ('SizeOfHeaders',                 c_uint32),
        ('CheckSum'     ,                 c_uint32),
        ('Subsystem',                     c_uint16),
        ('DllCharacteristics',            c_uint16),
        ('SizeOfStackReserve',            c_uint64),
        ('SizeOfStackCommit' ,            c_uint64),
        ('SizeOfHeapReserve',             c_uint64),
        ('SizeOfHeapCommit' ,             c_uint64),
        ('LoaderFlags'     ,              c_uint32),
        ('NumberOfRvaAndSizes',           c_uint32),
        ('DataDirectory',                 ARRAY(EFI_IMAGE_DATA_DIRECTORY, 16))
        ]

class EFI_IMAGE_OPTIONAL_HEADER(Union):
    _fields_ = [
        ('PeOptHdr',             EFI_IMAGE_OPTIONAL_HEADER32),
        ('PePlusOptHdr',         EFI_IMAGE_OPTIONAL_HEADER32_PLUS)
        ]

class EFI_IMAGE_NT_HEADERS32(Structure):
    _fields_ = [
        ('Signature',            c_uint32),
        ('FileHeader',           EFI_IMAGE_FILE_HEADER),
        ('OptionalHeader',       EFI_IMAGE_OPTIONAL_HEADER)
        ]


class EFI_IMAGE_DIRECTORY_ENTRY:
    EXPORT                     = 0
    IMPORT                     = 1
    RESOURCE                   = 2
    EXCEPTION                  = 3
    SECURITY                   = 4
    BASERELOC                  = 5
    DEBUG                      = 6
    COPYRIGHT                  = 7
    GLOBALPTR                  = 8
    TLS                        = 9
    LOAD_CONFIG                = 10

class EFI_FV_FILETYPE:
    ALL                        = 0x00
    RAW                        = 0x01
    FREEFORM                   = 0x02
    SECURITY_CORE              = 0x03
    PEI_CORE                   = 0x04
    DXE_CORE                   = 0x05
    PEIM                       = 0x06
    DRIVER                     = 0x07
    COMBINED_PEIM_DRIVER       = 0x08
    APPLICATION                = 0x09
    SMM                        = 0x0a
    FIRMWARE_VOLUME_IMAGE      = 0x0b
    COMBINED_SMM_DXE           = 0x0c
    SMM_CORE                   = 0x0d
    OEM_MIN                    = 0xc0
    OEM_MAX                    = 0xdf
    DEBUG_MIN                  = 0xe0
    DEBUG_MAX                  = 0xef
    FFS_MIN                    = 0xf0
    FFS_MAX                    = 0xff
    FFS_PAD                    = 0xf0

class EFI_SECTION_TYPE:
    """Enumeration of all valid firmware file section types."""
    ALL                        = 0x00
    COMPRESSION                = 0x01
    GUID_DEFINED               = 0x02
    DISPOSABLE                 = 0x03
    PE32                       = 0x10
    PIC                        = 0x11
    TE                         = 0x12
    DXE_DEPEX                  = 0x13
    VERSION                    = 0x14
    USER_INTERFACE             = 0x15
    COMPATIBILITY16            = 0x16
    FIRMWARE_VOLUME_IMAGE      = 0x17
    FREEFORM_SUBTYPE_GUID      = 0x18
    RAW                        = 0x19
    PEI_DEPEX                  = 0x1b
    SMM_DEPEX                  = 0x1c

def AlignPtr (offset, alignment = 8):
    return (offset + alignment - 1) & ~(alignment - 1)

def Bytes2Val (bytes):
    return reduce(lambda x,y: (x<<8)|y,  bytes[::-1] )

def Val2Bytes (value, blen):
    return [(value>>(i*8) & 0xff) for i in range(blen)]

def IsIntegerType (val):
    if sys.version_info[0] < 3:
        if type(val) in (int, long):
            return True
    else:
        if type(val) is int:
            return True
    return False

def IsStrType (val):
    if sys.version_info[0] < 3:
        if type(val) is str:
            return True
    else:
        if type(val) is bytes:
            return True
    return False

def HandleNameStr (val):
    if sys.version_info[0] < 3:
        rep = "0x%X ('%s')" % (Bytes2Val (bytearray (val)), val)
    else:
        rep = "0x%X ('%s')" % (Bytes2Val (bytearray (val)), str (val, 'utf-8'))
    return rep

def OutputStruct (obj, indent = 0, plen = 0):
    if indent:
        body = ''
    else:
        body = ('  ' * indent + '<%s>:\n') % obj.__class__.__name__

    if plen == 0:
        plen = sizeof(obj)

    max_key_len = 26
    pstr = ('  ' * (indent + 1) + '{0:<%d} = {1}\n') % max_key_len

    for field in obj._fields_:
        key = field[0]
        val = getattr(obj, key)
        rep = ''
        if not isinstance(val, c_uint24) and isinstance(val, Structure):
            body += pstr.format(key, val.__class__.__name__)
            body += OutputStruct (val, indent + 1)
            plen -= sizeof(val)
        else:
            if IsStrType (val):
                rep = HandleNameStr (val)
            elif IsIntegerType (val):
                rep = '0x%X' % val
            elif isinstance(val, c_uint24):
                rep = '0x%X' % val.get_value()
            elif 'c_ubyte_Array' in str(type(val)):
                if sizeof(val) == 16:
                    if sys.version_info[0] < 3:
                        rep = str(bytearray(val))
                    else:
                        rep = bytes(val)
                    rep = str(uuid.UUID(bytes_le = rep)).upper()
                else:
                    res = ['0x%02X'%i for i in bytearray(val)]
                    rep = '[%s]' % (','.join(res))
            else:
                rep = str(val)
            plen -= sizeof(field[1])
            body += pstr.format(key, rep)
        if plen <= 0:
            break
    return body

class Section:
    def __init__(self, offset, secdata):
        self.SecHdr   = EFI_COMMON_SECTION_HEADER.from_buffer (secdata, 0)
        self.SecData  = secdata[0:int(self.SecHdr.Size)]
        self.Offset   = offset

class FirmwareFile:
    def __init__(self, offset, filedata):
        self.FfsHdr   = EFI_FFS_FILE_HEADER.from_buffer (filedata, 0)
        self.FfsData  = filedata[0:int(self.FfsHdr.Size)]
        self.Offset   = offset
        self.SecList  = []

    def ParseFfs(self):
        ffssize = len(self.FfsData)
        offset  = sizeof(self.FfsHdr)
        if self.FfsHdr.Name != '\xff' * 16:
            while offset < (ffssize - sizeof (EFI_COMMON_SECTION_HEADER)):
                sechdr = EFI_COMMON_SECTION_HEADER.from_buffer (self.FfsData, offset)
                if int(sechdr.Size) < 0x4:
                    offset += int(sizeof(EFI_COMMON_SECTION_HEADER)) + int(sechdr.Size)
                    offset = AlignPtr(offset, 4)
                else:
                    sec = Section (offset, self.FfsData[offset:offset + int(sechdr.Size)])
                    self.SecList.append(sec)
                    offset += int(sechdr.Size)
                    offset  = AlignPtr(offset, 4)

class FirmwareVolume:
    def __init__(self, offset, fvdata):
        self.FvHdr    = EFI_FIRMWARE_VOLUME_HEADER.from_buffer (fvdata, 0)
        self.FvData   = fvdata[0 : self.FvHdr.FvLength]
        self.Offset   = offset
        if self.FvHdr.ExtHeaderOffset > 0:
            self.FvExtHdr = EFI_FIRMWARE_VOLUME_EXT_HEADER.from_buffer (self.FvData, self.FvHdr.ExtHeaderOffset)
        else:
            self.FvExtHdr = None
        self.FfsList  = []

    def ParseFv(self):
        fvsize = len(self.FvData)
        if self.FvExtHdr:
            offset = self.FvHdr.ExtHeaderOffset + self.FvExtHdr.ExtHeaderSize
        else:
            offset = self.FvHdr.HeaderLength
        offset = AlignPtr(offset)
        while offset < (fvsize - sizeof (EFI_FFS_FILE_HEADER)):
            ffshdr = EFI_FFS_FILE_HEADER.from_buffer (self.FvData, offset)
            if (ffshdr.Name == '\xff' * 16) and (int(ffshdr.Size) == 0xFFFFFF):
                offset = fvsize
            else:
                ffs = FirmwareFile (offset, self.FvData[offset:offset + int(ffshdr.Size)])
                ffs.ParseFfs()
                self.FfsList.append(ffs)
                offset += int(ffshdr.Size)
                offset = AlignPtr(offset)

class FspImage:
    def __init__(self, offset, fih, fihoff, patch):
        self.Fih       = fih
        self.FihOffset = fihoff
        self.Offset    = offset
        self.FvIdxList = []
        self.Type      = "XTMSXXXXOXXXXXXX"[(fih.ComponentAttribute >> 12) & 0x0F]
        self.PatchList = patch
        self.PatchList.append(fihoff + 0x1C)

    def AppendFv(self, FvIdx):
        self.FvIdxList.append(FvIdx)

    def Patch(self, delta, fdbin):
        count   = 0
        applied = 0
        for idx, patch in enumerate(self.PatchList):
            ptype = (patch>>24) & 0x0F
            if ptype not in [0x00, 0x0F]:
                raise Exception('ERROR: Invalid patch type %d !' % ptype)
            if patch & 0x80000000:
                patch = self.Fih.ImageSize - (0x1000000 - (patch & 0xFFFFFF))
            else:
                patch = patch & 0xFFFFFF
            if (patch < self.Fih.ImageSize) and (patch + sizeof(c_uint32) <= self.Fih.ImageSize):
                offset = patch + self.Offset
                value  = Bytes2Val(fdbin[offset:offset+sizeof(c_uint32)])
                value += delta
                fdbin[offset:offset+sizeof(c_uint32)] = Val2Bytes(value, sizeof(c_uint32))
                applied += 1
            count += 1
        # Don't count the FSP base address patch entry appended at the end
        if count != 0:
            count   -= 1
            applied -= 1
        return (count, applied)

class FirmwareDevice:
    def __init__(self, offset, fdfile):
        self.FvList  = []
        self.FspList = []
        self.FdFile = fdfile
        self.Offset = 0
        hfsp = open (self.FdFile, 'rb')
        self.FdData = bytearray(hfsp.read())
        hfsp.close()

    def ParseFd(self):
        offset = 0
        fdsize = len(self.FdData)
        self.FvList = []
        while (offset < fdsize):
            content = self.FdData[offset:offset + 4]

            if content == b'_FVH':
                fvOffset = offset - 40
                fvh = EFI_FIRMWARE_VOLUME_HEADER.from_buffer(self.FdData, fvOffset)
                if (fvOffset + fvh.FvLength) <= fdsize:
                    fv = FirmwareVolume(fvOffset, self.FdData[fvOffset:fvOffset + fvh.FvLength])
                    fv.ParseFv()
                    self.FvList.append(fv)
            offset += 4

    # old
    # def ParseFd(self):
    #     offset = 0
    #     fdsize = len(self.FdData)
    #     self.FvList  = []
    #     while offset < (fdsize - sizeof (EFI_FIRMWARE_VOLUME_HEADER)):
    #         fvh = EFI_FIRMWARE_VOLUME_HEADER.from_buffer (self.FdData, offset)
    #         if b'_FVH' != fvh.Signature:
    #             raise Exception("ERROR: Invalid FV header !")
    #         fv = FirmwareVolume (offset, self.FdData[offset:offset + fvh.FvLength])
    #         fv.ParseFv ()
    #         self.FvList.append(fv)
    #         offset += fv.FvHdr.FvLength

    def CheckFsp (self):
        if len(self.FspList) == 0:
            return

        fih = None
        for fsp in self.FspList:
            if not fih:
                fih = fsp.Fih
            else:
                newfih = fsp.Fih
                if (newfih.ImageId != fih.ImageId) or (newfih.ImageRevision != fih.ImageRevision):
                    raise Exception("ERROR: Inconsistent FSP ImageId or ImageRevision detected !")

    def ParseFsp(self):
        flen = 0
        for idx, fv in enumerate(self.FvList):
            # Check if this FV contains FSP header
            if flen == 0:
                if len(fv.FfsList) == 0:
                    continue
                ffs = fv.FfsList[0]
                if len(ffs.SecList) == 0:
                    continue
                sec = ffs.SecList[0]
                if sec.SecHdr.Type != EFI_SECTION_TYPE.RAW:
                    continue
                fihoffset = ffs.Offset + sec.Offset + sizeof(sec.SecHdr)
                fspoffset = fv.Offset
                offset    = fspoffset + fihoffset
                fih = FSP_INFORMATION_HEADER.from_buffer (self.FdData, offset)
                if b'FSPH' != fih.Signature:
                    continue

                offset += fih.HeaderLength
                offset = AlignPtr(offset, 4)
                plist  = []
                while True:
                    fch = FSP_COMMON_HEADER.from_buffer (self.FdData, offset)
                    if b'FSPP' != fch.Signature:
                        offset += fch.HeaderLength
                        offset = AlignPtr(offset, 4)
                    else:
                        fspp = FSP_PATCH_TABLE.from_buffer (self.FdData, offset)
                        offset += sizeof(fspp)
                        pdata  = (c_uint32 * fspp.PatchEntryNum).from_buffer(self.FdData, offset)
                        plist  = list(pdata)
                        break

                fsp  = FspImage (fspoffset, fih, fihoffset, plist)
                fsp.AppendFv (idx)
                self.FspList.append(fsp)
                flen = fsp.Fih.ImageSize - fv.FvHdr.FvLength
            else:
                fsp.AppendFv (idx)
                flen -= fv.FvHdr.FvLength
                if flen < 0:
                    raise Exception("ERROR: Incorrect FV size in image !")
        self.CheckFsp ()

class PeTeImage:
    def __init__(self, offset, data):
        self.Offset    = offset
        tehdr          = EFI_TE_IMAGE_HEADER.from_buffer (data, 0)
        if   tehdr.Signature == b'VZ': # TE image
            self.TeHdr   = tehdr
        elif tehdr.Signature == b'MZ': # PE image
            self.TeHdr   = None
            self.DosHdr  = EFI_IMAGE_DOS_HEADER.from_buffer (data, 0)
            self.PeHdr   = EFI_IMAGE_NT_HEADERS32.from_buffer (data, self.DosHdr.e_lfanew)
            if self.PeHdr.Signature != 0x4550:
                raise Exception("ERROR: Invalid PE32 header !")
            if self.PeHdr.OptionalHeader.PeOptHdr.Magic == 0x10b: # PE32 image
                if self.PeHdr.FileHeader.SizeOfOptionalHeader < EFI_IMAGE_OPTIONAL_HEADER32.DataDirectory.offset:
                    raise Exception("ERROR: Unsupported PE32 image !")
                if self.PeHdr.OptionalHeader.PeOptHdr.NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY.BASERELOC:
                    raise Exception("ERROR: No relocation information available !")
            elif self.PeHdr.OptionalHeader.PeOptHdr.Magic == 0x20b: # PE32+ image
                if self.PeHdr.FileHeader.SizeOfOptionalHeader < EFI_IMAGE_OPTIONAL_HEADER32_PLUS.DataDirectory.offset:
                    raise Exception("ERROR: Unsupported PE32+ image !")
                if self.PeHdr.OptionalHeader.PePlusOptHdr.NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY.BASERELOC:
                    raise Exception("ERROR: No relocation information available !")
            else:
                raise Exception("ERROR: Invalid PE32 optional header !")
        self.Offset    = offset
        self.Data      = data
        self.RelocList = []

    def IsTeImage(self):
        return  self.TeHdr is not None

    def ParseReloc(self):
        if self.IsTeImage():
            rsize   = self.TeHdr.DataDirectoryBaseReloc.Size
            roffset = sizeof(self.TeHdr) - self.TeHdr.StrippedSize + self.TeHdr.DataDirectoryBaseReloc.VirtualAddress
        else:
            if self.PeHdr.OptionalHeader.PeOptHdr.Magic == 0x10b: # PE32 image
                rsize   = self.PeHdr.OptionalHeader.PeOptHdr.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY.BASERELOC].Size
                roffset = self.PeHdr.OptionalHeader.PeOptHdr.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY.BASERELOC].VirtualAddress
            if self.PeHdr.OptionalHeader.PeOptHdr.Magic == 0x20b: # PE32+ image
                rsize   = self.PeHdr.OptionalHeader.PePlusOptHdr.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY.BASERELOC].Size
                roffset = self.PeHdr.OptionalHeader.PePlusOptHdr.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY.BASERELOC].VirtualAddress

        alignment = 4
        offset = roffset
        while offset < roffset + rsize:
            offset = AlignPtr(offset, 4)
            blkhdr = PE_RELOC_BLOCK_HEADER.from_buffer(self.Data, offset)
            offset += sizeof(blkhdr)
            # Read relocation type,offset pairs
            rlen  = blkhdr.BlockSize - sizeof(PE_RELOC_BLOCK_HEADER)
            rnum  = int (rlen/sizeof(c_uint16))
            rdata = (c_uint16 * rnum).from_buffer(self.Data, offset)
            for each in rdata:
                roff  = each & 0xfff
                rtype = each >> 12
                if rtype == 0: # IMAGE_REL_BASED_ABSOLUTE:
                    continue
                if ((rtype != 3) and (rtype != 10)): # IMAGE_REL_BASED_HIGHLOW and IMAGE_REL_BASED_DIR64
                    raise Exception("ERROR: Unsupported relocation type %d!" % rtype)
                # Calculate the offset of the relocation
                aoff  = blkhdr.PageRVA + roff
                if self.IsTeImage():
                    aoff += sizeof(self.TeHdr) - self.TeHdr.StrippedSize
                self.RelocList.append((rtype, aoff))
            offset += sizeof(rdata)

    def Rebase(self, delta, fdbin):
        count = 0
        if delta == 0:
            return count

        for (rtype, roff) in self.RelocList:
            if rtype == 3: # IMAGE_REL_BASED_HIGHLOW
                offset = roff + self.Offset
                value  = Bytes2Val(fdbin[offset:offset+sizeof(c_uint32)])
                value += delta
                fdbin[offset:offset+sizeof(c_uint32)] = Val2Bytes(value, sizeof(c_uint32))
                count += 1
            elif rtype == 10: # IMAGE_REL_BASED_DIR64
                offset = roff + self.Offset
                value  = Bytes2Val(fdbin[offset:offset+sizeof(c_uint64)])
                value += delta
                fdbin[offset:offset+sizeof(c_uint64)] = Val2Bytes(value, sizeof(c_uint64))
                count += 1
            else:
                raise Exception('ERROR: Unknown relocation type %d !' % rtype)

        if self.IsTeImage():
            offset  = self.Offset + EFI_TE_IMAGE_HEADER.ImageBase.offset
            size    = EFI_TE_IMAGE_HEADER.ImageBase.size
        else:
            offset  = self.Offset + self.DosHdr.e_lfanew
            offset += EFI_IMAGE_NT_HEADERS32.OptionalHeader.offset
            offset += EFI_IMAGE_OPTIONAL_HEADER32.ImageBase.offset
            size    = EFI_IMAGE_OPTIONAL_HEADER32.ImageBase.size

        value  = Bytes2Val(fdbin[offset:offset+size]) + delta
        fdbin[offset:offset+size] = Val2Bytes(value, size)

        return count

def ShowFspInfo (fspfile):
    fd = FirmwareDevice(0, fspfile)
    fd.ParseFd  ()
    fd.ParseFsp ()

    print ("\nFound the following %d Firmware Volumes in FSP binary:" % (len(fd.FvList)))
    for idx, fv in enumerate(fd.FvList):
        name = fv.FvExtHdr.FvName
        if not name:
            name = '\xff' * 16
        else:
            if sys.version_info[0] < 3:
                name = str(bytearray(name))
            else:
                name = bytes(name)
        guid = uuid.UUID(bytes_le = name)
        print ("FV%d:" % idx)
        print ("  GUID   : %s" % str(guid).upper())
        print ("  Offset : 0x%08X" %  fv.Offset)
        print ("  Length : 0x%08X" % fv.FvHdr.FvLength)
    print ("\n")

    for fsp in fd.FspList:
        fvlist = map(lambda x : 'FV%d' % x, fsp.FvIdxList)
        print ("FSP_%s contains %s" % (fsp.Type, ','.join(fvlist)))
        print ("%s" % (OutputStruct(fsp.Fih, 0, fsp.Fih.HeaderLength)))

def RebaseFspBin (FspBinary, FspComponent, FspBase, OutputFile):
    fd = FirmwareDevice(0, FspBinary)
    fd.ParseFd  ()
    fd.ParseFsp ()

    numcomp  = len(FspComponent)
    baselist = FspBase
    if numcomp != len(baselist):
        print ("ERROR: Required number of base does not match number of FSP component !")
        return

    newfspbin = fd.FdData[:]

    for idx, fspcomp in enumerate(FspComponent):

        found = False
        for fsp in fd.FspList:
            # Is this FSP 1.x single binary?
            if fsp.Fih.HeaderRevision < 3:
                found = True
                ftype = 'X'
                break
            ftype = fsp.Type.lower()
            if ftype == fspcomp:
                found = True
                break

        if not found:
            print ("ERROR: Could not find FSP_%c component to rebase !" % fspcomp.upper())
            return

        fspbase = baselist[idx]
        if fspbase.startswith('0x'):
            newbase = int(fspbase, 16)
        else:
            newbase = int(fspbase)
        oldbase = fsp.Fih.ImageBase
        delta = newbase - oldbase
        print ("Rebase FSP-%c from 0x%08X to 0x%08X:" % (ftype.upper(),oldbase,newbase))

        imglist = []
        for fvidx in fsp.FvIdxList:
            fv = fd.FvList[fvidx]
            for ffs in fv.FfsList:
                for sec in ffs.SecList:
                    if sec.SecHdr.Type in [EFI_SECTION_TYPE.TE, EFI_SECTION_TYPE.PE32]:   # TE or PE32
                        offset = fd.Offset + fv.Offset + ffs.Offset + sec.Offset + sizeof(sec.SecHdr)
                        imglist.append ((offset, len(sec.SecData) - sizeof(sec.SecHdr)))

        fcount  = 0
        pcount  = 0
        for (offset, length) in imglist:
            img = PeTeImage(offset, fd.FdData[offset:offset + length])
            img.ParseReloc()
            pcount += img.Rebase(delta, newfspbin)
            fcount += 1

        print ("  Patched %d entries in %d TE/PE32 images." % (pcount, fcount))

        (count, applied) = fsp.Patch(delta, newfspbin)
        print ("  Patched %d entries using FSP patch table." % applied)
        if count != applied:
            print ("  %d invalid entries are ignored !" % (count - applied))

    if OutputFile == '':
        filename = os.path.basename(FspBinary)
        base, ext  = os.path.splitext(filename)
        OutputFile = base + "_%08X" % newbase + ext

    fspname, ext = os.path.splitext(os.path.basename(OutputFile))
    filename = fspname + ext
    fd = open(filename, "wb")
    fd.write(newfspbin)
    fd.close()

# def GenFspManifest (FspBinary, SvnNum, OutputFile):
#     fd = FirmwareDevice(0, FspBinary)
#     fd.ParseFd()
#     fd.ParseFsp()
#
#     if OutputFile == '':
#         filename = os.path.basename(FspBinary)
#         base, ext  = os.path.splitext(filename)
#         OutputFile = base + "Manifest.bin"
#
#     fspname, ext = os.path.splitext(os.path.basename(OutputFile))
#     filename = fspname + ext
#
#     fspmanifestbin = bytearray([])
#     DigestSize = 64
#
#     # Component Manifest Additional Data
#     AddDataType = 1
#     AddDigestType = 0xB
#
#     AddDataType0 = 2
#
#     # Component Manifest
#     CompDataType = 0
#
#     # Manifest
#     ManifestSignature = b'_FM_'
#     ManifestSize = sizeof(c_uint32) + sizeof(c_uint32) + sizeof(c_uint8) + sizeof(c_uint24) + sizeof(c_uint32)
#     ManifestStructureVersion = 0x10
#     ManifestReservedData = 0x0
#     if SvnNum == '':
#         MainifestFspSvn = fd.FspList[0].Fih.ImageRevision
#     else:
#         MainifestFspSvn = eval(SvnNum)
#
#     offset = 0
#     fspmanifestbin[offset:offset + sizeof(c_uint32)] = ManifestSignature
#     offset += sizeof(c_uint32)
#     ManifestSizeOffset = offset
#     fspmanifestbin[ManifestSizeOffset:ManifestSizeOffset + sizeof(c_uint32)] = Val2Bytes(0, sizeof(c_uint32))
#     offset += sizeof(c_uint32)
#     fspmanifestbin[offset:offset + sizeof(c_uint8)] = Val2Bytes(ManifestStructureVersion, sizeof(c_uint8))
#     offset += sizeof(c_uint8)
#     fspmanifestbin[offset:offset + sizeof(c_uint24)] = Val2Bytes(ManifestReservedData, sizeof(c_uint24))
#     offset += sizeof(c_uint24)
#     fspmanifestbin[offset:offset + sizeof(c_uint32)] = Val2Bytes(MainifestFspSvn, sizeof(c_uint32))
#     offset += sizeof(c_uint32)
#
#     FspAddr = 0
#     for fsp in fd.FspList:
#         ImageSize = fsp.Fih.ImageSize
#         CfgRegionOffset = fsp.Fih.CfgRegionOffset
#         CfgRegionSize = fsp.Fih.CfgRegionSize
#
#         fspData = fd.FdData[FspAddr : (FspAddr + ImageSize)]
#         AddFspInfoHeader = fd.FdData[FspAddr + fsp.FihOffset : (FspAddr + fsp.FihOffset + sizeof(FSP_INFORMATION_HEADER))]
#         UDP_Data = fspData[CfgRegionOffset : (CfgRegionOffset + CfgRegionSize)]
#         fspData = fspData.replace(UDP_Data, b"")
#
#
#         AddDigestData = hashlib.sha256(fspData).hexdigest()
#
#         AddDataLength  = sizeof(c_uint16) + sizeof(c_uint16) + sizeof(c_uint16) + len(AddDigestData)
#         AddDataLength0 = sizeof(c_uint16) + sizeof(c_uint16) + CfgRegionSize
#         CompDataLength = sizeof(c_uint16) + sizeof(c_uint16) + sizeof(FSP_INFORMATION_HEADER) + AddDataLength + AddDataLength0
#
#         ManifestSize += CompDataLength
#
#         fspmanifestbin[offset:offset + sizeof(c_uint16)] = Val2Bytes(CompDataType, sizeof(c_uint16))
#         offset += sizeof(c_uint16)
#         fspmanifestbin[offset:offset + sizeof(c_uint16)] = Val2Bytes(CompDataLength, sizeof(c_uint16))
#         offset += sizeof(c_uint16)
#         fspmanifestbin[offset:offset + sizeof(FSP_INFORMATION_HEADER)] = AddFspInfoHeader
#         offset += sizeof(FSP_INFORMATION_HEADER)
#         # FSP Component Manifest Addtional Data for Code
#         fspmanifestbin[offset:offset + sizeof(c_uint16)] = Val2Bytes(AddDataType, sizeof(c_uint16))
#         offset += sizeof(c_uint16)
#         fspmanifestbin[offset:offset + sizeof(c_uint16)] = Val2Bytes(AddDataLength, sizeof(c_uint16))
#         offset += sizeof(c_uint16)
#         fspmanifestbin[offset:offset + sizeof(c_uint16)] = Val2Bytes(AddDigestType, sizeof(c_uint16))
#         offset += sizeof(c_uint16)
#         fspmanifestbin[offset:offset + DigestSize] = bytearray(AddDigestData, encoding="utf-8")
#         offset += DigestSize
#         # FSP Component Manifest Addtional Data for Configuration
#         fspmanifestbin[offset:offset + sizeof(c_uint16)] = Val2Bytes(AddDataType0, sizeof(c_uint16))
#         offset += sizeof(c_uint16)
#         fspmanifestbin[offset:offset + sizeof(c_uint16)] = Val2Bytes(AddDataLength0, sizeof(c_uint16))
#         offset += sizeof(c_uint16)
#         fspmanifestbin[offset:offset + CfgRegionSize] = UDP_Data
#         offset += CfgRegionSize
#
#         FspAddr += ImageSize
#
#     fspmanifestbin[ManifestSizeOffset:ManifestSizeOffset + sizeof(c_uint32)] = Val2Bytes(ManifestSize, sizeof(c_uint32))
#
#     fd = open(filename, "wb")
#     fd.write(bytearray(fspmanifestbin))
#     fd.close()

# def CheckOpenssl ():
#     #
#     # Generate file path to Open SSL command
#     #
#     try:
#         OpenSslPath = os.environ['OPENSSL_PATH']
#         global OpenSslCommand
#         OpenSslCommand = os.path.join(OpenSslPath, 'openssl')
#         if ' ' in OpenSslCommand:
#             OpenSslCommand = '"' + OpenSslCommand + '"'
#     except:
#         pass
#
#     #
#     # Verify that Open SSL command is available
#     #
#     try:
#         Process = subprocess.Popen('%s version' % (OpenSslCommand), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
#     except:
#         print('ERROR: Open SSL command not available.  Please verify PATH or set OPENSSL_PATH')
#         sys.exit(1)
#
#     Version = Process.communicate()
#     if Process.returncode != 0:
#         print('ERROR: Open SSL command not available.  Please verify PATH or set OPENSSL_PATH')
#         sys.exit(Process.returncode)
#     print(Version[0].decode())
#
#
# def SignFspManifest (FspManifest, SignerPrivateCertFile, OtherPublicCertFile, OutputFile):
#     CheckOpenssl()
#
#     fd = open(FspManifest, 'rb')
#     FspManifestBuffer = fd.read()
#     fd.close()
#
#     #
#     # Sign the input file using the specified private key and capture signature from STDOUT
#     #
#     Process = subprocess.Popen('%s smime -sign -binary -signer "%s" -outform DER -md sha256 -certfile "%s"' % (OpenSslCommand, SignerPrivateCertFile, OtherPublicCertFile), stdin=subprocess.PIPE,  stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
#     Signature = Process.communicate(input=FspManifestBuffer)[0]
#     if Process.returncode != 0:
#         sys.exit(Process.returncode)
#
#     if OutputFile == '':
#         filename = os.path.basename(FspManifest)
#         base, ext  = os.path.splitext(filename)
#         OutputFile = base + ".sign.bin"
#
#     fspname, ext = os.path.splitext(os.path.basename(OutputFile))
#     filename = fspname + ext
#
#     fd = open(filename, 'wb')
#     fd.write(Signature)
#     fd.write(FspManifestBuffer)
#     fd.close()
#
# def DecodeSignedFspManifest(SignedFspManifest, TrustedPublicCertFile, SignatureSizeStr, OutputFile):
#     CheckOpenssl()
#
#     fd = open(SignedFspManifest, 'rb')
#     SignedFspManifestBuffer = fd.read()
#     fd.close()
#
#     if SignatureSizeStr == '':
#         print("ERROR: please use the option --signature-size to specify the size of the signature data!")
#         sys.exit(1)
#     else:
#         try:
#             SignatureSize = eval(SignatureSizeStr)
#         except:
#             print ('%s is illegal' % SignatureSizeStr)
#             sys.exit(1)
#         if SignatureSize < 0:
#             print("ERROR: The value of option --signature-size can't be set to negative value!")
#             sys.exit(1)
#         elif SignatureSize > len(SignedFspManifestBuffer):
#             print("ERROR: The value of option --signature-size is exceed the size of the input file !")
#             sys.exit(1)
#
#     SignatureBuffer   = SignedFspManifestBuffer[0:SignatureSize]
#     FspManifestBuffer = SignedFspManifestBuffer[SignatureSize:]
#
#     if OutputFile == '':
#         filename = os.path.basename(SignedFspManifest)
#         base, ext  = filename.split('.')[0]
#         OutputFile = base + ".bin"
#
#     fspname, ext = os.path.splitext(os.path.basename(OutputFile))
#     filename = fspname + ext
#
#     #
#     # Save output file contents from input file
#     #
#     fd = open(filename, 'wb')
#     fd.write(FspManifestBuffer)
#     fd.close()
#
#     #
#     # Verify signature
#     #
#     Process = subprocess.Popen('%s smime -verify -inform DER -content %s -CAfile %s' % (OpenSslCommand, filename, TrustedPublicCertFile), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
#     Process.communicate(input=SignatureBuffer)[0]
#     if Process.returncode != 0:
#         print('ERROR: Verification failed')
#         os.remove(filename)
#         sys.exit(Process.returncode)
#
#     fd = open(filename, 'wb')
#     fd.write(FspManifestBuffer)
#     fd.close()

class FspComponent():
    def __init__(self, Mode):
        self.Mode = Mode
        if self.Mode == 'binary':
            self.EventLogHashDict = {'FSPT': '', 'FSPM': '', 'FSPS': ''}
            self.FlashBinHashDict = {'FSPT': '', 'FSPM': '', 'FSPS': ''}
        else:
            self.EventLogHashDict = {'FSPT-Code': '', 'FSPT-Udp': '', 'FSPM-Code': '', 'FSPM-Udp': '',
                                     'FSPS-Code': '', 'FSPS-Udp': ''}
            self.FlashBinHashDict = {'FSPT-Code': '', 'FSPT-Udp': '', 'FSPM-Code': '', 'FSPM-Udp': '',
                                     'FSPS-Code': '', 'FSPS-Udp': ''}

    def __GetHashSizeFromAlgo(self, HashAlgo):
        for item in HashInfo:
            if HashAlgo == item[0]:
                return item[1]
        return 0

    def __GetPcrEvent2Size(self, PcrEvent2Hdr, Buffer, Offset):
        HashAlgo = PcrEvent2Hdr.digests.digests[0].hashAlg
        DigestSize = self.__GetHashSizeFromAlgo(HashAlgo)
        DigestOffset = Offset + 3 * sizeof(c_uint32) + sizeof(c_uint16)
        Digest = Buffer[DigestOffset: DigestOffset + DigestSize]

        EventDataSizeOffset = Offset + 3 * sizeof(c_uint32) + DigestSize + sizeof(c_uint16)
        EventDataSize = c_uint32.from_buffer(Buffer, EventDataSizeOffset).value

        EventDataOffset = EventDataSizeOffset + sizeof(c_uint32)
        if PcrEvent2Hdr.eventType == EV_EFI_PLATFORM_FIRMWARE_BLOB2:
            BlobDescriptionSize = c_uint8.from_buffer(Buffer, EventDataOffset).value
            BlobDescription = Buffer[EventDataOffset + sizeof(c_uint8): EventDataOffset + sizeof(
                c_uint8) + BlobDescriptionSize].decode(encoding="ISO-8859-1")
            for key in self.EventLogHashDict.keys():
                if BlobDescription.startswith(key):
                    self.EventLogHashDict[key] = bytearray.hex(Digest)
                    print(key, bytearray.hex(Digest))

        Event2Size = EventDataOffset + EventDataSize - Offset
        return Event2Size

    def GetHashFromTcgEventLog(self, TcgEventLogBinPath):
        with open(TcgEventLogBinPath, 'rb') as f:
            BinData = bytearray(f.read())

        offset = 0
        BinLength = len(BinData)

        while offset < (BinLength - sizeof(tdTCG_PCR_EVENT2_HDR)):
            if offset == 0:
                PcrEventHdr = tdTCG_PCR_EVENT_HDR.from_buffer(BinData, offset)
                offset += sizeof(tdTCG_PCR_EVENT_HDR) + PcrEventHdr.eventDataSize
            else:
                PcrEvent2Hdr = tdTCG_PCR_EVENT2_HDR.from_buffer(BinData, offset)
                offset += self.__GetPcrEvent2Size(PcrEvent2Hdr, BinData, offset)
        return self.EventLogHashDict

    def GetHashFromFlashBin(self, FlashBinPath):
        fd = FirmwareDevice(0, FlashBinPath)
        fd.ParseFd()
        fd.ParseFsp()


        if self.Mode == 'binary':
            for fsp in fd.FspList:
                ImageSize = fsp.Fih.ImageSize
                FspAddr = fsp.Offset
                fspData = fd.FdData[FspAddr: (FspAddr + ImageSize)]

                hash_out = hashlib.sha256(fspData).hexdigest()
                print("FSP%s %s %s" % (fsp.Type, ImageSize, hash_out))
                for key in self.FlashBinHashDict.keys():
                    if key == "FSP{}".format(fsp.Type):
                        self.FlashBinHashDict[key] = hash_out
                FspAddr += ImageSize
        else:
            for fsp in fd.FspList:
                ImageSize = fsp.Fih.ImageSize
                CfgRegionOffset = fsp.Fih.CfgRegionOffset
                CfgRegionSize = fsp.Fih.CfgRegionSize

                FspAddr = fsp.Offset
                fspData = fd.FdData[FspAddr: (FspAddr + ImageSize)]
                UDP_Data = fspData[CfgRegionOffset: (CfgRegionOffset + CfgRegionSize)]
                fspData = fspData.replace(UDP_Data, b"")

                code_hash_out = hashlib.sha256(fspData).hexdigest()
                udp_hash_out = hashlib.sha256(UDP_Data).hexdigest()
                print("FSP%s-Code %s %s" % (fsp.Type, len(fspData), code_hash_out))
                print("FSP%s-Udp %s %s" % (fsp.Type, len(UDP_Data), udp_hash_out))
                for key in self.FlashBinHashDict.keys():
                    if key == "FSP{}-Code".format(fsp.Type):
                        self.FlashBinHashDict[key] = code_hash_out
                    if key == "FSP{}-Udp".format(fsp.Type):
                        self.FlashBinHashDict[key] = udp_hash_out
                FspAddr += ImageSize

        return self.FlashBinHashDict

    def Compare(self, TcgEventLogBinPath, FlashBinPath):
        self.GetHashFromTcgEventLog(TcgEventLogBinPath)
        self.GetHashFromFlashBin(FlashBinPath)

        if operator.eq(self.EventLogHashDict, self.FlashBinHashDict):
            print('Compare FSP component hash bettween Tcg event log binary and platform image [PASS]')
        else:
            print('Compare FSP component hash bettween Tcg event log binary and platform image [FAIL]')

def main():
    parser     = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title='commands', dest="which")

    parser_rebase = subparsers.add_parser('rebase',  help='rebase a FSP into a new base address')
    parser_rebase.set_defaults(which='rebase')
    parser_rebase.add_argument('-f',  '--fspbin' , dest='FspBinary',  type=str, help='FSP binary file path', required = True)
    parser_rebase.add_argument('-c',  '--fspcomp', choices=['t','m','s','o'],  nargs='+', dest='FspComponent', type=str, help='FSP component to rebase', default = "['t']", required = True)
    parser_rebase.add_argument('-b',  '--newbase', dest='FspBase', nargs='+', type=str, help='Rebased FSP binary file name', default = '', required = True)
    parser_rebase.add_argument('-o',  '--outfile', dest='OutputFile', type=str, help='Rebased FSP binary file name', default = '')

    parser_hash = subparsers.add_parser('hash',  help='generate hash(sha256) for FSP image or get hash from TCG event log')
    parser_hash.set_defaults(which='hash')
    parser_hash.add_argument('-f',  '--file', dest='File', type=str, help='FSP binary file path or TCG event log path', required = True)
    parser_hash.add_argument('--tcg', dest='TCG', action='store_true', help='Flag to check whether the file is Tcg event log')
    parser_hash.add_argument('-m', '--mode', choices=['binary', 'separation'], dest='Mode', type=str, help='Different mode to generate hash for FSP image', default='binary')

    # parser_manifest = subparsers.add_parser('manifest', help='generate FSP manifest')
    # parser_manifest.set_defaults(which='manifest')
    # parser_manifest.add_argument('-f', '--fspbin', dest='FspBinary', type=str, help='FSP binary file path', required=True)
    # parser_manifest.add_argument('-s', '--svn', dest='SVN', type=str, help='FSP manifest SVN', default='')
    # parser_manifest.add_argument('-o', '--outfile', dest='OutputFile', type=str, help='FSP manifest binary file name', default='')
    #
    # parser_encode = subparsers.add_parser('encode', help='Encode FSP manifest file')
    # parser_encode.set_defaults(which='encode')
    # parser_encode.add_argument('-f', '--fspmanifest', dest='FspManifest', type=str, help='FSP manifest binary file path', required=True)
    # parser_encode.add_argument('--signer-private-cert', dest='SignerPrivateCertFile', type=str, help='specify the signer private cert filename.  If not specified, a test signer private cert is used.')
    # parser_encode.add_argument('--other-public-cert', dest='OtherPublicCertFile', type=str, help='specify the other public cert filename.  If not specified, a test other public cert is used.')
    # parser_encode.add_argument('-o', '--outfile', dest='OutputFile', type=str, help='Signed FSP manifest binary file name', default='')
    #
    # parser_decode = subparsers.add_parser('decode', help='Decode FSP manifest file')
    # parser_decode.set_defaults(which='decode')
    # parser_decode.add_argument('-f', '--fspmanifest', dest='SignedFspManifest', type=str, help='FSP manifest binary file path', required=True)
    # parser_decode.add_argument('--trusted-public-cert', dest='TrustedPublicCertFile', type=str, help='specify the trusted public cert filename.  If not specified, a test trusted public cert is used.')
    # parser_decode.add_argument('--signature-size', dest='SignatureSizeStr', type=str, help='specify the signature size for decode process.', default='')
    # parser_decode.add_argument('-o', '--outfile', dest='OutputFile', type=str, help='Signed FSP manifest binary file name', default='')

    parser_compare = subparsers.add_parser('compare', help='Compare FSP component hash bettween event log binary and platform image')
    parser_compare.set_defaults(which='compare')
    parser_compare.add_argument('--evt', dest='EventLogBin', type=str, help='Event log binary file path', required=True)
    parser_compare.add_argument('--fd', dest='PlatformImage', type=str, help='Platform image file path', required=True)
    parser_compare.add_argument('-m', '--mode', choices=['binary', 'separation'], dest='Mode', type=str, help='Different mode to generate hash for FSP image', default='binary')

    parser_info = subparsers.add_parser('info',  help='display FSP information')
    parser_info.set_defaults(which='info')
    parser_info.add_argument('-f',  '--fspbin' , dest='FspBinary', type=str, help='FSP binary file path', required = True)

    args = parser.parse_args()

    if args.which in ['rebase', 'manifest', 'info']:
        if not os.path.exists(args.FspBinary):
            raise Exception ("ERROR: Could not locate FSP binary file '%s' !" % args.FspBinary)

    if args.which == 'hash':
        if not os.path.exists(args.File):
            raise Exception ("ERROR: Could not locate FSP binary file '%s' !" % args.File)

    # if args.which == 'encode':
    #     if not os.path.exists(args.FspManifest):
    #         raise Exception ("ERROR: Could not locate FSP manifest file '%s' !" % args.FspManifest)
    #     if not os.path.exists(args.SignerPrivateCertFile):
    #         raise Exception ("ERROR: Could not locate signer private cert file '%s' !" % args.SignerPrivateCertFile)
    #     if not os.path.exists(args.OtherPublicCertFile):
    #         raise Exception ("ERROR: Could not locate other public cert file '%s' !" % args.OtherPublicCertFile)
    #
    # if args.which == 'decode':
    #     if not os.path.exists(args.SignedFspManifest):
    #         raise Exception ("ERROR: Could not locate signed FSP manifest file '%s' !" % args.SignedFspManifest)
    #     if not os.path.exists(args.TrustedPublicCertFile):
    #         raise Exception("ERROR: Could not locate trusted public cert file '%s' !" % args.TrustedPublicCertFile)

    if args.which == 'compare':
        if not os.path.exists(args.EventLogBin):
            raise Exception("ERROR: Could not locate event log binary file '%s' !" % args.EventLogBin)
        if not os.path.exists(args.PlatformImage):
            raise Exception("ERROR: Could not locate platform image file '%s' !" % args.PlatformImage)

    if args.which == 'rebase':
        RebaseFspBin(args.FspBinary, args.FspComponent, args.FspBase, args.OutputFile)
    elif args.which == 'hash':
        Hash = FspComponent(args.Mode)
        if args.TCG:
            Hash.GetHashFromTcgEventLog(args.File)
        else:
            Hash.GetHashFromFlashBin(args.File)
    # elif args.which == 'manifest':
    #     GenFspManifest (args.FspBinary, args.SVN, args.OutputFile)
    # elif args.which == 'encode':
    #     SignFspManifest (args.FspManifest, args.SignerPrivateCertFile, args.OtherPublicCertFile, args.OutputFile)
    # elif args.which == 'decode':
    #     DecodeSignedFspManifest (args.SignedFspManifest, args.TrustedPublicCertFile, args.SignatureSizeStr, args.OutputFile)
    elif args.which == 'info':
        ShowFspInfo(args.FspBinary)
    elif args.which == 'compare':
        comp = FspComponent(args.Mode)
        comp.Compare(args.EventLogBin, args.PlatformImage)
    else:
        parser.print_help()

    return 0

if __name__ == '__main__':
    sys.exit(main())
