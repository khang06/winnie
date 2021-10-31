# This tool generates csrss_offsets.py by downloading and
# parsing symbols from the Microsoft symbol server.
# Requirements: construct, pefile
# Run with python2, NOT PYTHON3!

import sys, os

if not (sys.maxsize > 2**32) and os.name == 'nt':
    print('Sorry, 32-bit python is not supported because of WOW64 redirection. Please use 64-bit python')
    raise ValueError('Unsupported python version')

if sys.version_info >= (3, 0):
    print("Sorry, python3 isn't supported")
    raise ValueError('Unsupported python version')

import os.path
from pefile import PE
from shutil import copyfileobj

from pdbparse.peinfo import *

try:
    from urllib.parse import urlparse, urlencode
    from urllib.request import urlopen, Request, build_opener, FancyURLopener
    from urllib.error import HTTPError
except ImportError:
    from urlparse import urlparse
    from urllib import urlencode
    from urllib2 import urlopen, Request, HTTPError, build_opener
    from urllib import FancyURLopener


#SYM_URL = 'http://symbols.mozilla.org/firefox'
SYM_URLS = ['http://msdl.microsoft.com/download/symbols']
USER_AGENT = "Microsoft-Symbol-Server/6.11.0001.404"


class PDBOpener(FancyURLopener):
    version = USER_AGENT

    def http_error_default(self, url, fp, errcode, errmsg, headers):
        if errcode == 404:
            raise HTTPError(url, errcode, errmsg, headers, fp)
        else:
            FancyURLopener.http_error_default(url, fp, errcode, errmsg, headers)


lastprog = None


def progress(blocks, blocksz, totalsz):
    global lastprog
    if lastprog is None:
        sys.stderr.write("Connected. Downloading data..." + "\n")
    percent = int((100 * (blocks * blocksz) / float(totalsz)))
    if lastprog != percent and percent % 5 == 0: sys.stderr.write("%d%%" % percent + "\n")
    lastprog = percent
    sys.stdout.flush()


def download_file(guid, fname, path = None, quiet = False):
    if path is None:
        import tempfile
        path = tempfile.gettempdir()

    outfile = os.path.join(path, fname)
    if os.path.isfile(outfile):
        sys.stderr.write(outfile + ' already exists\n')
        return outfile
    ''' 
    Download the symbols specified by guid and filename. Note that 'guid'
    must be the GUID from the executable with the dashes removed *AND* the
    Age field appended. The resulting file will be saved to the path argument,
    which default to the current directory.
    '''

    # A normal GUID is 32 bytes. With the age field appended
    # the GUID argument should therefore be longer to be valid.
    # Exception: old-style PEs without a debug section use
    # TimeDateStamp+SizeOfImage
    if len(guid) == 32:
        sys.stderr.write("Warning: GUID is too short to be valid. Did you append the Age field?" + "\n")

    for sym_url in SYM_URLS:
        url = sym_url + "/%s/%s/" % (fname, guid)
        opener = build_opener()

        # Whatever extension the user has supplied it must be replaced with .pd_
        tries = [fname[:-1] + '_', fname]

        for t in tries:
            if not quiet: sys.stderr.write("Trying %s" % (url + t) + "\n")
            outfile = os.path.join(path, t)
            try:
                hook = None if quiet else progress
                PDBOpener().retrieve(url + t, outfile, reporthook = hook)
                if not quiet:
                    sys.stderr.write("\n")
                    sys.stderr.write("Saved symbols to %s" % (outfile) + "\n")
                return outfile
            except HTTPError as e:
                if not quiet:
                    sys.stderr.write("HTTP error %u" % (e.code) + "\n")
    return None


def handle_pe(pe_file):
    dbgdata, tp = get_pe_debug_data(pe_file)
    if tp == "IMAGE_DEBUG_TYPE_CODEVIEW":
        # XP+
        if dbgdata[:4] == b"RSDS":
            (guid, filename) = get_rsds(dbgdata)
        elif dbgdata[:4] == b"NB10":
            (guid, filename) = get_nb10(dbgdata)
        else:
            sys.stderr.write("ERR: CodeView section not NB10 or RSDS" + "\n")
            return
        guid = guid.upper()
        saved_file = download_file(guid, filename)
    elif tp == "IMAGE_DEBUG_TYPE_MISC":
        # Win2k
        # Get the .dbg file
        guid = get_pe_guid(pe_file)
        guid = guid.upper()
        filename = get_dbg_fname(dbgdata)
        saved_file = download_file(guid, filename)

        # Extract it if it's compressed
        # Note: requires cabextract!
        if saved_file.endswith("_"):
            os.system("cabextract %s" % saved_file)
            saved_file = saved_file.replace('.db_', '.dbg')

        from pdbparse.dbgold import DbgFile
        dbgfile = DbgFile.parse_stream(open(saved_file, 'rb'))
        cv_entry = [d for d in dbgfile.IMAGE_DEBUG_DIRECTORY if d.Type == "IMAGE_DEBUG_TYPE_CODEVIEW"][0]
        if cv_entry.Data[:4] == b"NB09":
            return
        elif cv_entry.Data[:4] == b"NB10":
            (guid, filename) = get_nb10(cv_entry.Data)

            guid = guid.upper()
            saved_file = download_file(guid, filename)
        else:
            sys.stderr.write("WARN: DBG file received from symbol server has unknown CodeView section" + "\n")
            return
    else:
        sys.stderr.write("Unknown type:", tp + "\n")
        return

    if saved_file != None and saved_file.endswith("_"):
        os.system("cabextract %s" % saved_file)
    return saved_file


def get_pe_from_pe(filename, symname = None):
    guid = get_pe_guid(filename)
    if symname is None:
        symname = os.path.basename(filename)
    saved_file = download_file(guid, symname)
    if saved_file and saved_file.endswith("_"):
        os.system("cabextract %s" % saved_file)

"""
These fields need to be zeroed:
System32/ntdll.dll
.data:00000001801798A8 CsrServerApiRoutine dq ?                ; DATA XREF: RtlRegisterThreadWithCsrss+46
.data:00000001801798A8                                         ; RtlRegisterThreadWithCsrss+93 ...
.data:00000001801798B0 CsrClientProcess db ?                   ; DATA XREF: RtlRegisterThreadWithCsrss+1B
.data:00000001801798B0                                         ; CsrClientConnectToServer+89 ...
.data:00000001801798B1 CsrInitOnceDone db ?                    ; DATA XREF: RtlRegisterThreadWithCsrss:loc_180014D6E
.data:00000001801798B1                                         ; CsrClientConnectToServer:loc_180078AF3 ...
.data:00000001801798B2                 align 20h
.data:00000001801798C0 CsrPortName     dw ?                    ; DATA XREF: CsrpConnectToServer+103
.data:00000001801798C0                                         ; CsrpConnectToServer+10A ...
.data:00000001801798C2 word_1801798C2  dw ?                    ; DATA XREF: CsrpConnectToServer+7D
.data:00000001801798C4                 align 8
.data:00000001801798C8 qword_1801798C8 dq ?                    ; DATA XREF: CsrpConnectToServer+8A
.data:00000001801798C8                                         ; CsrpConnectToServer+F1 ...
.data:00000001801798D0 CsrProcessId    dq ?                    ; DATA XREF: CsrpConnectToServer+320
.data:00000001801798D0                                         ; CsrGetProcessId
.data:00000001801798D8 CsrReadOnlySharedMemorySize dq ?        ; DATA XREF: CsrpConnectToServer+315
.data:00000001801798D8                                         ; CsrVerifyRegion+20
.data:00000001801798E0 CsrPortMemoryRemoteDelta dq ?           ; DATA XREF: CsrpConnectToServer+32F
.data:00000001801798E0                                         ; CsrClientCallServer+80 ...
.data:00000001801798E8 ; HANDLE CsrPortHandle
.data:00000001801798E8 CsrPortHandle   dq ?                    ; DATA XREF: CsrClientConnectToServer+AF
.data:00000001801798E8                                         ; CsrpConnectToServer+240 ...
.data:00000001801798F0 CsrPortHeap     dq ?                    ; DATA XREF: CsrClientConnectToServer+193
.data:00000001801798F0                                         ; CsrpConnectToServer+378 ...
.data:00000001801798F8 CsrPortBaseTag  dd ?                    ; DATA XREF: CsrClientConnectToServer+19F
.data:00000001801798F8                                         ; CsrpConnectToServer+388 ...
.data:00000001801798FC                 align 20h
.data:0000000180179900 CsrHeap         dq ?                    ; DATA XREF: CsrClientConnectToServer+56
.data:0000000180179900                                         ; CsrpConnectToServer+76 ...
.data:0000000180179908                 align 20h
.data:0000000180179920 HotPatchSpareGlobals db    ? ;

SysWOW64/ntdll.dll
.data:4B3A7FF4 _CsrServerApiRoutine dd ?               ; DATA XREF: RtlRegisterThreadWithCsrss()+6EC60
.data:4B3A7FF4                                         ; RtlRegisterThreadWithCsrss()+6EC85
.data:4B3A7FF8 _CsrClientProcess db ?                  ; DATA XREF: CsrClientConnectToServer(x,x,x,x,x)+28
.data:4B3A7FF8                                         ; RtlRegisterThreadWithCsrss():loc_4B31D554
.data:4B3A7FF9 _CsrInitOnceDone db ?                   ; DATA XREF: RtlRegisterThreadWithCsrss()+1F
.data:4B3A7FFA                 align 10h
.data:4B3A8000 _HotPatchSpareGlobals db    ? ;                               
"""

import pdbparse
def symbol_addresses(pdb,base=0):
    from operator import itemgetter, attrgetter
    class DummyOmap(object):
        def remap(self, addr):
            return addr

    addrs = {}
    try:
        # Do this the hard way to avoid having to load
        # the types stream in mammoth PDB files
        pdb.STREAM_DBI.load()
        pdb._update_names()
        pdb.STREAM_GSYM = pdb.STREAM_GSYM.reload()
        if pdb.STREAM_GSYM.size:
            pdb.STREAM_GSYM.load()
        pdb.STREAM_SECT_HDR = pdb.STREAM_SECT_HDR.reload()
        pdb.STREAM_SECT_HDR.load()
        # These are the dicey ones
        pdb.STREAM_OMAP_FROM_SRC = pdb.STREAM_OMAP_FROM_SRC.reload()
        pdb.STREAM_OMAP_FROM_SRC.load()
        pdb.STREAM_SECT_HDR_ORIG = pdb.STREAM_SECT_HDR_ORIG.reload()
        pdb.STREAM_SECT_HDR_ORIG.load()

    except AttributeError as e:
        pass
    # except Exception as e:
    #    print ("WARN: error %s parsing %s, skipping" % (e,pdbbase))
    #    not_found.append( (base, pdbbase) )
    #    continue

    try:
        sects = pdb.STREAM_SECT_HDR_ORIG.sections
        omap = pdb.STREAM_OMAP_FROM_SRC
    except AttributeError as e:
        # In this case there is no OMAP, so we use the given section
        # headers and use the identity function for omap.remap
        sects = pdb.STREAM_SECT_HDR.sections
        omap = DummyOmap()
    gsyms = pdb.STREAM_GSYM
    if not hasattr(gsyms, 'globals'):
        gsyms.globals = []

    last_sect = max(sects, key = attrgetter('VirtualAddress'))
    limit = base + last_sect.VirtualAddress + last_sect.Misc.VirtualSize

    for sym in gsyms.globals:
        if not hasattr(sym, 'offset'):
            continue
        off = sym.offset
        try:
            virt_base = sects[sym.segment - 1].VirtualAddress
        except IndexError:
            continue

        mapped = omap.remap(off + virt_base) + base
        addrs[sym.name]=mapped

    return addrs

def main():
    import platform

    genfile = 'csrss_offsets.h'
    me = os.path.basename(__file__)
    f = open(genfile, 'w')
    f.write('// This file was generated by a tool. Do not edit it manually!\n')
    f.write('// To regenerate it, please run ' + me + '\n\n')
    
    if platform.machine().endswith('64'):
        f.write('// This header is generated to target 64-bit Windows including SysWoW64\n\n')
    else:
        f.write('// This header is generated to target 32-bit Windows ONLY\n\n')
    
    f.write('#pragma once\n\n')

    if platform.machine().endswith('64'):
        f.write('#ifdef _WIN64\n\n')
        ntdll_pdb = handle_pe("C:\\Windows\\system32\\ntdll.dll")
        sys.stderr.write("Loading symbols for %s...\n" % ntdll_pdb)
        pdb = pdbparse.parse(ntdll_pdb, fast_load = True)
        addrs = symbol_addresses(pdb)
        rva_CsrServerApiRoutine_x64 = addrs['CsrServerApiRoutine']
        rva_HotPatchSpareGlobals_x64 = addrs['HotPatchSpareGlobals']
        f.write('// RVA of CsrServerApiRoutine up to HotPatchSpareGlobals in System32\\ntdll.exe\n')
        f.write('#define csrDataRva_x64 ' + hex(rva_CsrServerApiRoutine_x64) + '\n')
        f.write('// HotPatchSpareGlobals = ' + hex(rva_HotPatchSpareGlobals_x64) + '\n')
        f.write('#define csrDataSize_x64 ' + hex(rva_HotPatchSpareGlobals_x64 - rva_CsrServerApiRoutine_x64) + '\n')
        f.write('\n')
        
        f.write('#else\n\n')
        ntdll_pdb = handle_pe("C:\\Windows\\SysWOW64\\ntdll.dll")
        sys.stderr.write("Loading symbols for %s...\n" % ntdll_pdb)
        pdb = pdbparse.parse(ntdll_pdb, fast_load = True)
        addrs = symbol_addresses(pdb)
        rva_CsrServerApiRoutine = addrs['_CsrServerApiRoutine']
        rva_HotPatchSpareGlobals = addrs['_HotPatchSpareGlobals']
        f.write('// WoW64 ntdll.dll\n')
        f.write('// RVA of _CsrServerApiRoutine up to _HotPatchSpareGlobals in SysWOW64\\ntdll.dll\n')
        f.write('#define csrDataRva_x86 ' + hex(rva_CsrServerApiRoutine) + '\n')
        f.write('// HotPatchSpareGlobals = ' + hex(rva_HotPatchSpareGlobals) + '\n')
        f.write('#define csrDataSize_x86 ' + hex(rva_HotPatchSpareGlobals - rva_CsrServerApiRoutine) + '\n')
        f.write('\n')
        f.write('// RVA of CsrServerApiRoutine up to HotPatchSpareGlobals in System32\\ntdll.exe\n')
        f.write('#define csrDataRva_wow64 ' + hex(rva_CsrServerApiRoutine_x64) + '\n')
        f.write('// HotPatchSpareGlobals = ' + hex(rva_HotPatchSpareGlobals_x64) + '\n')
        f.write('#define csrDataSize_wow64 ' + hex(rva_HotPatchSpareGlobals_x64 - rva_CsrServerApiRoutine_x64) + '\n')
        f.write('\n')

        f.write('#endif\n')
    else:
        f.write('#ifdef WIN64\n\n')
        f.write('#error 64-bit csrss offsets missing; please consult ' + me + '\n')
        f.write('#define csrDataRva_x64 0\n')
        f.write('#define csrDataSize_x64 0\n')
        f.write('#define csrDataRva_wow64 0\n')
        f.write('#define csrDataSize_wow64 0\n')
        f.write('\n')

        f.write('#else\n\n')
        ntdll_pdb = handle_pe("C:\\Windows\\system32\\ntdll.dll")
        sys.stderr.write("Loading symbols for %s...\n" % ntdll_pdb)
        pdb = pdbparse.parse(ntdll_pdb, fast_load = True)
        addrs = symbol_addresses(pdb)
        rva_CsrServerApiRoutine = addrs['CsrServerApiRoutine']
        rva_HotPatchSpareGlobals = addrs['HotPatchSpareGlobals']
        f.write('// RVA of CsrServerApiRoutine up to HotPatchSpareGlobals in System32\\ntdll.exe\n')
        f.write('#define csrDataRva_x86 ' + hex(rva_CsrServerApiRoutine) + '\n')
        f.write('// HotPatchSpareGlobals = ' + hex(rva_HotPatchSpareGlobals) + '\n')
        f.write('#define csrDataSize_x86 ' + hex(rva_HotPatchSpareGlobals - rva_CsrServerApiRoutine) + '\n')
        f.write('\n')

        f.write('// WoW64 not supported on native 32-bit platform\n')
        f.write('#define csrDataRva_wow64 0\n')
        f.write('#define csrDataSize_wow64 0\n')

        f.write('\n')
        
        f.write('#endif\n')

    f.close()

    print 'Successfully generated ' + genfile

if __name__ == "__main__":
    main()
