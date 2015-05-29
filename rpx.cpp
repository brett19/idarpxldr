/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2001 by Ilfak Guilfanov (ig@datarescue.com)
 *                                              http://www.datarescue.com
 *      ALL RIGHTS RESERVED.
 *
 */

#include <vector>
#include <string>
#include "../idaldr.h"
#include "elf.h"

extern "C" {
#define TINFL_HEADER_FILE_ONLY
#include "tinfl.c"
};

//#define FAILED  do { msg(            "failed at %d (input file line %d)\n", __LINE__, nl); return 0; } while ( 0 )
#define FAILED  return deb(IDA_DEBUG_LDR,"failed at %d (input file line %d)\n", __LINE__, nl), 0

class BigEndianView {
public:
    BigEndianView(linput_t *li)
        : _li(li), _start(nullptr), _end(nullptr), _ptr(nullptr) {
    }

    BigEndianView(char *data, size_t size)
        : _li(nullptr), _start(data), _end(data+size), _ptr(data) {
    }

    template<typename T>
    int read(T &val) {
        if (_li) {
            return lreadbytes(_li, &val, sizeof(T), true);
        } else {
            return ptrRead((char*)&val, sizeof(T));
        }
    }

    int read(char *data, size_t size) {
        if (_li) {
            return qlread(_li, data, size);
        } else {
            memcpy(data, _ptr, size);
            _ptr += size;
            return size;
        }
    }

    void seek(int pos, int whence = SEEK_SET) {
        if (_li) {
            qlseek(_li, pos, whence);
        } else {
            if (whence == SEEK_CUR) {
                _ptr += pos;
            } else if (whence == SEEK_END) {
                _ptr = _end + pos;
            } else if (whence == SEEK_SET) {
                _ptr = _start + pos;
            }
        }
    }

private:
    int ptrRead(char *data, int size) {
        if (_ptr + size > _end) {
            size = _end - _ptr;
        }
        if (size == 1) {
            data[0] = *_ptr++;
        } else if (size == 2) {
            data[1] = *_ptr++;
            data[0] = *_ptr++;
        } else if (size == 4) {
            data[3] = *_ptr++;
            data[2] = *_ptr++;
            data[1] = *_ptr++;
            data[0] = *_ptr++;
        } else {
            for (int i = 0; i < size; ++i) {
                data[size - i - 1] = *_ptr++;
            }
        }
        return size;
    }

    linput_t *_li;
    char *_ptr;
    char *_start;
    char *_end;

};

static bool
    readHeader(BigEndianView &in, ElfHeader &header)
{
    in.read(header.e_magic);
    in.read(header.e_class);
    in.read(header.e_encoding);
    in.read(header.e_elf_version);
    in.read(header.e_abi);
    in.read(header.e_pad);
    in.read(header.e_type);
    in.read(header.e_machine);
    in.read(header.e_version);
    in.read(header.e_entry);
    in.read(header.e_phoff);
    in.read(header.e_shoff);
    in.read(header.e_flags);
    in.read(header.e_ehsize);
    in.read(header.e_phentsize);
    in.read(header.e_phnum);
    in.read(header.e_shentsize);
    in.read(header.e_shnum);
    in.read(header.e_shstrndx);

    if (header.e_magic != ElfHeader::Magic) {
        return false;
    }
    if (header.e_class != ELFCLASS32) {
        return false;
    }
    if (header.e_encoding != ELFDATA2MSB) {
        return false;
    }
    if (header.e_abi != EABI_CAFE) {
        return false;
    }
    if (header.e_machine != EM_PPC) {
        return false;
    }
    if (header.e_elf_version != EV_CURRENT) {
        return false;
    }
    if (header.e_shentsize != sizeof(ElfSectionHeader)) {
        return false;
    }

    return true;
}

static bool
    readSectionHeader(BigEndianView &in, ElfSectionHeader &shdr)
{
    in.read(shdr.sh_name);
    in.read(shdr.sh_type);
    in.read(shdr.sh_flags);
    in.read(shdr.sh_addr);
    in.read(shdr.sh_offset);
    in.read(shdr.sh_size);
    in.read(shdr.sh_link);
    in.read(shdr.sh_info);
    in.read(shdr.sh_addralign);
    in.read(shdr.sh_entsize);
    return true;
}

static bool
    readSymbol(BigEndianView &in, ElfSymbol &sym)
{
    in.read(sym.st_name);
    in.read(sym.st_value);
    in.read(sym.st_size);
    in.read(sym.st_info);
    in.read(sym.st_other);
    in.read(sym.st_shndx);
    return true;
}

static bool
    readRelocationAddend(BigEndianView &in, ElfRela &rela)
{
    in.read(rela.r_offset);
    in.read(rela.r_info);
    in.read(rela.r_addend);
    return true;
}

static bool
    readFileInfo(BigEndianView &in, RplFileInfo &info)
{
    in.read(info.rpl_min_version);
    in.read(info.rpl_text_size);
    in.read(info.rpl_text_align);
    in.read(info.rpl_data_size);
    in.read(info.rpl_data_align);
    in.read(info.rpl_loader_size);
    in.read(info.rpl_loader_info);
    in.read(info.rpl_temp_size);
    in.read(info.rpl_tramp_adjust);
    in.read(info.rpl_sda_base);
    in.read(info.rpl_sda2_base);
    in.read(info.rpl_stack_size);
    in.read(info.rpl_filename);
    in.read(info.rpl_flags);
    in.read(info.rpl_heap_size);
    in.read(info.rpl_tags);
    in.read(info.rpl_unk1);
    in.read(info.rpl_compression_level);
    in.read(info.rpl_unk2);
    in.read(info.rpl_file_info_pad);
    in.read(info.rpl_cafe_os_sdk_version);
    in.read(info.rpl_cafe_os_sdk_revision);
    in.read(info.rpl_unk3);
    in.read(info.rpl_unk4);
    return true;
}

struct RplSection
{
    //Section *section = nullptr;
    //ModuleSymbol *msym = nullptr;
    ElfSectionHeader header;
    std::vector<char> data;

    std::string libName;
    netnode imports;
};

static void
    loadFileInfo(RplFileInfo &info, std::vector<RplSection> &sections)
{
    for (auto &section : sections) {
        if (section.header.sh_type != SHT_RPL_FILEINFO) {
            continue;
        }

        auto in = BigEndianView(section.data.data(), section.data.size());
        readFileInfo(in, info);
        break;
    }
}

static bool
    readSections(BigEndianView &in, ElfHeader &header, std::vector<RplSection> &sections)
{
    sections.resize(header.e_shnum);

    for (auto i = 0u; i < sections.size(); ++i) {
        auto &section = sections[i];

        // Read section header
        in.seek(header.e_shoff + header.e_shentsize * i);
        readSectionHeader(in, section.header);

        if ((section.header.sh_type == SHT_NOBITS) || !section.header.sh_size) {
            continue;
        }

        // Read section data
        if (section.header.sh_flags & SHF_DEFLATED) {
            in.seek(section.header.sh_offset);

            // First 4 bytes are the original size
            uint32_t originalSize;
            in.read(originalSize);
            
            // Read the rest of the data which is deflated
            std::vector<char> data;
            data.resize(section.header.sh_size - 4);
            in.read(data.data(), data.size());

            // Inflate into the section data
            section.data.resize(originalSize);
            size_t decompSize = tinfl_decompress_mem_to_mem(section.data.data(), section.data.size(), data.data(), data.size(), TINFL_FLAG_PARSE_ZLIB_HEADER);

            msg("Decompressing Section %d: %d -> %d (expected %d)\n", i, data.size(), decompSize, originalSize);

            if (decompSize != originalSize) {
                section.data.clear();
            }
        } else {
            section.data.resize(section.header.sh_size);
            in.seek(section.header.sh_offset);
            in.read(section.data.data(), section.header.sh_size);
        }
    }

    return true;
}

//--------------------------------------------------------------------------
int idaapi accept_file(linput_t *li, char fileformatname[MAX_FILE_FORMAT_NAME], int n)
{
  if ( n )
    return 0;

  BigEndianView in(li);
  ElfHeader header;
  if (!readHeader(in, header)) {
      return 0;
  }

  qstrncpy(fileformatname, "RPX file", MAX_FILE_FORMAT_NAME);
  return ACCEPT_FIRST | 1;
}

struct RplSymbol {
    uint32_t index;
    uint16_t type;
    std::string name;
    uint32_t address;
};

struct RplModule {
    std::vector<RplSymbol> symbols;
};

static void
    processSymbols(RplModule &module, RplSection &symtab, std::vector<RplSection> &sections)
{
    BigEndianView in(symtab.data.data(), symtab.data.size());
    auto count = symtab.data.size() / sizeof(ElfSymbol);
    auto &strtab = sections[symtab.header.sh_link];

    for (auto i = 0u; i < count; ++i) {
        ElfSymbol header;
        readSymbol(in, header);

        auto name = strtab.data.data() + header.st_name;

        auto binding = header.st_info >> 4; // STB_*
        auto type = header.st_info & 0xf;   // STT_*

        msg("Symbol `%s` (value:%08x size:%08x info:%02x shndx:%04x\n", 
            name, header.st_value, header.st_size, header.st_info, header.st_shndx);

        RplSymbol symbol;
        symbol.index = i;
        symbol.name = name;
        symbol.type = type;
        symbol.address = 0x00000000;
        module.symbols.push_back(symbol);

        auto &section = sections[header.st_shndx];
        if (!section.libName.empty()) {
            section.imports.supset(header.st_value, name);
        }
    }
}

static void
    processRelocations(RplModule &module, RplSection &section, std::vector<RplSection> &sections)
{
    // TODO: Support more than one symbol section (symsec)
    auto symsec = sections[section.header.sh_link];
    auto in = BigEndianView(section.data.data(), section.data.size());
    auto count = section.data.size() / sizeof(ElfRela);

    // Find our relocation section addresses
    auto relsec = sections[section.header.sh_info];

    msg("Fixup Bits: %d\n", ph.high_fixup_bits);

    for (auto i = 0u; i < count; ++i) {
        ElfRela rela;
        readRelocationAddend(in, rela);

        auto index = rela.r_info >> 8;
        auto type = rela.r_info & 0xff;

        if (index >= module.symbols.size()) {
            loader_failure("Missing symbol");
        }
        auto &symbol = module.symbols[index];

        if (symbol.address == 0) {
            //loader_failure("Found relocation of unexpected type.");
        }

        uint32_t relocAddr = symbol.address + rela.r_addend;

        switch (type) {
        case R_PPC_ADDR32:
            patch_long(rela.r_offset, relocAddr);
            break;
        case R_PPC_ADDR16_LO:
            patch_word(rela.r_offset, relocAddr & 0xFFFF);
            break;
        case R_PPC_ADDR16_HI:
            patch_word(rela.r_offset, relocAddr >> 16);
            break;
        case R_PPC_ADDR16_HA:
            patch_word(rela.r_offset, (relocAddr + 0x8000) >> 16);
            break;
        case R_PPC_REL24:
            auto oval = get_original_long(rela.r_offset);
            patch_long(rela.r_offset, (oval & ~0x03fffffc) | ((relocAddr - rela.r_offset) & 0x03fffffc));
            break;
        }
    }
}

static RplSection*
    findSection(std::vector<RplSection> &sections, uint32_t ea)
{
    for (auto &section : sections) {
        if (ea >= section.header.sh_addr && ea < section.header.sh_addr + section.data.size()) {
            return &section;
        }
    }
    return nullptr;
}

//--------------------------------------------------------------------------
void idaapi load_file(linput_t *li, ushort _neflag, const char * /*fileformatname*/)
{
    BigEndianView in(li);
    
    if (ph.id != PLFM_PPC) {
        set_processor_type("ppc:PAIRED", SETPROC_ALL | SETPROC_FATAL);
    }

    ElfHeader header;
    if (!readHeader(in, header)) {
        loader_failure();
    }

    std::vector<RplSection> sections;
    if (!readSections(in, header, sections)) {
        loader_failure();
    }

    RplFileInfo info;
    loadFileInfo(info, sections);

    auto &strData = sections[header.e_shstrndx].data;

    uint32_t imp_offset = 0;
    uint32_t imp_size = 8 * 4096;

    for(auto section : sections) {
        char *sectionName = strData.data() + section.header.sh_name;

        msg("Loading Segment %s\n", sectionName);
        msg("  Address: %08x\n", section.header.sh_addr);
        msg("  Size: %x\n", section.data.size());
        msg("  Type: %08x\n", section.header.sh_type);
        msg("  Flags: %08x\n", section.header.sh_flags);
        msg("  Link: %08x\n", section.header.sh_link);
        msg("  Info: %08x\n", section.header.sh_info);
        msg("  AddrAlign: %08x\n", section.header.sh_addralign);
        msg("  EntSize: %08x\n", section.header.sh_entsize);

        if (section.header.sh_type == SHT_NULL) {
            continue;
        }

        // This logic seems a bit strange, but works for now!
        if (section.header.sh_type == SHT_PROGBITS && section.header.sh_flags & SHF_EXECINSTR) {
            auto section_end = section.header.sh_addr + section.data.size();
            if (imp_offset < section_end) {
                imp_offset = section_end;
            }
        }

        char *sectionClass = "";
        if (section.header.sh_type == SHT_NOBITS) {
            sectionClass = CLASS_BSS;
        } else if (section.header.sh_flags & SHF_EXECINSTR) {
            sectionClass = CLASS_CODE;
        } else {
            sectionClass = CLASS_DATA;
        }

        if (!(section.header.sh_flags & SHF_ALLOC)) {
            continue;
        }

        if (section.header.sh_type == SHT_NOBITS) {
            if (!add_segm(0, section.header.sh_addr, section.header.sh_addr+section.header.sh_size, sectionName, sectionClass)) {
                loader_failure();
            }
        } else {
            mem2base(section.data.data(), section.header.sh_addr, section.header.sh_addr+section.data.size(), -1);

            if (!add_segm(0, section.header.sh_addr, section.header.sh_addr+section.data.size(), sectionName, sectionClass)) {
                loader_failure();
            }
        }

        segment_t *s = getseg(section.header.sh_addr);
        
        set_segm_addressing(s, 1); //set 32 bit addressing

        s->defsr[0] = 0x00000000;
        s->defsr[1] = 0x00000000;
        s->defsr[2] = 0x00000000;
        s->defsr[3] = 0x00000000;
        s->defsr[4] = 0x00000000;
        s->defsr[5] = 0x00000000;
        s->defsr[6] = 0x00000000;

        s->perm = SEGPERM_READ;
        if (section.header.sh_flags & SHF_WRITE) {
            s->perm |= SEGPERM_WRITE;
        }
        if (section.header.sh_flags & SHF_EXECINSTR) {
            s->perm |= SEGPERM_EXEC;
        }

        if (section.header.sh_addralign == 0) {
            s->align = saAbs;
        } else if (section.header.sh_addralign == 1) {
            s->align = saRelByte;
        } else if (section.header.sh_addralign == 2) {
            s->align = saRelWord;
        } else if (section.header.sh_addralign == 4) {
            s->align = saRelDble;
        } else if (section.header.sh_addralign == 8) {
            s->align = saRelQword;
        } else if (section.header.sh_addralign == 16) {
            s->align = saRelPara;
        } else if (section.header.sh_addralign == 32) {
            s->align = saRel32Bytes;
        } else if (section.header.sh_addralign == 64) {
            s->align = saRel64Bytes;
        } else if (section.header.sh_addralign == 128) {
            s->align = saRel128Bytes;
        } else if (section.header.sh_addralign == 256) {
            s->align = saRelPage;
        } else if (section.header.sh_addralign == 512) {
            s->align = saRel512Bytes;
        } else if (section.header.sh_addralign == 1024) {
            s->align = saRel1024Bytes;
        } else if (section.header.sh_addralign == 2048) {
            s->align = saRel2048Bytes;
        } else if (section.header.sh_addralign == 4096) {
            s->align = saRel4K;
        } else {
            loader_failure("Unexpected section alignment %d", section.header.sh_addralign);
        }

        s->update();
    }
    
    create_filename_cmt();

    imp_offset = (imp_offset + 0x7) & ~0x7;

    if (!add_segm(0, imp_offset, imp_offset + imp_size, "plt.imports", CLASS_CODE)) {
        loader_failure();
    }

    segment_t *impseg = getseg(imp_offset);
    impseg->set_loader_segm(true);
    impseg->align = saRelQword;
    impseg->perm = SEGPERM_READ | SEGPERM_EXEC;
    impseg->defsr[0] = 0x00000000;
    impseg->defsr[1] = 0x00000000;
    impseg->defsr[2] = 0x00000000;
    impseg->defsr[3] = 0x00000000;
    impseg->defsr[4] = 0x00000000;
    impseg->defsr[5] = 0x00000000;
    impseg->defsr[6] = 0x00000000;
    impseg->update();

    RplModule module;

    for (auto i = 0u; i < sections.size(); ++i) {
        auto &section = sections[i];

        if (section.header.sh_type != SHT_RPL_IMPORTS) {
            continue;
        }

        auto iinfo = (RplImportInfo*)section.data.data();
        auto importName = (char*)iinfo->data;

        section.libName = importName;
        section.imports.create();
    }

    for (auto i = 0u; i < sections.size(); ++i) {
        auto &section = sections[i];

        if (section.header.sh_type != SHT_SYMTAB) {
            continue;
        }

        msg("Processing symbols in segment %d\n", i);
        processSymbols(module, section, sections);
    }

    for (auto i = 0u; i < sections.size(); ++i) {
        auto &section = sections[i];

        if (section.header.sh_type != SHT_RPL_IMPORTS) {
            continue;
        }

        import_module(section.libName.c_str(), NULL, section.imports, NULL, "wiiu");
    }

    uint32_t extern_idx = 0;
    for (auto &symbol : module.symbols) {
        if (symbol.type == STT_FUNC) {
            symbol.address = imp_offset + 8 * extern_idx++;

            std::string idaSymName = std::string(FUNC_IMPORT_PREFIX) + symbol.name;
            do_name_anyway(symbol.address, idaSymName.c_str(), 0);

            auto_make_code(symbol.address+0);
            auto_make_code(symbol.address+4);

            set_offset(symbol.address, 0, 0);
        } else if (symbol.type == STT_OBJECT) {
            symbol.address = imp_offset + 8 * extern_idx++;
            
            std::string idaSymName = std::string(FUNC_IMPORT_PREFIX) + symbol.name;
            do_name_anyway(symbol.address, idaSymName.c_str(), 0);

            doDwrd(symbol.address+0, 4);
            doDwrd(symbol.address+4, 4);

            set_offset(symbol.address, 0, 0);
        }
    }

    for (auto i = 0u; i < sections.size(); ++i) {
        auto &section = sections[i];

        if (section.header.sh_type != SHT_RELA) {
            continue;
        }

        msg("Processing relocation in segment %d\n", i);
        processRelocations(module, section, sections);
    }

    add_entry(header.e_entry, header.e_entry, "start", true);
    
}

//--------------------------------------------------------------------------
loader_t LDSC =
{
  IDP_INTERFACE_VERSION,
  LDRF_RELOAD,               // loader flags
//
//      check input file format. if recognized, then return 1
//      and fill 'fileformatname'.
//      otherwise return 0
//
  accept_file,
//
//      load file into the database.
//
  load_file,
//
//      create output file from the database.
//      this function may be absent.
//
  NULL,
  NULL
};
