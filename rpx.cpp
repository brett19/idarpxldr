/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2001 by Ilfak Guilfanov (ig@datarescue.com)
 *                                              http://www.datarescue.com
 *      ALL RIGHTS RESERVED.
 *
 */

#include "../idaldr.h"
#include "elf.h"

//#define FAILED  do { msg(            "failed at %d (input file line %d)\n", __LINE__, nl); return 0; } while ( 0 )
#define FAILED  return deb(IDA_DEBUG_LDR,"failed at %d (input file line %d)\n", __LINE__, nl), 0

class BigEndianIdaView {
public:
    BigEndianIdaView(linput_t *li)
        : _li(li) {
    }

    template<typename T>
    int read(T &val) {
        return lreadbytes(_li, &val, sizeof(T), true);
    }

    int seek(int pos, int whence = 0) {
        return qlseek(_li, pos, whence);
    }

private:
    linput_t *_li;

};

//--------------------------------------------------------------------------
int idaapi accept_file(linput_t *li, char fileformatname[MAX_FILE_FORMAT_NAME], int n)
{
  char line[MAXSTR];
  char *words[MAXSTR];

  if ( n )
    return 0;

  BigEndianIdaView in(li);
  ElfHeader header;

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
      return 0;
  }
  if (header.e_class != ELFCLASS32) {
      return 0;
  }
  if (header.e_encoding != ELFDATA2MSB) {
      return 0;
  }
  if (header.e_abi != EABI_CAFE) {
      return 0;
  }
  if (header.e_machine != EM_PPC) {
      return 0;
  }
  if (header.e_elf_version != EV_CURRENT) {
      return 0;
  }

  qstrncpy(fileformatname, "RPX file", MAX_FILE_FORMAT_NAME);
  return ACCEPT_FIRST | 1;
}

//--------------------------------------------------------------------------
void idaapi load_file(linput_t *li, ushort _neflag, const char * /*fileformatname*/)
{
    mem2base(0, 0, 0, -1);

    if (!add_segm(0, 0, 0, NAME_CODE, CLASS_CODE)) {
        loader_failure();
    }
    
    create_filename_cmt();
    
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
