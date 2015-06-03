#ifndef LIBDLBIND_ELFPROTO_H_
#define LIBDLBIND_ELFPROTO_H

#include <stdlib.h>

#define DT_LD_TEXTBUMP 0x6ffffee0
#define DT_LD_RODATABUMP 0x6ffffee1
#define DT_LD_DATABUMP 0x6ffffee2
#define DT_LD_DYNSTRBUMP 0x6ffffee3
#define DT_LD_DYNSYMBUMP 0x6ffffee4

#ifndef MAX_SYMS
#define MAX_SYMS 65536
#endif

#ifndef NBUCKET
#define NBUCKET 2048
#endif

#ifdef __cplusplus
extern "C" {
#endif
extern size_t _ld_elfproto_stored_sz;
extern size_t _ld_elfproto_memsz;
extern void *_ld_elfproto_begin;
#ifdef __cplusplus
}
#endif

#endif
