#ifndef LIBDLBIND_ELFPROTO_H_
#define LIBDLBIND_ELFPROTO_H_

#include <stdlib.h>

#define DT_DLBIND_TEXTBUMP 0x6ffffee0
#define DT_DLBIND_RODATABUMP 0x6ffffee1
#define DT_DLBIND_DATABUMP 0x6ffffee2
#define DT_DLBIND_DYNSTRBUMP 0x6ffffee3
#define DT_DLBIND_DYNSYMBUMP 0x6ffffee4

#ifndef MAX_SYMS
#define MAX_SYMS 65536
#endif

#ifndef NBUCKET
#define NBUCKET 2048
#endif

#ifdef __cplusplus
extern "C" {
#endif
extern size_t _dlbind_elfproto_headerscn_sz;
extern size_t _dlbind_elfproto_memsz;
extern void *_dlbind_elfproto_begin;
#ifdef __cplusplus
}
#endif

#endif
