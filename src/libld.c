#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <string.h>
#include <link.h>
#include "elfproto.h"
#include "symhash.h"
#include "libld.h"

/* Allocate a chunk of space in the file. */
void *dlalloc(void *l, size_t sz, unsigned flags)
{
	unsigned long dt_bump;
	switch (flags & (SHF_WRITE|SHF_EXECINSTR))
	{
		case SHF_WRITE:
			// use .data
			dt_bump = DT_LD_DATABUMP;
			break;
		case SHF_EXECINSTR:
			// use .text:
			dt_bump = DT_LD_TEXTBUMP;
			break;
		
		case (SHF_WRITE|SHF_EXECINSTR):
			// not allowed -- use 
			return NULL;
		
		case 0:
			// use .rodata:
			dt_bump = DT_LD_RODATABUMP;
			break;
		
		default:
			return NULL;
	}
	
	Elf64_Dyn *d = (Elf64_Dyn*) l->l_ld;
	while (d->d_tag != DT_NULL)
	{
		if (d->d_tag == dt_bump)
		{
			void *ret = (char*) d->d_un.d_ptr;
			*((char**) &d->d_un.d_ptr) += sz;
			return ret;
		}
	}
	
	return NULL;
}

/* Create a new symbol binding within a library created using dlnew().
 * The varargs may be used to specify the namespace, calling convention
 * and version string. Note that these need only be meaningful for text
 * symbols. Whether the object belongs in text, data or rodata is inferred
 * from the flags of the memory object containing address obj. */
int dlbind(void *lib, const char *symname, void *obj, size_t len, ...)
{
	/* What's the next free global symbol index? */
}

void *dlnew(void)
{
	/* Create a file, truncate it, mmap it */
	char filename[] = "/tmp/tmp.libld.XXXXXX";
	int fd = mkostemp(&filename[0], O_RDWR|O_CREAT);
	assert(fd != -1);
	/* Truncate the file to the necessary size */
	int ret = ftruncate(fd, _ld_elfproto_memsz);
	assert(ret == 0);
	void *addr = mmap(NULL, _ld_elfproto_memsz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	assert(addr != MAP_FAILED);
	/* Copy in the ELF proto (FIXME: better sparseness) */
	memcpy(addr, _ld_elfproto_begin, _ld_elfproto_stored_sz);
	munmap(addr, _ld_elfproto_memsz);
	close(fd);
	/* dlopen the file */
	struct link_map *handle = dlopen(filename, RTLD_LAZY | RTLD_GLOBAL | RTLD_NODELETE);
	assert(handle);
	return handle;
}
