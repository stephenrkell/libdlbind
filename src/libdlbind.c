#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <string.h>
#include <link.h>
#include <unistd.h>
#include "elfproto.h"
#include "symhash.h"
#include "dlbind.h"
#include "relf.h"

char *strdup(const char *s); /* why is <string.h> not good enough for this? */

/* Out-of-band signalling for detecting dlopening. */
__thread const char *dlbind_open_active_on __attribute__((visibility("hidden")));
/* Remove this once weak thread-locals actually work! */
int dlbind_dummy __attribute__((visibility("hidden")));

/* Allocate a chunk of space in the file. */
void *dlalloc(void *handle, size_t sz, unsigned flags)
{
	struct link_map *l = handle;
	Elf64_Sxword dt_bump;
	switch (flags & (SHF_WRITE|SHF_EXECINSTR))
	{
		case SHF_WRITE:
			// use .data
			dt_bump = DT_DLBIND_DATABUMP;
			break;
		case SHF_EXECINSTR:
			// use .text:
			dt_bump = DT_DLBIND_TEXTBUMP;
			break;
		
		case (SHF_WRITE|SHF_EXECINSTR):
			// not allowed -- use 
			return NULL;
		
		case 0:
			// use .rodata:
			dt_bump = DT_DLBIND_RODATABUMP;
			break;
		
		default:
			return NULL;
	}
	
	
	for (Elf64_Dyn *d = (Elf64_Dyn*) l->l_ld; d->d_tag != DT_NULL; ++d)
	{
		if (d->d_tag == dt_bump)
		{
			void *ret = (char*) d->d_un.d_ptr;
			*((char**) &d->d_un.d_ptr) += sz;
			return (void*)(l->l_addr + ret);
		}
	}
	
	return NULL;
}

/* Create a new symbol binding within a library created using dlnew().
 * The varargs may be used to specify the namespace, calling convention
 * and version string. Note that these need only be meaningful for text
 * symbols. Whether the object belongs in text, data or rodata is inferred
 * from the flags of the memory object containing address obj. */
void *dlbind(void *lib, const char *symname, void *obj, size_t len, ElfW(Word) type)
{
	struct link_map *l = (struct link_map *) lib;
	Elf64_Dyn *found_dynsym_ent = dynamic_lookup(l->l_ld, DT_SYMTAB);
	Elf64_Dyn *found_dynstr_ent = dynamic_lookup(l->l_ld, DT_STRTAB);
	Elf64_Dyn *found_hash_ent = dynamic_lookup(l->l_ld, DT_HASH);
	/* What's the next free global symbol index? */
	Elf64_Dyn *dynstr_bump_ent = dynamic_lookup(l->l_ld, DT_DLBIND_DYNSTRBUMP);
	Elf64_Dyn *dynsym_bump_ent = dynamic_lookup(l->l_ld, DT_DLBIND_DYNSYMBUMP);

	unsigned strind = dynstr_bump_ent->d_un.d_val;
	char *dynstr_insertion_pt = (char*) found_dynstr_ent->d_un.d_ptr 
			+ strind;
	unsigned symind = dynsym_bump_ent->d_un.d_val;
	Elf64_Sym *dynsym_insertion_pt = (Elf64_Sym *) found_dynsym_ent->d_un.d_ptr 
			+ symind;
	
	strcpy(dynstr_insertion_pt, symname);
	dynstr_bump_ent->d_un.d_val += strlen(symname) + 1;

	Elf64_Sym *shdr_sym = elf64_hash_get(
		(char*) found_hash_ent->d_un.d_ptr, 
		(2 + NBUCKET + MAX_SYMS) * sizeof (Elf64_Word),
		NBUCKET,
		MAX_SYMS,
		(Elf64_Sym*) found_dynsym_ent->d_un.d_ptr,
		(char*) found_dynstr_ent->d_un.d_ptr,
		"_SHDRS"
	);
	assert(shdr_sym);
	Elf64_Shdr *shdr = (Elf64_Shdr*) ((char*) l->l_addr + shdr_sym->st_value);
	assert(shdr == dlsym(lib, "_SHDRS"));
	if (!shdr) return NULL;
	
	unsigned n_shdrs = shdr_sym->st_size / sizeof (Elf64_Shdr);
	
	Elf64_Shdr *preceding_shdr = NULL;
	for (Elf64_Shdr *i_shdr = shdr; i_shdr < shdr + n_shdrs; ++i_shdr)
	{
		char *shdr_addr = (char*) l->l_addr + shdr->sh_addr;
		if (shdr_addr < (char*) obj
			&& (!preceding_shdr || shdr_addr > (char*) l->l_addr + preceding_shdr->sh_addr))
		{
			preceding_shdr = shdr;
		}
	}
	
	*dynsym_insertion_pt = (Elf64_Sym) { 
		.st_name = strind, 
		.st_info = ELF64_ST_INFO(STB_GLOBAL, type),
		.st_other = ELF64_ST_VISIBILITY(STV_DEFAULT),
		.st_shndx = preceding_shdr ? (preceding_shdr - shdr) : SHN_ABS,
		.st_value = preceding_shdr ? (uintptr_t) obj - l->l_addr : (uintptr_t) obj,
		.st_size = len
	};
	dynsym_bump_ent->d_un.d_val--;
	
	elf64_hash_put(
		(char*) found_hash_ent->d_un.d_ptr,    /* hash section */
		(2 + NBUCKET + MAX_SYMS) * sizeof (Elf64_Word), /* hash section size in bytes */
		NBUCKET,                       /* nbucket -- must match existing section! */
		MAX_SYMS,                      /* symbol table entry count */
		(Elf64_Sym*) found_dynsym_ent->d_un.d_ptr,  /* symbol table */
		(char*) found_dynstr_ent->d_un.d_ptr,
		symind           /* assume this symind was unused previously! */
	);

// 	Elf64_Shdr *shdr = dlsym(lib, "_SHDRS");
// 	if (!shdr) return -1;
// 	Elf64_Dyn *found_dynsym_ent = dynamic_lookup(dynamic, DT_SYMTAB);
// 	if (!found_dynsym_ent) return -3;
// 	Elf64_Dyn *found_hash_ent = dynamic_lookup(dynamic, DT_HASH);
// 	if (!found_hash_ent) return -4;
// 	
// 	/* Walk the shdrs until we find the dynsym */
// 	while (shdr->sh_vaddr != found_dynsym_ent->d_un.d_ptr) ++shdr;
// 	// FIXME: check for end somehow -- maybe _SHDRS symbol size info
// 	
// 	unsigned nlocal = shdr->sh_info;
	
	return dlreload(l);
}

extern void _dl_debug_state(void);

void *dlreload(void *h)
{
	struct link_map *l = (struct link_map *) h;
	char *copied = strdup(l->l_name);
	
	/* Un-relocate any relocations applied by ld.so. 
	 * We didn't create any relocation records, so we are mostly okay. 
	 * BUT ld.so also relocates certain d_ptr values in the .dynamic section. 
	 * So undo that bit. */
	Elf64_Dyn *found_dynsym_ent = dynamic_lookup(l->l_ld, DT_SYMTAB);
	if ((char*) found_dynsym_ent->d_un.d_ptr >= (char*) l->l_addr)
	{
		found_dynsym_ent->d_un.d_ptr -= l->l_addr;
	}
	Elf64_Dyn *found_dynstr_ent = dynamic_lookup(l->l_ld, DT_STRTAB);
	if ((char*) found_dynstr_ent->d_un.d_ptr >= (char*) l->l_addr)
	{
		found_dynstr_ent->d_un.d_ptr -= l->l_addr; 
	}
	Elf64_Dyn *found_hash_ent = dynamic_lookup(l->l_ld, DT_HASH);
	if ((char*) found_hash_ent->d_un.d_ptr >= (char*) l->l_addr)
	{
		found_hash_ent->d_un.d_ptr -= l->l_addr; 
	}
	Elf64_Dyn *found_rela_ent = dynamic_lookup(l->l_ld, DT_RELA);
	if ((char*) found_rela_ent->d_un.d_ptr >= (char*) l->l_addr)
	{
		found_rela_ent->d_un.d_ptr -= l->l_addr; 
	}
	dlclose(l);
	
	// void *r_brk = find_r_debug()->r_brk;

	/* signal to the debugger */
	// ((void(*)(void)) r_brk)();
	
	dlbind_open_active_on = copied;
	void *new_handle = dlopen(copied, RTLD_NOW | RTLD_GLOBAL /*| RTLD_NODELETE*/);
	dlbind_open_active_on = NULL;
	assert(new_handle);
	
	/* signal to the debugger */
	// ((void(*)(void)) r_brk)();
	
	free(copied);
	return new_handle;
}

void *dlcreate(const char *libname)
{
	// FIXME: pay attention to libname
	/* Create a file, truncate it, mmap it */
	// FIXME: use POSIX shared-memory interface with some pretence at portability
	char filename0[] = "/run/shm/tmp.dlbind.XXXXXX";
	char filename1[] = "/tmp/tmp.dlbind.XXXXXX";
	char *filename = (0 == access("/run/shm", R_OK|W_OK|X_OK)) ? filename0 : filename1;
	int fd = mkostemp(&filename[0], O_RDWR|O_CREAT);
	assert(fd != -1);
	/* Truncate the file to the necessary size */
	int ret = ftruncate(fd, _dlbind_elfproto_memsz);
	assert(ret == 0);
	void *addr = mmap(NULL, _dlbind_elfproto_memsz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	assert(addr != MAP_FAILED);
	/* Copy in the ELF proto (FIXME: better sparseness) */
	memcpy(addr, _dlbind_elfproto_begin, _dlbind_elfproto_stored_sz);
	munmap(addr, _dlbind_elfproto_memsz);
	close(fd);
	/* dlopen the file */
	dlbind_open_active_on = filename;
	struct link_map *handle = dlopen(filename, RTLD_NOW | RTLD_GLOBAL/* | RTLD_NODELETE*/);
	dlbind_open_active_on = NULL;
	assert(handle);
	return handle;
}

