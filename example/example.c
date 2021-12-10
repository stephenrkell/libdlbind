#include <stddef.h>
#include <sys/types.h>
#include "raw-syscalls-defs.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <dlfcn.h>
#include <assert.h>
#include <alloca.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "librunt.h"
#include "dlbind.h"
#include "systrap.h"
#include "relf.h"

// HACK for TEXT_WRITABLE_VADDR_DELTA
#include "../src/dlbind_internal.h"

int get_42(void)
{
	return 42;
}
void end_of_get_42(void) {}

// FIXME: should not be hidden?
extern __thread const char *dlbind_open_active_on __attribute__((visibility("hidden")));

void mmap_replacement(struct generic_syscall *s, post_handler *post) __attribute__((visibility("hidden")));
void mmap_replacement(struct generic_syscall *s, post_handler *post)
{
	/* Unpack the mmap arguments. */
	void *addr = (void*) s->args[0];
	size_t length = s->args[1];
	int prot = s->args[2];
	int flags = s->args[3];
	int fd = s->args[4];
	off_t offset = s->args[5];
	if (dlbind_open_active_on)
	{
		flags &= ~(0x3 /*MAP_SHARED|MAP_PRIVATE*/);
		flags |= 0x1 /* MAP_SHARED */;
	}
	void *ret = raw_mmap(addr, length, prot, flags, fd, offset);
	/* Do the post-handling and resume. */
	post(s, (long) ret, 1);
}

void openat_replacement(struct generic_syscall *s, post_handler *post) __attribute__((visibility("hidden")));
void openat_replacement(struct generic_syscall *s, post_handler *post)
{
	/* Unpack the arguments */
	int dirfd = (int) s->args[0];
	const char *path = (const char *) s->args[1];
	int flags = s->args[2];
	mode_t mode = s->args[3];

	if (dlbind_open_active_on)
	{
		flags &= ~(O_RDWR|O_RDONLY);
		flags |= O_RDWR;
	}
	int ret = raw_openat(dirfd, path, flags, mode);

	/* Do the post-handling and resume. */
	post(s, ret, 1);
}

static void trap_ldso_mappings(void)
{
	/* To trap the text segment of the ld.so, we get its phdrs
	 * from auxv. */
	__runt_auxv_init();
	const ElfW(auxv_t) *p_auxv;
	ElfW(auxv_t) *p_auxv_end;
	int ret = __runt_auxv_get_auxv(&p_auxv, &p_auxv_end);
	if (!ret) abort();
	// we'll want shdrs -- hmm; get the interpreter name
	ElfW(Phdr) *prog_phdr = (void*) auxv_lookup((ElfW(auxv_t) *) p_auxv, AT_PHDR)->a_un.a_val;
	unsigned prog_phnum = (unsigned long) auxv_lookup((ElfW(auxv_t) *) p_auxv, AT_PHNUM)->a_un.a_val;
	// first we need the program's load address
	uintptr_t load_addr = (uintptr_t) -1;
	for (unsigned i = 0; i < prog_phnum; ++i)
	{
		if (prog_phdr[i].p_type == PT_PHDR)
		{
			load_addr = (uintptr_t) prog_phdr - prog_phdr[i].p_vaddr;
			break;
		}
	}
	if (load_addr == (uintptr_t) -1) abort();
	char *buf = NULL;
	// now we get get the interp name
	for (unsigned i = 0; i < prog_phnum; ++i)
	{
		if (prog_phdr[i].p_type == PT_INTERP)
		{
			buf = alloca(prog_phdr[i].p_filesz);
			memcpy(buf, (void*) (load_addr + prog_phdr[i].p_vaddr), prog_phdr[i].p_filesz);
		}
	}
	if (buf == NULL) abort();
	// now we can open the file and snarf the shdrs
	int fd = open(buf, O_RDONLY);
	assert(fd != -1);
	struct stat s;
	ret = fstat(fd, &s);
	assert(ret == 0);
	unsigned long mapping_len = PAGE_SIZE * ((s.st_size + (PAGE_SIZE-1)) / PAGE_SIZE);
	void *mapping = mmap(NULL, mapping_len, PROT_READ, MAP_PRIVATE, fd, 0);
	assert(mapping != (void*) -1);
	void *ldso_base = (void*) auxv_lookup((ElfW(auxv_t) *) p_auxv, AT_BASE)->a_un.a_val;
	ElfW(Ehdr) *ehdr = ldso_base;
	// finally can we get its phdrs?
	ElfW(Phdr) *phdr = (void*)(((uintptr_t) ldso_base) + ehdr->e_phoff);
	printf("first phdr has type %d\n", phdr->p_type);
	for (unsigned i = 0; i < ehdr->e_phnum; ++i)
	{
		if (phdr[i].p_type == PT_LOAD &&
				phdr[i].p_flags & PF_X)
		{
			/* ... and we have the shdrs? */
			trap_one_executable_region_given_shdrs(
				ldso_base + phdr[i].p_vaddr,
				ldso_base + phdr[i].p_vaddr + phdr[i].p_memsz,
				"/lib64/ld-linux-x86-64.so.2" /* HACK */,
				/* is_writable */ phdr[i].p_flags & PF_W, /* is_readable */ phdr[i].p_flags & PF_R,
				(void*)(((uintptr_t) mapping) + ehdr->e_shoff), ehdr->e_shnum, (uintptr_t) ldso_base);
		}
	}
	munmap(mapping, mapping_len);
	close(fd);
}

int main(void)
{
	/* As well as doing our libdlbind stuff, we have to use libsystrap
	 * to
	 * - install sigill handler
	 * - set traps in ld.so
	 * - install a handler for mmap that does s/MAP_PRIVATE/MAP_SHARED/
	 * - install a handler for open that does s/O_RDONLY/O_RDWR/
	 */
	replaced_syscalls[__NR_mmap] = mmap_replacement;
	replaced_syscalls[__NR_openat] = openat_replacement;
	install_sigill_handler();
	trap_ldso_mappings();

	// create libfoo
	void *l = dlcreate("foo");

	// get some memory
	size_t len = (char*)end_of_get_42 - (char*)get_42;
	const char *alloc = dlalloc(l, len, SHF_EXECINSTR);
	assert(alloc);

	// copy our function into it
	// get a writable alias of the memory
	char *writable_alloc = /*dl_find_alias_with(SHF_READ|SHF_WRITE, alloc, l) */
		(char*)((uintptr_t) alloc + TEXT_WRITABLE_VADDR_DELTA); // HACK
	memcpy(writable_alloc, get_42, len);
	
	// FIXME: reinstate a realloc call: *reallocate* to the smaller size (was 200)
	// dlrealloc(l, alloc, len);

	// FIXME: this test case doesn't work! libdlbind only works within liballocs
	// where we can hook open() calls and change MAP_PRIVATE to MAP_SHARED.
	// Perhaps we can make libsystrap a dependency of libdlbind?
	
	// bind it
	void *reloaded = dlbind(l, "meaning", (void*)alloc, len, STT_FUNC);
	assert(reloaded == l);
	
	struct link_map *m = (struct link_map *) l;
	// before we dlsym our function, sysv_hash_lookup it
	ElfW(Word) *sysv_hash = get_sysv_hash_from_dyn(m->l_ld, m->l_addr);
	ElfW(Sym) *symtab = get_dynsym_from_dyn(m->l_ld, m->l_addr);
	if (!symtab) return 0;
	ElfW(Sym) *symtab_end = symtab + dynamic_symbol_count_from_dyn(m->l_ld, m->l_addr);
	unsigned char *strtab = get_dynstr_from_dyn(m->l_ld, m->l_addr);
	unsigned char *strtab_end = strtab + dynamic_xlookup(m->l_ld, DT_STRSZ)->d_un.d_val;
	assert(sysv_hash);
	ElfW(Sym) *found = /*sysv_*/hash_lookup(sysv_hash, symtab, strtab, "meaning");
	assert(found);

	// dlsym our function
	int (*func)(void) = (int(*)(void)) dlsym(l, "meaning");
	assert(func);

	// call it
	int v = func();
	printf("libdlbind-loaded function returned: %d\n", v);

	// FIXME: reinstate a dldelete call.
	// dldelete
	// dldelete(l);
	
	return 0;
}
