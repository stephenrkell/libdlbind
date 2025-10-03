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
#include <sys/statvfs.h>
#include <err.h>
#include "elfproto.h"
#include "symhash.h"
#include "dlbind.h"
#include "dlbind_internal.h"
#include "relf.h"

char *strdup(const char *s); /* why is <string.h> not good enough for this? */

/* Out-of-band signalling for detecting dlopening. */
__thread const char *dlbind_open_active_on __attribute__((visibility("hidden")));
/* Remove this once weak thread-locals actually work! */
int dlbind_dummy __attribute__((visibility("hidden")));

static void do_reload(void *h);

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
			// not allowed -- use multiple mappings
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
			return (void*)((uintptr_t) l->l_addr + ret);
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

	/* Sometimes .dynamic entries are relocated, sometimes they're not.
	 * FIXME: understand when this does and doesn't happen.
	 * FIXME: seems to be a risk of double-relocation if we do the reloc ourselves.
	 * Let's try it anyway.
	 */
#define FIXUP_PTR(p, base) \
	((uintptr_t) (p) > (uintptr_t) (base) \
		? (void*)(p) \
		: (void*)((*((uintptr_t *) &(p)) = ((uintptr_t)(base) + (uintptr_t)(p)))))

	unsigned strind = dynstr_bump_ent->d_un.d_val;
	char *dynstr_insertion_pt = (char*) FIXUP_PTR(found_dynstr_ent->d_un.d_ptr, l->l_addr) + strind;
	unsigned symind = dynsym_bump_ent->d_un.d_val;
	Elf64_Sym *dynsym_insertion_pt = (Elf64_Sym *) FIXUP_PTR(found_dynsym_ent->d_un.d_ptr, l->l_addr)
			+ symind;
	strcpy(dynstr_insertion_pt, symname);
	dynstr_bump_ent->d_un.d_val += strlen(symname) + 1;

	Elf64_Sym *shdr_sym = elf64_hash_get(
		(char*) FIXUP_PTR(found_hash_ent->d_un.d_ptr, l->l_addr),
		(2 + NBUCKET + MAX_SYMS) * sizeof (Elf64_Word),
		NBUCKET,
		MAX_SYMS,
		(Elf64_Sym*) FIXUP_PTR(found_dynsym_ent->d_un.d_ptr, l->l_addr),
		(char*) FIXUP_PTR(found_dynstr_ent->d_un.d_ptr, l->l_addr),
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
		char *shdr_addr = (char*) l->l_addr + i_shdr->sh_addr;
		if (shdr_addr <= (char*) obj
			&& (!preceding_shdr || shdr_addr > (char*) l->l_addr + preceding_shdr->sh_addr))
		{
			preceding_shdr = i_shdr;
		}
	}
	*dynsym_insertion_pt = (Elf64_Sym) {
		.st_name = strind,
		.st_info = ELF64_ST_INFO(STB_GLOBAL, type),
		.st_other = ELF64_ST_VISIBILITY(STV_DEFAULT),
		.st_shndx = preceding_shdr ? (preceding_shdr - shdr) : SHN_ABS,
		.st_value = preceding_shdr ? (uintptr_t) obj - (uintptr_t) l->l_addr : (uintptr_t) obj,
		.st_size = len
	};
	dynsym_bump_ent->d_un.d_val--;
	elf64_hash_put(
		(char*) FIXUP_PTR(found_hash_ent->d_un.d_ptr, l->l_addr),    /* hash section */
		(2 + NBUCKET + MAX_SYMS) * sizeof (Elf64_Word), /* hash section size in bytes */
		NBUCKET,                       /* nbucket -- must match existing section! */
		MAX_SYMS,                      /* symbol table entry count */
		(Elf64_Sym*) FIXUP_PTR(found_dynsym_ent->d_un.d_ptr, l->l_addr),  /* symbol table */
		(char*) FIXUP_PTR(found_dynstr_ent->d_un.d_ptr, l->l_addr),
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

	do_reload(l);
	return l; // dlreload(l);
}

extern void _dl_debug_state(void);

static
void do_reload(void *h)
{
	/* Unless FAKE_RELOAD is defined, we really do (potentially)
	 * unload and reload the object. This is the easiest for
	 * debuggers to grok. But it potentially moves the object,
	 * which is bad for clients.
	 * If FAKE_RELOAD is defined, we instead remove it from
 	 * the link map (behind the ld.so's back), call the r_brk
	 * function, then relink it. This will not move the object,
	 * but I think I never got it working as intended with gdb. */
	struct link_map *l = (struct link_map *) h;
	void *old_load_addr = (void*) l->l_addr;
	char *copied = strdup(l->l_name);

	/* Un-relocate any relocations applied by ld.so.
	 * We didn't create any relocation records, so we are mostly okay.
	 * BUT ld.so also relocates certain d_ptr values in the .dynamic section.
	 * So undo that bit. */
#ifndef FAKE_RELOAD
	Elf64_Dyn *found_dynsym_ent = dynamic_lookup(l->l_ld, DT_SYMTAB);
	if ((char*) found_dynsym_ent->d_un.d_ptr >= (char*) l->l_addr)
	{
		found_dynsym_ent->d_un.d_ptr -= (uintptr_t) l->l_addr;
	}
	Elf64_Dyn *found_dynstr_ent = dynamic_lookup(l->l_ld, DT_STRTAB);
	if ((char*) found_dynstr_ent->d_un.d_ptr >= (char*) l->l_addr)
	{
		found_dynstr_ent->d_un.d_ptr -= (uintptr_t) l->l_addr;
	}
	Elf64_Dyn *found_hash_ent = dynamic_lookup(l->l_ld, DT_HASH);
	if ((char*) found_hash_ent->d_un.d_ptr >= (char*) l->l_addr)
	{
		found_hash_ent->d_un.d_ptr -= (uintptr_t) l->l_addr;
	}
	Elf64_Dyn *found_rela_ent = dynamic_lookup(l->l_ld, DT_RELA);
	if ((char*) found_rela_ent->d_un.d_ptr >= (char*) l->l_addr)
	{
		found_rela_ent->d_un.d_ptr -= (uintptr_t) l->l_addr;
	}
	int failed = dlclose(l);
	_Bool still_loaded = 0;
	/* We might not actually have been unloaded. In particular, if we have dlsym()'d
	 * any of the contents of the object, ld.so remembers the "dependency" and can
	 * mark our object as RTLD_NODELETE. So check whether we were really unloaded,
	 * and if not, undo the un-relocation we just did, because the next dlopen will
	 * NOT go through the relocation step. FIXME: this is racy. */
	if (!failed) for (struct link_map *test_l = _r_debug.r_map; test_l; test_l = test_l->l_next)
	{
		if (l == test_l)
		{
			/* We didn't actually get unloaded. */
			still_loaded = 1;
		}
	}
	if (failed || still_loaded)
	{
		/* Okay. Undo the un-relocation. */
		if ((char*) found_dynsym_ent->d_un.d_ptr < (char*) l->l_addr)
		{
			found_dynsym_ent->d_un.d_ptr += (uintptr_t) l->l_addr;
		}
		Elf64_Dyn *found_dynstr_ent = dynamic_lookup(l->l_ld, DT_STRTAB);
		if ((char*) found_dynstr_ent->d_un.d_ptr < (char*) l->l_addr)
		{
			found_dynstr_ent->d_un.d_ptr += (uintptr_t) l->l_addr;
		}
		Elf64_Dyn *found_hash_ent = dynamic_lookup(l->l_ld, DT_HASH);
		if ((char*) found_hash_ent->d_un.d_ptr < (char*) l->l_addr)
		{
			found_hash_ent->d_un.d_ptr += (uintptr_t) l->l_addr;
		}
		Elf64_Dyn *found_rela_ent = dynamic_lookup(l->l_ld, DT_RELA);
		if ((char*) found_rela_ent->d_un.d_ptr < (char*) l->l_addr)
		{
			found_rela_ent->d_un.d_ptr += (uintptr_t) l->l_addr;
		}
	}
	dlbind_open_active_on = copied;
	void *new_handle = dlopen(copied, RTLD_NOW | RTLD_GLOBAL /*| RTLD_NODELETE*/);
	dlbind_open_active_on = NULL;
	assert(new_handle);
#else /* FAKE_RELOAD */
	struct link_map *old_handle = l;
	void *new_handle = old_handle;
	void (*r_brk)(void) = (void*) find_r_debug()->r_brk;

	/* Temporarily remove it from the linked list and signal to the debugger.
	 * HACK: this is racy. */
	if (old_handle->l_prev) old_handle->l_prev->l_next = old_handle->l_next;
	if (old_handle->l_next) old_handle->l_next->l_prev = old_handle->l_prev;
	r_brk();
	/* Now put it back and signal again. HACK again. */
	if (old_handle->l_prev) old_handle->l_prev->l_next = old_handle;
	if (old_handle->l_next) old_handle->l_next->l_prev = old_handle;
	r_brk();
#endif
	/* It's important we get the old load address back. */
	assert((void*) ((struct link_map *) new_handle)->l_addr == (old_load_addr));
	free(copied);
	// return new_handle;
}

static _Bool path_is_viable(const char *path)
{
	_Bool can_access = (0 == access(path, R_OK|W_OK|X_OK));
	if (!can_access) return 0;
	struct statvfs buf;
	int ret = statvfs(path, &buf);
	if (ret != 0) return 0;
	if (buf.f_flag & ST_RDONLY) return 0;
	if (buf.f_flag & ST_NOEXEC) return 0;
	return 1;
}

#define DLCREATE_MAX 16
static unsigned next_free_unlink_entry;
static const char *unlink_list[DLCREATE_MAX];

void *dlcreate_with_mmap(const char *libname, void*(*mmap)(void */*addr*/, size_t /*length*/,
   int /*prot*/, int /*flags*/, int /*fd*/, off_t /*offset*/))
{
	if (next_free_unlink_entry == DLCREATE_MAX) return NULL;
	// FIXME: proper error handling in this function (and file) please
	// FIXME: pay attention to libname
	/* Create a file, truncate it, mmap it */
	// FIXME: use POSIX shared-memory interface with some pretence at portability
	char filename0[] = "/run/shm/tmp.dlbind.XXXXXX";
	char filename1[] = "/tmp/tmp.dlbind.XXXXXX";
	char *filename = path_is_viable("/run/shm/.") ? filename0 : filename1;
	int fd = mkostemp(filename, O_RDWR|O_CREAT);
	if (fd == -1) err(1, "mkostemp(\"%s\", O_RDWR|O_CREAT)", filename);
	unlink_list[next_free_unlink_entry++] = strdup(filename);
	/* Truncate the file to the necessary size */
	int ret = ftruncate(fd, _dlbind_elfproto_memsz);
	if (ret != 0) err(1, "truncating %s to %ld bytes", filename, _dlbind_elfproto_memsz);
	/* The relatively large mapping is a problem for the liballocs + ecfs use case,
	 * because we get many extraneous megabytes in our coredump. Perhaps we can
	 * supply an alternative mmap function here? */
	void *addr = mmap(NULL, _dlbind_elfproto_memsz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) err(1, "mapping %s", filename);
	/* Copy in the ELF proto contents. We don't need to copy the actual sections
	 * area, which should all be zero. And be even more clever about sparseness,
	 * since large parts of the  dynsym and dynstr are initially zeroed too. */
	memcpy_elfproto_to(addr);
	munmap(addr, _dlbind_elfproto_memsz);
	/* dlopen the file */
	char *proc_filename = NULL;
	struct link_map *handle = NULL;
	ret = asprintf(&proc_filename, "/proc/%d/fd/%d", getpid(), fd);
	if (ret <= 0) goto out;
	assert(proc_filename != NULL);
	dlbind_open_active_on = proc_filename;
	handle = dlopen(proc_filename, RTLD_NOW | RTLD_GLOBAL/* | RTLD_NODELETE*/);
	dlbind_open_active_on = NULL;
	unlink(filename);
	/* At this point, the fd remains open but the file is unlinked. Cleanup
	 * problem solved! We can still access it through the magic /proc symlink.
	 * And so can the debugger! FIXME: this is too Linux-specific for my liking.
	 * FIXME: do the close() in dldelete(), rather than having it hang around
	 * until the process exits. */
out:
	if (!handle) { close(fd); err(1, "dlopening %s (really %s)", filename, proc_filename); }
	if (proc_filename) free(proc_filename);
	return handle;
}

void *dlcreate(const char *libname)
{
	return dlcreate_with_mmap(libname, mmap);
}
