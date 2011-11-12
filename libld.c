#define _GNU_SOURCE
#include <err.h>
#include <fcntl.h>
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <dlfcn.h>

#ifndef HAVE_ELF_SETSHSTRNDX
#define elf_setshstrndx(e, s) elfx_update_shstrndx((e), (s))
#endif

#include "libld.h"

const char greatest_version_arr[1] = { '\0' };
const char *greatest_version = &greatest_version_arr[0];

/* default parameters */
#ifndef LIBLD_MAX_CREATED_LIBRARIES 
#define LIBLD_MAX_CREATED_LIBRARIES 1
#endif
#ifndef LIBLD_STRTAB_SIZE
#define LIBLD_STRTAB_SIZE 4096
#endif
#ifndef LIBLD_SYMTAB_SIZE
#define LIBLD_SYMTAB_SIZE 4096
#endif
#ifndef LIBLD_TEXT_SIZE
#define LIBLD_TEXT_SIZE (16*4096)
#endif
#ifndef LIBLD_DATA_SIZE
#define LIBLD_DATA_SIZE 4096
#endif
#ifndef LIBLD_RODATA_SIZE
#define LIBLD_RODATA_SIZE 4096
#endif

static char basic_strtab[] = { 
	/* Offset 0 */ '\0',
	/* Offset 1 */ '.', 'f', 'o', 'o', '\0',
	/* Offset 6 */ '.', 's', 'h', 's', 't', 'r', 't', 'a', 'b', '\0',
	/* Offset 16 */ '.', 't', 'e', 'x', 't', '\0',
	/* Offset 22 */ '.', 'd', 'a', 't', 'a', '\0',
	/* Offset 28 */ '.', 'r', 'o', 'd', 'a', 't', 'a', '\0',
	/* Offset 36 */ '.', 'd', 'y', 'n', 's', 'y', 'm', '\0'
};
struct Ld_Entry
{
	int used;
	char filename[22] /* = "/tmp/tmp.libld.XXXXXX" */;
	int fd;
	Elf *elf;
	void *handle;
	
	char strtab[LIBLD_STRTAB_SIZE];
	unsigned strtab_insert_pos;
	Elf64_Half strtab_ndx;
	
	char text[LIBLD_TEXT_SIZE];
	unsigned text_insert_pos;
	Elf64_Half text_ndx;
	
	char data[LIBLD_DATA_SIZE];
	unsigned data_insert_pos;
	Elf64_Half data_ndx;

	char rodata[LIBLD_RODATA_SIZE];
	unsigned rodata_insert_pos;
	Elf64_Half rodata_ndx;
	
	char dynsym[LIBLD_SYMTAB_SIZE];
	unsigned dynsym_insert_pos;
	Elf64_Half dynsym_ndx;
} entries[LIBLD_MAX_CREATED_LIBRARIES];

uint64_t hash_words [] = {
	0x01234567,
	0x89abcdef,
	0xdeadc0de
};
void *libdl_handle(ld_handle_t lib)
{
	return lib->handle;
}

// static char basic_text[LIBLD_TEXT_SIZE];
// static char basic_data[LIBLD_DATA_SIZE];
// static char basic_rodata[LIBLD_RODATA_SIZE];
// static char basic_dynsym[LIBLD_SYMTAB_SIZE];

ld_handle_t dlnew(const char *libname)
{
	/* We create a temporary file, build an ELF file of fixed dimensions
	 * in it, and dlopen it with the magic flags. */
	int fd;
	Elf *e;
	Elf_Scn *scn;
	Elf_Data *data;
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;

	if (elf_version(EV_CURRENT) == EV_NONE) errx(EX_SOFTWARE, 
		"ELF library initialization failed: %s ", elf_errmsg(-1));

	/* allocate an entry record */
	struct Ld_Entry *ent = &entries[0];
	while (ent->used)
	{
		ent++;
		assert(ent < &entries[LIBLD_MAX_CREATED_LIBRARIES]);
	}
	/* populate the entry */
	strcpy(ent->filename, "/tmp/tmp.libld.XXXXXX");
	fd = mkostemp(ent->filename, O_RDWR|O_CREAT);
	assert(fd != -1 && "mkstemp failed");
	ent->used = 1;
	ent->fd = fd;
	memcpy(ent->strtab, basic_strtab, sizeof basic_strtab);
	ent->strtab_insert_pos = sizeof basic_strtab;
	
	/* begin file */
	if ((e = elf_begin(fd, ELF_C_WRITE /* 2 */, NULL)) == NULL) errx(EX_SOFTWARE, 
		"elf_begin() failed: %s.", elf_errmsg(-1));
	ent->elf = e;

	/* create ELF header */
	if ((ehdr = elf64_newehdr(e)) == NULL) errx(EX_SOFTWARE, 
		"elf64_newehdr() failed : %s.", elf_errmsg(-1));
	
	ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr->e_machine = EM_X86_64; /* 64-bit x86 object */
	ehdr->e_type = ET_DYN; /* shared object */

	/* create a phdr */
	if ((phdr = elf64_newphdr(e, 1)) == NULL) errx(EX_SOFTWARE,
		"elf64_newphdr() failed: %s.", elf_errmsg(-1));

	/* create a .hash section */
	if ((scn = elf_newscn (e)) == NULL) errx(EX_SOFTWARE, 
		"elf_newscn() failed: %s.", elf_errmsg(-1));
	/* create a data object for the .hash data */
	if ((data = elf_newdata(scn)) == NULL) errx (EX_SOFTWARE, 
		"elf_newdata() failed: %s.", elf_errmsg(-1));
	data->d_align = 4;
	data->d_off = 0LL;
	data->d_buf = hash_words; // will be copied by the library
	data->d_type = ELF_T_WORD;
	data->d_size = sizeof hash_words;
	data->d_version = EV_CURRENT;
	/* create a section header for .hash */
	if ((shdr = elf64_getshdr(scn)) == NULL) errx(EX_SOFTWARE, 
		"elf64_getshdr() failed :%s.", elf_errmsg(-1));
	shdr->sh_name = 1; /* offset 1 in */
	shdr->sh_type = SHT_HASH;
	shdr->sh_flags = SHF_ALLOC;
	shdr->sh_entsize = 0;

	/* create a section for strtab */
	if ((scn = elf_newscn(e)) == NULL) errx (EX_SOFTWARE, 
		"elf_newscn() failed : %s.", elf_errmsg(-1));
	/* create the strtab data */
	if ((data = elf_newdata(scn)) == NULL) errx(EX_SOFTWARE, 
		"elf_newdata() failed : %s.", elf_errmsg(-1));
	data->d_align = 1;
	data->d_buf = ent->strtab;
	data->d_off = 0LL;
	data->d_size = sizeof ent->strtab;
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;
	/*create the section header for strtab */
	if ((shdr = elf64_getshdr(scn)) == NULL) errx(EX_SOFTWARE, 
		"elf64_getshdr() failed: %s.", elf_errmsg(-1));
	shdr->sh_name = 6;
	shdr->sh_type = SHT_STRTAB;
	shdr->sh_flags = SHF_STRINGS|SHF_ALLOC;
	shdr->sh_entsize = 0;
	/* set the shrstr index */
	/* elf_setshstrndx(e, elf_ndxscn(scn)); */
	
	
	/* What other sections do we need to add?
	 * text, data, rodata. */
	/* create a .text section */
	if ((scn = elf_newscn (e)) == NULL) errx(EX_SOFTWARE, 
		"elf_newscn() failed: %s.", elf_errmsg(-1));
	/* create a data object for the .text data */
	if ((data = elf_newdata(scn)) == NULL) errx (EX_SOFTWARE, 
		"elf_newdata() failed: %s.", elf_errmsg(-1));
	data->d_align = 4;
	data->d_off = 0LL;
	data->d_buf = ent->text; // will be copied by the library
	data->d_type = ELF_T_BYTE;
	data->d_size = sizeof ent->text;
	data->d_version = EV_CURRENT;
	/* create a section header for .text */
	if ((shdr = elf64_getshdr(scn)) == NULL) errx(EX_SOFTWARE, 
		"elf64_getshdr() failed :%s.", elf_errmsg(-1));
	shdr->sh_name = 16; /* offset 16 in */
	shdr->sh_type = SHT_PROGBITS;
	shdr->sh_flags = SHF_ALLOC|SHF_EXECINSTR;
	shdr->sh_entsize = 0;
	
	ent->text_ndx = elf_ndxscn(scn);
	
	/* write data so far */
	if (elf_update(e, ELF_C_NULL) < 0) errx(EX_SOFTWARE, 
		"elf_update(NULL) failed: %s.",	elf_errmsg(-1));

	/* create a .data section */
	if ((scn = elf_newscn (e)) == NULL) errx(EX_SOFTWARE, 
		"elf_newscn() failed: %s.", elf_errmsg(-1));
	/* create a data object for the .text data */
	if ((data = elf_newdata(scn)) == NULL) errx (EX_SOFTWARE, 
		"elf_newdata() failed: %s.", elf_errmsg(-1));
	data->d_align = 4;
	data->d_off = 0LL;
	data->d_buf = ent->data; // will be copied by the library
	data->d_type = ELF_T_BYTE;
	data->d_size = sizeof ent->data;
	data->d_version = EV_CURRENT;
	/* create a section header for .data */
	if ((shdr = elf64_getshdr(scn)) == NULL) errx(EX_SOFTWARE, 
		"elf64_getshdr() failed :%s.", elf_errmsg(-1));
	shdr->sh_name = 22; /* offset 22 in */
	shdr->sh_type = SHT_PROGBITS;
	shdr->sh_flags = SHF_ALLOC|SHF_WRITE;
	shdr->sh_entsize = 0;
	
	ent->data_ndx = elf_ndxscn(scn);
	/* write data so far */
	if (elf_update(e, ELF_C_NULL) < 0) errx(EX_SOFTWARE, 
		"elf_update(NULL) failed: %s.",	elf_errmsg(-1));

	/* create a .rodata section */
	if ((scn = elf_newscn (e)) == NULL) errx(EX_SOFTWARE, 
		"elf_newscn() failed: %s.", elf_errmsg(-1));
	/* create a data object for the .text data */
	if ((data = elf_newdata(scn)) == NULL) errx (EX_SOFTWARE, 
		"elf_newdata() failed: %s.", elf_errmsg(-1));
	data->d_align = 4;
	data->d_off = 0LL;
	data->d_buf = ent->rodata; // will be copied by the library
	data->d_type = ELF_T_BYTE;
	data->d_size = sizeof ent->rodata;
	data->d_version = EV_CURRENT;
	/* create a section header for .rodata */
	if ((shdr = elf64_getshdr(scn)) == NULL) errx(EX_SOFTWARE, 
		"elf64_getshdr() failed :%s.", elf_errmsg(-1));
	shdr->sh_name = 28; /* offset 22 in */
	shdr->sh_type = SHT_PROGBITS;
	shdr->sh_flags = SHF_ALLOC;
	shdr->sh_entsize = 0;
	ent->rodata_ndx = elf_ndxscn(scn);
	/* write data so far */
	if (elf_update(e, ELF_C_NULL) < 0) errx(EX_SOFTWARE, 
		"elf_update(NULL) failed: %s.",	elf_errmsg(-1));
	
	/* we also need a dynsym */
	if ((scn = elf_newscn (e)) == NULL) errx(EX_SOFTWARE, 
		"elf_newscn() failed: %s.", elf_errmsg(-1));
	/* create a data object for the .text data */
	if ((data = elf_newdata(scn)) == NULL) errx (EX_SOFTWARE, 
		"elf_newdata() failed: %s.", elf_errmsg(-1));
	data->d_align = 4;
	data->d_off = 0LL;
	data->d_buf = ent->dynsym; // will be copied by the library
	data->d_type = ELF_T_SYM;
	data->d_size = sizeof ent->dynsym;
	data->d_version = EV_CURRENT;
	/* create a section header for .dynsym */
	if ((shdr = elf64_getshdr(scn)) == NULL) errx(EX_SOFTWARE, 
		"elf64_getshdr() failed :%s.", elf_errmsg(-1));
	shdr->sh_name = 28; /* offset 28 in */
	shdr->sh_type = SHT_DYNSYM;
	shdr->sh_flags = SHF_ALLOC;
	shdr->sh_entsize = sizeof (Elf64_Sym);
	ent->dynsym_ndx = elf_ndxscn(scn);
	/* write data so far */
	if (elf_update(e, ELF_C_NULL) < 0) errx(EX_SOFTWARE, 
		"elf_update(NULL) failed: %s.",	elf_errmsg(-1));
	
	/* populate the phdr */
	phdr->p_type = PT_PHDR;
	phdr->p_offset = ehdr->e_phoff;
	phdr->p_filesz = elf64_fsize(ELF_T_PHDR, 1, EV_CURRENT);
	(void) elf_flagphdr(e, ELF_C_SET, ELF_F_DIRTY);
	/* */
	if (elf_update(e, ELF_C_WRITE) < 0) errx(EX_SOFTWARE, 
		"elf_update() failed: %s.",	elf_errmsg(-1));
	
	/* end the file -- what happens if we don't do this? */
	/* (void) elf_end(e); */
	
	// we delay closing the fd until dldelete
	// but we do dlopen it!
	ent->handle = dlopen(ent->filename, RTLD_NOW|RTLD_LOCAL|RTLD_NODELETE);
	assert(ent->handle);
	return ent->handle;
}	

int dlbind(ld_handle_t lib, const char *symname, void *obj, size_t len, ...)
{
	/* We write more stuff to our temporary ELF file, and reopen it,
	 * exploiting the magic flags' behaviour.
	 * 
	 * Note that we don't need to create more sections. We just
	 * need to populate the sections we already have. But the result
	 * somehow has to get written back to the file. How to do this
	 * with libelf? */

	/* Start by updating the buffers with the new info. We need
	 * to update EITHER .data OR .rodata OR .text. 
	 * and BOTH strtab and dynsym.
	 
	 * HACK: assume text for now! */

	/* copy data */
	assert(lib->text_insert_pos + len < LIBLD_TEXT_SIZE);
	memcpy(lib->text + lib->text_insert_pos, obj, len);
	lib->text_insert_pos += len;
	
	/* add a string to the strtab */
	unsigned strtab_inserted_pos = lib->strtab_insert_pos;
	assert(lib->strtab_insert_pos + strlen(symname) + 1 < LIBLD_STRTAB_SIZE);
	strcpy(lib->strtab + lib->strtab_insert_pos, symname);
	lib->strtab_insert_pos += strlen(symname);
	lib->strtab[lib->strtab_insert_pos] = '\0';
	lib->strtab_insert_pos++;
	
	/* add a symbol to the dynsym */
	assert(lib->dynsym_insert_pos + sizeof (Elf64_Sym)< LIBLD_SYMTAB_SIZE);
	*(Elf64_Sym*)(lib->dynsym + lib->dynsym_insert_pos) = (Elf64_Sym) {
		  .st_name = strtab_inserted_pos,
		  .st_info = ELF64_ST_INFO(STT_FUNC, STB_GLOBAL),  /* Symbol type and binding */
		  .st_other = STV_DEFAULT,    /* Symbol visibility */
		  .st_shndx = lib->text_ndx,  /* Section index */
		  .st_value = (Elf64_Addr) obj, /* Symbol value */
		  .st_size = len              /* Symbol size */
	};
		  
	/* Now how do we update? Let's try... */
	Elf_Scn *scn;
	Elf_Data *data;
	Elf *e = lib->elf;

	/* create a section for strtab */
	if ((scn = elf_getscn(e, lib->strtab_ndx)) == NULL) errx (EX_SOFTWARE, 
		"elf_newscn() failed : %s.", elf_errmsg(-1));
	/* create the strtab data */
	if ((data = elf_getdata(scn, NULL)) == NULL) errx(EX_SOFTWARE, 
		"elf_newdata() failed : %s.", elf_errmsg(-1));
	data->d_buf = lib->strtab;
	
	/* .text */
	if ((scn = elf_getscn (e, lib->text_ndx)) == NULL) errx(EX_SOFTWARE, 
		"elf_newscn() failed: %s.", elf_errmsg(-1));
	/* create a data object for the .text data */
	if ((data = elf_getdata(scn, NULL)) == NULL) errx (EX_SOFTWARE, 
		"elf_newdata() failed: %s.", elf_errmsg(-1));
	data->d_buf = lib->text; // will be copied by the library

	/* .data section */
	if ((scn = elf_getscn (e, lib->data_ndx)) == NULL) errx(EX_SOFTWARE, 
		"elf_newscn() failed: %s.", elf_errmsg(-1));
	/* create a data object for the .text data */
	if ((data = elf_getdata(scn, NULL)) == NULL) errx (EX_SOFTWARE, 
		"elf_newdata() failed: %s.", elf_errmsg(-1));
	data->d_buf = lib->data; // will be copied by the library

	/* rodata */
	if ((scn = elf_getscn (e, lib->rodata_ndx)) == NULL) errx(EX_SOFTWARE, 
		"elf_newscn() failed: %s.", elf_errmsg(-1));
	/* create a data object for the .text data */
	if ((data = elf_getdata(scn, NULL)) == NULL) errx (EX_SOFTWARE, 
		"elf_newdata() failed: %s.", elf_errmsg(-1));
	data->d_buf = lib->rodata; // will be copied by the library
	
	/* dynsym */
	if ((scn = elf_getscn (e, lib->dynsym_ndx)) == NULL) errx(EX_SOFTWARE, 
		"elf_newscn() failed: %s.", elf_errmsg(-1));
	/* create a data object for the .text data */
	if ((data = elf_getdata(scn, NULL)) == NULL) errx (EX_SOFTWARE, 
		"elf_newdata() failed: %s.", elf_errmsg(-1));
	data->d_buf = lib->dynsym; 
	
	/* write data so far */
	if (elf_update(e, ELF_C_NULL) < 0) errx(EX_SOFTWARE, 
		"elf_update(NULL) failed: %s.",	elf_errmsg(-1));
	
	/* now close and reopen the library */
	dlclose(lib->handle);
	lib->handle = dlopen(lib->filename, RTLD_NOW|RTLD_LOCAL|RTLD_NODELETE);
	assert(lib->handle);
	return 0;
}

int dldelete(ld_handle_t arg)
{
	assert(arg - &entries[0] < LIBLD_MAX_CREATED_LIBRARIES);
	assert(arg->used);
	dlclose(arg->handle);
	elf_end(arg->elf);
	close(arg->fd);
	
	return 0; // FIXME: check for errors
}

void *dldsym(void *handle, const char *symbol, void *namespace,
    unsigned long conv, const char *version_string)
{
	assert(0);
	return NULL;
}
