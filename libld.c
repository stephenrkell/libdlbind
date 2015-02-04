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
#include <link.h>

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
#ifndef LIBLD_DYNSTR_SIZE
#define LIBLD_DYNSTR_SIZE 4096
#endif
#ifndef LIBLD_DYNSYM_SIZE
#define LIBLD_DYNSYM_SIZE 4096
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

static char shstrtab[] = { 
	/* Offset 0 */ '\0',
	/* Offset 1 */ '.', 's', 'h', 's', 't', 'r', 't', 'a', 'b', '\0',
	/* Offset 11 */ '.', 't', 'e', 'x', 't', '\0',
	/* Offset 17 */ '.', 'd', 'a', 't', 'a', '\0',
	/* Offset 23 */ '.', 'r', 'o', 'd', 'a', 't', 'a', '\0',
	/* Offset 31 */ '.', 'd', 'y', 'n', 's', 'y', 'm', '\0', 
	/* Offset 39 */ '.', 'd', 'y', 'n', 's', 't', 'r', '\0', 
	/* Offset 47 */ '.', 'h', 'a', 's', 'h', '\0',
	/* Offset 53 */ '.', 'd', 'y', 'n', 'a', 'm', 'i', 'c', '\0' 
};

static char basic_dynstr[] = { 
	/* Offset 0 */ '\0',
	/* Offset 1 */ '.', 'f', 'o', 'o', '\0',
	/* Offset 6 */ '_', 'D', 'Y', 'N', 'A', 'M', 'I', 'C', '\0' 
};

#define DYNAMIC_HASH_IDX 0
#define DYNAMIC_DYNSTR_IDX 1
#define DYNAMIC_DYNSYM_IDX 2
#define DYNAMIC_DEBUG_IDX 3
#define DYNAMIC_LAST_IDX (DYNAMIC_DEBUG_IDX+1)

static Elf64_Dyn basic_dynamic[] = { 
	[DYNAMIC_HASH_IDX]   = { DT_HASH, { .d_ptr = 4096 } }, 
	[DYNAMIC_DYNSTR_IDX] = { DT_STRTAB, { .d_ptr = 8192 } }, // text, data, rodata are each one page
	[DYNAMIC_DYNSYM_IDX] = { DT_SYMTAB, { .d_ptr = 20480 } }, 
	[DYNAMIC_DEBUG_IDX]  = { DT_DEBUG, { .d_ptr = 0 } }, 
	[DYNAMIC_LAST_IDX] =   { DT_NULL }
};

static void update_file(off_t *p_filepos, Elf *e)
{
	if ((*p_filepos = elf_update(e, ELF_C_WRITE)) < 0) errx(EX_SOFTWARE, 
		"elf_update(NULL) failed: %s.",	elf_errmsg(-1));
}

struct Ld_Entry
{
	int used;
	char filename[22] /* = "/tmp/tmp.libld.XXXXXX" */;
	int fd;
	Elf *elf;
	void *handle;
	Elf64_Addr next_vaddr;
	
	char dynstr[LIBLD_DYNSTR_SIZE];
	unsigned dynstr_insert_pos;
	Elf64_Half dynstr_ndx;
	
	char text[LIBLD_TEXT_SIZE];
	unsigned text_insert_pos;
	Elf64_Half text_ndx;
	
	char data[LIBLD_DATA_SIZE];
	unsigned data_insert_pos;
	Elf64_Half data_ndx;

	char rodata[LIBLD_RODATA_SIZE];
	unsigned rodata_insert_pos;
	Elf64_Half rodata_ndx;
	
	char dynsym[LIBLD_DYNSYM_SIZE];
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
// static char basic_dynsym[LIBLD_DYNSYM_SIZE];
static Elf64_Addr issue_vaddr(Elf64_Addr *p_next_vaddr, unsigned align, unsigned memsz, off_t fileoff)
{
// 	// NOTE: align is *not* an exponent; it's the actual value
// 	Elf64_Addr tmp;
// 	if (*p_next_vaddr % align == 0)
// 	{
// 		tmp = *p_next_vaddr;
// 		*p_next_vaddr += memsz;
// 		return tmp;
// 	}
// 	else
// 	{
// 		Elf64_Addr tmp = *p_next_vaddr;
// 		tmp += align;
// 		tmp &= ~(align - 1);
// 		assert(tmp % align == 0);
// 		assert(tmp < *p_next_vaddr + align);
// 		*p_next_vaddr = tmp + memsz;
// 		return tmp;
// 	}
	*p_next_vaddr = fileoff + memsz;
	return fileoff;
}
static Elf_Scn *create_section_and_header(off_t *p_filepos, Elf *e,
	char *buf, size_t size, int data_type, int section_name_idx, int section_type, int section_flags,
	unsigned align, unsigned entsize, unsigned link, unsigned info, Elf64_Addr *p_next_vaddr)
{
	Elf_Scn *scn;
	Elf_Data *data;
	/* create a section */
	off_t hash_start = *p_filepos;
	if ((scn = elf_newscn(e)) == NULL) errx(EX_SOFTWARE, 
		"elf_newscn() failed: %s.", elf_errmsg(-1));
	/* create a data object for the .hash data */
	if ((data = elf_newdata(scn)) == NULL) errx (EX_SOFTWARE, 
		"elf_newdata() failed: %s.", elf_errmsg(-1));
	data->d_align = align;
	data->d_off = 0LL;
	data->d_buf = buf; // will be copied by the library
	data->d_type = data_type;
	data->d_size = size;
	data->d_version = EV_CURRENT;

	/* create a section header */
	Elf64_Shdr *shdr;
	if ((shdr = elf64_getshdr(scn)) == NULL) errx(EX_SOFTWARE, 
		"elf64_getshdr() failed :%s.", elf_errmsg(-1));
	shdr->sh_name = section_name_idx; /* offset 1 in shstrtab */
	shdr->sh_type = section_type;
	shdr->sh_flags = section_flags;
	shdr->sh_link = link;
	shdr->sh_info = info;
	shdr->sh_entsize = entsize;
	/* update the file; libelf should fill in the offset */
	update_file(p_filepos, e);
	off_t section_offset = shdr->sh_offset;
	assert(*p_filepos >= section_offset);
	/* fill in the vaddr */
	Elf64_Addr vaddr = issue_vaddr(p_next_vaddr, data->d_align, data->d_size, section_offset);
	shdr->sh_addr = vaddr;

	/* assert that our shdr update took effect */
	assert(elf64_getshdr(scn)->sh_addr == vaddr);
	
	return scn;
}
ld_handle_t dlnew(const char *libname)
{
	/* We create a temporary file, build an ELF file of fixed dimensions
	 * in it, and dlopen it with the magic flags. */
	int fd;
	Elf *e;
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	off_t filepos = 0;

	if (elf_version(EV_CURRENT) == EV_NONE) errx(EX_SOFTWARE, 
		"ELF library initialization failed: %s ", elf_errmsg(-1));

	/* allocate an entry record */
	struct Ld_Entry *ent = &entries[0];
	while (ent->used && ent < &entries[LIBLD_MAX_CREATED_LIBRARIES])
	{
		ent++;
	}
	if (ent == &entries[LIBLD_MAX_CREATED_LIBRARIES])
	{
		return NULL;
	}
	/* populate the entry */
	strcpy(ent->filename, "/tmp/tmp.libld.XXXXXX");
	fd = mkostemp(ent->filename, O_RDWR|O_CREAT);
	assert(fd != -1 && "mkstemp failed");
	
	// FIXME: set sparse file behaviour
	
	ent->used = 1;
	ent->fd = fd;
	
	memcpy(ent->dynstr, basic_dynstr, sizeof basic_dynstr);
	ent->dynstr_insert_pos = sizeof basic_dynstr;
	
	/* begin file */
	// NOTES: libelf0 and libelf1 have different ABIs here. be careful!
	// in particular, libelf1 has ELF_C_RDWR et al. We don't use those.
	// Also, I think if we use ELF_C_WRITE, libelf1 will fail later on. FIXME.
	
	if ((e = elf_begin(fd, ELF_C_WRITE/*_MMAP*//* 2 */, NULL)) == NULL) errx(EX_SOFTWARE, 
		"elf_begin() failed: %s.", elf_errmsg(-1));
	ent->elf = e;

	/* create ELF header */
	if ((ehdr = elf64_newehdr(e)) == NULL) errx(EX_SOFTWARE, 
		"elf64_newehdr() failed : %s.", elf_errmsg(-1));
	
	ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr->e_machine = EM_X86_64; /* 64-bit x86 object */
	ehdr->e_type = ET_DYN; /* shared object */

	/* FIXME: want to generate phdrs from SHF_ALLOC, sh_vaddr, sh_offset. */
	/* create a phdr */
	if ((phdr = elf64_newphdr(e, 1)) == NULL) errx(EX_SOFTWARE,
		"elf64_newphdr() failed: %s.", elf_errmsg(-1));

	Elf_Scn *hash_scn = create_section_and_header(&filepos, e, 
		(char*) hash_words, sizeof hash_words, ELF_T_WORD, 47 /* offset in shstrtab */, 
		SHT_HASH, SHF_ALLOC, 4096, 0, 0, 0, 
		&ent->next_vaddr);
	Elf64_Addr hash_vaddr = elf64_getshdr(hash_scn)->sh_addr;
	
	Elf_Scn *shstrtab_scn = create_section_and_header(&filepos, e,
			shstrtab, sizeof shstrtab, ELF_T_BYTE, 1 /* offset in shstrtab */,
			SHT_STRTAB, SHF_STRINGS|SHF_ALLOC, 1, 0, 0, 0, 
			&ent->next_vaddr);
	/* set the shrstr index */
	elf_setshstrndx(e, elf_ndxscn(shstrtab_scn));

	/* create a section for dynstr */
	Elf_Scn *dynstr_scn = create_section_and_header(&filepos, e, 
			ent->dynstr, sizeof ent->dynstr, ELF_T_BYTE, 39,
			SHT_STRTAB, SHF_STRINGS|SHF_ALLOC, 1, 0, 0, 0, 
			&ent->next_vaddr);
	Elf64_Addr dynstr_vaddr = elf64_getshdr(dynstr_scn)->sh_addr;
	ent->dynstr_ndx = elf_ndxscn(dynstr_scn);
	
	/* create a section for text */
	Elf_Scn *text_scn = create_section_and_header(&filepos, e,
			ent->text, sizeof ent->text, ELF_T_BYTE, 11,
			SHT_PROGBITS, SHF_ALLOC|SHF_EXECINSTR, 4096, 0, 0, 0,
			&ent->next_vaddr);
	ent->text_ndx = elf_ndxscn(text_scn);
	
	/* create a .data section */
	Elf_Scn *data_scn = create_section_and_header(&filepos, e,
			ent->data, sizeof ent->data, ELF_T_BYTE, 17,
			SHT_PROGBITS, SHF_ALLOC|SHF_WRITE, 4096, 0, 0, 0,
			&ent->next_vaddr);
	ent->data_ndx = elf_ndxscn(data_scn);

	Elf_Scn *rodata_scn = create_section_and_header(&filepos, e,
			ent->rodata, sizeof ent->rodata, ELF_T_BYTE, 23,
			SHT_PROGBITS, SHF_ALLOC, 4096, 0, 0, 0, 
			&ent->next_vaddr);
	ent->rodata_ndx = elf_ndxscn(rodata_scn);
	
	Elf_Scn *dynsym_scn = create_section_and_header(&filepos, e,
			ent->dynsym, sizeof ent->dynsym, ELF_T_SYM, 31,
			SHT_DYNSYM, SHF_ALLOC, 4096, sizeof (Elf64_Sym), elf_ndxscn(dynstr_scn), /* all global */ 0,
			&ent->next_vaddr);
	ent->dynsym_ndx = elf_ndxscn(dynsym_scn);
	Elf64_Addr dynsym_vaddr = elf64_getshdr(dynsym_scn)->sh_addr;
	
	Elf64_Dyn our_dynamic[sizeof basic_dynamic / sizeof (Elf64_Dyn)];
	memcpy(our_dynamic, basic_dynamic, sizeof basic_dynamic);
	our_dynamic[DYNAMIC_HASH_IDX].d_un.d_ptr = hash_vaddr;
	our_dynamic[DYNAMIC_DYNSTR_IDX].d_un.d_ptr = dynstr_vaddr;
	our_dynamic[DYNAMIC_DYNSYM_IDX].d_un.d_ptr = dynsym_vaddr;
	Elf_Scn *dynamic_scn = create_section_and_header(&filepos, e,
			(char*) &our_dynamic[0], sizeof our_dynamic, ELF_T_DYN, 53,
			SHT_DYNAMIC, SHF_ALLOC, 4096, sizeof (Elf64_Dyn), 0, 0,
			&ent->next_vaddr);
	off_t dynamic_filepos = elf64_getshdr(dynamic_scn)->sh_offset;
	Elf64_Addr dynamic_vaddr = elf64_getshdr(dynamic_scn)->sh_addr;
	
	/* Make symbol table index 1 be the _DYNAMIC symbol. */
	Elf_Data *dynsym_data = NULL;
	dynsym_data = elf_getdata(dynsym_scn, dynsym_data);
	((Elf64_Sym *) dynsym_data->d_buf)[1] = (Elf64_Sym) {
		.st_name = 6,
		.st_info = ELF64_ST_INFO(STB_LOCAL, STT_OBJECT),
		.st_other = ELF64_ST_VISIBILITY(STV_DEFAULT),
		.st_shndx = elf_ndxscn(dynamic_scn),
		.st_value = dynamic_vaddr,
		.st_size = elf64_getshdr(dynamic_scn)->sh_size
	};

	/* create phdr table with two entries */
	if ((phdr = elf64_newphdr(e, 2)) == NULL) errx(EX_SOFTWARE,
		"elf64_newphdr() failed: %s.", elf_errmsg(-1));
	/* populate phdr[0] -- LOAD the whole lot */
	phdr[0].p_type = PT_LOAD;
	phdr[0].p_offset = 0;
	phdr[0].p_flags = PF_R | PF_W | PF_X;
	phdr[0].p_filesz = filepos;
	// NOT: elf64_fsize(ELF_T_PHDR, 1, EV_CURRENT);
	phdr[0].p_memsz = ent->next_vaddr;
	
	/* populate phdr[1] -- make a PT_DYNAMIC */
	phdr[1].p_type = PT_DYNAMIC;
	phdr[1].p_offset = dynamic_filepos;
	phdr[1].p_vaddr = dynamic_vaddr;
	phdr[1].p_flags = PF_R;
	phdr[1].p_filesz = sizeof basic_dynamic;
	// NOT: elf64_fsize(ELF_T_PHDR, 1, EV_CURRENT);
	phdr[1].p_memsz = sizeof basic_dynamic;
	(void) elf_flagphdr(e, ELF_C_SET, ELF_F_DIRTY);
	update_file(&filepos, e);

	/* elf_end() the WRITE handlen and elf_begin a RDWR one */
	elf_end(e);

	if ((e = elf_begin(fd, ELF_C_RDWR/*_MMAP*//* 2 */, NULL)) == NULL) errx(EX_SOFTWARE, 
		"elf_begin() failed: %s.", elf_errmsg(-1));

	ent->elf = e;
	ent->text_insert_pos = 0;

	ent->data_insert_pos = 0;
	
	ent->rodata_insert_pos = 0;

	ent->dynsym_insert_pos = 2 * sizeof (Elf64_Sym);

	// we delay closing the fd until dldelete
	// but we do dlopen it!
	ent->handle = dlopen(ent->filename, RTLD_NOW|RTLD_LOCAL|RTLD_NODELETE);
	assert(ent->handle);
	return ent;
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

	/* copy data out of libelf's structures into our working buffer */
	assert(lib->text_insert_pos + len < LIBLD_TEXT_SIZE);
	memcpy(lib->text + lib->text_insert_pos, obj, len);
	lib->text_insert_pos += len;
	
	/* add a string to the strtab */
	unsigned dynstr_inserted_pos = lib->dynstr_insert_pos;
	assert(lib->dynstr_insert_pos + strlen(symname) + 1 < LIBLD_DYNSTR_SIZE);
	strcpy(lib->dynstr + lib->dynstr_insert_pos, symname);
	lib->dynstr_insert_pos += strlen(symname);
	lib->dynstr[lib->dynstr_insert_pos] = '\0';
	lib->dynstr_insert_pos++;
	
	/* add a symbol to the dynsym */
	assert(lib->dynsym_insert_pos + sizeof (Elf64_Sym)< LIBLD_DYNSYM_SIZE);
	*(Elf64_Sym*)(lib->dynsym + lib->dynsym_insert_pos) = (Elf64_Sym) {
		  .st_name = dynstr_inserted_pos,
		  .st_info = ELF64_ST_INFO(STT_FUNC, STB_GLOBAL),  /* Symbol type and binding */
		  .st_other = STV_DEFAULT,    /* Symbol visibility */
		  .st_shndx = lib->text_ndx,  /* Section index */
		  .st_value = (Elf64_Addr) ((char*) obj - (char*) ((struct link_map *) lib->handle)->l_addr), /* Symbol value */
		  .st_size = len              /* Symbol size */
	};
		  
	/* Now how do we update? Let's try... */
	Elf_Scn *scn;
	Elf_Data *data;
	Elf *e = lib->elf;

	/* create a section for strtab */
	if ((scn = elf_getscn(e, lib->dynstr_ndx)) == NULL) errx (EX_SOFTWARE, 
		"elf_newscn() failed : %s.", elf_errmsg(-1));
	/* create the strtab data */
	if ((data = elf_getdata(scn, NULL)) == NULL) errx(EX_SOFTWARE, 
		"elf_newdata() failed : %s.", elf_errmsg(-1));
	data->d_buf = lib->dynstr;
	
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
	if (elf_update(e, ELF_C_WRITE) < 0) errx(EX_SOFTWARE, 
		"elf_update(NULL) failed: %s.",	elf_errmsg(-1));
	
	/* FIXME: update hash section! */
	
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
