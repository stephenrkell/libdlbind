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
	
static Elf64_Dyn basic_dynamic[] = { 
	{ DT_HASH, { .d_ptr = 4096 } }, 
	{ DT_STRTAB, { .d_ptr = 8192 } }, // text, data, rodata are each one page
	{ DT_SYMTAB, { .d_ptr = 20480 } }, 
	{ DT_DEBUG, { .d_ptr = 0 } }, 
	{ DT_NULL }, 
};

static void update_file(off_t *p_filepos, Elf *e)
{
	if ((*p_filepos = elf_update(e, ELF_C_NULL)) < 0) errx(EX_SOFTWARE, 
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
static Elf64_Addr issue_vaddr(Elf64_Addr *p_next_vaddr, unsigned align, unsigned memsz)
{
	// NOTE: align is *not* an exponent; it's the actual value
	Elf64_Addr tmp;
	if (*p_next_vaddr % align == 0)
	{
		tmp = *p_next_vaddr;
		*p_next_vaddr += memsz;
		return tmp;
	}
	else
	{
		Elf64_Addr tmp = *p_next_vaddr;
		tmp += align;
		tmp &= ~(align - 1);
		assert(tmp % align == 0);
		assert(tmp < *p_next_vaddr + align);
		*p_next_vaddr = tmp + memsz;
		return tmp;
	}
}
static Elf_Scn *create_section_and_header(off_t *p_filepos, Elf *e,
	char *buf, size_t size, int data_type, int section_name_idx, int section_type, int section_flags,
	unsigned align, unsigned entsize, ElfW(Addr) *p_next_vaddr)
{
	Elf_Scn *scn;
	/* create a .hash section */
	off_t hash_start = *p_filepos;
	if ((scn = elf_newscn(e)) == NULL) errx(EX_SOFTWARE, 
		"elf_newscn() failed: %s.", elf_errmsg(-1));
	/* create a data object for the .hash data */
	if ((data = elf_newdata(scn)) == NULL) errx (EX_SOFTWARE, 
		"elf_newdata() failed: %s.", elf_errmsg(-1));
	data->d_align = align;
	data->d_off = 0LL;
	data->d_buf = hash_words; // will be copied by the library
	data->d_type = data_type;
	data->d_size = size;
	data->d_version = EV_CURRENT;

	/* create a section header for .hash */
	
	if ((shdr = elf64_getshdr(scn)) == NULL) errx(EX_SOFTWARE, 
		"elf64_getshdr() failed :%s.", elf_errmsg(-1));
	shdr->sh_name = section_name_idx; /* offset 1 in shstrtab */
	shdr->sh_type = section_type;
	shdr->sh_flags = section_flags;
	shdr->sh_entsize = entsize;
	shdr->sh_addr = issue_vaddr(p_next_vaddr, data->d_align, data->d_size);

	/* write it to the file */
	update_file(p_filepos, e);
	
	return scn;
}
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
	off_t filepos;

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
	
	// FIXME: set sparse file behaviour
	
	ent->used = 1;
	ent->fd = fd;
	memcpy(ent->strtab, basic_dynstr, sizeof basic_dynstr);
	ent->strtab_insert_pos = sizeof basic_dynstr;
	
	/* begin file */
	// NOTES: libelf0 and libelf1 have different ABIs here. be careful!
	// in particular, libelf1 has ELF_C_RDWR et al. We don't use those.
	// Also, I think if we use ELF_C_WRITE, libelf1 will fail later on. FIXME.
	
	if ((e = elf_begin(fd, ELF_C_WRITE/*ELF_C_RDWR*//*_MMAP*//* 2 */, NULL)) == NULL) errx(EX_SOFTWARE, 
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


	create_section_and_header(&filepos, e, 
		hash_words, sizeof hash_words, ELF_T_WORD, 47 /* offset 1 in shstrtab */, 
		SHT_HASH, SHF_ALLOC, 4096, 0,
		&ent->next_vaddr);

	/* create a section for shstrtab */
	off_t shstrtab_start = filepos;
	if ((scn = elf_newscn(e)) == NULL) errx (EX_SOFTWARE, 
		"elf_newscn() failed : %s.", elf_errmsg(-1));
	/* create the shstrtab data */
	if ((data = elf_newdata(scn)) == NULL) errx(EX_SOFTWARE, 
		"elf_newdata() failed : %s.", elf_errmsg(-1));
	data->d_align = 1;
	data->d_buf = shstrtab;
	data->d_off = 0LL;
	data->d_size = sizeof shstrtab;
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;
	/* create the section header for strtab */
	if ((shdr = elf64_getshdr(scn)) == NULL) errx(EX_SOFTWARE, 
		"elf64_getshdr() failed: %s.", elf_errmsg(-1));
	shdr->sh_name = 1; // offset in shstrtab
	shdr->sh_type = SHT_STRTAB;
	shdr->sh_flags = SHF_STRINGS|SHF_ALLOC;
	shdr->sh_entsize = 0;
	shdr->sh_addr = issue_vaddr(&ent->next_vaddr, data->d_align, data->d_size);
	/* set the shrstr index */
	elf_setshstrndx(e, elf_ndxscn(scn));

	/* create a section for dynstr */
	off_t dynstr_start = filepos;
	if ((scn = elf_newscn(e)) == NULL) errx (EX_SOFTWARE, 
		"elf_newscn() failed : %s.", elf_errmsg(-1));
	/* create the dynstr data */
	if ((data = elf_newdata(scn)) == NULL) errx(EX_SOFTWARE, 
		"elf_newdata() failed : %s.", elf_errmsg(-1));
	data->d_align = 4096;
	data->d_buf = ent->strtab;
	data->d_off = 0LL;
	data->d_size = sizeof ent->strtab;
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;
	/* create the section header for dynstr */
	if ((shdr = elf64_getshdr(scn)) == NULL) errx(EX_SOFTWARE, 
		"elf64_getshdr() failed: %s.", elf_errmsg(-1));
	shdr->sh_name = 1; // offset in shstrtab
	shdr->sh_type = SHT_STRTAB;
	shdr->sh_flags = SHF_STRINGS|SHF_ALLOC;
	shdr->sh_entsize = 0;
	shdr->sh_addr = issue_vaddr(&ent->next_vaddr, data->d_align, data->d_size);
	
	/* What other sections do we need to add?
	 * text, data, rodata. */
	Elf_Scn *dynstr_scn;
	/* create a .text section */
	off_t text_start = filepos;
	if ((dynstr_scn = scn = elf_newscn (e)) == NULL) errx(EX_SOFTWARE, 
		"elf_newscn() failed: %s.", elf_errmsg(-1));
	/* create a data object for the .text data */
	if ((data = elf_newdata(scn)) == NULL) errx (EX_SOFTWARE, 
		"elf_newdata() failed: %s.", elf_errmsg(-1));
	data->d_align = 4096;
	data->d_off = 0LL;
	data->d_buf = ent->text; // will be copied by the library
	data->d_type = ELF_T_BYTE;
	data->d_size = sizeof ent->text;
	data->d_version = EV_CURRENT;
	/* create a section header for .text */
	if ((shdr = elf64_getshdr(scn)) == NULL) errx(EX_SOFTWARE, 
		"elf64_getshdr() failed :%s.", elf_errmsg(-1));
	shdr->sh_name = 11; /* offset 11 in shstrtab */
	shdr->sh_type = SHT_PROGBITS;
	shdr->sh_flags = SHF_ALLOC|SHF_EXECINSTR;
	shdr->sh_entsize = 0;
	shdr->sh_addr = issue_vaddr(&ent->next_vaddr, data->d_align, data->d_size);
	
	ent->text_ndx = elf_ndxscn(scn);
	
	/* write data so far */
	update_file(&filepos, e);

	/* create a .data section */
	off_t data_start = filepos;
	if ((scn = elf_newscn (e)) == NULL) errx(EX_SOFTWARE, 
		"elf_newscn() failed: %s.", elf_errmsg(-1));
	/* create a data object for the .text data */
	if ((data = elf_newdata(scn)) == NULL) errx (EX_SOFTWARE, 
		"elf_newdata() failed: %s.", elf_errmsg(-1));
	data->d_align = 4096;
	data->d_off = 0LL;
	data->d_buf = ent->data; // will be copied by the library
	data->d_type = ELF_T_BYTE;
	data->d_size = sizeof ent->data;
	data->d_version = EV_CURRENT;
	/* create a section header for .data */
	if ((shdr = elf64_getshdr(scn)) == NULL) errx(EX_SOFTWARE, 
		"elf64_getshdr() failed :%s.", elf_errmsg(-1));
	shdr->sh_name = 17; /* offset 17 in shstrtab */
	shdr->sh_type = SHT_PROGBITS;
	shdr->sh_flags = SHF_ALLOC|SHF_WRITE;
	shdr->sh_entsize = 0;
	shdr->sh_addr = issue_vaddr(&ent->next_vaddr, data->d_align, data->d_size);
	
	ent->data_ndx = elf_ndxscn(scn);
	/* write data so far */
	update_file(&filepos, e);

	/* create a .rodata section */
	off_t rodata_start = filepos;
	if ((scn = elf_newscn (e)) == NULL) errx(EX_SOFTWARE, 
		"elf_newscn() failed: %s.", elf_errmsg(-1));
	/* create a data object for the .text data */
	if ((data = elf_newdata(scn)) == NULL) errx (EX_SOFTWARE, 
		"elf_newdata() failed: %s.", elf_errmsg(-1));
	data->d_align = 4096;
	data->d_off = 0LL;
	data->d_buf = ent->rodata; // will be copied by the library
	data->d_type = ELF_T_BYTE;
	data->d_size = sizeof ent->rodata;
	data->d_version = EV_CURRENT;
	/* create a section header for .rodata */
	if ((shdr = elf64_getshdr(scn)) == NULL) errx(EX_SOFTWARE, 
		"elf64_getshdr() failed :%s.", elf_errmsg(-1));
	shdr->sh_name = 23; /* offset 23 in shstrtab */
	shdr->sh_type = SHT_PROGBITS;
	shdr->sh_flags = SHF_ALLOC;
	shdr->sh_entsize = 0;
	shdr->sh_addr = issue_vaddr(&ent->next_vaddr, data->d_align, data->d_size);
	ent->rodata_ndx = elf_ndxscn(scn);
	/* write data so far */
	update_file(&filepos, e);
	
	/* we also need a dynsym */
	off_t dynsym_start = filepos;
	if ((scn = elf_newscn (e)) == NULL) errx(EX_SOFTWARE, 
		"elf_newscn() failed: %s.", elf_errmsg(-1));
	/* create a data object for the .dynsym data */
	if ((data = elf_newdata(scn)) == NULL) errx (EX_SOFTWARE, 
		"elf_newdata() failed: %s.", elf_errmsg(-1));
	data->d_align = 4096;
	data->d_off = 0LL;
	data->d_buf = ent->dynsym; // will be copied by the library
	data->d_type = ELF_T_SYM;
	data->d_size = sizeof ent->dynsym;
	data->d_version = EV_CURRENT;
	/* create a section header for .dynsym */
	if ((shdr = elf64_getshdr(scn)) == NULL) errx(EX_SOFTWARE, 
		"elf64_getshdr() failed :%s.", elf_errmsg(-1));
	shdr->sh_name = 31; /* offset 31 in shstrtab */
	shdr->sh_type = SHT_DYNSYM;
	shdr->sh_flags = SHF_ALLOC;
	shdr->sh_link = elf_ndxscn(dynstr_scn);
	shdr->sh_info = /* index of the first non-local symbol; we make everything global */ 0;
	shdr->sh_entsize = sizeof (Elf64_Sym);
	shdr->sh_addr = issue_vaddr(&ent->next_vaddr, data->d_align, data->d_size);
	ent->dynsym_ndx = elf_ndxscn(scn);
	/* write data so far */
	update_file(&filepos, e);
	off_t end_of_dynsym_filepos = filepos;
	Elf64_Addr end_of_dynsym_vaddr = ent->next_vaddr;
	
	/* we also need a .dynamic */
	off_t dynamic_start = filepos;
	if ((scn = elf_newscn (e)) == NULL) errx(EX_SOFTWARE, 
		"elf_newscn() failed: %s.", elf_errmsg(-1));
	/* create a data object for the .dynsym data */
	if ((data = elf_newdata(scn)) == NULL) errx (EX_SOFTWARE, 
		"elf_newdata() failed: %s.", elf_errmsg(-1));
	data->d_align = 4096;
	data->d_off = 0LL;
	data->d_buf = basic_dynamic; // will be copied by the library
	data->d_type = ELF_T_SYM;
	data->d_size = sizeof basic_dynamic;
	data->d_version = EV_CURRENT;
	/* create a section header for .dynamic */
	if ((shdr = elf64_getshdr(scn)) == NULL) errx(EX_SOFTWARE, 
		"elf64_getshdr() failed :%s.", elf_errmsg(-1));
	shdr->sh_name = 53; /* offset 53 in shstrtab */
	shdr->sh_type = SHT_DYNAMIC;
	shdr->sh_flags = SHF_ALLOC;
	shdr->sh_link = elf_ndxscn(dynstr_scn);
	shdr->sh_info = 0;
	shdr->sh_entsize = sizeof (Elf64_Dyn);
	shdr->sh_addr = issue_vaddr(&ent->next_vaddr, data->d_align, data->d_size);
	Elf64_Addr dynamic_vaddr = shdr->sh_addr;
	ent->dynsym_ndx = elf_ndxscn(scn);
	/* write data so far */
	update_file(&filepos, e);
	off_t end_of_dynamic_filepos = filepos;
	Elf64_Addr end_of_dynamic_vaddr = ent->next_vaddr;

	/* create phdr table with two entries */
	if ((phdr = elf64_newphdr(e, 2)) == NULL) errx(EX_SOFTWARE,
		"elf64_newphdr() failed: %s.", elf_errmsg(-1));
	/* populate phdr[0] -- LOAD the whole lot */
	phdr[0].p_type = PT_LOAD;
	phdr[0].p_offset = 0;
	phdr[0].p_flags = PF_R | PF_W | PF_X;
	phdr[0].p_filesz = end_of_dynamic_filepos;
	// NOT: elf64_fsize(ELF_T_PHDR, 1, EV_CURRENT);
	phdr[0].p_memsz = end_of_dynsym_vaddr;
	
	/* populate phdr[1] -- make a PT_DYNAMIC */
	phdr[1].p_type = PT_DYNAMIC;
	phdr[1].p_offset = end_of_dynsym_filepos;;
	phdr[1].p_vaddr = dynamic_vaddr;
	phdr[1].p_flags = PF_R;
	phdr[1].p_filesz = filepos - end_of_dynsym_filepos;
	// NOT: elf64_fsize(ELF_T_PHDR, 1, EV_CURRENT);
	phdr[1].p_memsz = ent->next_vaddr - end_of_dynsym_vaddr;
	(void) elf_flagphdr(e, ELF_C_SET, ELF_F_DIRTY);
	/* */
	update_file(&filepos, e);
	
	/* end the file -- what happens if we don't do this? */
	(void) elf_end(e);
	
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
