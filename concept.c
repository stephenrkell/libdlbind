/* We want a test program which
 * 
 * - creates a temporary file and truncate to a certain size (enough to hold n entry points);
 * - uses libelf to build an ELF file in it;
 * - uses libffi to generate an entry point in its text region;
 * - loads the ELF file;
 * - dlsyms the entry point;
 * - calls through the entry point to a private function; 
 * - can be backtraced showing the dynamically-generated code;
 * - (optionally) supports updating the entry point to use a different private function
 * - (optionally) supports mapping (not CoW but write-through!) chunks of text into the heap
 */

#include <err.h>
#include <fcntl.h>
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>

#ifndef HAVE_ELF_SETSHSTRNDX
#define elf_setshstrndx(e, s) elfx_update_shstrndx((e), (s))
#endif

uint64_t hash_words [] = {
	0x01234567,
	0x89abcdef,
	0xdeadc0de
};
	
char string_table [] = { 
	/* Offset 0 */ '\0',
	/* Offset 1 */ '.', 'f', 'o', 'o', '\0',
	/* Offset 6 */ '.', 's', 'h', 's', 't', 'r', 't', 'a', 'b', '\0'
};


int main(int argc, char **argv)
{  
	int fd;
	Elf *e;
	Elf_Scn *scn;
	Elf_Data *data;
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	if (argc != 2) errx(EX_USAGE, "usage: %s filename", argv[0]);
	if (elf_version(EV_CURRENT) == EV_NONE) errx(EX_SOFTWARE, 
		"ELF library initialization failed: %s ", elf_errmsg(-1));
	if ((fd = open(argv[1], O_WRONLY|O_CREAT, 0777)) < 0) errx(EX_OSERR, 
		"open \"%s\" failed", argv[1]);
	if ((e = elf_begin(fd, ELF_C_WRITE, NULL)) == NULL) errx(EX_SOFTWARE, 
		"elf_begin() failed: %s.", elf_errmsg(-1));

	if ((ehdr = elf64_newehdr(e)) == NULL) errx(EX_SOFTWARE, 
		"elf64_newehdr() failed : %s.", elf_errmsg(-1));
	
	ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr->e_machine = EM_X86_64; /* 64-bit x86 object */
	ehdr->e_type = ET_EXEC;

	if ((phdr = elf64_newphdr(e, 1)) == NULL) errx(EX_SOFTWARE,
		"elf64_newphdr() failed: %s.", elf_errmsg(-1));

	if ((scn = elf_newscn (e)) == NULL) errx(EX_SOFTWARE, 
		"elf_newscn() failed: %s.", elf_errmsg(-1));
	if ((data = elf_newdata(scn)) == NULL) errx (EX_SOFTWARE, 
		"elf_newdata() failed: %s.", elf_errmsg(-1));
	data->d_align = 4;
	data->d_off = 0LL;
	data->d_buf = hash_words;
	data->d_type = ELF_T_WORD;
	data->d_size = sizeof hash_words;
	data->d_version = EV_CURRENT;

	if ((shdr = elf64_getshdr(scn)) == NULL) errx(EX_SOFTWARE, 
		"elf64_getshdr() failed :%s.", elf_errmsg(-1));
	shdr->sh_name = 1;
	shdr->sh_type = SHT_HASH;
	shdr->sh_flags = SHF_ALLOC;
	shdr->sh_entsize = 0;

	if ((scn = elf_newscn(e)) == NULL) errx (EX_SOFTWARE, 
		"elf_newscn() failed : %s.", elf_errmsg(-1));
	if ((data = elf_newdata(scn)) == NULL) errx(EX_SOFTWARE, 
		"elf_newdata() failed : %s.", elf_errmsg(-1));
	data->d_align = 1;
	data->d_buf = string_table;
	data->d_off = 0LL;
	data->d_size = sizeof string_table;
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;
	if ((shdr = elf64_getshdr(scn)) == NULL) errx(EX_SOFTWARE, 
		"elf64_getshdr() failed: %s.", elf_errmsg(-1));
	shdr->sh_name = 6;
	shdr->sh_type = SHT_STRTAB;
	shdr->sh_flags = SHF_STRINGS|SHF_ALLOC;
	shdr->sh_entsize = 0;
	elf_setshstrndx(e, elf_ndxscn(scn));
	if (elf_update(e, ELF_C_NULL) < 0) errx(EX_SOFTWARE, 
		"elf_update(NULL) failed: %s.",	elf_errmsg(-1));
	phdr->p_type = PT_PHDR;
	phdr->p_offset = ehdr->e_phoff;
	phdr->p_filesz = elf64_fsize(ELF_T_PHDR, 1, EV_CURRENT);
	(void) elf_flagphdr(e, ELF_C_SET, ELF_F_DIRTY);
	if (elf_update(e, ELF_C_WRITE) < 0) errx(EX_SOFTWARE, 
		"elf_update() failed: %s.",	elf_errmsg(-1));
	(void) elf_end(e);
	(void) close(fd);
	exit(EX_OK);
}
