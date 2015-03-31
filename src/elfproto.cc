#include <cstddef>
#include <cstdlib>
#include <elf.h>

/* FIXME: for some reason, g++ is happy to do the address calculations 
 * whereas gcc isn't. */
 
extern "C" {
#include "symhash.h"
}

#include "elfproto.h"

/* We define the basic headers and structure of the ELF file
 * we're instantiating.
 * 
 * To instantiate this prototype, we:
 * 
 * - create a new temporary file
 * - mmap it (*not* a private mapping)
 * - write its ELF headers etc., allowing a certain
 *   amount of space for text (rx), rodata (r) and data (rw).
 * - all this space is trailing; we just define the headers here.
 * - dlopen() it -- this will make a *private* mapping, and if we
 *   use RTLD_NODELETE, it will keep the data sections around on a
 *   reload.
 * - It's therefore important that any updates are made to the live,
 *   dlopen()'d copy, not our on-disk mmap() copy. In effect, the mmap()'d
 *   copy on disk is just a zygote, and could just be a fixed data file.
 *   The difference is that we must give it a fresh name to allow multiple
 *   copies per process, without the loader thinking they're the "same" object.
 * - In effect, RTLD_NODELETE undoes the unwanted "private mapping" effect
 *   from this process's point of view: reloading does not throw away changes.
 * - PROBLEM: from the debugger's point of view, the file hasn't changed!
 *   So we need to hack the loader so that it doesn't use MAP_PRIVATE.
 */

#define DYNAMIC_N 14
#define RELA_DYN_N 1
#define SHSTRTAB_SZ 128
#define PHDRS_N 5
#define SHDRS_N 10
#define DYNSTR_SZ (256 * MAX_SYMS)

// forward-declare everything up-front, so that we can cross-refer
/* FIXME: forward-declaration requires us to use "extern" but then "static".
 * Sadly the only way around this seems to be to write this file in assembly. */

extern Elf64_Ehdr ehdr;
extern Elf64_Phdr phdrs[PHDRS_N];
extern Elf64_Shdr shdrs[SHDRS_N] ;
extern Elf64_Dyn dynamic[DYNAMIC_N];
extern Elf64_Sym dynsym[MAX_SYMS];
extern Elf64_Rela rela_dyn[RELA_DYN_N];
extern char shstrtab[SHSTRTAB_SZ];
extern char dynstr[DYNSTR_SZ];
extern Elf64_Word hash[2 + NBUCKET + MAX_SYMS];
extern unsigned long first_user_word;

#ifndef TEXT_SZ
#define TEXT_SZ 33554432
#endif

#ifndef DATA_SZ
#define DATA_SZ 16777216
#endif

#ifndef RODATA_SZ
#define RODATA_SZ 8388608
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

static Elf64_Ehdr ehdr  __attribute__((section(".elf_zygote"))) = {
	.e_ident = { '\x7f', 'E', 'L', 'F', ELFCLASS64, ELFDATA2LSB, EV_CURRENT, ELFOSABI_GNU, 0 },
	.e_type = ET_DYN,
	.e_machine = EM_X86_64,
	.e_version = EV_CURRENT,
	.e_entry = 0,
	.e_phoff = (char*) &phdrs[0] - (char*) &ehdr,
	.e_shoff = (char*) &shdrs[0] - (char*) &ehdr,
	.e_flags = 0,
	.e_ehsize = sizeof (Elf64_Ehdr),
	.e_phentsize = sizeof (Elf64_Phdr),
	.e_phnum = PHDRS_N /* text, data, rodata, dynamic */,
	.e_shentsize = sizeof (Elf64_Shdr), 
	.e_shnum = SHDRS_N /* null, shstrtab, text, data, rodata, dynsym, dynstr, hash, dynamic, rela.dyn */,
	.e_shstrndx = 1, 
	
};

static Elf64_Phdr phdrs[]  __attribute__((section(".elf_zygote"))) = {
	(Elf64_Phdr) {
		.p_type = PT_DYNAMIC,                 
		.p_flags = PF_R | PF_W,
		.p_offset = (char*) &dynamic[0] - (char*) &ehdr,
		.p_vaddr = (char*) &dynamic[0] - (char*) &ehdr,
		.p_paddr = (char*) &dynamic[0] - (char*) &ehdr,
		.p_filesz = sizeof dynamic, // could implement bss here
		.p_memsz = sizeof dynamic,
		.p_align = sizeof (void*)
	},
	(Elf64_Phdr) { /* metadata mapping. Include the shdrs! dlbind() wants them. */
		.p_type = PT_LOAD,
		.p_flags = PF_R | PF_W,
		.p_offset = (char*) &shdrs[0] - (char*) &ehdr,
		.p_vaddr = (char*) &shdrs[0] - (char*) &ehdr,
		.p_paddr = (char*) &shdrs[0] - (char*) &ehdr,
		.p_filesz = (char*) &dynstr[DYNSTR_SZ] - (char*) &shdrs[0],
		.p_memsz = (char*) &dynstr[DYNSTR_SZ] - (char*) &shdrs[0],
		.p_align = PAGE_SIZE
	},
	(Elf64_Phdr) {
		.p_type = PT_LOAD,
		.p_flags = PF_R | PF_X,
		.p_offset = (char*) &first_user_word - (char*) &ehdr,
		.p_vaddr = (char*) &first_user_word - (char*) &ehdr,
		.p_paddr = (char*) &first_user_word - (char*) &ehdr,
		.p_filesz = TEXT_SZ,
		.p_memsz = TEXT_SZ,
		.p_align = PAGE_SIZE
	},
	(Elf64_Phdr) {
		.p_type = PT_LOAD,
		.p_flags = PF_R,
		.p_offset = (char*) &first_user_word + TEXT_SZ - (char*) &ehdr,
		.p_vaddr = (char*) &first_user_word + TEXT_SZ - (char*) &ehdr,
		.p_paddr = (char*) &first_user_word + TEXT_SZ - (char*) &ehdr,
		.p_filesz = RODATA_SZ,
		.p_memsz = RODATA_SZ,
		.p_align = PAGE_SIZE
	},
	(Elf64_Phdr) {
		.p_type = PT_LOAD,
		.p_flags = PF_R | PF_W,
		.p_offset = (char*) &first_user_word + TEXT_SZ + RODATA_SZ - (char*) &ehdr,
		.p_vaddr = (char*) &first_user_word + TEXT_SZ + RODATA_SZ - (char*) &ehdr,
		.p_paddr = (char*) &first_user_word + TEXT_SZ + RODATA_SZ - (char*) &ehdr,
		.p_filesz = DATA_SZ, // could implement bss here
		.p_memsz = DATA_SZ,
		.p_align = PAGE_SIZE
	}
};

#define NDX_SHSTRTAB 1
#define NDX_DYNAMIC 2
#define NDX_DYNSYM 3
#define NDX_RELA_DYN 4
#define NDX_HASH 5
#define NDX_DYNSTR 6
#define NDX_TEXT 7
#define NDX_RODATA 8
#define NDX_DATA 9
// FIXME: while we're using g++ and it doesn't support nontrivial designated
// initializers, we don't designate even though we'd like to. 

static Elf64_Shdr shdrs[SHDRS_N] __attribute__((section(".elf_zygote"))) = {
	/*[0] =*/ (Elf64_Shdr) { // null
		.sh_name = 0,
		.sh_type = 0,
		.sh_flags = 0,
		.sh_addr = 0,
		.sh_offset = 0,
		.sh_size = 0,
		.sh_link = 0,
		.sh_info = 0,
		.sh_addralign = 0,
		.sh_entsize = 0
	},
	/*[NDX_SHSTRTAB] =*/ (Elf64_Shdr) { // shstrtab
		.sh_name = 1,
		.sh_type = SHT_STRTAB,
		.sh_flags = 0,
		.sh_addr = 0,
		.sh_offset = (char*) &shstrtab[0] - (char*) &ehdr,
		.sh_size = sizeof shstrtab,
		.sh_link = 0,
		.sh_info = 0,
		.sh_addralign = 1,
		.sh_entsize = 0
	},
	/*[NDX_DYNAMIC] =*/ (Elf64_Shdr) { // dynamic 
		.sh_name = 53,
		.sh_type = SHT_DYNAMIC,
		.sh_flags = SHF_ALLOC | SHF_WRITE,
		.sh_addr = (char*) &dynamic[0] - (char*) &ehdr,
		.sh_offset = (char*) &dynamic[0] - (char*) &ehdr,
		.sh_size = sizeof dynamic,
		.sh_link = NDX_DYNSTR,
		.sh_info = 0,
		.sh_addralign = sizeof (Elf64_Dyn),
		.sh_entsize = sizeof (Elf64_Dyn)
	},
	/*[NDX_DYNSYM] =*/ (Elf64_Shdr) { // dynsym
		.sh_name = 31,
		.sh_type = SHT_DYNSYM,
		.sh_flags = SHF_ALLOC,
		.sh_addr = (char*) &dynsym[0] - (char*) &ehdr,
		.sh_offset = (char*) &dynsym[0] - (char*) &ehdr,
		.sh_size = sizeof dynsym,
		.sh_link = NDX_DYNSTR,
		.sh_info = MAX_SYMS - 1,  /* index of the first non-local sym */
		.sh_addralign = sizeof (Elf64_Sym),
		.sh_entsize = sizeof (Elf64_Sym)
	},
	/*[NDX_RELA_DYN] =*/ (Elf64_Shdr) { // rela.dyn
		.sh_name = 62,
		.sh_type = SHT_RELA,
		.sh_flags = SHF_ALLOC,
		.sh_addr = (char*) &rela_dyn[0] - (char*) &ehdr,
		.sh_offset = (char*) &rela_dyn[0] - (char*) &ehdr,
		.sh_size = sizeof rela_dyn,
		.sh_link = NDX_DYNSYM, /* dynsym section index */
		.sh_info = 0,
		.sh_addralign = sizeof (Elf64_Rela),
		.sh_entsize = sizeof (Elf64_Rela)
	},
	/*[NDX_HASH] = */ (Elf64_Shdr) { // hash
		.sh_name = 47,
		.sh_type = SHT_HASH,
		.sh_flags = SHF_ALLOC,
		.sh_addr = (char*) &hash[0] - (char*) &ehdr,
		.sh_offset = (char*) &hash[0] - (char*) &ehdr,
		.sh_size = sizeof hash,
		.sh_link = NDX_DYNSYM, /* dynsym section index */
		.sh_info = 0,
		.sh_addralign = sizeof (Elf64_Word),
		.sh_entsize = sizeof (Elf64_Word)
	},
	/*[NDX_DYNSTR] =*/ (Elf64_Shdr) { // dynstr
		.sh_name = 39,
		.sh_type = SHT_STRTAB,
		.sh_flags = SHF_ALLOC,
		.sh_addr = &dynstr[0] - (char*) &ehdr,
		.sh_offset = &dynstr[0] - (char*) &ehdr,
		.sh_size = sizeof dynstr,
		.sh_link = 0,
		.sh_info = 0,
		.sh_addralign = 1,
		.sh_entsize = 0
	},
	/*[NDX_TEXT] =*/ (Elf64_Shdr) { // text
		.sh_name = 11,
		.sh_type = SHT_PROGBITS,
		.sh_flags = SHF_ALLOC | SHF_EXECINSTR,
		.sh_addr = (char*) &first_user_word - (char*) &ehdr,
		.sh_offset = (char*) &first_user_word - (char*) &ehdr,
		.sh_size = TEXT_SZ,
		.sh_link = 0,
		.sh_info = 0,
		.sh_addralign = 16,
		.sh_entsize = 0
	},
	/*[NDX_RODATA] =*/ (Elf64_Shdr) { // rodata
		.sh_name = 23,
		.sh_type = SHT_PROGBITS,
		.sh_flags = SHF_ALLOC,
		.sh_addr = (char*) &first_user_word + TEXT_SZ - (char*) &ehdr,
		.sh_offset = (char*) &first_user_word + TEXT_SZ - (char*) &ehdr,
		.sh_size = RODATA_SZ,
		.sh_link = 0,
		.sh_info = 0,
		.sh_addralign = sizeof (void*),
		.sh_entsize = 0
	},
	/*[NDX_DATA] =*/ (Elf64_Shdr) { // data
		.sh_name = 17,
		.sh_type = SHT_PROGBITS,
		.sh_flags = SHF_ALLOC | SHF_WRITE,
		.sh_addr = (char*) &first_user_word + TEXT_SZ + RODATA_SZ - (char*) &ehdr,
		.sh_offset = (char*) &first_user_word + TEXT_SZ + RODATA_SZ - (char*) &ehdr,
		.sh_size = DATA_SZ,
		.sh_link = 0,
		.sh_info = 0,
		.sh_addralign = sizeof (void*),
		.sh_entsize = 0
	}
	// bss?
};

static Elf64_Dyn dynamic[DYNAMIC_N] __attribute__((section(".elf_zygote"))) = {
	(Elf64_Dyn) {
		.d_tag = DT_HASH,
		.d_un = { d_ptr: (Elf64_Addr) shdrs[NDX_HASH].sh_addr }
	},
	(Elf64_Dyn) {
		.d_tag = DT_STRTAB,
		.d_un = { d_ptr: (Elf64_Addr) shdrs[NDX_DYNSTR].sh_addr }
	},
	(Elf64_Dyn) {
		.d_tag = DT_SYMTAB,
		.d_un = { d_ptr: (Elf64_Addr) shdrs[NDX_DYNSYM].sh_addr }
	},
	(Elf64_Dyn) {
		.d_tag = DT_SYMENT,
		.d_un = { d_val: sizeof (Elf64_Sym) }
	},
	(Elf64_Dyn) {
		.d_tag = DT_RELA,
		.d_un = { d_ptr: (Elf64_Addr) shdrs[NDX_RELA_DYN].sh_addr }
	},
	(Elf64_Dyn) {
		.d_tag = DT_RELASZ,
		.d_un = { d_val: sizeof rela_dyn }
	},
	(Elf64_Dyn) {
		.d_tag = DT_RELAENT,
		.d_un = { d_val: sizeof (Elf64_Rela) }
	},
	(Elf64_Dyn) {
		.d_tag = DT_STRSZ,
		.d_un = { d_val: sizeof dynstr }
	},
	(Elf64_Dyn) {
		.d_tag = DT_LD_TEXTBUMP,
		.d_un = { d_ptr: shdrs[NDX_TEXT].sh_addr }
	},
	(Elf64_Dyn) {
		.d_tag = DT_LD_RODATABUMP,
		.d_un = { d_val: shdrs[NDX_RODATA].sh_addr }
	},
	(Elf64_Dyn) {
		.d_tag = DT_LD_DATABUMP,
		.d_un = { d_val: shdrs[NDX_DATA].sh_addr }
	},
	(Elf64_Dyn) {
		.d_tag = DT_LD_DYNSTRBUMP,
		.d_un = { d_val: 17 }
	},
	(Elf64_Dyn) {
		.d_tag = DT_LD_DYNSYMBUMP,
		.d_un = { d_val: MAX_SYMS - 2 }
	},
	(Elf64_Dyn) {
		.d_tag = DT_NULL,
		.d_un = { d_val: 0 }
	}
};

static Elf64_Sym dynsym[MAX_SYMS] __attribute__((section(".elf_zygote"))) = {
	[0] = (Elf64_Sym) {
		.st_name = 0,
		.st_info = 0,
		.st_other = 0,
		.st_shndx = 0,
		.st_value = 0,
		.st_size = 0
	},
	[1] = (Elf64_Sym) { // define a local symbol for the shdrs
		.st_name = 10, /* _SHDRS */
		.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_OBJECT),
		.st_other = ELF64_ST_VISIBILITY(STV_DEFAULT),
		.st_shndx = SHN_ABS,
		.st_value = phdrs[1].p_vaddr,
		.st_size = sizeof shdrs
	}, /* , // do this in the init function, until g++ supports designated initializers
	
	/*[MAX_SYMS - 1] = (Elf64_Sym) { // _DYNAMIC
		.st_name = 1, 
		.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_NOTYPE),
		.st_other = ELF64_ST_VISIBILITY(STV_DEFAULT),
		.st_shndx = 0,
		.st_value = shdrs[NDX_DYNAMIC].sh_addr,
		.st_size = sizeof dynamic
	}*/
};

static Elf64_Rela rela_dyn[RELA_DYN_N] __attribute__((section(".elf_zygote"))) = {
	/* do we need RELATIVEs for the .dynamic section? */
};

static Elf64_Word hash[2 + NBUCKET + MAX_SYMS]  __attribute__((section(".elf_zygote"))) = {
	NBUCKET,
	MAX_SYMS
};

static char shstrtab[SHSTRTAB_SZ] __attribute__((section(".elf_zygote"))) = {
	/* Offset 0 */ '\0',
	/* Offset 1 */ '.', 's', 'h', 's', 't', 'r', 't', 'a', 'b', '\0',
	/* Offset 11 */ '.', 't', 'e', 'x', 't', '\0',
	/* Offset 17 */ '.', 'd', 'a', 't', 'a', '\0',
	/* Offset 23 */ '.', 'r', 'o', 'd', 'a', 't', 'a', '\0',
	/* Offset 31 */ '.', 'd', 'y', 'n', 's', 'y', 'm', '\0', 
	/* Offset 39 */ '.', 'd', 'y', 'n', 's', 't', 'r', '\0', 
	/* Offset 47 */ '.', 'h', 'a', 's', 'h', '\0',
	/* Offset 53 */ '.', 'd', 'y', 'n', 'a', 'm', 'i', 'c', '\0',
	/* Offset 62 */ '.', 'r', 'e', 'l', 'a', '.', 'd', 'y', 'n', '\0'
};

static char dynstr[DYNSTR_SZ] __attribute__((section(".elf_zygote"))) = {
	/* Offset 0 */  '\0',
	/* Offset 1 */  '_', 'D', 'Y', 'N', 'A', 'M', 'I', 'C', '\0',
	/* Offset 10 */ '_', 'S', 'H', 'D', 'R', 'S', '\0'
};

static unsigned long first_user_word __attribute__((section(".elf_zygote")));

size_t _ld_elfproto_stored_sz;
size_t _ld_elfproto_memsz;
void *_ld_elfproto_begin = &ehdr;

static void init(void) __attribute__((constructor));
static void init(void)
{	
	dynsym[MAX_SYMS - 1/* 2 */] = (Elf64_Sym) { // _DYNAMIC
		.st_name = 1, 
		.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_OBJECT),
		.st_other = ELF64_ST_VISIBILITY(STV_DEFAULT),
		.st_shndx = NDX_DYNAMIC,
		.st_value = /* NO! can't do this, because C++ initialization and destruction
		     is weird: shdrs is initialized by code. */ // shdrs[NDX_DYNAMIC].sh_addr,
			 // duplicate the address calculation instead
			 (char*) &dynamic[0] - (char*) &ehdr,
		.st_size = sizeof dynamic
	};
	// _SHDRS is a local sym

	elf64_hash_init(
		(char *) &hash[0],            /* hash section */
		sizeof hash,              /* hash section size in bytes */
		NBUCKET,         /* nbucket */
		MAX_SYMS,
		&dynsym[0],
		&dynstr[0]
	);
	_ld_elfproto_stored_sz = ((char*) &first_user_word - (char*) &ehdr);
	_ld_elfproto_memsz = _ld_elfproto_stored_sz + TEXT_SZ + DATA_SZ + RODATA_SZ;
}
