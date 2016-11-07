#ifndef LIBDLBIND_SYMHASH_H_
#define LIBDLBIND_SYMHASH_H_

#include <elf.h>

void
elf64_hash_init(
	char *section,            /* hash section */
	size_t size,              /* hash section size in bytes */
	unsigned nbucket,          /* nbucket */
	unsigned nsyms,
	Elf64_Sym *symtab /* [nsyms] */,
	const char *strtab
	);

void
elf64_hash_put(
	char *section,            /* has section */
	size_t size,              /* hash section size in bytes */
	unsigned nbucket,         /* nbucket -- must match existing section! */
	unsigned nsyms,           /* symbol table entry count */
	Elf64_Sym *symtab /* [nsyms] */,    /* symbol table */
	const char *strtab,
	unsigned symind           /* assume this symind was unused previously! */
	);

Elf64_Sym *
elf64_hash_get(
	char *section,            /* has section */
	size_t size,              /* hash section size in bytes */
	unsigned nbucket,         /* nbucket -- must match existing section! */
	unsigned nsyms,           /* symbol table entry count */
	Elf64_Sym *symtab /* [nsyms] */,    /* symbol table */
	const char *strtab,
	const char *key
	);

#endif
