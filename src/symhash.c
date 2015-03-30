#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <elf.h>
#include "symhash.h"

/* Mutable implementation of the ELF symbol hash table.
 * 
 * The table is fixed-size, for now, and uses an upper-bound
 * on the symtab size.
 * 
 * No public look-up function! Use dlsym().
 * 
 */

static 
unsigned long
elf64_hash(const unsigned char *name)
{
	unsigned long h = 0, g;
	while (*name)
	{
		h = (h << 4) + *name++;
		if (0 != (g = (h & 0xf0000000))) h ^= g >> 24;
		h &= 0x0fffffff;
	}
	return h;
}

static
void 
chain_sym(Elf64_Word *buckets,
		unsigned nbucket,
		unsigned nchain,
		const char *name,
		unsigned symind
		)
{
	assert(name[0] != '\0');
	
	/* Which bucket does the sym go in? */
	unsigned bucket = elf64_hash(name) % nbucket;
	/* Find a place to chain it */
	Elf64_Word *pos = &buckets[bucket];
	while (*pos != STN_UNDEF)
	{
		pos = &buckets[nbucket + *pos];
	}
	*pos = symind;
}
static
unsigned 
bucket_lookup(Elf64_Word *buckets,
		unsigned nbucket,
		unsigned nchain,
		const char *name,
		Elf64_Sym *symtab,
		const char *strtab
		)
{
	/* Which bucket does the sym go in? */
	unsigned bucket = elf64_hash(name) % nbucket;
	/* Find it */
	Elf64_Word *pos = &buckets[bucket];
	while (*pos != STN_UNDEF)
	{
		unsigned stroff = symtab[*pos].st_name;
		if (0 == strcmp(strtab + stroff, name)) return *pos;
	}
	return STN_UNDEF;
}

void
elf64_hash_init(
	char *section,            /* hash section */
	size_t size,              /* hash section size in bytes */
	unsigned nbucket,          /* nbucket */
	unsigned nsyms,
	Elf64_Sym *symtab /* [nsyms] */,
	const char *strtab
	)
{
	/* nchain is nsyms */
	Elf64_Word *words = (Elf64_Word *) section;
	words[0] = nbucket;
	words[1] = nsyms; // i.e. nchain
	for (unsigned i = 1; i < nsyms; ++i)
	{
		const char *symname = &strtab[symtab[i].st_name];
		elf64_hash_put(section, size, nbucket, nsyms, symtab, strtab, i);
	}
}

void
elf64_hash_put(
	char *section,            /* has section */
	size_t size,              /* hash section size in bytes */
	unsigned nbucket,         /* nbucket -- must match existing section! */
	unsigned nsyms,           /* symbol table entry count */
	Elf64_Sym *symtab,    /* symbol table */
	const char *strtab,
	unsigned symind           /* assume this symind was unused previously! */
	)
{
	const char *key = &strtab[symtab[symind].st_name];
	
	// the empty string is always in the table
	if (*key == '\0') return;
	
	/* nchain is nsyms */
	Elf64_Word *words = (Elf64_Word *) section;
	
	/* Assert that symname is not currently used */
	assert(STN_UNDEF == bucket_lookup(&words[2],
			nbucket,
			nsyms,
			key,
			symtab,
			strtab
		)
	);
	
	/* Assert that symind is not in the table. */
	
	
	/* Chain it. */
	chain_sym(&words[2], nbucket, nsyms, key, symind);
}


// elf_hash_del(
