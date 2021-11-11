#ifndef DLBIND_H_
#define DLBIND_H_

#include <stdlib.h>
#include <elf.h>

/* For forcing init (for early-startup usage). */
void __libdlbind_do_init(void);

/* We extend the libdl interface with calls to dynamically create 
 * new libraries. */

/* Create a new shared library in this address space. */
void *dlcreate(const char *libname);

/* Allocate a chunk of space in the file. The flags are SHF_* flags. */
void *dlalloc(void *l, size_t sz, unsigned flags);

/* Create a new symbol binding within a library created using dlnew().
 * FIXME: maybe by varargs, allow specifying the namespace, calling convention
 * and version string. Note that these need only be meaningful for text
 * symbols.
 * Currently this returns the reloaded handle. We shouldn't push
 * reloading onto clients. */
void *dlbind(void *lib, const char *symname, void *obj, size_t len, Elf64_Word type);

/* Closes and releases all resources associated with this handle. 
 * It must have been returned by dlcreate(). */
// FIXME: this is not implemented. Instead we unlink everything in a destructor
int dldelete(void *);

/* Lookup a text symbol, accounting for namespace, calling convention
 * and version string. */
void *dldsym(void *handle, const char *symbol, void *namespace,
    unsigned long conv, const char *version_string);

/* The "conv" descriptor has the following encoding. 
 * LSB: must be 1 -- allows us to extend the encoding 
        to be specified by a pointer to block, later.
 * 4 bits: describing per-call options
 * 3 bits * n: describing per-argument options, for up to 
        9 arguments (32-bit sytems), or
        19 arguments (64-bit systems).
 * 
 * Think "multiple entry points".
 */
enum argument_options
{
	INDIRECT = 1,
	APP_CHECKED = 2,   /* e.g. nonnull, ... */
	LANGVM_CHECKED = 4, /* e.g. already [known to be] a valid Java object, ... 
	                       -- hmm, could merge this with INDIRECT and save bits? */
	MAX_PLUS_ONE = 8
};

#endif
