#ifndef LIBLD_H_
#define LIBLD_H_

#include <stdlib.h>

/* We extend the libdl interface with calls to dynamically create 
 * new libraries. */

//struct Ld_Entry;
//typedef struct Ld_Entry *ld_handle_t;

#define DT_LD_TEXTBUMP 0x6ffffee0
#define DT_LD_RODATABUMP 0x6ffffee1
#define DT_LD_DATABUMP 0x6ffffee2

/* Create a new shared library in this address space. */
void * dlnew(const char *libname);

/* Allocate a chunk of space in the file. */
void *dlalloc(void *l, size_t sz, unsigned flags);

/* Create a new symbol binding within a library created using dlnew().
 * The varargs may be used to specify the namespace, calling convention
 * and version string. Note that these need only be meaningful for text
 * symbols. Whether the object belongs in text, data or rodata is inferred
 * from the flags of the memory object containing address obj. */
int dlbind(void *lib, const char *symname, void *obj, size_t len, ...);

/* Closes and releases all resources associated with this handle. 
 * It must have been returned by dlnew(). */
int dldelete(void *);

/* Lookup a text symbol, accounting for namespace, calling convention
 * and version string. */
void *dldsym(void *handle, const char *symbol, void *namespace,
    unsigned long conv, const char *version_string);

extern const char *greatest_version;

/* The "conv" descriptor has the following encoding. 
 * LSB: must be 1 -- allows us to extend the encoding 
        to be specified by a pointer to block, later.
 * 4 bits: describing per-call options
 * 3 bits * n: describing per-argument options, for up to 
        9 arguments (32-bit sytems), or
        19 arguments (64-bit systems). */
enum argument_options
{
	INDIRECT = 1,
	APP_CHECKED = 2,   /* e.g. nonnull, ... */
	LANGVM_CHECKED = 4, /* e.g. already a valid Java object, ... 
	                       -- hmm, could merge this with INDIRECT and save bits? 
	                          i.e. */
	MAX_PLUS_ONE = 8
};

#endif
