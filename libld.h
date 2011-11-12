#ifndef LIBLD_H_
#define LIBLD_H_

#include <stdlib.h>

/* We extend the libdl interface with calls to dynamically create 
 * new libraries. */

struct Ld_Entry;
typedef struct Ld_Entry *ld_handle_t;

/* Create a new shared library in this address space. */
ld_handle_t dlnew(const char *libname);

/* Create a new symbol binding within a library created using dlnew().
 * The varargs may be used to specify the namespace, calling convention
 * and version string. Note that these need only be meaningful for text
 * symbols. Whether the object belongs in text, data or rodata is inferred
 * from the flags of the memory object containing address obj. */
int dlbind(ld_handle_t lib, const char *symname, void *obj, size_t len, ...);

/* Closes and releases all resources associated with this handle. 
 * It must have been returned by dlnew(). */
int dldelete(ld_handle_t);

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

/* HACKy helper: until we have unified libdl handles with libld handles,
 * provide a function to map between them. */
void *libdl_handle(ld_handle_t);

#endif
