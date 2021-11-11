#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <dlfcn.h>
#include <assert.h>
#include "dlbind.h"

int get_42(void)
{
	return 42;
}
void end_of_get_42(void) {}

int main(void)
{
	// create libfoo
	void *l = dlcreate("foo");
	
	// get some memory
	size_t len = (char*)end_of_get_42 - (char*)get_42;
	const char *alloc = dlalloc(l, len, SHF_EXECINSTR);
	assert(alloc);
	
	// copy our function into it
	// get a writable alias of the memory
	char *writable_alloc = /*dl_find_alias_with(SHF_READ|SHF_WRITE, alloc, l) */
		(char*)((uintptr_t) alloc + 33554432); // HACK
	memcpy(writable_alloc, get_42, len);
	
	// FIXME: reinstate a realloc call: *reallocate* to the smaller size (was 200)
	// dlrealloc(l, alloc, len);

	// FIXME: this test case doesn't work! libdlbind only works within liballocs
	// where we can hook open() calls and change MAP_PRIVATE to MAP_SHARED.
	// Perhaps we can make libsystrap a dependency of libdlbind?
	
	// bind it
	void *reloaded = dlbind(l, "meaning", (void*)alloc, len, STT_FUNC);
	assert(reloaded == l);
	
	// dlsym our function
	int (*func)(void) = (int(*)(void)) dlsym(l, "meaning");
	assert(func);
	
	// call it
	int m = func();
	printf("libdlbind-loaded function returned: %d\n", m);
	
	// FIXME: reinstate a dldelete call.
	// dldelete
	// dldelete(l);
	
	return 0;
}
