#include "libld.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <dlfcn.h>
#include <assert.h>

int get_42(void)
{
	return 42;
}
void end_of_get_42(void) {}

int main(void)
{
	// create libfoo
	ld_handle_t l = dlnew("foo");
	
	// get some memory
	char *alloc = dlalloc(l, 200, SHF_EXECINSTR);
	assert(alloc);
	
	// copy our function into it
	size_t len = (char*)end_of_get_42 - (char*)get_42;
	memcpy(alloc, get_42, len);
	
	// *reallocate* to the smaller size
	dlrealloc(l, alloc, len);
	
	// bind it using libld
	dlbind(l, "meaning", alloc, len);
	
	// dlsym our greetings function
	void *handle = libdl_handle(l);
	void (*func)(void) = (void(*)(void)) dlsym(handle, "meaning");
	assert(func);
	
	// call it
	int m = func();
	printf("libld-loaded function returned: %d\n", m);
	
	// dldelete
	dldelete(l);
	
	return 0;
}
