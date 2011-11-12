#include "libld.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <dlfcn.h>
#include <assert.h>

static void hello(void)
{
	printf("Hello from a libld-loaded library\n");
}
static void end_of_hello(void) {}

int main(void)
{
	// create libfoo
	ld_handle_t l = dlnew("foo");
	
	// get some memory
	char *alloc = (char*) memalign(4096, 4096);
	assert(alloc);
	
	// copy our function into it
	size_t len = (char*)end_of_hello - (char*)hello;
	memcpy(alloc, hello, len);
	
	// bind it using libld
	dlbind(l, "greetings", alloc, len);
	
	// dlsym our greetings function
	void *handle = libdl_handle(l);
	void (*func)(void) = (void(*)(void)) dlsym(handle, "greetings");
	
	// call it
	func();
	
	// dldelete
	dldelete(l);
	
	return 0;
}
