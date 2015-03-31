#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <string.h>
#include <link.h>
#include "libld.h"

int get_42(void)
{
	return 42;
}
void end_of_get_42(void) {}

int get_43(void)
{
	return 43;
}
void end_of_get_43(void) {}

#define MAX(a, b) (((a) < (b)) ? (b) : (a))

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define PAGE_BOUNDARY_LOWER_OR_EQ(addr) (void*)(((uintptr_t) (addr)) % PAGE_SIZE == 0 ? (addr) : \
	(void*)(((uintptr_t)(addr) / PAGE_SIZE) * PAGE_SIZE))
#define PAGE_BOUNDARY_HIGHER_OR_EQ(addr) (void*)(((uintptr_t) (addr)) % PAGE_SIZE == 0 ? (addr) : \
	(void*)((((uintptr_t)(addr) / PAGE_SIZE) + 1) * PAGE_SIZE))

int main(void)
{
	/* dlnew the file */
	struct link_map *handle = dlcreate(NULL);
	assert(handle);
	
	/* now allow, bind, etc.. */
	int *p_int = dlalloc(handle, sizeof (int), SHF_WRITE);
	assert(p_int);
	handle = dlbind(handle, "my_int", p_int, sizeof *p_int, STT_OBJECT);
	assert(handle);
	void *addr = dlsym(handle, "my_int");
	assert(addr);
	assert(addr == p_int);
	
	/* Can we modify data/code and have it survive a reload? */
	*p_int = 69105;
	size_t sizeof_get_42 = (char*) end_of_get_42 - (char*) get_42;
	size_t sizeof_get_43 = (char*) end_of_get_43 - (char*) get_43;
	size_t function_size = MAX(sizeof_get_42, sizeof_get_43);
	int (*p_func)(void) = dlalloc(handle, function_size, SHF_EXECINSTR);
	/* We have to mprotect it before we write it. */
	int ret = mprotect(PAGE_BOUNDARY_LOWER_OR_EQ(p_func), 
		PAGE_BOUNDARY_HIGHER_OR_EQ(p_func) - PAGE_BOUNDARY_LOWER_OR_EQ(p_func), 
		PROT_READ|PROT_WRITE);
	assert(ret == 0);
	/* Write the function */
	memcpy(p_func, (char*) get_42, sizeof_get_42);
	/* Bind it */
	handle = dlbind(handle, "my_func", p_func, function_size, STT_FUNC);
	addr = dlsym(handle, "my_func");
	assert(addr);
	assert(addr == p_func);
	/* Re-mprotect it. */
	ret = mprotect(PAGE_BOUNDARY_LOWER_OR_EQ(p_func), 
		PAGE_BOUNDARY_HIGHER_OR_EQ(p_func) - PAGE_BOUNDARY_LOWER_OR_EQ(p_func), 
		PROT_READ|PROT_EXEC);
	assert(ret == 0);
	assert(p_func() == 42);

	/* Did our int value survive? */
	assert(*p_int == 69105);
	/* Can we modify the code we just wrote? */
	ret = mprotect(PAGE_BOUNDARY_LOWER_OR_EQ(p_func), 
		PAGE_BOUNDARY_HIGHER_OR_EQ(p_func) - PAGE_BOUNDARY_LOWER_OR_EQ(p_func), 
		PROT_READ|PROT_WRITE);
	assert(ret == 0);
	memcpy(p_func, (char*) get_43, sizeof_get_43);
	ret = mprotect(PAGE_BOUNDARY_LOWER_OR_EQ(p_func), 
		PAGE_BOUNDARY_HIGHER_OR_EQ(p_func) - PAGE_BOUNDARY_LOWER_OR_EQ(p_func), 
		PROT_READ|PROT_EXEC);
	assert(ret == 0);
	/* Does the code modification survive a reload? */
	handle = dlreload(handle);
	assert(p_func() == 43);
	
	return 0;
}
