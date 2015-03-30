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
#include "elfproto.h"
#include "symhash.h"

int main(void)
{
	/* dlnew the file */
	struct link_map *handle = dlnew();
	assert(handle);
	/* now allow, bind, etc.. */
	void *alloc = handle->l_ld
	/* now reload */
	return 0;
}
