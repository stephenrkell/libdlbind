#ifndef DLBIND_INTERNAL_H_
#define DLBIND_INTERNAL_H_

extern __thread const char *dlbind_open_active_on __attribute__((visibility("hidden")));
void memcpy_elfproto_to(void *dest) __attribute__((visibility("hidden")));

#endif
