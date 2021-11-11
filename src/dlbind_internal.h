#ifndef DLBIND_INTERNAL_H_
#define DLBIND_INTERNAL_H_

#ifndef TEXT_SZ
#define TEXT_SZ 33554432
#endif

#ifndef DATA_SZ
#define DATA_SZ 16777216
#endif

#ifndef RODATA_SZ
#define RODATA_SZ 8388608
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

/* FIXME: this shouldn't be a fixed value, for security.
 * Instead, randomize it at elfproto instantiation time.
 * On 64-bit platforms we can reserve a large vaddr space,
 * giving plenty of entropy. On 32-bit platforms we may
 * need to do some kind of "emulated W|X" using mremap and
 * hysteresis, and/or to whitelist which code is allowed
 * to do writes. */
#ifndef TEXT_WRITABLE_VADDR_DELTA
#define TEXT_WRITABLE_VADDR_DELTA 67108864
#endif

extern __thread const char *dlbind_open_active_on __attribute__((visibility("hidden")));
void memcpy_elfproto_to(void *dest) __attribute__((visibility("hidden")));

#endif
