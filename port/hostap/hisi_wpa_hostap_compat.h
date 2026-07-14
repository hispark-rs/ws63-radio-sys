#ifndef HISI_WPA_HOSTAP_COMPAT_H
#define HISI_WPA_HOSTAP_COMPAT_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <limits.h>

/* Keep hostap's fixed-width aliases compatible with its printf contracts.
 * Some RV32 newlib builds spell uint32_t as unsigned long; it is still four
 * bytes, but upstream correctly uses %u for u32 throughout the state machine.
 * Fixing the aliases here preserves both width and C variadic type identity. */
typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
typedef long long s64;
typedef int s32;
typedef short s16;
typedef signed char s8;
#define WPA_TYPES_DEFINED
typedef unsigned int gid_t;

typedef struct hisi_wpa_file FILE;
struct in_addr { uint32_t s_addr; };
struct in6_addr { uint8_t s6_addr[16]; };

/* Freestanding libc surface used directly by upstream hostap. Most memory and
 * string operations are routed through os_* by OS_NO_C_LIB_DEFINES; keep the
 * remaining declarations explicit so the native profile cannot accidentally
 * inherit a host libc contract. Implementations are supplied by the firmware's
 * shared Rust/C runtime shim. */
int hisi_wpa_atoi(const char *value);
int hisi_wpa_abs(int value);
int hisi_wpa_isspace(int value);
int hisi_wpa_isblank(int value);
long hisi_wpa_strtol(const char *restrict value, char **restrict end, int base);
void hisi_wpa_qsort(void *base, size_t count, size_t size,
    int (*compare)(const void *left, const void *right));
int hisi_wpa_sscanf(const char *input, const char *format, ...);
int hisi_wpa_vsnprintf(char *buffer, size_t size, const char *format,
    va_list arguments);
void hisi_wpa_abort(void) __attribute__((noreturn));

/* newlib/Zephyr-compatible values used by hostap's internal negative errno
 * returns. These are part of the WS63 driver shim contract, not a claim that
 * the firmware provides a global errno implementation. */
#ifndef EAGAIN
#define EAGAIN 11
#endif
#ifndef EBUSY
#define EBUSY 16
#endif
#ifndef EINVAL
#define EINVAL 22
#endif
#ifndef EIO
#define EIO 5
#endif
#ifndef EOPNOTSUPP
#define EOPNOTSUPP 95
#endif
#ifndef EOF
#define EOF (-1)
#endif

/* The !IEEE8021X_EAPOL inline stub in upstream eapol_supp_sm.h uses free()
 * directly. Keep that allocation on the installed RTOS allocator instead of
 * introducing a second libc heap. os_free is declared by os.h before the stub
 * is instantiated. */
#define free os_free
#define memset os_memset
#define abort hisi_wpa_abort
#define abs hisi_wpa_abs
#define atoi hisi_wpa_atoi
#define isspace hisi_wpa_isspace
#define isblank hisi_wpa_isblank
#define qsort hisi_wpa_qsort
#define sscanf hisi_wpa_sscanf
#define strtol hisi_wpa_strtol
#define vsnprintf hisi_wpa_vsnprintf

/* Upstream includes.h pulls POSIX networking headers even when no socket,
 * file, or daemon backend is selected. The native profile injects this header
 * before every translation unit and uses only the freestanding declarations
 * below. */
#ifndef INCLUDES_H
#define INCLUDES_H
#endif

#if !defined(__APPLE__) && !defined(__linux__) && !defined(__GLIBC__) && \
    !defined(__FreeBSD__) && !defined(__NetBSD__) && \
    !defined(__DragonFly__) && !defined(__OpenBSD__)
#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN 1234
#endif
#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN 4321
#endif
#ifndef __BYTE_ORDER
#define __BYTE_ORDER __LITTLE_ENDIAN
#endif
#endif

#ifndef OS_NO_C_LIB_DEFINES
#define OS_NO_C_LIB_DEFINES
#endif
#include "common.h"

#endif
