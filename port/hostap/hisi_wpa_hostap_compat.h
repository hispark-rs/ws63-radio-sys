#ifndef HISI_WPA_HOSTAP_COMPAT_H
#define HISI_WPA_HOSTAP_COMPAT_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct hisi_wpa_file FILE;

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

#define OS_NO_C_LIB_DEFINES
#include "common.h"

#endif
