#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct hisi_wpa_file FILE;

#define OS_NO_C_LIB_DEFINES
#include "os.h"

#include "hisi_wpa_port.h"

#define HISI_WPA_C_ALIGNMENT 8u

static int split_time(uint64_t microseconds, os_time_t *sec, os_time_t *usec)
{
    if (sec == NULL || usec == NULL)
        return -1;
    *sec = (os_time_t) (microseconds / 1000000u);
    *usec = (os_time_t) (microseconds % 1000000u);
    return 0;
}

void os_sleep(os_time_t sec, os_time_t usec)
{
    uint64_t total_us;
    uint64_t milliseconds;

    if (sec < 0 || usec < 0)
        return;
    total_us = (uint64_t) sec * 1000000u + (uint64_t) usec;
    milliseconds = (total_us + 999u) / 1000u;
    if (milliseconds > UINT32_MAX)
        milliseconds = UINT32_MAX;
    (void) hisi_wpa_os_sleep_ms((uint32_t) milliseconds);
}

int os_get_time(struct os_time *time)
{
    uint64_t value;
    if (time == NULL || hisi_wpa_os_wall_clock_us(&value) != 0)
        return -1;
    return split_time(value, &time->sec, &time->usec);
}

int os_get_reltime(struct os_reltime *time)
{
    uint64_t value;
    if (time == NULL || hisi_wpa_os_monotonic_us(&value) != 0)
        return -1;
    return split_time(value, &time->sec, &time->usec);
}

int os_mktime(int year, int month, int day, int hour, int min, int sec,
    os_time_t *time)
{
    (void) year; (void) month; (void) day; (void) hour;
    (void) min; (void) sec; (void) time;
    return -1;
}

int os_gmtime(os_time_t time, struct os_tm *result)
{
    (void) time; (void) result;
    return -1;
}

int os_daemonize(const char *pid_file)
{
    (void) pid_file;
    return -1;
}

void os_daemonize_terminate(const char *pid_file) { (void) pid_file; }

int os_get_random(unsigned char *buffer, size_t length)
{
    return hisi_wpa_os_fill_entropy(buffer, length);
}

unsigned long os_random(void)
{
    uint32_t value = 0;
    if (hisi_wpa_os_fill_entropy((uint8_t *) &value, sizeof(value)) != 0)
        return 0;
    return (unsigned long) value;
}

char *os_rel2abs_path(const char *path) { (void) path; return NULL; }
int os_program_init(void) { return hisi_wpa_os_current() == NULL ? -1 : 0; }
void os_program_deinit(void) {}
int os_setenv(const char *name, const char *value, int overwrite)
{
    (void) name; (void) value; (void) overwrite; return -1;
}
int os_unsetenv(const char *name) { (void) name; return -1; }
char *os_readfile(const char *name, size_t *length)
{
    (void) name; (void) length; return NULL;
}
int os_file_exists(const char *name) { (void) name; return 0; }
int os_fdatasync(FILE *stream) { (void) stream; return 0; }

void *os_malloc(size_t size)
{
    return hisi_wpa_os_allocate_zeroed(size, HISI_WPA_C_ALIGNMENT);
}

void *os_zalloc(size_t size) { return os_malloc(size); }

void *os_realloc(void *pointer, size_t size)
{
    return hisi_wpa_os_reallocate_zeroed(pointer, size,
        HISI_WPA_C_ALIGNMENT);
}

void os_free(void *pointer)
{
    if (pointer != NULL)
        hisi_wpa_os_deallocate(pointer);
}

void *os_memcpy(void *destination, const void *source, size_t length)
{
    uint8_t *dst = destination;
    const uint8_t *src = source;
    size_t index;
    for (index = 0; index < length; index++)
        dst[index] = src[index];
    return destination;
}

void *os_memmove(void *destination, const void *source, size_t length)
{
    uint8_t *dst = destination;
    const uint8_t *src = source;
    size_t index;
    if ((uintptr_t) dst <= (uintptr_t) src) {
        for (index = 0; index < length; index++)
            dst[index] = src[index];
    } else {
        for (index = length; index > 0; index--)
            dst[index - 1] = src[index - 1];
    }
    return destination;
}

void *os_memset(void *destination, int value, size_t length)
{
    uint8_t *dst = destination;
    size_t index;
    for (index = 0; index < length; index++)
        dst[index] = (uint8_t) value;
    return destination;
}

int os_memcmp(const void *left, const void *right, size_t length)
{
    const uint8_t *a = left;
    const uint8_t *b = right;
    size_t index;
    for (index = 0; index < length; index++) {
        if (a[index] != b[index])
            return (int) a[index] - (int) b[index];
    }
    return 0;
}

int os_memcmp_const(const void *left, const void *right, size_t length)
{
    const uint8_t *a = left;
    const uint8_t *b = right;
    uint8_t difference = 0;
    size_t index;
    for (index = 0; index < length; index++)
        difference |= a[index] ^ b[index];
    return difference;
}

void *os_memdup(const void *source, size_t length)
{
    void *copy = os_malloc(length);
    if (copy != NULL && source != NULL)
        os_memcpy(copy, source, length);
    return copy;
}

size_t os_strlen(const char *string)
{
    const char *end = string;
    while (*end != '\0') end++;
    return (size_t) (end - string);
}

char *os_strdup(const char *string)
{
    size_t length = os_strlen(string) + 1;
    char *copy = os_malloc(length);
    if (copy != NULL)
        os_memcpy(copy, string, length);
    return copy;
}

int os_strcmp(const char *left, const char *right)
{
    while (*left != '\0' && *left == *right) { left++; right++; }
    return (unsigned char) *left - (unsigned char) *right;
}

int os_strncmp(const char *left, const char *right, size_t length)
{
    size_t index;
    for (index = 0; index < length; index++) {
        unsigned char a = (unsigned char) left[index];
        unsigned char b = (unsigned char) right[index];
        if (a != b || a == 0)
            return (int) a - (int) b;
    }
    return 0;
}

static unsigned char ascii_lower(unsigned char value)
{
    return value >= 'A' && value <= 'Z' ? (unsigned char) (value + 32) : value;
}

int os_strcasecmp(const char *left, const char *right)
{
    while (*left != '\0' && ascii_lower((unsigned char) *left) ==
        ascii_lower((unsigned char) *right)) { left++; right++; }
    return (int) ascii_lower((unsigned char) *left) -
        (int) ascii_lower((unsigned char) *right);
}

int os_strncasecmp(const char *left, const char *right, size_t length)
{
    size_t index;
    for (index = 0; index < length; index++) {
        unsigned char a = ascii_lower((unsigned char) left[index]);
        unsigned char b = ascii_lower((unsigned char) right[index]);
        if (a != b || a == 0)
            return (int) a - (int) b;
    }
    return 0;
}

char *os_strchr(const char *string, int value)
{
    do {
        if (*string == (char) value) return (char *) string;
    } while (*string++ != '\0');
    return NULL;
}

char *os_strrchr(const char *string, int value)
{
    const char *match = NULL;
    do {
        if (*string == (char) value) match = string;
    } while (*string++ != '\0');
    return (char *) match;
}

char *os_strstr(const char *haystack, const char *needle)
{
    size_t length = os_strlen(needle);
    if (length == 0) return (char *) haystack;
    while (*haystack != '\0') {
        if (os_strncmp(haystack, needle, length) == 0)
            return (char *) haystack;
        haystack++;
    }
    return NULL;
}

size_t os_strlcpy(char *destination, const char *source, size_t size)
{
    size_t length = os_strlen(source);
    size_t copy = size == 0 ? 0 : (length < size - 1 ? length : size - 1);
    if (copy != 0) os_memcpy(destination, source, copy);
    if (size != 0) destination[copy] = '\0';
    return length;
}

__attribute__((weak)) int os_snprintf(char *destination, size_t size,
    const char *format, ...)
{
    (void) format;
    if (size != 0 && destination != NULL)
        destination[0] = '\0';
    return -1;
}

int os_exec(const char *program, const char *argument, int wait_completion)
{
    (void) program; (void) argument; (void) wait_completion; return -1;
}
