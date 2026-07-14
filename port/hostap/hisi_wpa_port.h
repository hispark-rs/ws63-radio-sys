#ifndef HISI_WPA_PORT_H
#define HISI_WPA_PORT_H

#include "hisi_wpa_supplicant.h"

const struct hisi_wpa_os_hooks *hisi_wpa_os_current(void);
void *hisi_wpa_os_allocate_zeroed(size_t size, size_t alignment);
void *hisi_wpa_os_reallocate_zeroed(void *pointer, size_t size,
    size_t alignment);
void hisi_wpa_os_deallocate(void *pointer);
int32_t hisi_wpa_os_monotonic_us(uint64_t *value);
int32_t hisi_wpa_os_wall_clock_us(uint64_t *value);
int32_t hisi_wpa_os_sleep_ms(uint32_t milliseconds);
int32_t hisi_wpa_os_fill_entropy(uint8_t *output, size_t output_len);
int32_t hisi_wpa_os_wait_for_work(uint32_t timeout_ms);
void hisi_wpa_os_wake_runner(void);

#endif
