#ifndef HISI_WPA_DRIVER_PORT_H
#define HISI_WPA_DRIVER_PORT_H

#include <stddef.h>
#include <stdint.h>

#include "hisi_wpa_supplicant.h"

int32_t hisi_wpa_driver_install(const struct hisi_wpa_driver_hooks *hooks);
int32_t hisi_wpa_driver_uninstall(void *driver);
const struct hisi_wpa_driver_hooks *hisi_wpa_driver_current(void);
const struct hisi_wpa_driver_hooks *hisi_wpa_driver_acquire(void);
void hisi_wpa_driver_release(void);
int hisi_wpa_l2_is_active(void);

int32_t hisi_wpa_driver_feed_scan_result(void *private_data,
    const struct hisi_wpa_scan_result *result);
int32_t hisi_wpa_driver_feed_scan_done(void *private_data, int32_t status);
int32_t hisi_wpa_driver_feed_associate_result(void *private_data,
    const struct hisi_wpa_associate_result *result);
int32_t hisi_wpa_driver_feed_disconnect(void *private_data,
    const struct hisi_wpa_disconnect_event *event);
int hisi_wpa_driver_is_disconnected(const void *private_data);

/* Called only by the runner after it dequeues a bounded vendor event. */
int32_t hisi_wpa_l2_feed(const uint8_t source[6], const uint8_t *frame,
    size_t frame_len);

#endif
