#ifndef HISI_WPA_CONTEXT_INTERNAL_H
#define HISI_WPA_CONTEXT_INTERNAL_H

#include "hisi_wpa_supplicant.h"

#include "common/defs.h"

struct wpa_global;
struct wpa_supplicant;
struct wpa_ssid;

#define HISI_WPA_EVENT_CAPACITY 8u

struct hisi_wpa_context {
    struct wpa_global *global;
    struct wpa_supplicant *interface;
    struct wpa_ssid *network;
    void *driver_owner;
    enum wpa_states observed_state;
    struct hisi_wpa_event events[HISI_WPA_EVENT_CAPACITY];
    uint32_t dropped_events;
    uint32_t total_dropped_events;
    uint8_t event_read;
    uint8_t event_write;
    uint8_t max_event_depth;
    uint8_t initialized;
    uint8_t first_eapol_retry_pending;
    uint8_t first_eapol_timeouts;
    uint8_t first_eapol_disconnect_events;
    uint8_t first_eapol_fallbacks;
    uint8_t first_eapol_local_disconnects;
    uint8_t first_eapol_cached_retries;
    uint8_t first_eapol_scan_retries;
    uint8_t temporary_reject_retries;
    uint8_t temporary_reject_cached_retries;
    uint8_t temporary_reject_scan_retries;
    uint8_t temporary_reject_retry_pending;
};

#endif
