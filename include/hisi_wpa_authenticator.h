#ifndef HISI_WPA_AUTHENTICATOR_H
#define HISI_WPA_AUTHENTICATOR_H

#include <stddef.h>
#include <stdint.h>

#include "hisi_wpa_supplicant.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HISI_WPA_AP_ABI_VERSION 1u

enum hisi_wpa_ap_security {
    HISI_WPA_AP_SECURITY_OPEN = 0,
    HISI_WPA_AP_SECURITY_WPA2_PSK = 1,
    HISI_WPA_AP_SECURITY_WPA3_SAE = 2,
};

struct hisi_wpa_ap_beacon {
    uint16_t abi_version;
    uint8_t hidden_ssid;
    uint8_t sae_pwe;
    uint16_t beacon_interval;
    uint8_t dtim_period;
    uint8_t channel;
    uint32_t frequency_mhz;
    const uint8_t *head;
    size_t head_len;
    const uint8_t *tail;
    size_t tail_len;
};

/*
 * WS63-specific AP driver capabilities consumed by the upstream hostapd port.
 * This is deliberately separate from hisi_wpa_driver_hooks: selecting an AP
 * authenticator must not pull hostapd into the default STA supplicant archive.
 */
struct hisi_wpa_ap_driver_hooks {
    uint16_t abi_version;
    uint16_t reserved;
    void *driver;
    int32_t (*get_own_address)(void *driver, uint8_t address[6]);
    int32_t (*set_netdev_enabled)(void *driver, uint8_t enabled);
    int32_t (*configure_beacon)(void *driver,
        const struct hisi_wpa_ap_beacon *beacon);
    int32_t (*send_eapol)(void *driver, const uint8_t destination[6],
        const uint8_t *frame, size_t frame_len);
    int32_t (*send_mgmt)(void *driver, uint32_t frequency_mhz,
        const uint8_t *frame, size_t frame_len);
    int32_t (*install_key)(void *driver, const struct hisi_wpa_key *key,
        const uint8_t *material, size_t material_len);
    int32_t (*remove_key)(void *driver, const struct hisi_wpa_key *key);
    int32_t (*remove_station)(void *driver, const uint8_t address[6]);
};

int32_t hisi_wpa_ap_driver_install(
    const struct hisi_wpa_ap_driver_hooks *hooks);
int32_t hisi_wpa_ap_driver_uninstall(void *driver);

_Static_assert(offsetof(struct hisi_wpa_ap_driver_hooks, driver) ==
    sizeof(void *), "hisi_wpa_ap_driver_hooks prefix drift");
_Static_assert(sizeof(struct hisi_wpa_ap_driver_hooks) == 10 * sizeof(void *),
    "hisi_wpa_ap_driver_hooks ABI drift");

#ifdef __cplusplus
}
#endif

#endif
