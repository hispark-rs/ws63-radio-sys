#include "hisi_wpa_hostap_compat.h"
#include "drivers/driver.h"

#include "hisi_wpa_ap_driver_port.h"

struct ws63_ap_driver_data {
    struct hostapd_data *hostapd;
    struct hisi_wpa_ap_driver_hooks hooks;
    uint8_t own_address[ETH_ALEN];
};

static int map_cipher(enum wpa_alg algorithm, uint8_t *cipher)
{
    switch (algorithm) {
    case WPA_ALG_NONE:
        *cipher = HISI_WPA_CIPHER_NONE;
        return 0;
    case WPA_ALG_TKIP:
        *cipher = HISI_WPA_CIPHER_TKIP;
        return 0;
    case WPA_ALG_CCMP:
        *cipher = HISI_WPA_CIPHER_CCMP;
        return 0;
    case WPA_ALG_BIP_CMAC_128:
        *cipher = HISI_WPA_CIPHER_BIP_CMAC_128;
        return 0;
    case WPA_ALG_GCMP:
        *cipher = HISI_WPA_CIPHER_GCMP;
        return 0;
    case WPA_ALG_GCMP_256:
        *cipher = HISI_WPA_CIPHER_GCMP_256;
        return 0;
    case WPA_ALG_CCMP_256:
        *cipher = HISI_WPA_CIPHER_CCMP_256;
        return 0;
    case WPA_ALG_BIP_GMAC_128:
        *cipher = HISI_WPA_CIPHER_BIP_GMAC_128;
        return 0;
    case WPA_ALG_BIP_GMAC_256:
        *cipher = HISI_WPA_CIPHER_BIP_GMAC_256;
        return 0;
    case WPA_ALG_BIP_CMAC_256:
        *cipher = HISI_WPA_CIPHER_BIP_CMAC_256;
        return 0;
    default:
        return -1;
    }
}

static uint32_t map_key_flags(enum key_flag flags)
{
    uint32_t mapped = 0;
    if ((flags & KEY_FLAG_MODIFY) != 0)
        mapped |= HISI_WPA_KEY_FLAG_MODIFY;
    if ((flags & KEY_FLAG_DEFAULT) != 0)
        mapped |= HISI_WPA_KEY_FLAG_DEFAULT;
    if ((flags & KEY_FLAG_RX) != 0)
        mapped |= HISI_WPA_KEY_FLAG_RX;
    if ((flags & KEY_FLAG_TX) != 0)
        mapped |= HISI_WPA_KEY_FLAG_TX;
    if ((flags & KEY_FLAG_GROUP) != 0)
        mapped |= HISI_WPA_KEY_FLAG_GROUP;
    if ((flags & KEY_FLAG_PAIRWISE) != 0)
        mapped |= HISI_WPA_KEY_FLAG_PAIRWISE;
    return mapped;
}

static void *ws63_ap_init(struct hostapd_data *hostapd,
    struct wpa_init_params *params)
{
    const struct hisi_wpa_ap_driver_hooks *hooks =
        hisi_wpa_ap_driver_acquire();
    struct ws63_ap_driver_data *driver;
    if (hooks == NULL || hostapd == NULL || params == NULL ||
        params->own_addr == NULL)
        goto failed;
    driver = os_zalloc(sizeof(*driver));
    if (driver == NULL)
        goto failed;
    driver->hostapd = hostapd;
    driver->hooks = *hooks;
    if (driver->hooks.get_own_address(driver->hooks.driver,
        driver->own_address) != 0 ||
        driver->hooks.set_netdev_enabled(driver->hooks.driver, 1) != 0) {
        os_free(driver);
        goto failed;
    }
    os_memcpy(params->own_addr, driver->own_address,
        sizeof(driver->own_address));
    return driver;

failed:
    if (hooks != NULL)
        hisi_wpa_ap_driver_release();
    return NULL;
}

static void ws63_ap_deinit(void *private_data)
{
    struct ws63_ap_driver_data *driver = private_data;
    if (driver == NULL)
        return;
    (void) driver->hooks.set_netdev_enabled(driver->hooks.driver, 0);
    os_memset(driver, 0, sizeof(*driver));
    os_free(driver);
    hisi_wpa_ap_driver_release();
}

static int ws63_ap_set_beacon(void *private_data,
    struct wpa_driver_ap_params *params)
{
    struct ws63_ap_driver_data *driver = private_data;
    struct hisi_wpa_ap_beacon beacon = { 0 };
    if (driver == NULL || params == NULL || params->freq == NULL ||
        params->ssid == NULL || params->ssid_len == 0 ||
        params->ssid_len > HISI_WPA_MAX_SSID_LEN ||
        params->beacon_int <= 0 || params->beacon_int > UINT16_MAX ||
        params->dtim_period <= 0 || params->dtim_period > UINT8_MAX ||
        params->freq->freq <= 0 || params->freq->channel <= 0 ||
        params->freq->channel > UINT8_MAX ||
        (params->head_len != 0 && params->head == NULL) ||
        (params->tail_len != 0 && params->tail == NULL))
        return -1;
    beacon.abi_version = HISI_WPA_AP_ABI_VERSION;
    beacon.hidden_ssid = (uint8_t) params->hide_ssid;
    beacon.sae_pwe = (uint8_t) params->sae_pwe;
    beacon.beacon_interval = (uint16_t) params->beacon_int;
    beacon.dtim_period = (uint8_t) params->dtim_period;
    beacon.channel = (uint8_t) params->freq->channel;
    beacon.frequency_mhz = (uint32_t) params->freq->freq;
    beacon.auth_algorithms = params->auth_algs;
    beacon.wpa_versions = params->wpa_version;
    beacon.privacy = params->privacy != 0;
    beacon.ssid_len = (uint8_t) params->ssid_len;
    os_memcpy(beacon.ssid, params->ssid, params->ssid_len);
    beacon.head = params->head;
    beacon.head_len = params->head_len;
    beacon.tail = params->tail;
    beacon.tail_len = params->tail_len;
    return driver->hooks.configure_beacon(driver->hooks.driver, &beacon);
}

static int ws63_ap_set_key(void *private_data,
    struct wpa_driver_set_key_params *params)
{
    struct ws63_ap_driver_data *driver = private_data;
    struct hisi_wpa_key key = { 0 };
    if (driver == NULL || params == NULL || params->key_idx < 0 ||
        params->key_idx > (int) UINT8_MAX ||
        params->seq_len > sizeof(key.sequence) ||
        (params->seq_len != 0 && params->seq == NULL) ||
        map_cipher(params->alg, &key.cipher) != 0)
        return -1;
    key.abi_version = HISI_WPA_ABI_VERSION;
    key.key_index = (uint8_t) params->key_idx;
    key.flags = map_key_flags(params->key_flag);
    if (params->addr != NULL) {
        os_memcpy(key.peer, params->addr, sizeof(key.peer));
        key.peer_present = 1;
    }
    key.sequence_len = (uint8_t) params->seq_len;
    if (params->seq_len != 0)
        os_memcpy(key.sequence, params->seq, params->seq_len);
    if (params->alg == WPA_ALG_NONE)
        return driver->hooks.remove_key(driver->hooks.driver, &key);
    if (params->key == NULL || params->key_len == 0)
        return -1;
    return driver->hooks.install_key(driver->hooks.driver, &key,
        params->key, params->key_len);
}

static int ws63_ap_send_mlme(void *private_data, const uint8_t *frame,
    size_t frame_len, int no_ack, unsigned int frequency_mhz,
    const uint16_t *csa_offsets, size_t csa_offsets_len, int no_encrypt,
    unsigned int wait_ms, int link_id)
{
    struct ws63_ap_driver_data *driver = private_data;
    (void) no_ack;
    if (driver == NULL || frame == NULL || frame_len == 0 ||
        csa_offsets != NULL || csa_offsets_len != 0 || no_encrypt != 0 ||
        wait_ms != 0 || link_id >= 0)
        return -1;
    return driver->hooks.send_mgmt(driver->hooks.driver, frequency_mhz,
        frame, frame_len);
}

static int ws63_ap_send_eapol(void *private_data,
    const uint8_t destination[6], const uint8_t *frame, size_t frame_len,
    int encrypt, const uint8_t *own_address, u32 flags, int link_id)
{
    struct ws63_ap_driver_data *driver = private_data;
    (void) encrypt;
    (void) flags;
    if (driver == NULL || destination == NULL || frame == NULL ||
        frame_len == 0 || own_address == NULL || link_id >= 0 ||
        os_memcmp(own_address, driver->own_address,
            sizeof(driver->own_address)) != 0)
        return -1;
    return driver->hooks.send_eapol(driver->hooks.driver, destination,
        frame, frame_len);
}

static int ws63_ap_remove_station(void *private_data,
    const uint8_t address[6])
{
    struct ws63_ap_driver_data *driver = private_data;
    if (driver == NULL || address == NULL)
        return -1;
    return driver->hooks.remove_station(driver->hooks.driver, address);
}

static const uint8_t *ws63_ap_get_mac_addr(void *private_data)
{
    struct ws63_ap_driver_data *driver = private_data;
    return driver == NULL ? NULL : driver->own_address;
}

const struct wpa_driver_ops wpa_driver_ws63_ap_ops = {
    .name = "ws63-ap",
    .desc = "HiSilicon WS63 native AP driver",
    .set_key = ws63_ap_set_key,
    .send_mlme = ws63_ap_send_mlme,
    .set_ap = ws63_ap_set_beacon,
    .hapd_init = ws63_ap_init,
    .hapd_deinit = ws63_ap_deinit,
    .hapd_send_eapol = ws63_ap_send_eapol,
    .sta_remove = ws63_ap_remove_station,
    .get_mac_addr = ws63_ap_get_mac_addr,
};
