#include "hisi_wpa_hostap_compat.h"
#include "drivers/driver.h"

#include "hisi_wpa_driver_port.h"

struct ws63_driver_data {
    void *supplicant_context;
    struct hisi_wpa_driver_hooks hooks;
    uint8_t own_address[ETH_ALEN];
};

static int map_cipher(enum wpa_alg algorithm, uint8_t *cipher)
{
    switch (algorithm) {
    case WPA_ALG_NONE:
        *cipher = HISI_WPA_CIPHER_NONE;
        return 0;
    case WPA_ALG_WEP:
        *cipher = HISI_WPA_CIPHER_WEP;
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
    if ((flags & KEY_FLAG_PMK) != 0)
        mapped |= HISI_WPA_KEY_FLAG_PMK;
    return mapped;
}

static void *ws63_init(void *context, const char *ifname)
{
    const struct hisi_wpa_driver_hooks *hooks = hisi_wpa_driver_acquire();
    struct ws63_driver_data *driver;
    (void) ifname;
    if (hooks == NULL || context == NULL)
        goto failed;
    driver = os_zalloc(sizeof(*driver));
    if (driver == NULL)
        goto failed;
    driver->supplicant_context = context;
    driver->hooks = *hooks;
    if (driver->hooks.get_own_address(driver->hooks.driver,
        driver->own_address) != 0) {
        os_free(driver);
        goto failed;
    }
    return driver;

failed:
    if (hooks != NULL)
        hisi_wpa_driver_release();
    return NULL;
}

static void ws63_deinit(void *private_data)
{
    struct ws63_driver_data *driver = private_data;
    if (driver == NULL)
        return;
    os_memset(driver, 0, sizeof(*driver));
    os_free(driver);
    hisi_wpa_driver_release();
}

static const uint8_t *ws63_get_mac_addr(void *private_data)
{
    struct ws63_driver_data *driver = private_data;
    return driver == NULL ? NULL : driver->own_address;
}

static int ws63_set_key(void *private_data,
    struct wpa_driver_set_key_params *params)
{
    struct ws63_driver_data *driver = private_data;
    struct hisi_wpa_key key = { 0 };
    if (driver == NULL || params == NULL || params->key_idx < 0 ||
        params->key_idx > UINT8_MAX || params->seq_len > sizeof(key.sequence) ||
        (params->seq_len != 0 && params->seq == NULL) ||
        check_key_flag(params->key_flag) != 0 ||
        (params->key_flag & KEY_FLAG_PMK) != 0 ||
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

static int ws63_send_mlme(void *private_data, const uint8_t *frame,
    size_t frame_len, int no_ack, unsigned int frequency_mhz,
    const uint16_t *csa_offsets, size_t csa_offsets_len, int no_encrypt,
    unsigned int wait_ms, int link_id)
{
    struct ws63_driver_data *driver = private_data;
    (void) no_ack;
    if (driver == NULL || frame == NULL || frame_len == 0 ||
        csa_offsets != NULL || csa_offsets_len != 0 || no_encrypt != 0 ||
        wait_ms != 0 || link_id >= 0)
        return -1;
    return driver->hooks.send_mgmt(driver->hooks.driver, frequency_mhz,
        frame, frame_len);
}

const struct wpa_driver_ops wpa_driver_ws63_ops = {
    .name = "ws63",
    .desc = "HiSilicon WS63 native driver",
    .set_key = ws63_set_key,
    .init = ws63_init,
    .deinit = ws63_deinit,
    .get_mac_addr = ws63_get_mac_addr,
    .send_mlme = ws63_send_mlme,
};
