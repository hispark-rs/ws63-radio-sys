#include "hisi_wpa_hostap_compat.h"
#include "drivers/driver.h"
#include "common/ieee802_11_defs.h"

#include "hisi_wpa_driver_port.h"

#define WS63_MAX_SCAN_RESULTS 32u
static uint32_t g_driver_diagnostic;

uint32_t hisi_wpa_driver_diagnostic_word(void)
{
    return g_driver_diagnostic;
}

struct ws63_driver_data {
    void *supplicant_context;
    struct hisi_wpa_driver_hooks hooks;
    uint8_t own_address[ETH_ALEN];
    uint8_t current_bssid[ETH_ALEN];
    uint8_t current_ssid[HISI_WPA_MAX_SSID_LEN];
    size_t current_ssid_len;
    int associated;
    struct wpa_scan_res *scan_results[WS63_MAX_SCAN_RESULTS];
    size_t scan_result_count;
};

static void clear_scan_results(struct ws63_driver_data *driver)
{
    size_t index;
    for (index = 0; index < driver->scan_result_count; index++)
        os_free(driver->scan_results[index]);
    os_memset(driver->scan_results, 0, sizeof(driver->scan_results));
    driver->scan_result_count = 0;
}

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
    clear_scan_results(driver);
    os_memset(driver, 0, sizeof(*driver));
    os_free(driver);
    hisi_wpa_driver_release();
}

static int ws63_scan(void *private_data, struct wpa_driver_scan_params *params)
{
    struct ws63_driver_data *driver = private_data;
    struct hisi_wpa_scan_request request = { 0 };
    size_t count = 0;
    if (driver == NULL || params == NULL || params->num_ssids != 1 ||
        params->ssids[0].ssid_len > HISI_WPA_MAX_SSID_LEN ||
        (params->ssids[0].ssid_len != 0 && params->ssids[0].ssid == NULL) ||
        params->extra_ies_len > HISI_WPA_MAX_SCAN_IE_LEN ||
        (params->extra_ies_len != 0 && params->extra_ies == NULL))
        return -1;
    request.abi_version = HISI_WPA_ABI_VERSION;
    request.ssid_len = (uint8_t) params->ssids[0].ssid_len;
    if (request.ssid_len != 0)
        os_memcpy(request.ssid, params->ssids[0].ssid, request.ssid_len);
    if (params->bssid != NULL) {
        os_memcpy(request.bssid, params->bssid, sizeof(request.bssid));
        request.bssid_present = 1;
    }
    if (params->freqs != NULL) {
        while (params->freqs[count] != 0) {
            if (count == HISI_WPA_MAX_SCAN_FREQUENCIES)
                return -1;
            request.frequencies[count] = params->freqs[count];
            count++;
        }
    }
    request.num_frequencies = (uint8_t) count;
    request.extra_ies = params->extra_ies;
    request.extra_ies_len = params->extra_ies_len;
    clear_scan_results(driver);
    return driver->hooks.start_scan(driver->hooks.driver, &request);
}

static struct wpa_scan_results *ws63_get_scan_results(void *private_data)
{
    struct ws63_driver_data *driver = private_data;
    struct wpa_scan_results *results;
    if (driver == NULL)
        return NULL;
    results = os_zalloc(sizeof(*results));
    if (results == NULL)
        return NULL;
    if (driver->scan_result_count != 0) {
        results->res = os_calloc(driver->scan_result_count,
            sizeof(*results->res));
        if (results->res == NULL) {
            os_free(results);
            return NULL;
        }
        os_memcpy(results->res, driver->scan_results,
            driver->scan_result_count * sizeof(*results->res));
    }
    results->num = driver->scan_result_count;
    (void) os_get_reltime(&results->fetch_time);
    os_memset(driver->scan_results, 0, sizeof(driver->scan_results));
    driver->scan_result_count = 0;
    return results;
}

static uint32_t map_cipher_suite(unsigned int suite)
{
    switch (suite) {
    case WPA_CIPHER_NONE:
        return 0;
    case WPA_CIPHER_CCMP:
        return RSN_CIPHER_SUITE_CCMP;
    case WPA_CIPHER_CCMP_256:
        return RSN_CIPHER_SUITE_CCMP_256;
    case WPA_CIPHER_GCMP:
        return RSN_CIPHER_SUITE_GCMP;
    case WPA_CIPHER_GCMP_256:
        return RSN_CIPHER_SUITE_GCMP_256;
    case WPA_CIPHER_TKIP:
        return RSN_CIPHER_SUITE_TKIP;
    default:
        return UINT32_MAX;
    }
}

static uint32_t map_key_mgmt_suite(unsigned int suite)
{
    switch (suite) {
    case WPA_KEY_MGMT_PSK:
        return RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X;
    case WPA_KEY_MGMT_PSK_SHA256:
        return RSN_AUTH_KEY_MGMT_PSK_SHA256;
    case WPA_KEY_MGMT_SAE:
        return RSN_AUTH_KEY_MGMT_SAE;
    default:
        return UINT32_MAX;
    }
}

static int ws63_get_capa(void *private_data, struct wpa_driver_capa *capa)
{
    struct ws63_driver_data *driver = private_data;
    uint64_t flags = 0;
    if (driver == NULL || capa == NULL)
        return -1;
    if (driver->hooks.get_driver_flags(driver->hooks.driver, &flags) != 0)
        return -1;
    os_memset(capa, 0, sizeof(*capa));
    capa->key_mgmt = WPA_DRIVER_CAPA_KEY_MGMT_WPA2_PSK;
    capa->enc = WPA_DRIVER_CAPA_ENC_CCMP;
    capa->auth = WPA_DRIVER_AUTH_OPEN;
#ifdef CONFIG_SAE
    capa->key_mgmt |= WPA_DRIVER_CAPA_KEY_MGMT_SAE;
    capa->enc |= WPA_DRIVER_CAPA_ENC_BIP;
#endif
    capa->flags = flags;
    return 0;
}

static int ws63_associate(void *private_data,
    struct wpa_driver_associate_params *params)
{
    struct ws63_driver_data *driver = private_data;
    struct hisi_wpa_associate_request request = { 0 };
    int status;
    size_t index;
    g_driver_diagnostic = 8u;
    if (driver == NULL || params == NULL || params->ssid == NULL ||
        params->ssid_len == 0 || params->ssid_len > HISI_WPA_MAX_SSID_LEN ||
        params->mode != IEEE80211_MODE_INFRA ||
        params->wpa_ie_len > HISI_WPA_MAX_SCAN_IE_LEN ||
        (params->wpa_ie_len != 0 && params->wpa_ie == NULL))
        return -1;
    g_driver_diagnostic = 9u;
    for (index = 0; index < 4; index++) {
        if (params->wep_key[index] != NULL || params->wep_key_len[index] != 0)
            return -1;
    }
    g_driver_diagnostic = 10u;
    request.abi_version = HISI_WPA_ABI_VERSION;
    request.ssid_len = (uint8_t) params->ssid_len;
    os_memcpy(request.ssid, params->ssid, params->ssid_len);
    os_memcpy(driver->current_ssid, params->ssid, params->ssid_len);
    driver->current_ssid_len = params->ssid_len;
    if (params->bssid != NULL) {
        os_memcpy(request.bssid, params->bssid, sizeof(request.bssid));
        request.bssid_present = 1;
    }
    request.frequency_mhz = params->freq.freq > 0 ?
        (uint32_t) params->freq.freq : 0;
    if ((params->wpa_proto & ~(WPA_PROTO_WPA | WPA_PROTO_RSN)) != 0)
        return -1;
    if ((params->wpa_proto & WPA_PROTO_WPA) != 0)
        request.wpa_versions |= HISI_WPA_VERSION_1;
    if ((params->wpa_proto & WPA_PROTO_RSN) != 0)
        request.wpa_versions |= HISI_WPA_VERSION_2;
    request.pairwise_suite = map_cipher_suite(params->pairwise_suite);
    request.group_suite = map_cipher_suite(params->group_suite);
    request.key_mgmt_suite = map_key_mgmt_suite(params->key_mgmt_suite);
    g_driver_diagnostic = 11u;
    if (request.pairwise_suite == UINT32_MAX ||
        request.group_suite == UINT32_MAX ||
        request.key_mgmt_suite == UINT32_MAX)
        return -1;
    g_driver_diagnostic = 12u;
    /* Match the WS63 driver_soc oracle: hostap may advertise OPEN|SAE for
     * external authentication. OPEN is the firmware association mode; the SAE
     * AKM suite causes firmware to emit EVENT_EXTERNAL_AUTH. */
    if ((params->auth_alg & WPA_AUTH_ALG_OPEN) != 0)
        request.auth_type = HISI_WPA_AUTH_OPEN;
    else if ((params->auth_alg & WPA_AUTH_ALG_SAE) != 0)
        request.auth_type = HISI_WPA_AUTH_SAE;
    else
        return -1;
    g_driver_diagnostic = 13u;
    if (params->mgmt_frame_protection < NO_MGMT_FRAME_PROTECTION ||
        params->mgmt_frame_protection > MGMT_FRAME_PROTECTION_REQUIRED)
        return -1;
    request.pmf = (uint8_t) params->mgmt_frame_protection;
    request.sae_pwe = (uint8_t) params->sae_pwe;
    request.privacy = params->pairwise_suite != WPA_CIPHER_NONE;
    request.association_ies = params->wpa_ie;
    request.association_ies_len = params->wpa_ie_len;
    status = driver->hooks.associate(driver->hooks.driver, &request);
    g_driver_diagnostic = status == 0 ? 1u : 14u;
    return status;
}

static int ws63_deauthenticate(void *private_data, const uint8_t *address,
    uint16_t reason)
{
    struct ws63_driver_data *driver = private_data;
    (void) address;
    if (driver == NULL)
        return -1;
    if (driver->hooks.deauthenticate(driver->hooks.driver, reason) != 0)
        return -1;
    driver->associated = 0;
    return 0;
}

static int ws63_get_bssid(void *private_data, uint8_t *bssid)
{
    struct ws63_driver_data *driver = private_data;
    if (driver == NULL || bssid == NULL || !driver->associated)
        return -1;
    os_memcpy(bssid, driver->current_bssid, ETH_ALEN);
    return 0;
}

static int ws63_get_ssid(void *private_data, uint8_t *ssid)
{
    struct ws63_driver_data *driver = private_data;
    if (driver == NULL || ssid == NULL || !driver->associated ||
        driver->current_ssid_len == 0)
        return -1;
    os_memcpy(ssid, driver->current_ssid, driver->current_ssid_len);
    return (int) driver->current_ssid_len;
}

int32_t hisi_wpa_driver_feed_scan_result(void *private_data,
    const struct hisi_wpa_scan_result *result)
{
    struct ws63_driver_data *driver = private_data;
    struct wpa_scan_res *stored;
    size_t ies_len;
    if (driver == NULL || result == NULL ||
        result->abi_version != HISI_WPA_ABI_VERSION ||
        result->frequency_mhz <= 0 || result->ie_len > HISI_WPA_MAX_SCAN_IE_LEN ||
        result->beacon_ie_len > HISI_WPA_MAX_SCAN_IE_LEN - result->ie_len ||
        driver->scan_result_count == WS63_MAX_SCAN_RESULTS)
        return -1;
    ies_len = result->ie_len + result->beacon_ie_len;
    if (ies_len != 0 && result->ies == NULL)
        return -1;
    stored = os_zalloc(sizeof(*stored) + ies_len);
    if (stored == NULL)
        return -1;
    stored->flags = result->flags;
    os_memcpy(stored->bssid, result->bssid, sizeof(stored->bssid));
    stored->freq = result->frequency_mhz;
    stored->beacon_int = result->beacon_interval;
    stored->caps = result->capabilities;
    stored->qual = result->quality;
    stored->level = result->level_mbm;
    stored->age = result->age_ms;
    stored->ie_len = result->ie_len;
    stored->beacon_ie_len = result->beacon_ie_len;
    if (ies_len != 0)
        os_memcpy(stored + 1, result->ies, ies_len);
    driver->scan_results[driver->scan_result_count++] = stored;
    return 0;
}

int32_t hisi_wpa_driver_feed_scan_done(void *private_data, int32_t status)
{
    struct ws63_driver_data *driver = private_data;
    if (driver == NULL)
        return -1;
    wpa_supplicant_event(driver->supplicant_context, EVENT_SCAN_RESULTS, NULL);
    return status == 0 ? 0 : -1;
}

int32_t hisi_wpa_driver_feed_associate_result(void *private_data,
    const struct hisi_wpa_associate_result *result)
{
    struct ws63_driver_data *driver = private_data;
    union wpa_event_data event;
    if (driver == NULL || result == NULL ||
        result->abi_version != HISI_WPA_ABI_VERSION ||
        (result->request_ies_len != 0 && result->request_ies == NULL) ||
        (result->response_ies_len != 0 && result->response_ies == NULL))
        return -1;
    os_memset(&event, 0, sizeof(event));
    if (result->status != 0) {
        driver->associated = 0;
        event.assoc_reject.bssid = result->bssid;
        event.assoc_reject.resp_ies = result->response_ies;
        event.assoc_reject.resp_ies_len = result->response_ies_len;
        event.assoc_reject.status_code = result->status;
        wpa_supplicant_event(driver->supplicant_context,
            EVENT_ASSOC_REJECT, &event);
        return 0;
    }
    os_memcpy(driver->current_bssid, result->bssid,
        sizeof(driver->current_bssid));
    driver->associated = 1;
    event.assoc_info.req_ies = result->request_ies;
    event.assoc_info.req_ies_len = result->request_ies_len;
    event.assoc_info.resp_ies = result->response_ies;
    event.assoc_info.resp_ies_len = result->response_ies_len;
    event.assoc_info.addr = result->bssid;
    event.assoc_info.freq = result->frequency_mhz;
    wpa_supplicant_event(driver->supplicant_context, EVENT_ASSOC, &event);
    return 0;
}

int32_t hisi_wpa_driver_feed_disconnect(void *private_data,
    const struct hisi_wpa_disconnect_event *disconnect)
{
    struct ws63_driver_data *driver = private_data;
    union wpa_event_data event;
    if (driver == NULL || disconnect == NULL ||
        disconnect->abi_version != HISI_WPA_ABI_VERSION ||
        (disconnect->ies_len != 0 && disconnect->ies == NULL))
        return -1;
    os_memset(&event, 0, sizeof(event));
    driver->associated = 0;
    event.disassoc_info.reason_code = disconnect->reason;
    event.disassoc_info.ie = disconnect->ies;
    event.disassoc_info.ie_len = disconnect->ies_len;
    wpa_supplicant_event(driver->supplicant_context, EVENT_DISASSOC, &event);
    return 0;
}

int hisi_wpa_driver_is_disconnected(const void *private_data)
{
    const struct ws63_driver_data *driver = private_data;
    return driver != NULL && !driver->associated;
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
        params->key_idx > (int) UINT8_MAX ||
        params->seq_len > sizeof(key.sequence) ||
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
    {
        int status = driver->hooks.send_mgmt(driver->hooks.driver,
            frequency_mhz, frame, frame_len);
        g_driver_diagnostic = status == 0 ? 3u : 12u;
        return status;
    }
}

#ifdef CONFIG_SAE
static int ws63_send_external_auth_status(void *private_data,
    struct external_auth *params)
{
    struct ws63_driver_data *driver = private_data;
    struct hisi_wpa_external_auth_status status = { 0 };
    int result;
    if (driver == NULL || params == NULL || params->bssid == NULL ||
        params->mld_addr != NULL)
        return -1;
    status.abi_version = HISI_WPA_ABI_VERSION;
    status.status = params->status;
    os_memcpy(status.bssid, params->bssid, sizeof(status.bssid));
    if (params->pmkid != NULL) {
        status.pmkid_present = 1;
        os_memcpy(status.pmkid, params->pmkid, sizeof(status.pmkid));
    }
    result = driver->hooks.send_external_auth_status(driver->hooks.driver,
        &status);
    g_driver_diagnostic = result == 0 ? 4u : 13u;
    return result;
}
#endif

const struct wpa_driver_ops wpa_driver_ws63_ops = {
    .name = "ws63",
    .desc = "HiSilicon WS63 native driver",
    .set_key = ws63_set_key,
    .init = ws63_init,
    .deinit = ws63_deinit,
    .get_bssid = ws63_get_bssid,
    .get_ssid = ws63_get_ssid,
    .get_mac_addr = ws63_get_mac_addr,
    .get_capa = ws63_get_capa,
    .send_mlme = ws63_send_mlme,
    .scan2 = ws63_scan,
    .get_scan_results2 = ws63_get_scan_results,
    .associate = ws63_associate,
    .deauthenticate = ws63_deauthenticate,
#ifdef CONFIG_SAE
    .send_external_auth_status = ws63_send_external_auth_status,
#endif
};
