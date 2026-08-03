#include "hisi_wpa_hostap_compat.h"
#include "hisi_wpa_authenticator.h"

#include "common/defs.h"
#include "common/wpa_common.h"
#include "drivers/driver.h"
#include "ap/ap_config.h"
#include "ap/hostapd.h"
#include "eloop.h"

#define HISI_WPA_AP_IFNAME "wlan0"
#define HISI_WPA_AP_CONFIG_NAME "memory:ws63-ap"

extern const struct wpa_driver_ops wpa_driver_ws63_ap_ops;

struct hisi_wpa_ap_context {
    struct hapd_interfaces interfaces;
    struct hostapd_iface *interface;
    struct hisi_wpa_ap_config config;
    void *driver_owner;
    uint8_t passphrase[HISI_WPA_AP_MAX_PASSPHRASE_LEN + 1u];
    uint8_t passphrase_len;
    uint8_t configured;
    uint8_t started;
};

static struct hisi_wpa_ap_context *g_config_context;

static void clear_secret(uint8_t *secret, size_t length)
{
    volatile uint8_t *cursor = secret;
    while (length-- != 0)
        *cursor++ = 0;
}

static struct hostapd_config *memory_config_read(const char *name)
{
    struct hisi_wpa_ap_context *context = g_config_context;
    struct hostapd_config *config;
    struct hostapd_bss_config *bss;
    char *passphrase;
    if (context == NULL || name == NULL || !context->configured)
        return NULL;
    config = hostapd_config_defaults();
    if (config == NULL)
        return NULL;
    bss = config->bss[0];
    config->driver = &wpa_driver_ws63_ap_ops;
    config->channel = context->config.channel;
    config->hw_mode = HOSTAPD_MODE_IEEE80211G;
    config->hw_mode_set = 1;
    config->beacon_int = context->config.beacon_interval;
    config->ieee80211n = 1;
    os_strlcpy(bss->iface, HISI_WPA_AP_IFNAME, sizeof(bss->iface));
    bss->dtim_period = context->config.dtim_period;
    bss->max_num_sta = context->config.max_stations;
    bss->ignore_broadcast_ssid = context->config.hidden_ssid;
    bss->ssid.ssid_len = context->config.ssid_len;
    bss->ssid.ssid_set = 1;
    os_memcpy(bss->ssid.ssid, context->config.ssid,
        context->config.ssid_len);
    bss->auth_algs = WPA_AUTH_ALG_OPEN;
    bss->ieee80211w = context->config.pmf;
    if (context->config.security == HISI_WPA_AP_SECURITY_OPEN) {
        bss->wpa = 0;
        bss->wpa_key_mgmt = WPA_KEY_MGMT_NONE;
        bss->wpa_pairwise = WPA_CIPHER_NONE;
        bss->rsn_pairwise = WPA_CIPHER_NONE;
    } else {
        passphrase = os_zalloc((size_t) context->passphrase_len + 1u);
        if (passphrase == NULL) {
            hostapd_config_free(config);
            return NULL;
        }
        os_memcpy(passphrase, context->passphrase,
            context->passphrase_len);
        bss->wpa = WPA_PROTO_RSN;
        bss->wpa_key_mgmt = context->config.security ==
            HISI_WPA_AP_SECURITY_WPA3_SAE ? WPA_KEY_MGMT_SAE :
            WPA_KEY_MGMT_PSK;
        bss->wpa_pairwise = WPA_CIPHER_CCMP;
        bss->rsn_pairwise = WPA_CIPHER_CCMP;
        bss->ssid.wpa_passphrase = passphrase;
        bss->ssid.wpa_passphrase_set = 1;
        bss->sae_pwe = context->config.sae_pwe;
    }
    hostapd_set_security_params(bss, 1);
    if (hostapd_config_check(config, 1) != 0) {
        hostapd_config_free(config);
        return NULL;
    }
    return config;
}

static int ws63_driver_init(struct hostapd_iface *interface)
{
    struct hostapd_data *hostapd;
    struct wpa_init_params params;
    if (interface == NULL || interface->num_bss != 1)
        return -1;
    hostapd = interface->bss[0];
    if (hostapd == NULL || hostapd->driver == NULL ||
        hostapd->driver->hapd_init == NULL)
        return -1;
    os_memset(&params, 0, sizeof(params));
    params.ifname = hostapd->conf->iface;
    params.driver_params = hostapd->iconf->driver_params;
    params.own_addr = hostapd->own_addr;
    hostapd->drv_priv = hostapd->driver->hapd_init(hostapd, &params);
    return hostapd->drv_priv == NULL ? -1 : 0;
}

size_t hisi_wpa_ap_context_size(void)
{
    return sizeof(struct hisi_wpa_ap_context);
}

size_t hisi_wpa_ap_context_align(void)
{
    return _Alignof(struct hisi_wpa_ap_context);
}

struct hisi_wpa_ap_context *hisi_wpa_ap_create(void *storage,
    size_t storage_len, const struct hisi_wpa_ap_driver_hooks *hooks)
{
    struct hisi_wpa_ap_context *context;
    if (storage == NULL || hooks == NULL ||
        storage_len < sizeof(struct hisi_wpa_ap_context) ||
        (uintptr_t) storage % _Alignof(struct hisi_wpa_ap_context) != 0 ||
        hisi_wpa_ap_driver_install(hooks) != 0)
        return NULL;
    context = storage;
    os_memset(context, 0, sizeof(*context));
    context->driver_owner = hooks->driver;
    return context;
}

int32_t hisi_wpa_ap_configure(struct hisi_wpa_ap_context *context,
    const struct hisi_wpa_ap_config *config, const uint8_t *passphrase,
    size_t passphrase_len)
{
    if (context == NULL || config == NULL || context->started ||
        config->abi_version != HISI_WPA_AP_ABI_VERSION ||
        config->ssid_len == 0 || config->ssid_len > HISI_WPA_MAX_SSID_LEN ||
        config->channel == 0 || config->channel > 14 ||
        config->beacon_interval == 0 || config->dtim_period == 0 ||
        config->max_stations == 0 || config->hidden_ssid > 2 ||
        config->security > HISI_WPA_AP_SECURITY_WPA3_SAE)
        return -1;
    if (config->security == HISI_WPA_AP_SECURITY_OPEN) {
        if (passphrase != NULL || passphrase_len != 0)
            return -1;
    } else if (passphrase == NULL || passphrase_len < 8 ||
        passphrase_len > HISI_WPA_AP_MAX_PASSPHRASE_LEN) {
        return -1;
    }
#ifndef CONFIG_SAE
    if (config->security == HISI_WPA_AP_SECURITY_WPA3_SAE)
        return -1;
#endif
    clear_secret(context->passphrase, sizeof(context->passphrase));
    context->config = *config;
    if (passphrase_len != 0)
        os_memcpy(context->passphrase, passphrase, passphrase_len);
    context->passphrase_len = (uint8_t) passphrase_len;
    context->configured = 1;
    return 0;
}

int32_t hisi_wpa_ap_start(struct hisi_wpa_ap_context *context)
{
    if (context == NULL || !context->configured || context->started ||
        g_config_context != NULL)
        return -1;
    g_config_context = context;
    if (eloop_init() != 0)
        goto failed_eloop_init;
    os_memset(&context->interfaces, 0, sizeof(context->interfaces));
    context->interfaces.config_read_cb = memory_config_read;
    context->interfaces.driver_init = ws63_driver_init;
    context->interfaces.global_ctrl_sock = -1;
    dl_list_init(&context->interfaces.global_ctrl_dst);
    context->interface = hostapd_init(&context->interfaces,
        HISI_WPA_AP_CONFIG_NAME);
    if (context->interface == NULL)
        goto failed_hostapd_init;
    context->interface->interfaces = &context->interfaces;
    context->interfaces.count = 1;
    context->interfaces.iface = &context->interface;
    if (ws63_driver_init(context->interface) != 0)
        goto failed_driver_init;
    if (hostapd_setup_interface(context->interface) != 0)
        goto failed_setup_interface;
    context->started = 1;
    return 0;

failed_setup_interface:
    hostapd_interface_deinit_free(context->interface);
    context->interface = NULL;
    eloop_destroy();
    g_config_context = NULL;
    return -24;
failed_driver_init:
    hostapd_interface_deinit_free(context->interface);
    context->interface = NULL;
    eloop_destroy();
    g_config_context = NULL;
    return -23;
failed_hostapd_init:
    eloop_destroy();
    g_config_context = NULL;
    return -22;
failed_eloop_init:
    g_config_context = NULL;
    return -21;
}

struct hisi_wpa_poll_result hisi_wpa_ap_poll(
    struct hisi_wpa_ap_context *context, uint64_t now_ms,
    uint32_t work_budget)
{
    struct hisi_wpa_poll_result result = { 0 };
    uint64_t deadline;
    (void) now_ms;
    if (context == NULL || !context->started) {
        result.status = -1;
        return result;
    }
    result.work_completed = hisi_wpa_eloop_run_once(work_budget);
    deadline = hisi_wpa_eloop_next_deadline_us();
    result.next_deadline_ms = deadline == UINT64_MAX ? UINT64_MAX :
        (deadline + 999u) / 1000u;
    return result;
}

int32_t hisi_wpa_ap_feed_eapol(struct hisi_wpa_ap_context *context,
    const uint8_t source[6], const uint8_t *frame, size_t frame_len)
{
    if (context == NULL || !context->started || source == NULL ||
        frame == NULL || frame_len == 0)
        return -1;
    drv_event_eapol_rx(context->interface->bss[0], source, frame,
        frame_len);
    return 0;
}

int32_t hisi_wpa_ap_feed_mgmt(struct hisi_wpa_ap_context *context,
    uint32_t frequency_mhz, int32_t rssi_dbm, const uint8_t *frame,
    size_t frame_len)
{
    union wpa_event_data event;
    if (context == NULL || !context->started || frequency_mhz == 0 ||
        frame == NULL || frame_len == 0)
        return -1;
    os_memset(&event, 0, sizeof(event));
    event.rx_mgmt.frame = frame;
    event.rx_mgmt.frame_len = frame_len;
    event.rx_mgmt.freq = (int) frequency_mhz;
    event.rx_mgmt.ssi_signal = rssi_dbm;
    wpa_supplicant_event(context->interface->bss[0], EVENT_RX_MGMT,
        &event);
    return 0;
}

int32_t hisi_wpa_ap_feed_associated(struct hisi_wpa_ap_context *context,
    const uint8_t address[6], const uint8_t *request_ies,
    size_t request_ies_len, uint8_t reassociated)
{
    union wpa_event_data event;
    if (context == NULL || !context->started || address == NULL ||
        (request_ies_len != 0 && request_ies == NULL))
        return -1;
    os_memset(&event, 0, sizeof(event));
    event.assoc_info.addr = address;
    event.assoc_info.req_ies = request_ies;
    event.assoc_info.req_ies_len = request_ies_len;
    event.assoc_info.reassoc = reassociated != 0;
    wpa_supplicant_event(context->interface->bss[0], EVENT_ASSOC, &event);
    return 0;
}

int32_t hisi_wpa_ap_feed_disassociated(struct hisi_wpa_ap_context *context,
    const uint8_t address[6])
{
    union wpa_event_data event;
    if (context == NULL || !context->started || address == NULL)
        return -1;
    os_memset(&event, 0, sizeof(event));
    event.disassoc_info.addr = address;
    wpa_supplicant_event(context->interface->bss[0], EVENT_DISASSOC,
        &event);
    return 0;
}

int32_t hisi_wpa_ap_stop(struct hisi_wpa_ap_context *context)
{
    if (context == NULL || !context->started || g_config_context != context)
        return -1;
    hostapd_interface_deinit_free(context->interface);
    context->interface = NULL;
    context->interfaces.iface = NULL;
    context->interfaces.count = 0;
    eloop_destroy();
    context->started = 0;
    g_config_context = NULL;
    return 0;
}

void hisi_wpa_ap_destroy(struct hisi_wpa_ap_context *context)
{
    void *driver_owner;
    if (context == NULL)
        return;
    driver_owner = context->driver_owner;
    if (context->started)
        (void) hisi_wpa_ap_stop(context);
    clear_secret(context->passphrase, sizeof(context->passphrase));
    os_memset(context, 0, sizeof(*context));
    if (driver_owner != NULL)
        (void) hisi_wpa_ap_driver_uninstall(driver_owner);
}
