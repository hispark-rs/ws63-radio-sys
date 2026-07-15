#include "hisi_wpa_hostap_compat.h"
#include "hisi_wpa_supplicant.h"
#include "hisi_wpa_driver_port.h"

#include "common/defs.h"
#include "drivers/driver.h"
#include "eloop.h"
#include "config.h"
#include "wpa_supplicant_i.h"

#define HISI_WPA_EVENT_CAPACITY 8u
#define HISI_WPA_IFNAME "wlan0"

extern int32_t hisi_wpa_l2_feed(const uint8_t source[6],
    const uint8_t *frame, size_t frame_len);

struct hisi_wpa_context {
    struct wpa_global *global;
    struct wpa_supplicant *interface;
    struct wpa_ssid *network;
    void *driver_owner;
    enum wpa_states observed_state;
    struct hisi_wpa_event events[HISI_WPA_EVENT_CAPACITY];
    uint32_t dropped_events;
    uint8_t event_read;
    uint8_t event_write;
    uint8_t initialized;
};

static uint64_t timestamp_ms(void)
{
    struct os_reltime now = { 0 };
    if (os_get_reltime(&now) != 0)
        return 0;
    return (uint64_t) now.sec * 1000u + (uint64_t) now.usec / 1000u;
}

static void push_event(struct hisi_wpa_context *context, uint8_t kind,
    int32_t status)
{
    uint8_t next = (uint8_t) ((context->event_write + 1u) %
        HISI_WPA_EVENT_CAPACITY);
    struct hisi_wpa_event *event;
    if (next == context->event_read) {
        context->dropped_events++;
        return;
    }
    event = &context->events[context->event_write];
    os_memset(event, 0, sizeof(*event));
    event->abi_version = HISI_WPA_ABI_VERSION;
    event->kind = kind;
    event->status = status;
    event->timestamp_ms = timestamp_ms();
    context->event_write = next;
}

static uint8_t event_for_state(enum wpa_states state)
{
    switch (state) {
    case WPA_AUTHENTICATING:
    case WPA_ASSOCIATING:
        return HISI_WPA_EVENT_AUTHENTICATING;
    case WPA_ASSOCIATED:
    case WPA_4WAY_HANDSHAKE:
    case WPA_GROUP_HANDSHAKE:
        return HISI_WPA_EVENT_ASSOCIATED;
    case WPA_COMPLETED:
        return HISI_WPA_EVENT_AUTHORIZED;
    case WPA_DISCONNECTED:
    case WPA_INTERFACE_DISABLED:
    case WPA_INACTIVE:
        return HISI_WPA_EVENT_DISCONNECTED;
    default:
        return HISI_WPA_EVENT_NONE;
    }
}

static int32_t failure_status_for_state(
    const struct wpa_supplicant *interface, enum wpa_states state)
{
    if (state != WPA_DISCONNECTED && state != WPA_INTERFACE_DISABLED &&
        state != WPA_INACTIVE)
        return 0;
    if (interface->auth_status_code != WLAN_STATUS_SUCCESS)
        return (int32_t) (0x10000000u | interface->auth_status_code);
    if (interface->assoc_status_code != WLAN_STATUS_SUCCESS)
        return (int32_t) (0x20000000u | interface->assoc_status_code);
    if (interface->disconnect_reason != 0)
        return (int32_t) (0x30000000u |
            ((uint32_t) interface->disconnect_reason & 0xffffu));
    return 0;
}

static void observe_state(struct hisi_wpa_context *context)
{
    enum wpa_states state;
    uint8_t event;
    if (context->interface == NULL)
        return;
    state = context->interface->wpa_state;
    if (state == context->observed_state)
        return;
    context->observed_state = state;
    event = event_for_state(state);
    if (event != HISI_WPA_EVENT_NONE)
        push_event(context, event,
            failure_status_for_state(context->interface, state));
}

size_t hisi_wpa_context_size(void)
{
    return sizeof(struct hisi_wpa_context);
}

size_t hisi_wpa_context_align(void)
{
    return _Alignof(struct hisi_wpa_context);
}

struct hisi_wpa_context *hisi_wpa_create(void *storage, size_t storage_len,
    const struct hisi_wpa_driver_hooks *hooks)
{
    struct hisi_wpa_context *context;
    if (storage == NULL || hooks == NULL ||
        storage_len < sizeof(struct hisi_wpa_context) ||
        (uintptr_t) storage % _Alignof(struct hisi_wpa_context) != 0 ||
        hisi_wpa_driver_install(hooks) != 0)
        return NULL;
    context = storage;
    os_memset(context, 0, sizeof(*context));
    context->driver_owner = hooks->driver;
    context->observed_state = WPA_INTERFACE_DISABLED;
    return context;
}

int32_t hisi_wpa_init(struct hisi_wpa_context *context)
{
    struct wpa_params params;
    struct wpa_interface interface;
    if (context == NULL || context->initialized)
        return -1;
    os_memset(&params, 0, sizeof(params));
    params.wpa_debug_level = MSG_INFO;
    context->global = wpa_supplicant_init(&params);
    if (context->global == NULL)
        return -2;
    os_memset(&interface, 0, sizeof(interface));
    interface.driver = "ws63";
    interface.ifname = HISI_WPA_IFNAME;
    context->interface = wpa_supplicant_add_iface(context->global,
        &interface, NULL);
    if (context->interface == NULL) {
        wpa_supplicant_deinit(context->global);
        context->global = NULL;
        return -3;
    }
    context->observed_state = context->interface->wpa_state;
    context->initialized = 1;
    return 0;
}

static int all_zero(const uint8_t *data, size_t len)
{
    size_t index;
    for (index = 0; index < len; index++) {
        if (data[index] != 0)
            return 0;
    }
    return 1;
}

int32_t hisi_wpa_configure(struct hisi_wpa_context *context,
    const struct hisi_wpa_network_config *config,
    const uint8_t *passphrase, size_t passphrase_len)
{
    struct wpa_ssid *network;
    int is_wpa3;
    if (context == NULL || !context->initialized || config == NULL ||
        config->abi_version != HISI_WPA_ABI_VERSION ||
        (config->security != HISI_WPA_SECURITY_WPA2_PSK &&
        config->security != HISI_WPA_SECURITY_WPA3_SAE) ||
        config->ssid_len == 0 || config->ssid_len > HISI_WPA_MAX_SSID_LEN ||
        passphrase == NULL || passphrase_len < 8 || passphrase_len > 63)
        return -1;
    is_wpa3 = config->security == HISI_WPA_SECURITY_WPA3_SAE;
#ifndef CONFIG_SAE
    if (is_wpa3)
        return -1;
#endif
    if (is_wpa3 &&
        (config->pmf != HISI_WPA_PMF_REQUIRED ||
        config->sae_pwe > HISI_WPA_SAE_PWE_BOTH))
        return -1;
    if (context->network != NULL) {
        if (wpa_config_remove_network(context->interface->conf,
            context->network->id) != 0)
            return -2;
        context->network = NULL;
    }
    network = wpa_config_add_network(context->interface->conf);
    if (network == NULL)
        return -3;
    wpa_config_set_network_defaults(network);
    network->ssid = os_memdup(config->ssid, config->ssid_len);
    if (is_wpa3)
        network->sae_password = dup_binstr(passphrase, passphrase_len);
    else
        network->passphrase = dup_binstr(passphrase, passphrase_len);
    if (network->ssid == NULL ||
        (is_wpa3 ? network->sae_password == NULL :
        network->passphrase == NULL)) {
        (void) wpa_config_remove_network(context->interface->conf,
            network->id);
        return -4;
    }
    network->ssid_len = config->ssid_len;
    network->key_mgmt = is_wpa3 ? WPA_KEY_MGMT_SAE : WPA_KEY_MGMT_PSK;
    network->proto = WPA_PROTO_RSN;
    network->pairwise_cipher = WPA_CIPHER_CCMP;
    network->group_cipher = WPA_CIPHER_CCMP;
    network->ieee80211w = config->pmf == HISI_WPA_PMF_REQUIRED ?
        MGMT_FRAME_PROTECTION_REQUIRED :
        config->pmf == HISI_WPA_PMF_OPTIONAL ?
        MGMT_FRAME_PROTECTION_OPTIONAL : NO_MGMT_FRAME_PROTECTION;
    if (is_wpa3) {
        network->sae_pwe = (enum sae_pwe) config->sae_pwe;
        /* hostap 2.11 builds wpa_driver_associate_params.sae_pwe from the
         * interface-wide configuration, not from wpa_ssid. Keep both values
         * aligned so the selected PWE mode reaches the WS63 firmware. */
        context->interface->conf->sae_pwe =
            (enum sae_pwe) config->sae_pwe;
    }
#ifdef CONFIG_SAE
    if (is_wpa3) {
        int *groups = os_malloc(2 * sizeof(*groups));
        if (groups == NULL) {
            (void) wpa_config_remove_network(context->interface->conf,
                network->id);
            return -5;
        }
        groups[0] = 19;
        groups[1] = 0;
        os_free(context->interface->conf->sae_groups);
        context->interface->conf->sae_groups = groups;
    }
#endif
    if (!all_zero(config->bssid, sizeof(config->bssid))) {
        network->bssid_set = 1;
        os_memcpy(network->bssid, config->bssid, sizeof(config->bssid));
    }
    if (!is_wpa3)
        wpa_config_update_psk(network);
    context->network = network;
    return 0;
}

int32_t hisi_wpa_connect(struct hisi_wpa_context *context)
{
    if (context == NULL || context->interface == NULL ||
        context->network == NULL)
        return -1;
    wpa_supplicant_select_network(context->interface, context->network);
    observe_state(context);
    return 0;
}

int32_t hisi_wpa_disconnect(struct hisi_wpa_context *context)
{
    if (context == NULL || context->interface == NULL)
        return -1;
    wpa_supplicant_deauthenticate(context->interface,
        WLAN_REASON_DEAUTH_LEAVING);
    observe_state(context);
    return 0;
}

uint32_t hisi_wpa_context_diagnostic_word(
    const struct hisi_wpa_context *context)
{
    const struct wpa_supplicant *wpa_s;
    uint32_t word;
    if (context == NULL || context->interface == NULL)
        return UINT32_MAX;
    wpa_s = context->interface;
    word = (uint32_t) wpa_s->wpa_state & 0x0fu;
    word |= wpa_s->disconnected ? 1u << 4 : 0;
    word |= wpa_s->scanning ? 1u << 5 : 0;
    word |= wpa_s->current_ssid != NULL ? 1u << 6 : 0;
    word |= wpa_s->current_ssid != NULL && wpa_s->current_ssid->disabled ?
        1u << 7 : 0;
    word |= wpa_s->conf->ap_scan == 0 ? 1u << 8 : 0;
    word |= wpa_s->p2p_mgmt ? 1u << 9 : 0;
    word |= wpa_s->last_scan_res_used != 0 ? 1u << 10 : 0;
    word |= wpa_s->connect_without_scan != NULL ? 1u << 11 : 0;
    return word;
}

int32_t hisi_wpa_feed_eapol(struct hisi_wpa_context *context,
    const uint8_t source[6], const uint8_t *frame, size_t frame_len)
{
    if (context == NULL)
        return -1;
    if (!context->initialized)
        return -2;
    return hisi_wpa_l2_feed(source, frame, frame_len);
}

int32_t hisi_wpa_feed_mgmt(struct hisi_wpa_context *context,
    uint32_t frequency_mhz, int32_t rssi_dbm,
    const uint8_t *frame, size_t frame_len)
{
    union wpa_event_data event;
    if (context == NULL || context->interface == NULL || frame == NULL ||
        frame_len == 0)
        return -1;
    os_memset(&event, 0, sizeof(event));
    /* WS63 SAE is driven by external-auth. Authentication management frames
     * must remain EVENT_RX_MGMT so upstream SME can match commit/confirm to
     * the active external-auth transaction. EVENT_AUTH is the direct-SME
     * contract and silently strands this path. */
    event.rx_mgmt.freq = (int) frequency_mhz;
    event.rx_mgmt.ssi_signal = rssi_dbm;
    event.rx_mgmt.frame = frame;
    event.rx_mgmt.frame_len = frame_len;
    wpa_supplicant_event(context->interface, EVENT_RX_MGMT, &event);
    observe_state(context);
    return 0;
}

int32_t hisi_wpa_feed_external_auth(struct hisi_wpa_context *context,
    const struct hisi_wpa_external_auth_event *external)
{
    union wpa_event_data event;
    if (context == NULL || context->interface == NULL || external == NULL ||
        external->abi_version != HISI_WPA_ABI_VERSION ||
        external->action > HISI_WPA_EXTERNAL_AUTH_ABORT ||
        external->ssid_len > HISI_WPA_MAX_SSID_LEN ||
        external->pmkid_present > 1)
        return -1;
    if (external->action == HISI_WPA_EXTERNAL_AUTH_START &&
        external->ssid_len == 0)
        return -1;
    os_memset(&event, 0, sizeof(event));
    event.external_auth.action = external->action;
    event.external_auth.bssid = external->bssid;
    event.external_auth.ssid = external->ssid_len == 0 ? NULL :
        external->ssid;
    event.external_auth.ssid_len = external->ssid_len;
    event.external_auth.key_mgmt_suite = external->key_mgmt_suite;
    event.external_auth.status = external->status;
    event.external_auth.pmkid = external->pmkid_present ? external->pmkid :
        NULL;
    event.external_auth.mld_addr = NULL;
    wpa_supplicant_event(context->interface, EVENT_EXTERNAL_AUTH, &event);
    observe_state(context);
    return 0;
}

int32_t hisi_wpa_feed_scan_result(struct hisi_wpa_context *context,
    const struct hisi_wpa_scan_result *result)
{
    if (context == NULL || context->interface == NULL ||
        context->interface->drv_priv == NULL)
        return -1;
    return hisi_wpa_driver_feed_scan_result(context->interface->drv_priv,
        result);
}

int32_t hisi_wpa_feed_scan_done(struct hisi_wpa_context *context,
    int32_t status)
{
    int32_t result;
    if (context == NULL || context->interface == NULL ||
        context->interface->drv_priv == NULL)
        return -1;
    result = hisi_wpa_driver_feed_scan_done(context->interface->drv_priv,
        status);
    observe_state(context);
    return result;
}

int32_t hisi_wpa_feed_associate_result(struct hisi_wpa_context *context,
    const struct hisi_wpa_associate_result *result)
{
    int32_t status;
    if (context == NULL || context->interface == NULL ||
        context->interface->drv_priv == NULL)
        return -1;
    status = hisi_wpa_driver_feed_associate_result(
        context->interface->drv_priv, result);
    observe_state(context);
    return status;
}

int32_t hisi_wpa_feed_disconnect(struct hisi_wpa_context *context,
    const struct hisi_wpa_disconnect_event *event)
{
    int32_t status;
    if (context == NULL || context->interface == NULL ||
        context->interface->drv_priv == NULL)
        return -1;
    status = hisi_wpa_driver_feed_disconnect(context->interface->drv_priv,
        event);
    observe_state(context);
    return status;
}

struct hisi_wpa_poll_result hisi_wpa_poll(struct hisi_wpa_context *context,
    uint64_t now_ms, uint32_t work_budget)
{
    struct hisi_wpa_poll_result result = { 0 };
    uint64_t deadline;
    (void) now_ms;
    if (context == NULL || !context->initialized) {
        result.status = -1;
        return result;
    }
    result.work_pending = hisi_wpa_eloop_run_once(work_budget);
    observe_state(context);
    deadline = hisi_wpa_eloop_next_deadline_us();
    result.next_deadline_ms = deadline == UINT64_MAX ? UINT64_MAX :
        (deadline + 999u) / 1000u;
    if (context->event_read != context->event_write)
        result.work_pending++;
    return result;
}

int32_t hisi_wpa_next_event(struct hisi_wpa_context *context,
    struct hisi_wpa_event *event)
{
    uint32_t dropped;
    if (context == NULL || event == NULL)
        return -1;
    if (context->dropped_events != 0) {
        dropped = context->dropped_events;
        context->dropped_events = 0;
        os_memset(event, 0, sizeof(*event));
        event->abi_version = HISI_WPA_ABI_VERSION;
        event->kind = HISI_WPA_EVENT_FAILED;
        event->data_len = sizeof(dropped);
        event->status = HISI_WPA_STATUS_EVENT_OVERFLOW;
        event->timestamp_ms = timestamp_ms();
        os_memcpy(event->data, &dropped, sizeof(dropped));
        return 1;
    }
    if (context->event_read == context->event_write)
        return 0;
    *event = context->events[context->event_read];
    context->event_read = (uint8_t) ((context->event_read + 1u) %
        HISI_WPA_EVENT_CAPACITY);
    return 1;
}

void hisi_wpa_destroy(struct hisi_wpa_context *context)
{
    void *driver_owner;
    if (context == NULL)
        return;
    driver_owner = context->driver_owner;
    if (context->global != NULL)
        wpa_supplicant_deinit(context->global);
    os_memset(context, 0, sizeof(*context));
    if (driver_owner != NULL)
        (void) hisi_wpa_driver_uninstall(driver_owner);
}
