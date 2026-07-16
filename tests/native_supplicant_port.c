#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct hisi_wpa_file FILE;

#include "hisi_wpa_supplicant.h"
#include "hisi_wpa_driver_port.h"
#include "common.h"
#include "common/ieee802_11_defs.h"
#include "drivers/driver.h"
#include "eloop.h"
#include "l2_packet/l2_packet.h"

extern const struct wpa_driver_ops wpa_driver_ws63_ops;
int hisi_wpa_sscanf(const char *input, const char *format, ...);
int hisi_wpa_vsnprintf(char *buffer, size_t size, const char *format,
    va_list arguments);
long hisi_wpa_strtol(const char *value, char **end, int base);
void hisi_wpa_qsort(void *base, size_t count, size_t size,
    int (*compare)(const void *left, const void *right));

struct allocation {
    size_t size;
};

static uint64_t now;
static unsigned int wake_count;
static unsigned int wait_count;
static unsigned int callback_count;
static uintptr_t callback_order[8];
static uint8_t sent_destination[6];
static uint8_t sent_frame[64];
static size_t sent_frame_len;
static uint8_t received_source[6];
static uint8_t received_frame[64];
static size_t received_frame_len;
static struct hisi_wpa_key installed_key;
static uint8_t installed_material[32];
static size_t installed_material_len;
static struct hisi_wpa_key removed_key;
static uint8_t sent_mgmt[64];
static size_t sent_mgmt_len;
static uint32_t sent_mgmt_frequency;
static struct hisi_wpa_scan_request started_scan;
static struct hisi_wpa_associate_request started_association;
static uint16_t deauthentication_reason;
static struct hisi_wpa_external_auth_status external_auth_status;
static enum wpa_event_type last_driver_event;
static uint64_t driver_flags = WPA_DRIVER_FLAGS_SAE | WPA_DRIVER_FLAGS_SME;

void wpa_supplicant_event(void *context, enum wpa_event_type event,
    union wpa_event_data *data)
{
    assert(context == (void *) 0x789au);
    (void) data;
    last_driver_event = event;
}

static void *allocate_zeroed(void *context, size_t size, size_t alignment)
{
    struct allocation *allocation;
    (void) context;
    assert(alignment <= _Alignof(max_align_t));
    allocation = calloc(1, sizeof(*allocation) + size);
    if (allocation == NULL)
        return NULL;
    allocation->size = size;
    return allocation + 1;
}

static void *reallocate_zeroed(void *context, void *pointer, size_t size,
    size_t alignment)
{
    struct allocation *old_allocation;
    void *replacement;
    size_t copy;
    (void) context;
    if (pointer == NULL)
        return allocate_zeroed(context, size, alignment);
    old_allocation = (struct allocation *) pointer - 1;
    replacement = allocate_zeroed(context, size, alignment);
    if (replacement == NULL)
        return NULL;
    copy = old_allocation->size < size ? old_allocation->size : size;
    memcpy(replacement, pointer, copy);
    free(old_allocation);
    return replacement;
}

static void deallocate(void *context, void *pointer)
{
    (void) context;
    if (pointer != NULL)
        free((struct allocation *) pointer - 1);
}

static int32_t monotonic_us(void *context, uint64_t *value)
{
    (void) context;
    *value = now;
    return 0;
}

static int32_t wall_clock_us(void *context, uint64_t *value)
{
    (void) context;
    *value = 1700000000000000ull + now;
    return 0;
}

static int32_t sleep_ms(void *context, uint32_t milliseconds)
{
    (void) context;
    now += (uint64_t) milliseconds * 1000u;
    return 0;
}

static int32_t fill_entropy(void *context, uint8_t *output, size_t length)
{
    size_t index;
    (void) context;
    for (index = 0; index < length; index++)
        output[index] = (uint8_t) (0xa0u + index);
    return 0;
}

static int32_t wait_for_work(void *context, uint32_t timeout_ms)
{
    (void) context;
    wait_count++;
    if (timeout_ms != UINT32_MAX)
        now += (uint64_t) timeout_ms * 1000u;
    return 0;
}

static void wake_runner(void *context)
{
    (void) context;
    wake_count++;
}

static void record_timeout(void *eloop_data, void *user_data)
{
    assert(user_data == (void *) 0x55u);
    callback_order[callback_count++] = (uintptr_t) eloop_data;
}

static void terminate_timeout(void *eloop_data, void *user_data)
{
    (void) eloop_data;
    (void) user_data;
    callback_count++;
    eloop_terminate();
}

static const struct hisi_wpa_os_hooks hooks = {
    .abi_version = HISI_WPA_ABI_VERSION,
    .context = (void *) 0x1234u,
    .allocate_zeroed = allocate_zeroed,
    .reallocate_zeroed = reallocate_zeroed,
    .deallocate = deallocate,
    .monotonic_us = monotonic_us,
    .wall_clock_us = wall_clock_us,
    .sleep_ms = sleep_ms,
    .fill_entropy = fill_entropy,
    .wait_for_work = wait_for_work,
    .wake_runner = wake_runner,
};

static int32_t get_own_address(void *driver, uint8_t address[6])
{
    static const uint8_t own[6] = { 0x02, 0x00, 0x73, 0x11, 0x22, 0x33 };
    assert(driver == (void *) 0x4567u);
    memcpy(address, own, sizeof(own));
    return 0;
}

static int32_t get_driver_flags(void *driver, uint64_t *flags)
{
    assert(driver == (void *) 0x4567u);
    assert(flags != NULL);
    *flags = driver_flags;
    return 0;
}

static int32_t send_eapol(void *driver, const uint8_t destination[6],
    const uint8_t *frame, size_t frame_len)
{
    assert(driver == (void *) 0x4567u);
    assert(frame_len <= sizeof(sent_frame));
    memcpy(sent_destination, destination, sizeof(sent_destination));
    memcpy(sent_frame, frame, frame_len);
    sent_frame_len = frame_len;
    return 0;
}

static int32_t send_mgmt(void *driver, uint32_t frequency_mhz,
    const uint8_t *frame, size_t frame_len)
{
    assert(driver == (void *) 0x4567u);
    assert(frame_len <= sizeof(sent_mgmt));
    memcpy(sent_mgmt, frame, frame_len);
    sent_mgmt_len = frame_len;
    sent_mgmt_frequency = frequency_mhz;
    return 0;
}

static int32_t install_key(void *driver, const struct hisi_wpa_key *key,
    const uint8_t *material, size_t material_len)
{
    assert(driver == (void *) 0x4567u);
    assert(key != NULL && key->abi_version == HISI_WPA_ABI_VERSION);
    assert(material_len <= sizeof(installed_material));
    installed_key = *key;
    memcpy(installed_material, material, material_len);
    installed_material_len = material_len;
    return 0;
}

static int32_t remove_key(void *driver, const struct hisi_wpa_key *key)
{
    assert(driver == (void *) 0x4567u);
    assert(key != NULL && key->abi_version == HISI_WPA_ABI_VERSION);
    removed_key = *key;
    return 0;
}

static int32_t start_scan(void *driver,
    const struct hisi_wpa_scan_request *request)
{
    assert(driver == (void *) 0x4567u);
    assert(request != NULL && request->abi_version == HISI_WPA_ABI_VERSION);
    started_scan = *request;
    return 0;
}

static int32_t associate(void *driver,
    const struct hisi_wpa_associate_request *request)
{
    assert(driver == (void *) 0x4567u);
    assert(request != NULL && request->abi_version == HISI_WPA_ABI_VERSION);
    started_association = *request;
    return 0;
}

static int32_t deauthenticate(void *driver, uint16_t reason)
{
    assert(driver == (void *) 0x4567u);
    deauthentication_reason = reason;
    return 0;
}

static int32_t send_external_auth_status(void *driver,
    const struct hisi_wpa_external_auth_status *status)
{
    assert(driver == (void *) 0x4567u);
    assert(status != NULL && status->abi_version == HISI_WPA_ABI_VERSION);
    external_auth_status = *status;
    return 0;
}

static const struct hisi_wpa_driver_hooks driver_hooks = {
    .abi_version = HISI_WPA_ABI_VERSION,
    .reserved = 0,
    .driver = (void *) 0x4567u,
    .get_own_address = get_own_address,
    .get_driver_flags = get_driver_flags,
    .send_eapol = send_eapol,
    .send_mgmt = send_mgmt,
    .install_key = install_key,
    .remove_key = remove_key,
    .start_scan = start_scan,
    .associate = associate,
    .deauthenticate = deauthenticate,
    .send_external_auth_status = send_external_auth_status,
};

static void receive_eapol(void *context, const uint8_t *source,
    const uint8_t *frame, size_t frame_len)
{
    assert(context == (void *) 0x6789u);
    assert(frame_len <= sizeof(received_frame));
    memcpy(received_source, source, sizeof(received_source));
    memcpy(received_frame, frame, frame_len);
    received_frame_len = frame_len;
}

static void test_os_contract(void)
{
    struct os_reltime relative;
    struct os_time wall;
    uint8_t random[4];
    uint8_t *buffer = os_zalloc(8);
    size_t index;

    assert(buffer != NULL);
    for (index = 0; index < 8; index++)
        assert(buffer[index] == 0);
    buffer[0] = 0x5a;
    buffer = os_realloc(buffer, 16);
    assert(buffer != NULL && buffer[0] == 0x5a);
    for (index = 8; index < 16; index++)
        assert(buffer[index] == 0);
    os_free(buffer);

    now = 1234567;
    assert(os_get_reltime(&relative) == 0);
    assert(relative.sec == 1 && relative.usec == 234567);
    assert(os_get_time(&wall) == 0 && wall.sec > 1700000000);
    os_sleep(0, 1501);
    assert(now == 1236567);
    assert(os_get_random(random, sizeof(random)) == 0);
    assert(random[0] == 0xa0 && random[3] == 0xa3);
}

static void test_timeout_order_and_cancellation(void)
{
    struct os_reltime remaining;
    unsigned int wakes_before = wake_count;
    now = 0;
    callback_count = 0;
    assert(eloop_init() == 0);
    assert(eloop_register_timeout(0, 10000, record_timeout,
        (void *) 10u, (void *) 0x55u) == 0);
    assert(eloop_register_timeout(0, 5000, record_timeout,
        (void *) 5u, (void *) 0x55u) == 0);
    assert(eloop_register_timeout(0, 20000, record_timeout,
        (void *) 20u, (void *) 0x55u) == 0);
    assert(wake_count == wakes_before + 3);
    assert(hisi_wpa_eloop_next_deadline_us() == 5000);
    assert(hisi_wpa_eloop_run_once(8) == 0);

    now = 5000;
    assert(hisi_wpa_eloop_run_once(1) == 1);
    assert(callback_count == 1 && callback_order[0] == 5);
    assert(eloop_deplete_timeout(0, 1000, record_timeout,
        (void *) 20u, (void *) 0x55u) == 1);
    assert(hisi_wpa_eloop_next_deadline_us() == 6000);
    assert(eloop_replenish_timeout(0, 10000, record_timeout,
        (void *) 20u, (void *) 0x55u) == 1);
    assert(eloop_cancel_timeout_one(record_timeout, (void *) 10u,
        (void *) 0x55u, &remaining) == 1);
    assert(remaining.sec == 0 && remaining.usec == 5000);
    assert(eloop_cancel_timeout(record_timeout, ELOOP_ALL_CTX,
        ELOOP_ALL_CTX) == 1);
    assert(hisi_wpa_eloop_next_deadline_us() == UINT64_MAX);
    assert(eloop_register_read_sock(1, NULL, NULL, NULL) == -1);
    eloop_destroy();
}

static void test_runner_waits_until_deadline(void)
{
    now = 0;
    wait_count = 0;
    callback_count = 0;
    assert(eloop_init() == 0);
    assert(eloop_register_timeout(0, 2500, terminate_timeout,
        NULL, NULL) == 0);
    eloop_run();
    assert(wait_count == 1);
    assert(now == 3000);
    assert(callback_count == 1);
    assert(eloop_terminated());
    eloop_destroy();
}

static void test_l2_packet_bridge(void)
{
    static const uint8_t source[6] = { 1, 2, 3, 4, 5, 6 };
    static const uint8_t destination[6] = { 6, 5, 4, 3, 2, 1 };
    static const uint8_t payload[4] = { 0x88, 0x8e, 0x01, 0x02 };
    struct l2_packet_data *l2;
    struct l2_packet_data *duplicate;
    struct {
        struct l2_ethhdr header;
        uint8_t payload[sizeof(payload)];
    } frame;
    uint8_t own[6];

    assert(hisi_wpa_driver_install(&driver_hooks) == 0);
    assert(hisi_wpa_driver_install(&driver_hooks) == 0);
    l2 = l2_packet_init("wlan0", NULL, 0x888e, receive_eapol,
        (void *) 0x6789u, 0);
    assert(l2 != NULL);
    duplicate = l2_packet_init("wlan0", NULL, 0x888e, receive_eapol,
        NULL, 0);
    assert(duplicate == NULL);
    assert(hisi_wpa_driver_uninstall(driver_hooks.driver) == -2);
    assert(l2_packet_get_own_addr(l2, own) == 0);
    assert(own[0] == 0x02 && own[5] == 0x33);
    assert(l2_packet_send(l2, destination, 0x888e, payload,
        sizeof(payload)) == 0);
    assert(sent_frame_len == sizeof(payload));
    assert(memcmp(sent_destination, destination, sizeof(destination)) == 0);
    assert(hisi_wpa_l2_feed(source, payload, sizeof(payload)) == 0);
    assert(hisi_wpa_l2_feed(NULL, payload, sizeof(payload)) == -4);
    assert(hisi_wpa_l2_feed(source, NULL, sizeof(payload)) == -4);
    assert(hisi_wpa_l2_feed(source, payload, 0) == -4);
    assert(received_frame_len == sizeof(payload));
    assert(memcmp(received_source, source, sizeof(source)) == 0);

    memcpy(frame.header.h_dest, destination, sizeof(destination));
    memcpy(frame.header.h_source, source, sizeof(source));
    frame.header.h_proto = 0x8e88;
    memcpy(frame.payload, payload, sizeof(payload));
    l2_packet_deinit(l2);
    l2 = l2_packet_init("wlan0", own, 0x888e, NULL, NULL, 1);
    assert(l2 != NULL);
    assert(l2_packet_send(l2, NULL, 0x888e, (const uint8_t *) &frame,
        sizeof(frame)) == 0);
    assert(memcmp(sent_destination, destination, sizeof(destination)) == 0);
    assert(sent_frame_len == sizeof(payload));
    assert(memcmp(sent_frame, payload, sizeof(payload)) == 0);
    l2_packet_deinit(l2);
    assert(hisi_wpa_driver_uninstall(driver_hooks.driver) == 0);
}

static void test_ws63_driver_bridge(void)
{
    static const uint8_t peer[6] = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
    static const uint8_t sequence[6] = { 1, 2, 3, 4, 5, 6 };
    static const uint8_t material[16] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    };
    static const uint8_t management[4] = { 0xb0, 0, 0, 0 };
    static const uint8_t ssid[] = "test";
    static const uint8_t scan_ies[] = { 0, 4, 't', 'e', 's', 't' };
    static const uint8_t rsn_ie[] = { 48, 2, 1, 0 };
    int frequencies[] = { 2412, 0 };
    struct wpa_driver_set_key_params params = { 0 };
    struct wpa_driver_scan_params scan = { 0 };
    struct wpa_driver_associate_params association = { 0 };
    struct hisi_wpa_associate_result association_result = { 0 };
    struct hisi_wpa_scan_result scan_result = { 0 };
    struct wpa_scan_results *results;
    const uint8_t *own;
    void *driver;

    assert(hisi_wpa_driver_install(&driver_hooks) == 0);
    driver = wpa_driver_ws63_ops.init((void *) 0x789au, "wlan0");
    assert(driver != NULL);
    assert(hisi_wpa_driver_is_disconnected(driver));
    assert(hisi_wpa_driver_uninstall(driver_hooks.driver) == -2);
    own = wpa_driver_ws63_ops.get_mac_addr(driver);
    assert(own != NULL && own[0] == 0x02 && own[5] == 0x33);

    params.alg = WPA_ALG_CCMP;
    params.addr = peer;
    params.key_idx = 0;
    params.seq = sequence;
    params.seq_len = sizeof(sequence);
    params.key = material;
    params.key_len = sizeof(material);
    params.key_flag = KEY_FLAG_PAIRWISE_RX_TX;
    assert(wpa_driver_ws63_ops.set_key(driver, &params) == 0);
    assert(installed_key.cipher == HISI_WPA_CIPHER_CCMP);
    assert(installed_key.peer_present == 1);
    assert(installed_key.sequence_len == sizeof(sequence));
    assert(installed_key.flags == (HISI_WPA_KEY_FLAG_PAIRWISE |
        HISI_WPA_KEY_FLAG_RX | HISI_WPA_KEY_FLAG_TX));
    assert(memcmp(installed_key.peer, peer, sizeof(peer)) == 0);
    assert(memcmp(installed_key.sequence, sequence, sizeof(sequence)) == 0);
    assert(installed_material_len == sizeof(material));
    assert(memcmp(installed_material, material, sizeof(material)) == 0);

    params.key_flag = KEY_FLAG_PMK;
    assert(wpa_driver_ws63_ops.set_key(driver, &params) == -1);
    params.key_flag = KEY_FLAG_PAIRWISE_RX_TX;
    params.seq_len = HISI_WPA_KEY_SEQUENCE_LEN + 1;
    assert(wpa_driver_ws63_ops.set_key(driver, &params) == -1);
    params.seq_len = sizeof(sequence);

    params.alg = WPA_ALG_NONE;
    params.key = NULL;
    params.key_len = 0;
    assert(wpa_driver_ws63_ops.set_key(driver, &params) == 0);
    assert(removed_key.cipher == HISI_WPA_CIPHER_NONE);

    assert(wpa_driver_ws63_ops.send_mlme(driver, management,
        sizeof(management), 0, 2412, NULL, 0, 0, 0, -1) == 0);
    assert(sent_mgmt_frequency == 2412);
    assert(sent_mgmt_len == sizeof(management));
    assert(memcmp(sent_mgmt, management, sizeof(management)) == 0);
    assert(wpa_driver_ws63_ops.send_mlme(driver, management,
        sizeof(management), 0, 2412, NULL, 0, 0, 0, 0) == -1);

    {
        struct wpa_driver_capa capability;
        assert(wpa_driver_ws63_ops.get_capa(driver, &capability) == 0);
        assert((capability.key_mgmt &
            WPA_DRIVER_CAPA_KEY_MGMT_WPA2_PSK) != 0);
#ifdef CONFIG_SAE
        assert((capability.key_mgmt & WPA_DRIVER_CAPA_KEY_MGMT_SAE) != 0);
        assert((capability.flags & WPA_DRIVER_FLAGS_SAE) != 0);
        assert((capability.flags & WPA_DRIVER_FLAGS_SME) != 0);
#else
        assert(capability.flags == driver_flags);
#endif
    }

    scan.ssids[0].ssid = ssid;
    scan.ssids[0].ssid_len = sizeof(ssid) - 1;
    scan.num_ssids = 1;
    scan.freqs = frequencies;
    scan.bssid = peer;
    assert(wpa_driver_ws63_ops.scan2(driver, &scan) == 0);
    assert(started_scan.ssid_len == sizeof(ssid) - 1);
    assert(memcmp(started_scan.ssid, ssid, sizeof(ssid) - 1) == 0);
    assert(started_scan.num_frequencies == 1 &&
        started_scan.frequencies[0] == 2412);
    assert(started_scan.bssid_present == 1 &&
        memcmp(started_scan.bssid, peer, sizeof(peer)) == 0);

    scan_result.abi_version = HISI_WPA_ABI_VERSION;
    scan_result.capabilities = 0x11;
    scan_result.bssid[0] = 0x02;
    scan_result.frequency_mhz = 2412;
    scan_result.level_mbm = -4200;
    scan_result.ie_len = sizeof(scan_ies);
    scan_result.ies = scan_ies;
    assert(hisi_wpa_driver_feed_scan_result(driver, &scan_result) == 0);
    assert(hisi_wpa_driver_feed_scan_done(driver, 0) == 0);
    results = wpa_driver_ws63_ops.get_scan_results2(driver);
    assert(results != NULL && results->num == 1);
    assert(results->res[0]->freq == 2412 && results->res[0]->level == -4200);
    assert(results->res[0]->ie_len == sizeof(scan_ies));
    assert(memcmp(results->res[0] + 1, scan_ies, sizeof(scan_ies)) == 0);
    os_free(results->res[0]);
    os_free(results->res);
    os_free(results);

    association.bssid = peer;
    association.ssid = ssid;
    association.ssid_len = sizeof(ssid) - 1;
    association.freq.freq = 2412;
    association.wpa_ie = rsn_ie;
    association.wpa_ie_len = sizeof(rsn_ie);
    association.wpa_proto = WPA_PROTO_RSN;
    association.pairwise_suite = WPA_CIPHER_CCMP;
    association.group_suite = WPA_CIPHER_CCMP;
    association.key_mgmt_suite = WPA_KEY_MGMT_PSK;
    association.auth_alg = WPA_AUTH_ALG_OPEN;
    association.mode = IEEE80211_MODE_INFRA;
    association.mgmt_frame_protection = MGMT_FRAME_PROTECTION_OPTIONAL;
    association.sae_pwe = SAE_PWE_NOT_SET;
    assert(wpa_driver_ws63_ops.associate(driver, &association) == 0);
    assert(hisi_wpa_driver_is_disconnected(driver));
    assert(hisi_wpa_driver_diagnostic_word() == 1);
    assert(started_association.auth_type == HISI_WPA_AUTH_OPEN);
    assert(started_association.pmf == HISI_WPA_PMF_OPTIONAL);
    assert(started_association.frequency_mhz == 2412);
    assert(started_association.wpa_versions == HISI_WPA_VERSION_2);
    assert(started_association.association_ies_len == sizeof(rsn_ie));
    association_result.abi_version = HISI_WPA_ABI_VERSION;
    association_result.frequency_mhz = 2412;
    memcpy(association_result.bssid, peer, sizeof(peer));
    assert(hisi_wpa_driver_feed_associate_result(driver,
        &association_result) == 0);
    assert(!hisi_wpa_driver_is_disconnected(driver));
#ifdef CONFIG_SAE
    association.key_mgmt_suite = WPA_KEY_MGMT_SAE;
    association.auth_alg = WPA_AUTH_ALG_OPEN | WPA_AUTH_ALG_SAE;
    association.mgmt_frame_protection = MGMT_FRAME_PROTECTION_REQUIRED;
    association.sae_pwe = SAE_PWE_BOTH;
    assert(wpa_driver_ws63_ops.associate(driver, &association) == 0);
    assert(started_association.auth_type == HISI_WPA_AUTH_OPEN);
    assert(started_association.key_mgmt_suite == RSN_AUTH_KEY_MGMT_SAE);
#endif
    assert(wpa_driver_ws63_ops.deauthenticate(driver, peer, 3) == 0);
    assert(deauthentication_reason == 3);
    assert(hisi_wpa_driver_is_disconnected(driver));

#ifdef CONFIG_SAE
    {
        static const uint8_t pmkid[16] = { 1, 2, 3, 4 };
        struct external_auth auth_status = { 0 };
        auth_status.bssid = peer;
        auth_status.status = WLAN_STATUS_SUCCESS;
        auth_status.pmkid = pmkid;
        assert(wpa_driver_ws63_ops.send_external_auth_status(driver,
            &auth_status) == 0);
        assert(hisi_wpa_driver_diagnostic_word() == 4);
        assert(external_auth_status.status == WLAN_STATUS_SUCCESS);
        assert(memcmp(external_auth_status.bssid, peer, ETH_ALEN) == 0);
        assert(external_auth_status.pmkid_present == 1);
        assert(memcmp(external_auth_status.pmkid, pmkid, sizeof(pmkid)) == 0);
    }
#endif

    wpa_driver_ws63_ops.deinit(driver);
    assert(hisi_wpa_driver_uninstall(driver_hooks.driver) == 0);
}

static int native_format(char *buffer, size_t size, const char *format, ...)
{
    int result;
    va_list arguments;
    va_start(arguments, format);
    result = hisi_wpa_vsnprintf(buffer, size, format, arguments);
    va_end(arguments);
    return result;
}

static int compare_ints(const void *left, const void *right)
{
    int a = *(const int *) left;
    int b = *(const int *) right;
    return (a > b) - (a < b);
}

static void test_freestanding_contract(void)
{
    char formatted[64];
    char truncated[5];
    char *end;
    unsigned int first = 0;
    unsigned int second = 0;
    int values[] = { 7, -1, 9, 0, 7 };

    assert(native_format(formatted, sizeof(formatted),
        "x=%02x s=%-4.3s n=%lld z=%zu", 0xau, "hello",
        -1234567890123ll, (size_t) 17) == 33);
    assert(strcmp(formatted, "x=0a s=hel  n=-1234567890123 z=17") == 0);
    assert(native_format(truncated, sizeof(truncated), "abcdef") == 6);
    assert(strcmp(truncated, "abcd") == 0);
    assert(native_format(NULL, 0, "%08X", 0x12u) == 8);
    assert(native_format(formatted, sizeof(formatted), "%f", 1.0) == -1);

    assert(hisi_wpa_strtol(" -0x20tail", &end, 0) == -32);
    assert(strcmp(end, "tail") == 0);
    assert(hisi_wpa_strtol("075", &end, 0) == 61 && *end == '\0');
    assert(hisi_wpa_strtol("no", &end, 10) == 0 && end[0] == 'n');

    assert(hisi_wpa_sscanf("15:4", "%u:%u", &first, &second) == 2);
    assert(first == 15 && second == 4);
    assert(hisi_wpa_sscanf("9", "%u:%u", &first, &second) == 1);
    assert(first == 9);
    assert(hisi_wpa_sscanf("1:2", "%d:%d", &first, &second) == -1);

    hisi_wpa_qsort(values, sizeof(values) / sizeof(values[0]),
        sizeof(values[0]), compare_ints);
    assert(values[0] == -1 && values[1] == 0 && values[2] == 7 &&
        values[3] == 7 && values[4] == 9);
}

int main(void)
{
    struct hisi_wpa_os_hooks conflicting_hooks = hooks;
    struct hisi_wpa_driver_hooks invalid_driver_hooks = driver_hooks;
    invalid_driver_hooks.abi_version++;
    assert(hisi_wpa_driver_install(&invalid_driver_hooks) == -1);
    invalid_driver_hooks = driver_hooks;
    invalid_driver_hooks.reserved = 1;
    assert(hisi_wpa_driver_install(&invalid_driver_hooks) == -1);
    assert(hisi_wpa_os_install(&hooks) == 0);
    assert(hisi_wpa_os_install(&hooks) == 0);
    conflicting_hooks.sleep_ms = NULL;
    assert(hisi_wpa_os_install(&conflicting_hooks) == -1);
    conflicting_hooks = hooks;
    conflicting_hooks.context = (void *) 0x5678u;
    assert(hisi_wpa_os_install(&conflicting_hooks) == -2);
    test_os_contract();
    assert(eloop_init() == 0);
    assert(eloop_init() == -1);
    eloop_destroy();
    test_timeout_order_and_cancellation();
    test_runner_waits_until_deadline();
    test_l2_packet_bridge();
    test_ws63_driver_bridge();
    test_freestanding_contract();
    assert(hisi_wpa_os_uninstall(hooks.context) == 0);
    return 0;
}
