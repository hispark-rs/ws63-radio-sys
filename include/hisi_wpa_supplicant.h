#ifndef HISI_WPA_SUPPLICANT_H
#define HISI_WPA_SUPPLICANT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HISI_WPA_ABI_VERSION 5u
#define HISI_WPA_MAX_SSID_LEN 32u
#define HISI_WPA_EVENT_DATA_LEN 128u
#define HISI_WPA_KEY_SEQUENCE_LEN 16u
#define HISI_WPA_STATUS_EVENT_OVERFLOW (-1001)

#define HISI_WPA_CIPHER_NONE 0u
#define HISI_WPA_CIPHER_WEP 1u
#define HISI_WPA_CIPHER_TKIP 2u
#define HISI_WPA_CIPHER_CCMP 3u
#define HISI_WPA_CIPHER_BIP_CMAC_128 4u
#define HISI_WPA_CIPHER_GCMP 5u
#define HISI_WPA_CIPHER_GCMP_256 6u
#define HISI_WPA_CIPHER_CCMP_256 7u
#define HISI_WPA_CIPHER_BIP_GMAC_128 8u
#define HISI_WPA_CIPHER_BIP_GMAC_256 9u
#define HISI_WPA_CIPHER_BIP_CMAC_256 10u

#define HISI_WPA_KEY_FLAG_MODIFY (1u << 0)
#define HISI_WPA_KEY_FLAG_DEFAULT (1u << 1)
#define HISI_WPA_KEY_FLAG_RX (1u << 2)
#define HISI_WPA_KEY_FLAG_TX (1u << 3)
#define HISI_WPA_KEY_FLAG_GROUP (1u << 4)
#define HISI_WPA_KEY_FLAG_PAIRWISE (1u << 5)
#define HISI_WPA_KEY_FLAG_PMK (1u << 6)

struct hisi_wpa_context;

enum hisi_wpa_security {
    HISI_WPA_SECURITY_WPA2_PSK = 1,
    HISI_WPA_SECURITY_WPA3_SAE = 2,
};

enum hisi_wpa_pmf {
    HISI_WPA_PMF_DISABLED = 0,
    HISI_WPA_PMF_OPTIONAL = 1,
    HISI_WPA_PMF_REQUIRED = 2,
};

enum hisi_wpa_sae_pwe {
    HISI_WPA_SAE_PWE_HUNT_AND_PECK = 0,
    HISI_WPA_SAE_PWE_HASH_TO_ELEMENT = 1,
    HISI_WPA_SAE_PWE_BOTH = 2,
};

enum hisi_wpa_event_kind {
    HISI_WPA_EVENT_NONE = 0,
    HISI_WPA_EVENT_AUTHENTICATING = 1,
    HISI_WPA_EVENT_ASSOCIATED = 2,
    HISI_WPA_EVENT_AUTHORIZED = 3,
    HISI_WPA_EVENT_DISCONNECTED = 4,
    HISI_WPA_EVENT_FAILED = 5,
};

struct hisi_wpa_network_config {
    uint16_t abi_version;
    uint8_t security;
    uint8_t pmf;
    uint8_t ssid_len;
    uint8_t sae_pwe;
    uint8_t channel;
    uint8_t reserved0;
    uint8_t ssid[HISI_WPA_MAX_SSID_LEN];
    uint8_t bssid[6];
    uint8_t reserved1[2];
};

struct hisi_wpa_key {
    uint16_t abi_version;
    uint8_t cipher;
    uint8_t key_index;
    uint32_t flags;
    uint8_t peer[6];
    uint8_t peer_present;
    uint8_t sequence_len;
    uint8_t sequence[HISI_WPA_KEY_SEQUENCE_LEN];
};

struct hisi_wpa_event {
    uint16_t abi_version;
    uint8_t kind;
    uint8_t data_len;
    int32_t status;
    uint64_t timestamp_ms;
    uint8_t data[HISI_WPA_EVENT_DATA_LEN];
};

struct hisi_wpa_poll_result {
    int32_t status;
    uint32_t work_pending;
    uint64_t next_deadline_ms;
};

struct hisi_wpa_os_hooks {
    uint16_t abi_version;
    uint16_t reserved;
    void *context;
    void *(*allocate_zeroed)(void *context, size_t size, size_t alignment);
    void *(*reallocate_zeroed)(void *context, void *pointer, size_t size,
        size_t alignment);
    void (*deallocate)(void *context, void *pointer);
    int32_t (*monotonic_us)(void *context, uint64_t *value);
    int32_t (*wall_clock_us)(void *context, uint64_t *value);
    int32_t (*sleep_ms)(void *context, uint32_t milliseconds);
    int32_t (*fill_entropy)(void *context, uint8_t *output,
        size_t output_len);
    int32_t (*wait_for_work)(void *context, uint32_t timeout_ms);
    void (*wake_runner)(void *context);
};

struct hisi_wpa_driver_hooks {
    uint16_t abi_version;
    uint16_t reserved;
    void *driver;
    int32_t (*get_own_address)(void *driver, uint8_t address[6]);
    /* frame starts at the IEEE 802.1X/EAPOL header; no Ethernet header. */
    int32_t (*send_eapol)(void *driver, const uint8_t dst[6],
        const uint8_t *frame, size_t frame_len);
    int32_t (*send_mgmt)(void *driver, uint32_t frequency_mhz,
        const uint8_t *frame, size_t frame_len);
    int32_t (*install_key)(void *driver, const struct hisi_wpa_key *key,
        const uint8_t *material, size_t material_len);
    int32_t (*remove_key)(void *driver, const struct hisi_wpa_key *key);
};

int32_t hisi_wpa_driver_install(const struct hisi_wpa_driver_hooks *hooks);
int32_t hisi_wpa_driver_uninstall(void *driver);

int32_t hisi_wpa_os_install(const struct hisi_wpa_os_hooks *hooks);
int32_t hisi_wpa_os_uninstall(void *context);

uint32_t hisi_wpa_eloop_run_once(uint32_t work_budget);
uint64_t hisi_wpa_eloop_next_deadline_us(void);
void hisi_wpa_eloop_wake(void);

size_t hisi_wpa_context_size(void);
size_t hisi_wpa_context_align(void);
struct hisi_wpa_context *hisi_wpa_create(void *storage, size_t storage_len,
    const struct hisi_wpa_driver_hooks *hooks);
int32_t hisi_wpa_init(struct hisi_wpa_context *context);
int32_t hisi_wpa_configure(struct hisi_wpa_context *context,
    const struct hisi_wpa_network_config *config,
    const uint8_t *passphrase, size_t passphrase_len);
int32_t hisi_wpa_connect(struct hisi_wpa_context *context);
int32_t hisi_wpa_disconnect(struct hisi_wpa_context *context);
int32_t hisi_wpa_feed_eapol(struct hisi_wpa_context *context,
    const uint8_t source[6], const uint8_t *frame, size_t frame_len);
int32_t hisi_wpa_feed_mgmt(struct hisi_wpa_context *context,
    uint32_t frequency_mhz, int32_t rssi_dbm,
    const uint8_t *frame, size_t frame_len);
struct hisi_wpa_poll_result hisi_wpa_poll(struct hisi_wpa_context *context,
    uint64_t now_ms, uint32_t work_budget);
int32_t hisi_wpa_next_event(struct hisi_wpa_context *context,
    struct hisi_wpa_event *event);
void hisi_wpa_destroy(struct hisi_wpa_context *context);

_Static_assert(sizeof(struct hisi_wpa_network_config) == 48,
    "hisi_wpa_network_config ABI drift");
_Static_assert(sizeof(struct hisi_wpa_key) == 32,
    "hisi_wpa_key ABI drift");
_Static_assert(offsetof(struct hisi_wpa_key, flags) == 4,
    "hisi_wpa_key flags offset drift");
_Static_assert(offsetof(struct hisi_wpa_key, sequence) == 16,
    "hisi_wpa_key sequence offset drift");
_Static_assert(sizeof(struct hisi_wpa_event) == 144,
    "hisi_wpa_event ABI drift");
_Static_assert(sizeof(struct hisi_wpa_poll_result) == 16,
    "hisi_wpa_poll_result ABI drift");
_Static_assert(offsetof(struct hisi_wpa_os_hooks, context) == sizeof(void *),
    "hisi_wpa_os_hooks prefix drift");
_Static_assert(sizeof(struct hisi_wpa_os_hooks) == 11 * sizeof(void *),
    "hisi_wpa_os_hooks ABI drift");
_Static_assert(offsetof(struct hisi_wpa_driver_hooks, driver) == sizeof(void *),
    "hisi_wpa_driver_hooks prefix drift");
_Static_assert(sizeof(struct hisi_wpa_driver_hooks) == 7 * sizeof(void *),
    "hisi_wpa_driver_hooks ABI drift");

#ifdef __cplusplus
}
#endif

#endif
