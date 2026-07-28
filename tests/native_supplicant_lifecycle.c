#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct hisi_wpa_file FILE;

#include "hisi_wpa_supplicant.h"
#include "hisi_wpa_context_internal.h"
#include "hisi_wpa_port.h"
#include "crypto/aes.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"

#undef free
void free(void *pointer);

struct allocation {
    size_t size;
};

struct driver_state {
    unsigned int install_count;
    unsigned int remove_count;
    unsigned int pairwise_remove_count;
    unsigned int deauthenticate_count;
    bool key_active;
    struct hisi_wpa_key installed;
    struct hisi_wpa_key removed;
};

static uint64_t now_us;

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
    struct allocation *allocation;
    void *replacement;
    size_t copy;
    if (pointer == NULL)
        return allocate_zeroed(context, size, alignment);
    allocation = (struct allocation *) pointer - 1;
    replacement = allocate_zeroed(context, size, alignment);
    if (replacement == NULL)
        return NULL;
    copy = allocation->size < size ? allocation->size : size;
    memcpy(replacement, pointer, copy);
    free(allocation);
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
    *value = now_us;
    return 0;
}

static int32_t wall_clock_us(void *context, uint64_t *value)
{
    (void) context;
    *value = 1700000000000000ull + now_us;
    return 0;
}

static int32_t sleep_ms(void *context, uint32_t milliseconds)
{
    (void) context;
    now_us += (uint64_t) milliseconds * 1000u;
    return 0;
}

static int32_t fill_entropy(void *context, uint8_t *output, size_t length)
{
    size_t index;
    (void) context;
    for (index = 0; index < length; index++)
        output[index] = (uint8_t) (0x40u + index);
    return 0;
}

static int32_t wait_for_work(void *context, uint32_t timeout_ms)
{
    (void) context;
    if (timeout_ms != UINT32_MAX)
        now_us += (uint64_t) timeout_ms * 1000u;
    return 0;
}

static void wake_runner(void *context)
{
    (void) context;
}

static int32_t get_own_address(void *driver, uint8_t address[6])
{
    static const uint8_t own[6] = { 0x02, 0, 0x73, 0x11, 0x22, 0x33 };
    assert(driver != NULL);
    memcpy(address, own, sizeof(own));
    return 0;
}

static int32_t get_driver_flags(void *driver, uint64_t *flags)
{
    assert(driver != NULL && flags != NULL);
    *flags = WPA_DRIVER_FLAGS_SME;
    return 0;
}

static int32_t send_eapol(void *driver, const uint8_t destination[6],
    const uint8_t *frame, size_t frame_len)
{
    (void) driver;
    (void) destination;
    (void) frame;
    (void) frame_len;
    return 0;
}

static int32_t send_mgmt(void *driver, uint32_t frequency_mhz,
    const uint8_t *frame, size_t frame_len)
{
    (void) driver;
    (void) frequency_mhz;
    (void) frame;
    (void) frame_len;
    return 0;
}

static int32_t install_key(void *driver, const struct hisi_wpa_key *key,
    const uint8_t *material, size_t material_len)
{
    struct driver_state *state = driver;
    assert(state != NULL && key != NULL && material != NULL);
    assert(material_len != 0);
    state->installed = *key;
    state->install_count++;
    state->key_active = true;
    return 0;
}

static int32_t remove_key(void *driver, const struct hisi_wpa_key *key)
{
    struct driver_state *state = driver;
    assert(state != NULL && key != NULL);
    state->removed = *key;
    state->remove_count++;
    if (key->flags & HISI_WPA_KEY_FLAG_PAIRWISE) {
        state->pairwise_remove_count++;
        if (!state->key_active)
            return -17;
        state->key_active = false;
    }
    return 0;
}

static int32_t start_scan(void *driver,
    const struct hisi_wpa_scan_request *request)
{
    (void) driver;
    (void) request;
    return 0;
}

static int32_t associate(void *driver,
    const struct hisi_wpa_associate_request *request)
{
    (void) driver;
    (void) request;
    return 0;
}

static int32_t deauthenticate(void *driver, uint16_t reason)
{
    struct driver_state *state = driver;
    assert(state != NULL);
    assert(reason == WLAN_REASON_DEAUTH_LEAVING);
    state->deauthenticate_count++;
    return 0;
}

static int32_t send_external_auth_status(void *driver,
    const struct hisi_wpa_external_auth_status *status)
{
    (void) driver;
    (void) status;
    return 0;
}

/*
 * The lifecycle under test does not perform a handshake. These stubs satisfy
 * the explicit crypto ABI of the complete hostap profile so the host test
 * links the same source closure as the target archive.
 */
void *aes_encrypt_init(const u8 *key, size_t len)
{
    (void) key;
    (void) len;
    return (void *) 1;
}

int aes_encrypt(void *context, const u8 *plain, u8 *crypt)
{
    (void) context;
    memcpy(crypt, plain, 16);
    return 0;
}

void aes_encrypt_deinit(void *context)
{
    (void) context;
}

void *aes_decrypt_init(const u8 *key, size_t len)
{
    return aes_encrypt_init(key, len);
}

int aes_decrypt(void *context, const u8 *crypt, u8 *plain)
{
    return aes_encrypt(context, crypt, plain);
}

void aes_decrypt_deinit(void *context)
{
    (void) context;
}

int hmac_sha1_vector(const u8 *key, size_t key_len, size_t num_elem,
    const u8 *address[], const size_t *length, u8 *mac)
{
    (void) key;
    (void) key_len;
    (void) num_elem;
    (void) address;
    (void) length;
    memset(mac, 0, 20);
    return 0;
}

int hmac_sha1(const u8 *key, size_t key_len, const u8 *data,
    size_t data_len, u8 *mac)
{
    const u8 *address[] = { data };
    const size_t length[] = { data_len };
    return hmac_sha1_vector(key, key_len, 1, address, length, mac);
}

int hmac_sha256_vector(const u8 *key, size_t key_len, size_t num_elem,
    const u8 *address[], const size_t *length, u8 *mac)
{
    (void) key;
    (void) key_len;
    (void) num_elem;
    (void) address;
    (void) length;
    memset(mac, 0, 32);
    return 0;
}

int pbkdf2_sha1(const char *passphrase, const u8 *ssid, size_t ssid_len,
    int iterations, u8 *buffer, size_t buffer_len)
{
    (void) passphrase;
    (void) ssid;
    (void) ssid_len;
    (void) iterations;
    memset(buffer, 0, buffer_len);
    return 0;
}

int main(void)
{
    static const uint8_t peer[6] = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
    static const uint8_t material[16] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    };
    struct driver_state state = { 0 };
    struct hisi_wpa_os_hooks os_hooks = {
        .abi_version = HISI_WPA_ABI_VERSION,
        .context = &state,
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
    struct hisi_wpa_driver_hooks driver_hooks = {
        .abi_version = HISI_WPA_ABI_VERSION,
        .driver = &state,
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
    struct hisi_wpa_context *context;
    void *storage;

    assert(hisi_wpa_os_install(&os_hooks) == 0);
    storage = calloc(1, hisi_wpa_context_size());
    assert(storage != NULL);
    context = hisi_wpa_create(storage, hisi_wpa_context_size(),
        &driver_hooks);
    assert(context != NULL);
    assert(hisi_wpa_init(context) == 0);

    state.install_count = 0;
    state.remove_count = 0;
    state.pairwise_remove_count = 0;
    state.deauthenticate_count = 0;
    state.key_active = false;
    memcpy(context->interface->bssid, peer, sizeof(peer));
    context->interface->wpa_state = WPA_COMPLETED;
    assert(wpa_drv_set_key(context->interface, -1, WPA_ALG_CCMP, peer, 0,
        1, NULL, 0, material, sizeof(material),
        KEY_FLAG_PAIRWISE_RX_TX) == 0);
    assert(state.install_count == 1);
    assert(state.key_active);

    assert(hisi_wpa_disconnect(context) == 0);
    assert(state.deauthenticate_count == 1);
    assert(state.remove_count == 2);
    assert(state.pairwise_remove_count == 1);
    assert(!state.key_active);
    assert(state.removed.cipher == HISI_WPA_CIPHER_NONE);
    assert(state.removed.key_index == 0);
    assert(state.removed.peer_present == 1);
    assert(memcmp(state.removed.peer, peer, sizeof(peer)) == 0);

    assert(hisi_wpa_disconnect(context) == 0);
    assert(state.remove_count == 2);
    assert(state.pairwise_remove_count == 1);
    assert(!state.key_active);

    hisi_wpa_destroy(context);
    free(storage);
    assert(hisi_wpa_os_uninstall(os_hooks.context) == 0);
    return 0;
}
