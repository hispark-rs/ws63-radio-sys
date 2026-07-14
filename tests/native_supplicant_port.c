#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct hisi_wpa_file FILE;

#define OS_NO_C_LIB_DEFINES
#include "hisi_wpa_supplicant.h"
#include "hisi_wpa_driver_port.h"
#include "common.h"
#include "eloop.h"
#include "l2_packet/l2_packet.h"

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
    (void) driver; (void) frequency_mhz; (void) frame; (void) frame_len;
    return -1;
}

static int32_t install_key(void *driver, const struct hisi_wpa_key *key,
    const uint8_t *material, size_t material_len)
{
    (void) driver; (void) key; (void) material; (void) material_len;
    return -1;
}

static int32_t remove_key(void *driver, const struct hisi_wpa_key *key)
{
    (void) driver; (void) key;
    return -1;
}

static const struct hisi_wpa_driver_hooks driver_hooks = {
    .driver = (void *) 0x4567u,
    .get_own_address = get_own_address,
    .send_eapol = send_eapol,
    .send_mgmt = send_mgmt,
    .install_key = install_key,
    .remove_key = remove_key,
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

int main(void)
{
    struct hisi_wpa_os_hooks conflicting_hooks = hooks;
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
    assert(hisi_wpa_os_uninstall(hooks.context) == 0);
    return 0;
}
