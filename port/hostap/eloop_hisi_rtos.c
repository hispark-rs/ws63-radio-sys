#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "hisi_wpa_hostap_compat.h"
#include "os.h"
#include "eloop.h"

#include "hisi_wpa_port.h"

struct hisi_timeout {
    struct hisi_timeout *next;
    uint64_t deadline_us;
    eloop_timeout_handler handler;
    void *eloop_data;
    void *user_data;
};

static struct hisi_timeout *g_timeouts;
static int g_initialized;
static int g_terminate;

static uint64_t saturating_add(uint64_t left, uint64_t right)
{
    return UINT64_MAX - left < right ? UINT64_MAX : left + right;
}

static int now_us(uint64_t *value)
{
    return hisi_wpa_os_monotonic_us(value);
}

static uint64_t timeout_delta(unsigned int seconds, unsigned int microseconds)
{
    uint64_t value = (uint64_t) seconds * 1000000u;
    return saturating_add(value, microseconds);
}

static int context_matches(void *actual, void *expected)
{
    return expected == ELOOP_ALL_CTX || actual == expected;
}

static int timeout_matches(const struct hisi_timeout *timeout,
    eloop_timeout_handler handler, void *eloop_data, void *user_data)
{
    return timeout->handler == handler &&
        context_matches(timeout->eloop_data, eloop_data) &&
        context_matches(timeout->user_data, user_data);
}

static void insert_timeout(struct hisi_timeout *timeout)
{
    struct hisi_timeout **cursor = &g_timeouts;
    while (*cursor != NULL && (*cursor)->deadline_us <= timeout->deadline_us)
        cursor = &(*cursor)->next;
    timeout->next = *cursor;
    *cursor = timeout;
}

int eloop_init(void)
{
    if (hisi_wpa_os_current() == NULL || g_initialized)
        return -1;
    g_timeouts = NULL;
    g_terminate = 0;
    g_initialized = 1;
    return 0;
}

int eloop_register_read_sock(int sock, eloop_sock_handler handler,
    void *eloop_data, void *user_data)
{
    (void) sock; (void) handler; (void) eloop_data; (void) user_data;
    return -1;
}

void eloop_unregister_read_sock(int sock) { (void) sock; }

int eloop_register_sock(int sock, eloop_event_type type,
    eloop_sock_handler handler, void *eloop_data, void *user_data)
{
    (void) sock; (void) type; (void) handler; (void) eloop_data;
    (void) user_data; return -1;
}

void eloop_unregister_sock(int sock, eloop_event_type type)
{
    (void) sock; (void) type;
}

int eloop_register_event(void *event, size_t event_size,
    eloop_event_handler handler, void *eloop_data, void *user_data)
{
    (void) event; (void) event_size; (void) handler; (void) eloop_data;
    (void) user_data; return -1;
}

void eloop_unregister_event(void *event, size_t event_size)
{
    (void) event; (void) event_size;
}

int eloop_register_timeout(unsigned int seconds, unsigned int microseconds,
    eloop_timeout_handler handler, void *eloop_data, void *user_data)
{
    struct hisi_timeout *timeout;
    uint64_t current;
    if (!g_initialized || handler == NULL || now_us(&current) != 0)
        return -1;
    timeout = os_zalloc(sizeof(*timeout));
    if (timeout == NULL)
        return -1;
    timeout->deadline_us = saturating_add(current,
        timeout_delta(seconds, microseconds));
    timeout->handler = handler;
    timeout->eloop_data = eloop_data;
    timeout->user_data = user_data;
    insert_timeout(timeout);
    hisi_wpa_os_wake_runner();
    return 0;
}

int eloop_cancel_timeout(eloop_timeout_handler handler, void *eloop_data,
    void *user_data)
{
    struct hisi_timeout **cursor = &g_timeouts;
    int cancelled = 0;
    while (*cursor != NULL) {
        struct hisi_timeout *timeout = *cursor;
        if (!timeout_matches(timeout, handler, eloop_data, user_data)) {
            cursor = &timeout->next;
            continue;
        }
        *cursor = timeout->next;
        os_free(timeout);
        cancelled++;
    }
    if (cancelled != 0)
        hisi_wpa_os_wake_runner();
    return cancelled;
}

int eloop_cancel_timeout_one(eloop_timeout_handler handler, void *eloop_data,
    void *user_data, struct os_reltime *remaining)
{
    struct hisi_timeout **cursor = &g_timeouts;
    uint64_t current = 0;
    (void) now_us(&current);
    while (*cursor != NULL) {
        struct hisi_timeout *timeout = *cursor;
        uint64_t left;
        if (!timeout_matches(timeout, handler, eloop_data, user_data)) {
            cursor = &timeout->next;
            continue;
        }
        *cursor = timeout->next;
        left = timeout->deadline_us > current ?
            timeout->deadline_us - current : 0;
        if (remaining != NULL) {
            remaining->sec = (os_time_t) (left / 1000000u);
            remaining->usec = (os_time_t) (left % 1000000u);
        }
        os_free(timeout);
        hisi_wpa_os_wake_runner();
        return 1;
    }
    return 0;
}

int eloop_is_timeout_registered(eloop_timeout_handler handler,
    void *eloop_data, void *user_data)
{
    struct hisi_timeout *cursor;
    for (cursor = g_timeouts; cursor != NULL; cursor = cursor->next) {
        if (timeout_matches(cursor, handler, eloop_data, user_data))
            return 1;
    }
    return 0;
}

static int update_timeout(unsigned int seconds, unsigned int microseconds,
    eloop_timeout_handler handler, void *eloop_data, void *user_data,
    int deplete)
{
    struct hisi_timeout **cursor = &g_timeouts;
    uint64_t current;
    uint64_t requested;
    if (now_us(&current) != 0)
        return -1;
    requested = saturating_add(current, timeout_delta(seconds, microseconds));
    while (*cursor != NULL) {
        struct hisi_timeout *timeout = *cursor;
        int change;
        if (!timeout_matches(timeout, handler, eloop_data, user_data)) {
            cursor = &timeout->next;
            continue;
        }
        change = deplete ? timeout->deadline_us > requested :
            timeout->deadline_us < requested;
        if (!change)
            return 0;
        *cursor = timeout->next;
        timeout->deadline_us = requested;
        insert_timeout(timeout);
        hisi_wpa_os_wake_runner();
        return 1;
    }
    return -1;
}

int eloop_deplete_timeout(unsigned int seconds, unsigned int microseconds,
    eloop_timeout_handler handler, void *eloop_data, void *user_data)
{
    return update_timeout(seconds, microseconds, handler, eloop_data,
        user_data, 1);
}

int eloop_replenish_timeout(unsigned int seconds, unsigned int microseconds,
    eloop_timeout_handler handler, void *eloop_data, void *user_data)
{
    return update_timeout(seconds, microseconds, handler, eloop_data,
        user_data, 0);
}

int eloop_register_signal(int signal, eloop_signal_handler handler,
    void *user_data)
{
    (void) signal; (void) handler; (void) user_data; return -1;
}

int eloop_register_signal_terminate(eloop_signal_handler handler,
    void *user_data)
{
    (void) handler; (void) user_data; return -1;
}

int eloop_register_signal_reconfig(eloop_signal_handler handler,
    void *user_data)
{
    (void) handler; (void) user_data; return -1;
}

int eloop_sock_requeue(void) { return -1; }

uint32_t hisi_wpa_eloop_run_once(uint32_t work_budget)
{
    uint32_t completed = 0;
    uint64_t current;
    if (!g_initialized || work_budget == 0)
        return 0;
    while (completed < work_budget && g_timeouts != NULL) {
        struct hisi_timeout *timeout;
        if (now_us(&current) != 0 || g_timeouts->deadline_us > current)
            break;
        timeout = g_timeouts;
        g_timeouts = timeout->next;
        {
            eloop_timeout_handler handler = timeout->handler;
            void *eloop_data = timeout->eloop_data;
            void *user_data = timeout->user_data;
            os_free(timeout);
            handler(eloop_data, user_data);
        }
        completed++;
    }
    return completed;
}

uint64_t hisi_wpa_eloop_next_deadline_us(void)
{
    return g_timeouts == NULL ? UINT64_MAX : g_timeouts->deadline_us;
}

void hisi_wpa_eloop_wake(void) { hisi_wpa_os_wake_runner(); }

void eloop_run(void)
{
    while (!g_terminate) {
        uint64_t current;
        uint64_t deadline;
        uint64_t remaining;
        uint64_t timeout_ms;
        (void) hisi_wpa_eloop_run_once(UINT32_MAX);
        if (g_terminate)
            break;
        deadline = hisi_wpa_eloop_next_deadline_us();
        if (deadline == UINT64_MAX) {
            if (hisi_wpa_os_wait_for_work(UINT32_MAX) != 0)
                break;
            continue;
        }
        if (now_us(&current) != 0)
            break;
        remaining = deadline > current ? deadline - current : 0;
        timeout_ms = (remaining + 999u) / 1000u;
        if (timeout_ms > UINT32_MAX)
            timeout_ms = UINT32_MAX;
        if (hisi_wpa_os_wait_for_work((uint32_t) timeout_ms) != 0)
            break;
    }
}

void eloop_terminate(void)
{
    g_terminate = 1;
    hisi_wpa_os_wake_runner();
}

void eloop_destroy(void)
{
    while (g_timeouts != NULL) {
        struct hisi_timeout *timeout = g_timeouts;
        g_timeouts = timeout->next;
        os_free(timeout);
    }
    g_initialized = 0;
    g_terminate = 0;
}

int eloop_terminated(void) { return g_terminate; }
void eloop_wait_for_read_sock(int sock) { (void) sock; }
