#include "hisi_wpa_port.h"

static struct hisi_wpa_os_hooks g_hooks;
static int g_installed;

static int hooks_valid(const struct hisi_wpa_os_hooks *hooks)
{
    return hooks != NULL && hooks->abi_version == HISI_WPA_ABI_VERSION &&
        hooks->reserved == 0 && hooks->allocate_zeroed != NULL &&
        hooks->reallocate_zeroed != NULL && hooks->deallocate != NULL &&
        hooks->monotonic_us != NULL && hooks->sleep_ms != NULL &&
        hooks->fill_entropy != NULL && hooks->wait_for_work != NULL &&
        hooks->wake_runner != NULL;
}

static int hooks_equal(const struct hisi_wpa_os_hooks *left,
    const struct hisi_wpa_os_hooks *right)
{
    return left->abi_version == right->abi_version &&
        left->reserved == right->reserved &&
        left->context == right->context &&
        left->allocate_zeroed == right->allocate_zeroed &&
        left->reallocate_zeroed == right->reallocate_zeroed &&
        left->deallocate == right->deallocate &&
        left->monotonic_us == right->monotonic_us &&
        left->wall_clock_us == right->wall_clock_us &&
        left->sleep_ms == right->sleep_ms &&
        left->fill_entropy == right->fill_entropy &&
        left->wait_for_work == right->wait_for_work &&
        left->wake_runner == right->wake_runner;
}

int32_t hisi_wpa_os_install(const struct hisi_wpa_os_hooks *hooks)
{
    if (!hooks_valid(hooks))
        return -1;
    if (g_installed)
        return hooks_equal(&g_hooks, hooks) ? 0 : -2;
    g_hooks = *hooks;
    g_installed = 1;
    return 0;
}

int32_t hisi_wpa_os_uninstall(void *context)
{
    if (!g_installed || g_hooks.context != context)
        return -1;
    g_hooks = (struct hisi_wpa_os_hooks) { 0 };
    g_installed = 0;
    return 0;
}

const struct hisi_wpa_os_hooks *hisi_wpa_os_current(void)
{
    return g_installed ? &g_hooks : NULL;
}

void *hisi_wpa_os_allocate_zeroed(size_t size, size_t alignment)
{
    const struct hisi_wpa_os_hooks *hooks = hisi_wpa_os_current();
    return hooks == NULL ? NULL :
        hooks->allocate_zeroed(hooks->context, size, alignment);
}

void *hisi_wpa_os_reallocate_zeroed(void *pointer, size_t size,
    size_t alignment)
{
    const struct hisi_wpa_os_hooks *hooks = hisi_wpa_os_current();
    return hooks == NULL ? NULL :
        hooks->reallocate_zeroed(hooks->context, pointer, size, alignment);
}

void hisi_wpa_os_deallocate(void *pointer)
{
    const struct hisi_wpa_os_hooks *hooks = hisi_wpa_os_current();
    if (hooks != NULL)
        hooks->deallocate(hooks->context, pointer);
}

int32_t hisi_wpa_os_monotonic_us(uint64_t *value)
{
    const struct hisi_wpa_os_hooks *hooks = hisi_wpa_os_current();
    return hooks == NULL ? -1 : hooks->monotonic_us(hooks->context, value);
}

int32_t hisi_wpa_os_wall_clock_us(uint64_t *value)
{
    const struct hisi_wpa_os_hooks *hooks = hisi_wpa_os_current();
    return hooks == NULL || hooks->wall_clock_us == NULL ? -1 :
        hooks->wall_clock_us(hooks->context, value);
}

int32_t hisi_wpa_os_sleep_ms(uint32_t milliseconds)
{
    const struct hisi_wpa_os_hooks *hooks = hisi_wpa_os_current();
    return hooks == NULL ? -1 : hooks->sleep_ms(hooks->context, milliseconds);
}

int32_t hisi_wpa_os_fill_entropy(uint8_t *output, size_t output_len)
{
    const struct hisi_wpa_os_hooks *hooks = hisi_wpa_os_current();
    return hooks == NULL ? -1 :
        hooks->fill_entropy(hooks->context, output, output_len);
}

int32_t hisi_wpa_os_wait_for_work(uint32_t timeout_ms)
{
    const struct hisi_wpa_os_hooks *hooks = hisi_wpa_os_current();
    return hooks == NULL ? -1 :
        hooks->wait_for_work(hooks->context, timeout_ms);
}

void hisi_wpa_os_wake_runner(void)
{
    const struct hisi_wpa_os_hooks *hooks = hisi_wpa_os_current();
    if (hooks != NULL)
        hooks->wake_runner(hooks->context);
}
