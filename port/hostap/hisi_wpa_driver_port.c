#include "hisi_wpa_driver_port.h"

static struct hisi_wpa_driver_hooks g_hooks;
static int g_installed;
static size_t g_users;

static int hooks_valid(const struct hisi_wpa_driver_hooks *hooks)
{
    return hooks != NULL && hooks->abi_version == HISI_WPA_ABI_VERSION &&
        hooks->reserved == 0 && hooks->driver != NULL &&
        hooks->get_own_address != NULL && hooks->send_eapol != NULL &&
        hooks->send_mgmt != NULL && hooks->install_key != NULL &&
        hooks->remove_key != NULL;
}

static int hooks_equal(const struct hisi_wpa_driver_hooks *left,
    const struct hisi_wpa_driver_hooks *right)
{
    return left->abi_version == right->abi_version &&
        left->reserved == right->reserved &&
        left->driver == right->driver &&
        left->get_own_address == right->get_own_address &&
        left->send_eapol == right->send_eapol &&
        left->send_mgmt == right->send_mgmt &&
        left->install_key == right->install_key &&
        left->remove_key == right->remove_key;
}

int32_t hisi_wpa_driver_install(const struct hisi_wpa_driver_hooks *hooks)
{
    if (!hooks_valid(hooks))
        return -1;
    if (g_installed)
        return hooks_equal(&g_hooks, hooks) ? 0 : -2;
    g_hooks = *hooks;
    g_installed = 1;
    return 0;
}

int32_t hisi_wpa_driver_uninstall(void *driver)
{
    if (!g_installed || g_hooks.driver != driver)
        return -1;
    if (g_users != 0 || hisi_wpa_l2_is_active())
        return -2;
    g_hooks = (struct hisi_wpa_driver_hooks) { 0 };
    g_installed = 0;
    return 0;
}

const struct hisi_wpa_driver_hooks *hisi_wpa_driver_current(void)
{
    return g_installed ? &g_hooks : NULL;
}

const struct hisi_wpa_driver_hooks *hisi_wpa_driver_acquire(void)
{
    if (!g_installed)
        return NULL;
    g_users++;
    return &g_hooks;
}

void hisi_wpa_driver_release(void)
{
    if (g_users != 0)
        g_users--;
}
