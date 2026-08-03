#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "hisi_wpa_ap_driver_port.h"

static int32_t get_own_address(void *driver, uint8_t address[6])
{
    const uint8_t expected[6] = { 0x02, 0, 0, 0, 0, 1 };
    assert(driver == (void *) 0x1234u);
    memcpy(address, expected, sizeof(expected));
    return 0;
}

static int32_t set_netdev_enabled(void *driver, uint8_t enabled)
{
    assert(driver == (void *) 0x1234u);
    assert(enabled <= 1);
    return 0;
}

static int32_t configure_beacon(void *driver,
    const struct hisi_wpa_ap_beacon *beacon)
{
    assert(driver == (void *) 0x1234u);
    assert(beacon != NULL && beacon->abi_version == HISI_WPA_AP_ABI_VERSION);
    return 0;
}

static int32_t send_frame(void *driver, const uint8_t destination[6],
    const uint8_t *frame, size_t frame_len)
{
    assert(driver == (void *) 0x1234u);
    assert(destination != NULL && frame != NULL && frame_len != 0);
    return 0;
}

static int32_t send_mgmt(void *driver, uint32_t frequency_mhz,
    const uint8_t *frame, size_t frame_len)
{
    assert(driver == (void *) 0x1234u);
    assert(frequency_mhz != 0 && frame != NULL && frame_len != 0);
    return 0;
}

static int32_t install_key(void *driver, const struct hisi_wpa_key *key,
    const uint8_t *material, size_t material_len)
{
    assert(driver == (void *) 0x1234u);
    assert(key != NULL && material != NULL && material_len != 0);
    return 0;
}

static int32_t remove_key(void *driver, const struct hisi_wpa_key *key)
{
    assert(driver == (void *) 0x1234u);
    assert(key != NULL);
    return 0;
}

static int32_t remove_station(void *driver, const uint8_t address[6])
{
    assert(driver == (void *) 0x1234u);
    assert(address != NULL);
    return 0;
}

static const struct hisi_wpa_ap_driver_hooks hooks = {
    .abi_version = HISI_WPA_AP_ABI_VERSION,
    .driver = (void *) 0x1234u,
    .get_own_address = get_own_address,
    .set_netdev_enabled = set_netdev_enabled,
    .configure_beacon = configure_beacon,
    .send_eapol = send_frame,
    .send_mgmt = send_mgmt,
    .install_key = install_key,
    .remove_key = remove_key,
    .remove_station = remove_station,
};

int main(void)
{
    struct hisi_wpa_ap_driver_hooks conflicting = hooks;
    const struct hisi_wpa_ap_driver_hooks *acquired;

    assert(hisi_wpa_ap_driver_install(NULL) == -1);
    assert(hisi_wpa_ap_driver_install(&hooks) == 0);
    assert(hisi_wpa_ap_driver_install(&hooks) == 0);

    conflicting.driver = (void *) 0x5678u;
    assert(hisi_wpa_ap_driver_install(&conflicting) == -2);

    acquired = hisi_wpa_ap_driver_acquire();
    assert(acquired != NULL && acquired->driver == hooks.driver);
    assert(hisi_wpa_ap_driver_uninstall(hooks.driver) == -2);
    hisi_wpa_ap_driver_release();
    assert(hisi_wpa_ap_driver_uninstall(hooks.driver) == 0);
    assert(hisi_wpa_ap_driver_acquire() == NULL);
    return 0;
}
