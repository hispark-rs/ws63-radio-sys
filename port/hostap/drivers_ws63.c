#include "hisi_wpa_hostap_compat.h"
#include "drivers/driver.h"

extern const struct wpa_driver_ops wpa_driver_ws63_ops;

const struct wpa_driver_ops *const wpa_drivers[] = {
    &wpa_driver_ws63_ops,
    NULL,
};
