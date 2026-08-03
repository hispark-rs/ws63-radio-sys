#ifndef HISI_WPA_AP_DRIVER_PORT_H
#define HISI_WPA_AP_DRIVER_PORT_H

#include "hisi_wpa_authenticator.h"

const struct hisi_wpa_ap_driver_hooks *hisi_wpa_ap_driver_acquire(void);
void hisi_wpa_ap_driver_release(void);

#endif
