#include "utils/includes.h"

#include "crypto/dh_groups.h"

/*
 * WPA3-Personal on WS63 supports SAE group 19 through crypto_ec_init().
 * Finite-field groups are outside this source profile; fail closed instead of
 * pulling the generic DH implementation and its unused crypto ABI into the
 * firmware.
 */
const struct dh_group *dh_groups_get(int id)
{
    (void) id;
    return NULL;
}
