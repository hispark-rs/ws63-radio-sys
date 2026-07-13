/* WS63 radio/NVS partition contract.
 *
 * These values match the official ws63_all_nv partition. The runtime owns
 * generic memory mechanics; this chip-specific integration crate owns the
 * radio calibration/configuration partition selected by its blob ABI.
 */
PROVIDE(__nv_storage_start = 0x005FC000);
PROVIDE(__nv_storage_length = 0x00004000);
