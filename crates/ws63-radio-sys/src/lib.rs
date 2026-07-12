#![no_std]

//! Raw WS63 radio blob integration contract.
//!
//! This crate deliberately contains no safe radio API and no scheduler policy.
//! Its Cargo build script exports the checked-out blob paths and this module
//! records the archive ordering/roots that define the current vendor ABI.

/// Blob ABI revision consumed by this integration crate.
pub const BLOB_ABI_REVISION: &str = "ws63-rf-2026-07-13";

/// Archive name and extraction policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Archive {
    pub name: &'static str,
    pub whole_archive: bool,
}

/// Base Wi-Fi archives in vendor link order.
pub const WIFI_ARCHIVES: &[Archive] = &[
    Archive {
        name: "wifi_alg_anti_interference",
        whole_archive: false,
    },
    Archive {
        name: "wifi_alg_cca_opt",
        whole_archive: false,
    },
    Archive {
        name: "wifi_alg_edca_opt",
        whole_archive: false,
    },
    Archive {
        name: "wifi_alg_temp_protect",
        whole_archive: false,
    },
    Archive {
        name: "wifi_alg_txbf",
        whole_archive: false,
    },
    Archive {
        name: "wifi_driver_hmac",
        whole_archive: false,
    },
    Archive {
        name: "wifi_driver_dmac",
        whole_archive: false,
    },
    Archive {
        name: "wifi_driver_tcm",
        whole_archive: false,
    },
    Archive {
        name: "bg_common",
        whole_archive: false,
    },
    Archive {
        name: "wifi_rom_data",
        whole_archive: true,
    },
];

/// Symbols that root optional Wi-Fi archive members.
pub const WIFI_ROOT_SYMBOLS: &[&str] = &[
    "alg_anti_intf_init",
    "alg_cca_opt_init",
    "alg_edca_opt_init",
    "alg_temp_protect_init",
    "alg_hmac_txbf_init",
    "dmac_psm_process_tim_elm_patch",
    "hh503_dispatch_trig_event_encap_patch",
];

/// Additional archive names for the vendor WPA2-Personal path.
pub const WPA2_ARCHIVES: &[&str] = &[
    "wpa_supplicant",
    "drv_security_unified",
    "hal_security_unified",
    "c",
    "m",
];

/// Symbols that root the ROM callback/data ABI payload.
pub const ROM_CALLBACK_ROOT_SYMBOLS: &[&str] = &["__wrap_log_event_wifi_print1", "g_systick_clock"];
