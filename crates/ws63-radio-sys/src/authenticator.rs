//! Raw, versioned ABI for the upstream hostapd WS63 authenticator port.
//!
//! The AP and STA contexts are separate target archives. Applications select
//! exactly one role per WS63 firmware image and drive its context from the
//! shared radio runner.

use crate::supplicant::{Key, PollResult};
use core::ffi::{c_int, c_void};

pub const ABI_VERSION: u16 = 1;
pub const MAX_SSID_LEN: usize = 32;

#[repr(C)]
pub struct Context {
    _private: [u8; 0],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Security {
    Open = 0,
    Wpa2Psk = 1,
    Wpa3Sae = 2,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Config {
    pub abi_version: u16,
    pub security: u8,
    pub pmf: u8,
    pub ssid_len: u8,
    pub sae_pwe: u8,
    pub channel: u8,
    pub hidden_ssid: u8,
    pub beacon_interval: u16,
    pub dtim_period: u8,
    pub max_stations: u8,
    pub reserved: [u8; 4],
    pub ssid: [u8; MAX_SSID_LEN],
}

#[repr(C)]
pub struct Beacon {
    pub abi_version: u16,
    pub hidden_ssid: u8,
    pub sae_pwe: u8,
    pub beacon_interval: u16,
    pub dtim_period: u8,
    pub channel: u8,
    pub frequency_mhz: u32,
    pub auth_algorithms: u32,
    pub wpa_versions: u32,
    pub privacy: u8,
    pub ssid_len: u8,
    pub reserved: [u8; 2],
    pub ssid: [u8; MAX_SSID_LEN],
    pub head: *const u8,
    pub head_len: usize,
    pub tail: *const u8,
    pub tail_len: usize,
}

pub type GetOwnAddress = unsafe extern "C" fn(driver: *mut c_void, address: *mut u8) -> c_int;
pub type SetNetdevEnabled = unsafe extern "C" fn(driver: *mut c_void, enabled: u8) -> c_int;
pub type ConfigureBeacon =
    unsafe extern "C" fn(driver: *mut c_void, beacon: *const Beacon) -> c_int;
pub type SendEapol = unsafe extern "C" fn(
    driver: *mut c_void,
    destination: *const u8,
    frame: *const u8,
    frame_len: usize,
) -> c_int;
pub type SendMgmt = unsafe extern "C" fn(
    driver: *mut c_void,
    frequency_mhz: u32,
    frame: *const u8,
    frame_len: usize,
) -> c_int;
pub type InstallKey = unsafe extern "C" fn(
    driver: *mut c_void,
    key: *const Key,
    material: *const u8,
    material_len: usize,
) -> c_int;
pub type RemoveKey = unsafe extern "C" fn(driver: *mut c_void, key: *const Key) -> c_int;
pub type RemoveStation = unsafe extern "C" fn(driver: *mut c_void, address: *const u8) -> c_int;

#[repr(C)]
pub struct DriverHooks {
    pub abi_version: u16,
    pub reserved: u16,
    pub driver: *mut c_void,
    pub get_own_address: Option<GetOwnAddress>,
    pub set_netdev_enabled: Option<SetNetdevEnabled>,
    pub configure_beacon: Option<ConfigureBeacon>,
    pub send_eapol: Option<SendEapol>,
    pub send_mgmt: Option<SendMgmt>,
    pub install_key: Option<InstallKey>,
    pub remove_key: Option<RemoveKey>,
    pub remove_station: Option<RemoveStation>,
}

unsafe extern "C" {
    pub fn hisi_wpa_ap_driver_install(hooks: *const DriverHooks) -> c_int;
    pub fn hisi_wpa_ap_driver_uninstall(driver: *mut c_void) -> c_int;
    pub fn hisi_wpa_ap_context_size() -> usize;
    pub fn hisi_wpa_ap_context_align() -> usize;
    pub fn hisi_wpa_ap_create(
        storage: *mut c_void,
        storage_len: usize,
        hooks: *const DriverHooks,
    ) -> *mut Context;
    pub fn hisi_wpa_ap_configure(
        context: *mut Context,
        config: *const Config,
        passphrase: *const u8,
        passphrase_len: usize,
    ) -> c_int;
    pub fn hisi_wpa_ap_start(context: *mut Context) -> c_int;
    pub fn hisi_wpa_ap_poll(context: *mut Context, now_ms: u64, work_budget: u32) -> PollResult;
    pub fn hisi_wpa_ap_feed_eapol(
        context: *mut Context,
        source: *const u8,
        frame: *const u8,
        frame_len: usize,
    ) -> c_int;
    pub fn hisi_wpa_ap_feed_mgmt(
        context: *mut Context,
        frequency_mhz: u32,
        rssi_dbm: i32,
        frame: *const u8,
        frame_len: usize,
    ) -> c_int;
    pub fn hisi_wpa_ap_stop(context: *mut Context) -> c_int;
    pub fn hisi_wpa_ap_destroy(context: *mut Context);
}

const _: () = {
    assert!(core::mem::size_of::<Config>() == 48);
    assert!(core::mem::offset_of!(DriverHooks, driver) == core::mem::size_of::<usize>());
    assert!(core::mem::size_of::<DriverHooks>() == 10 * core::mem::size_of::<usize>());
};
