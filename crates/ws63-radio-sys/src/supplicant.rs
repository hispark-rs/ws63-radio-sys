//! Raw, versioned ABI for the upstream hostap supplicant port.
//!
//! The ABI deliberately exposes no hostap internal structures. The C port owns
//! one opaque context driven by the radio runner; callbacks below are platform
//! driver hooks and must never call application code.

use core::ffi::{c_int, c_void};

pub const ABI_VERSION: u16 = 5;
pub const MAX_SSID_LEN: usize = 32;
pub const EVENT_DATA_LEN: usize = 128;
pub const KEY_SEQUENCE_LEN: usize = 16;

pub mod cipher {
    pub const NONE: u8 = 0;
    pub const WEP: u8 = 1;
    pub const TKIP: u8 = 2;
    pub const CCMP: u8 = 3;
    pub const BIP_CMAC_128: u8 = 4;
    pub const GCMP: u8 = 5;
    pub const GCMP_256: u8 = 6;
    pub const CCMP_256: u8 = 7;
    pub const BIP_GMAC_128: u8 = 8;
    pub const BIP_GMAC_256: u8 = 9;
    pub const BIP_CMAC_256: u8 = 10;
}

pub mod key_flag {
    pub const MODIFY: u32 = 1 << 0;
    pub const DEFAULT: u32 = 1 << 1;
    pub const RX: u32 = 1 << 2;
    pub const TX: u32 = 1 << 3;
    pub const GROUP: u32 = 1 << 4;
    pub const PAIRWISE: u32 = 1 << 5;
    pub const PMK: u32 = 1 << 6;
}

#[repr(C)]
pub struct Context {
    _private: [u8; 0],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Security {
    Wpa2Psk = 1,
    Wpa3Sae = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Pmf {
    Disabled = 0,
    Optional = 1,
    Required = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SaePwe {
    HuntAndPeck = 0,
    HashToElement = 1,
    Both = 2,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct NetworkConfig {
    pub abi_version: u16,
    pub security: u8,
    pub pmf: u8,
    pub ssid_len: u8,
    pub sae_pwe: u8,
    pub channel: u8,
    pub reserved0: u8,
    pub ssid: [u8; MAX_SSID_LEN],
    pub bssid: [u8; 6],
    pub reserved1: [u8; 2],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Key {
    pub abi_version: u16,
    pub cipher: u8,
    pub key_index: u8,
    pub flags: u32,
    pub peer: [u8; 6],
    pub peer_present: u8,
    pub sequence_len: u8,
    pub sequence: [u8; KEY_SEQUENCE_LEN],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Event {
    pub abi_version: u16,
    pub kind: u8,
    pub data_len: u8,
    pub status: i32,
    pub timestamp_ms: u64,
    pub data: [u8; EVENT_DATA_LEN],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct PollResult {
    pub status: i32,
    pub work_pending: u32,
    pub next_deadline_ms: u64,
}

pub type AllocateZeroed =
    unsafe extern "C" fn(context: *mut c_void, size: usize, alignment: usize) -> *mut c_void;
pub type ReallocateZeroed = unsafe extern "C" fn(
    context: *mut c_void,
    pointer: *mut c_void,
    size: usize,
    alignment: usize,
) -> *mut c_void;
pub type Deallocate = unsafe extern "C" fn(context: *mut c_void, pointer: *mut c_void);
pub type MonotonicUs = unsafe extern "C" fn(context: *mut c_void, value: *mut u64) -> c_int;
pub type WallClockUs = unsafe extern "C" fn(context: *mut c_void, value: *mut u64) -> c_int;
pub type SleepMs = unsafe extern "C" fn(context: *mut c_void, milliseconds: u32) -> c_int;
pub type FillEntropy =
    unsafe extern "C" fn(context: *mut c_void, output: *mut u8, output_len: usize) -> c_int;
pub type WaitForWork = unsafe extern "C" fn(context: *mut c_void, timeout_ms: u32) -> c_int;
pub type WakeRunner = unsafe extern "C" fn(context: *mut c_void);

#[repr(C)]
pub struct OsHooks {
    pub abi_version: u16,
    pub reserved: u16,
    pub context: *mut c_void,
    pub allocate_zeroed: Option<AllocateZeroed>,
    pub reallocate_zeroed: Option<ReallocateZeroed>,
    pub deallocate: Option<Deallocate>,
    pub monotonic_us: Option<MonotonicUs>,
    pub wall_clock_us: Option<WallClockUs>,
    pub sleep_ms: Option<SleepMs>,
    pub fill_entropy: Option<FillEntropy>,
    pub wait_for_work: Option<WaitForWork>,
    pub wake_runner: Option<WakeRunner>,
}

pub type SendEapol = unsafe extern "C" fn(
    driver: *mut c_void,
    dst: *const u8,
    frame: *const u8,
    frame_len: usize,
) -> c_int;
pub type GetOwnAddress = unsafe extern "C" fn(driver: *mut c_void, address: *mut u8) -> c_int;
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
#[repr(C)]
pub struct DriverHooks {
    pub abi_version: u16,
    pub reserved: u16,
    pub driver: *mut c_void,
    pub get_own_address: Option<GetOwnAddress>,
    pub send_eapol: Option<SendEapol>,
    pub send_mgmt: Option<SendMgmt>,
    pub install_key: Option<InstallKey>,
    pub remove_key: Option<RemoveKey>,
}

unsafe extern "C" {
    pub fn hisi_wpa_os_install(hooks: *const OsHooks) -> c_int;
    pub fn hisi_wpa_os_uninstall(context: *mut c_void) -> c_int;
    pub fn hisi_wpa_eloop_run_once(work_budget: u32) -> u32;
    pub fn hisi_wpa_eloop_next_deadline_us() -> u64;
    pub fn hisi_wpa_eloop_wake();
    pub fn hisi_wpa_driver_install(hooks: *const DriverHooks) -> c_int;
    pub fn hisi_wpa_driver_uninstall(driver: *mut c_void) -> c_int;
    pub fn hisi_wpa_context_size() -> usize;
    pub fn hisi_wpa_create(
        storage: *mut c_void,
        storage_len: usize,
        hooks: *const DriverHooks,
    ) -> *mut Context;
    pub fn hisi_wpa_init(context: *mut Context) -> c_int;
    pub fn hisi_wpa_configure(
        context: *mut Context,
        config: *const NetworkConfig,
        passphrase: *const u8,
        passphrase_len: usize,
    ) -> c_int;
    pub fn hisi_wpa_connect(context: *mut Context) -> c_int;
    pub fn hisi_wpa_disconnect(context: *mut Context) -> c_int;
    pub fn hisi_wpa_feed_eapol(
        context: *mut Context,
        source: *const u8,
        frame: *const u8,
        frame_len: usize,
    ) -> c_int;
    pub fn hisi_wpa_feed_mgmt(
        context: *mut Context,
        frequency_mhz: u32,
        rssi_dbm: i32,
        frame: *const u8,
        frame_len: usize,
    ) -> c_int;
    pub fn hisi_wpa_poll(context: *mut Context, now_ms: u64, work_budget: u32) -> PollResult;
    pub fn hisi_wpa_next_event(context: *mut Context, event: *mut Event) -> c_int;
    pub fn hisi_wpa_destroy(context: *mut Context);
}

const _: () = {
    assert!(core::mem::size_of::<NetworkConfig>() == 48);
    assert!(core::mem::size_of::<Key>() == 32);
    assert!(core::mem::offset_of!(Key, flags) == 4);
    assert!(core::mem::offset_of!(Key, sequence) == 16);
    assert!(core::mem::size_of::<Event>() == 144);
    assert!(core::mem::size_of::<PollResult>() == 16);
    assert!(core::mem::offset_of!(OsHooks, context) == core::mem::size_of::<usize>());
    assert!(core::mem::size_of::<OsHooks>() == 11 * core::mem::size_of::<usize>());
    assert!(core::mem::offset_of!(DriverHooks, driver) == core::mem::size_of::<usize>());
    assert!(core::mem::size_of::<DriverHooks>() == 7 * core::mem::size_of::<usize>());
};
