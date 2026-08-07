//! Raw WS63 SLE announce/seek ABI.
//!
//! The layout is derived from the pinned WS63 SDK's
//! `sle_device_discovery.h`. This module intentionally exposes only the S1
//! discovery slice; connection and SSAP declarations are added only with their
//! own archive and silicon evidence.

use core::ffi::c_void;

/// Vendor SLE error code.
pub type ErrorCode = u32;

/// Maximum number of PHY parameter entries in one seek request.
pub const SEEK_PHY_COUNT: usize = 3;

/// Raw WS63 SLE device address.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Address {
    /// Vendor address type (`0` public, `6` random).
    pub address_type: u8,
    /// Six address octets in vendor order.
    pub bytes: [u8; 6],
}

/// Raw announce parameters consumed asynchronously by the vendor stack.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AnnounceParameters {
    pub announce_handle: u8,
    pub announce_mode: u8,
    pub announce_gt_role: u8,
    pub announce_level: u8,
    pub announce_interval_min: u32,
    pub announce_interval_max: u32,
    pub announce_channel_map: u8,
    pub announce_tx_power: i8,
    pub own_address: Address,
    pub peer_address: Address,
    pub connection_interval_min: u16,
    pub connection_interval_max: u16,
    pub connection_max_latency: u16,
    pub connection_supervision_timeout: u16,
    pub extended_parameters: *mut c_void,
}

/// Raw announce and seek-response payload pointers.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AnnounceData {
    pub announce_data_len: u16,
    pub seek_response_data_len: u16,
    pub announce_data: *mut u8,
    pub seek_response_data: *mut u8,
}

/// Raw seek parameters for the three WS63 SLE PHYs.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SeekParameters {
    pub own_address_type: u8,
    pub filter_duplicates: u8,
    pub filter_policy: u8,
    pub phys: u8,
    pub seek_type: [u8; SEEK_PHY_COUNT],
    pub interval: [u16; SEEK_PHY_COUNT],
    pub window: [u16; SEEK_PHY_COUNT],
}

/// Vendor-owned seek result valid only during its callback.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SeekResult {
    pub event_type: u8,
    pub address: Address,
    pub direct_address: Address,
    pub rssi: u8,
    pub data_status: u8,
    pub data_length: u8,
    pub data: *mut u8,
}

pub type EnableCallback = unsafe extern "C" fn(status: ErrorCode);
pub type DisableCallback = unsafe extern "C" fn(status: ErrorCode);
pub type AnnounceEnableCallback = unsafe extern "C" fn(announce_id: u32, status: ErrorCode);
pub type AnnounceDisableCallback = unsafe extern "C" fn(announce_id: u32, status: ErrorCode);
pub type AnnounceTerminalCallback = unsafe extern "C" fn(announce_id: u32);
pub type AnnounceRemoveCallback = unsafe extern "C" fn(announce_id: u32, status: ErrorCode);
pub type SeekEnableCallback = unsafe extern "C" fn(status: ErrorCode);
pub type SeekDisableCallback = unsafe extern "C" fn(status: ErrorCode);
pub type SeekResultCallback = unsafe extern "C" fn(result: *mut SeekResult);
pub type DfrCallback = unsafe extern "C" fn();

/// Raw callback table registered with the WS63 SLE discovery service.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AnnounceSeekCallbacks {
    pub enable: Option<EnableCallback>,
    pub disable: Option<DisableCallback>,
    pub announce_enable: Option<AnnounceEnableCallback>,
    pub announce_disable: Option<AnnounceDisableCallback>,
    pub announce_terminal: Option<AnnounceTerminalCallback>,
    pub announce_remove: Option<AnnounceRemoveCallback>,
    pub seek_enable: Option<SeekEnableCallback>,
    pub seek_disable: Option<SeekDisableCallback>,
    pub seek_result: Option<SeekResultCallback>,
    pub dfr: Option<DfrCallback>,
}

unsafe extern "C" {
    pub fn enable_sle() -> ErrorCode;
    pub fn disable_sle() -> ErrorCode;
    pub fn sle_announce_seek_register_callbacks(callbacks: *mut AnnounceSeekCallbacks)
    -> ErrorCode;
    pub fn sle_set_announce_param(
        announce_id: u8,
        parameters: *const AnnounceParameters,
    ) -> ErrorCode;
    pub fn sle_set_announce_data(announce_id: u8, data: *const AnnounceData) -> ErrorCode;
    pub fn sle_start_announce(announce_id: u8) -> ErrorCode;
    pub fn sle_stop_announce(announce_id: u8) -> ErrorCode;
    pub fn sle_set_seek_param(parameters: *mut SeekParameters) -> ErrorCode;
    pub fn sle_start_seek() -> ErrorCode;
    pub fn sle_stop_seek() -> ErrorCode;
}

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::size_of::<Address>() == 7);
    assert!(core::mem::size_of::<AnnounceParameters>() == 40);
    assert!(core::mem::offset_of!(AnnounceParameters, extended_parameters) == 36);
    assert!(core::mem::size_of::<AnnounceData>() == 12);
    assert!(core::mem::size_of::<SeekParameters>() == 20);
    assert!(core::mem::offset_of!(SeekParameters, interval) == 8);
    assert!(core::mem::size_of::<SeekResult>() == 24);
    assert!(core::mem::offset_of!(SeekResult, data) == 20);
    assert!(core::mem::size_of::<AnnounceSeekCallbacks>() == 40);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_layout_is_byte_exact() {
        assert_eq!(core::mem::size_of::<Address>(), 7);
        assert_eq!(core::mem::offset_of!(Address, bytes), 1);
    }

    #[test]
    fn seek_arrays_follow_vendor_phy_order() {
        assert_eq!(SEEK_PHY_COUNT, 3);
        assert_eq!(core::mem::offset_of!(SeekParameters, seek_type), 4);
        assert_eq!(core::mem::offset_of!(SeekParameters, interval), 8);
        assert_eq!(core::mem::offset_of!(SeekParameters, window), 14);
    }
}
