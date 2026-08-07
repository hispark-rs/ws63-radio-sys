//! Raw WS63 SLE discovery and connection ABI.
//!
//! The layout is derived from the pinned WS63 SDK's
//! `sle_device_discovery.h` and `sle_connection_manager.h`. This module exposes
//! the bounded S1 discovery and S2 connect/disconnect slices; SSAP declarations
//! remain out of scope until their own archive and silicon evidence exists.

use core::ffi::c_void;

/// Vendor SLE error code.
pub type ErrorCode = u32;

/// Maximum number of PHY parameter entries in one seek request.
pub const SEEK_PHY_COUNT: usize = 3;

pub const CONNECTION_STATE_NONE: u32 = 0;
pub const CONNECTION_STATE_CONNECTED: u32 = 1;
pub const CONNECTION_STATE_DISCONNECTED: u32 = 2;
pub const PAIR_STATE_NONE: u32 = 1;
pub const PAIR_STATE_PAIRING: u32 = 2;
pub const PAIR_STATE_PAIRED: u32 = 3;
pub const DISCONNECT_BY_REMOTE: u32 = 0x10;
pub const DISCONNECT_BY_LOCAL: u32 = 0x11;

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

/// Default parameters used while establishing an SLE connection.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DefaultConnectionParameters {
    pub enable_filter_policy: u8,
    pub initiate_phys: u8,
    pub gt_negotiate: u8,
    pub scan_interval: u16,
    pub scan_window: u16,
    pub min_interval: u16,
    pub max_interval: u16,
    pub timeout: u16,
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
pub type ConnectionStateChangedCallback = unsafe extern "C" fn(
    connection_id: u16,
    address: *const Address,
    connection_state: u32,
    pair_state: u32,
    disconnect_reason: u32,
);
pub type ConnectionParameterUpdateRequestCallback =
    unsafe extern "C" fn(connection_id: u16, status: ErrorCode, parameters: *const c_void);
pub type ConnectionParameterUpdateCallback =
    unsafe extern "C" fn(connection_id: u16, status: ErrorCode, parameters: *const c_void);
pub type AuthenticationCompleteCallback = unsafe extern "C" fn(
    connection_id: u16,
    address: *const Address,
    status: ErrorCode,
    event: *const c_void,
);
pub type PairCompleteCallback =
    unsafe extern "C" fn(connection_id: u16, address: *const Address, status: ErrorCode);
pub type ReadRssiCallback = unsafe extern "C" fn(connection_id: u16, rssi: i8, status: ErrorCode);
pub type LowLatencyCallback = unsafe extern "C" fn(status: u8, address: *mut Address, rate: u8);
pub type SetPhyCallback =
    unsafe extern "C" fn(connection_id: u16, status: ErrorCode, parameters: *const c_void);
pub type PairRemoveCallback = unsafe extern "C" fn(address: *const Address, status: ErrorCode);

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

/// Raw callback table registered with the WS63 SLE connection manager.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ConnectionCallbacks {
    pub connection_state_changed: Option<ConnectionStateChangedCallback>,
    pub connection_parameter_update_request: Option<ConnectionParameterUpdateRequestCallback>,
    pub connection_parameter_update: Option<ConnectionParameterUpdateCallback>,
    pub authentication_complete: Option<AuthenticationCompleteCallback>,
    pub pair_complete: Option<PairCompleteCallback>,
    pub read_rssi: Option<ReadRssiCallback>,
    pub low_latency: Option<LowLatencyCallback>,
    pub set_phy: Option<SetPhyCallback>,
    pub pair_remove: Option<PairRemoveCallback>,
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
    pub fn sle_set_local_addr(address: *mut Address) -> ErrorCode;
    pub fn sle_default_connection_param_set(
        parameters: *mut DefaultConnectionParameters,
    ) -> ErrorCode;
    pub fn sle_connection_register_callbacks(callbacks: *mut ConnectionCallbacks) -> ErrorCode;
    pub fn sle_connect_remote_device(address: *const Address) -> ErrorCode;
    pub fn sle_disconnect_remote_device(address: *const Address) -> ErrorCode;
    pub fn sle_pair_remote_device(address: *const Address) -> ErrorCode;
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
    assert!(core::mem::size_of::<DefaultConnectionParameters>() == 14);
    assert!(core::mem::offset_of!(DefaultConnectionParameters, scan_interval) == 4);
    assert!(core::mem::size_of::<ConnectionCallbacks>() == 36);
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

    #[test]
    fn connection_parameters_match_vendor_alignment() {
        assert_eq!(core::mem::size_of::<DefaultConnectionParameters>(), 14);
        assert_eq!(
            core::mem::offset_of!(DefaultConnectionParameters, scan_interval),
            4
        );
        assert_eq!(
            core::mem::offset_of!(DefaultConnectionParameters, timeout),
            12
        );
    }
}
