//! Raw WS63 SLE SSAP server/notification ABI.
//!
//! This is the bounded S3 slice required to register one server property and
//! copy one client notification. Discovery, read/write and indication APIs are
//! intentionally deferred until they have separate evidence.

use crate::sle::ErrorCode;

pub const UUID_BYTES: usize = 16;
pub const PROPERTY_TYPE_VALUE: u8 = 0;
pub const PERMISSION_READ_WRITE: u16 = 0x03;
pub const OPERATE_READ_NOTIFY: u32 = 0x09;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Uuid {
    pub len: u8,
    pub bytes: [u8; UUID_BYTES],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ServerPropertyInfo {
    pub uuid: Uuid,
    pub permissions: u16,
    pub operate_indication: u32,
    pub value_len: u16,
    pub value: *mut u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NotifyIndicate {
    pub handle: u16,
    pub property_type: u8,
    pub value_len: u16,
    pub value: *mut u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ClientHandleValue {
    pub handle: u16,
    pub property_type: u8,
    pub data_len: u16,
    pub data: *mut u8,
}

pub type StartServiceCallback = unsafe extern "C" fn(server_id: u8, handle: u16, status: ErrorCode);
pub type ClientNotificationCallback = unsafe extern "C" fn(
    client_id: u8,
    connection_id: u16,
    data: *mut ClientHandleValue,
    status: ErrorCode,
);
pub type OpaqueCallback = unsafe extern "C" fn();

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ServerCallbacks {
    pub add_service: Option<OpaqueCallback>,
    pub add_property: Option<OpaqueCallback>,
    pub add_descriptor: Option<OpaqueCallback>,
    pub start_service: Option<StartServiceCallback>,
    pub delete_all_services: Option<OpaqueCallback>,
    pub read_request: Option<OpaqueCallback>,
    pub read_by_uuid_request: Option<OpaqueCallback>,
    pub write_request: Option<OpaqueCallback>,
    pub mtu_changed: Option<OpaqueCallback>,
    pub indicate_confirmed: Option<OpaqueCallback>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ClientCallbacks {
    pub find_structure: Option<OpaqueCallback>,
    pub find_property: Option<OpaqueCallback>,
    pub find_structure_complete: Option<OpaqueCallback>,
    pub read_confirmed: Option<OpaqueCallback>,
    pub read_by_uuid_complete: Option<OpaqueCallback>,
    pub write_confirmed: Option<OpaqueCallback>,
    pub exchange_info: Option<OpaqueCallback>,
    pub notification: Option<ClientNotificationCallback>,
    pub indication: Option<OpaqueCallback>,
}

unsafe extern "C" {
    pub fn ssaps_register_callbacks(callbacks: *mut ServerCallbacks) -> ErrorCode;
    pub fn ssaps_register_server(app_uuid: *mut Uuid, server_id: *mut u8) -> ErrorCode;
    pub fn ssaps_add_service_sync(
        server_id: u8,
        service_uuid: *mut Uuid,
        is_primary: bool,
        handle: *mut u16,
    ) -> ErrorCode;
    pub fn ssaps_add_property_sync(
        server_id: u8,
        service_handle: u16,
        property: *mut ServerPropertyInfo,
        handle: *mut u16,
    ) -> ErrorCode;
    pub fn ssaps_start_service(server_id: u8, service_handle: u16) -> ErrorCode;
    pub fn ssaps_notify_indicate(
        server_id: u8,
        connection_id: u16,
        parameters: *mut NotifyIndicate,
    ) -> ErrorCode;
    pub fn ssapc_register_callbacks(callbacks: *mut ClientCallbacks) -> ErrorCode;
}

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::size_of::<Uuid>() == 17);
    assert!(core::mem::size_of::<ServerPropertyInfo>() == 32);
    assert!(core::mem::offset_of!(ServerPropertyInfo, value) == 28);
    assert!(core::mem::size_of::<NotifyIndicate>() == 12);
    assert!(core::mem::size_of::<ClientHandleValue>() == 12);
    assert!(core::mem::size_of::<ServerCallbacks>() == 40);
    assert!(core::mem::size_of::<ClientCallbacks>() == 36);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_is_byte_exact() {
        assert_eq!(core::mem::size_of::<Uuid>(), 17);
        assert_eq!(core::mem::offset_of!(Uuid, bytes), 1);
    }
}
