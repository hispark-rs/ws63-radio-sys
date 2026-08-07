//! Raw WS63 SLE SSAP server/notification ABI.
//!
//! This is the bounded S3 slice required to register one server property,
//! discover that service, trigger one read request, and copy one client
//! notification. Write and indication APIs remain outside this evidence slice.

use crate::sle::ErrorCode;

pub const UUID_BYTES: usize = 16;
pub const FIND_TYPE_PRIMARY_SERVICE: u8 = 1;
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExchangeInfo {
    pub mtu_size: u32,
    pub version: u16,
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

pub type ClientWriteParameters = ClientHandleValue;
pub type ClientWriteResult = ClientHandleValue;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FindServiceResult {
    pub start_handle: u16,
    pub end_handle: u16,
    pub uuid: Uuid,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FindStructureParameters {
    pub find_type: u8,
    pub start_handle: u16,
    pub end_handle: u16,
    pub uuid: Uuid,
    pub reserved: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FindStructureResult {
    pub find_type: u8,
    pub uuid: Uuid,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerReadRequest {
    pub request_id: u16,
    pub handle: u16,
    pub property_type: u8,
    pub need_response: bool,
    pub need_authorize: bool,
}

pub type StartServiceCallback = unsafe extern "C" fn(server_id: u8, handle: u16, status: ErrorCode);
pub type ClientNotificationCallback = unsafe extern "C" fn(
    client_id: u8,
    connection_id: u16,
    data: *mut ClientHandleValue,
    status: ErrorCode,
);
pub type ExchangeInfoCallback = unsafe extern "C" fn(
    client_id: u8,
    connection_id: u16,
    parameters: *mut ExchangeInfo,
    status: ErrorCode,
);
pub type FindStructureCallback = unsafe extern "C" fn(
    client_id: u8,
    connection_id: u16,
    service: *mut FindServiceResult,
    status: ErrorCode,
);
pub type FindStructureCompleteCallback = unsafe extern "C" fn(
    client_id: u8,
    connection_id: u16,
    result: *mut FindStructureResult,
    status: ErrorCode,
);
pub type ServerReadRequestCallback = unsafe extern "C" fn(
    server_id: u8,
    connection_id: u16,
    request: *mut ServerReadRequest,
    status: ErrorCode,
);
pub type ClientWriteConfirmedCallback = unsafe extern "C" fn(
    client_id: u8,
    connection_id: u16,
    result: *mut ClientWriteResult,
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
    pub read_request: Option<ServerReadRequestCallback>,
    pub read_by_uuid_request: Option<OpaqueCallback>,
    pub write_request: Option<OpaqueCallback>,
    pub mtu_changed: Option<OpaqueCallback>,
    pub indicate_confirmed: Option<OpaqueCallback>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ClientCallbacks {
    pub find_structure: Option<FindStructureCallback>,
    pub find_property: Option<OpaqueCallback>,
    pub find_structure_complete: Option<FindStructureCompleteCallback>,
    pub read_confirmed: Option<OpaqueCallback>,
    pub read_by_uuid_complete: Option<OpaqueCallback>,
    pub write_confirmed: Option<ClientWriteConfirmedCallback>,
    pub exchange_info: Option<ExchangeInfoCallback>,
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
    pub fn ssaps_set_info(server_id: u8, info: *mut ExchangeInfo) -> ErrorCode;
    pub fn ssaps_notify_indicate(
        server_id: u8,
        connection_id: u16,
        parameters: *mut NotifyIndicate,
    ) -> ErrorCode;
    pub fn ssapc_register_callbacks(callbacks: *mut ClientCallbacks) -> ErrorCode;
    pub fn ssapc_exchange_info_req(
        client_id: u8,
        connection_id: u16,
        parameters: *mut ExchangeInfo,
    ) -> ErrorCode;
    pub fn ssapc_find_structure(
        client_id: u8,
        connection_id: u16,
        parameters: *mut FindStructureParameters,
    ) -> ErrorCode;
    pub fn ssapc_read_req(
        client_id: u8,
        connection_id: u16,
        handle: u16,
        property_type: u8,
    ) -> ErrorCode;
    pub fn ssapc_write_req(
        client_id: u8,
        connection_id: u16,
        parameters: *mut ClientWriteParameters,
    ) -> ErrorCode;
}

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::size_of::<Uuid>() == 17);
    assert!(core::mem::size_of::<ExchangeInfo>() == 8);
    assert!(core::mem::size_of::<ServerPropertyInfo>() == 32);
    assert!(core::mem::offset_of!(ServerPropertyInfo, value) == 28);
    assert!(core::mem::size_of::<NotifyIndicate>() == 12);
    assert!(core::mem::size_of::<ClientHandleValue>() == 12);
    assert!(core::mem::size_of::<FindServiceResult>() == 22);
    assert!(core::mem::size_of::<FindStructureParameters>() == 24);
    assert!(core::mem::size_of::<FindStructureResult>() == 18);
    assert!(core::mem::size_of::<ServerReadRequest>() == 8);
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
