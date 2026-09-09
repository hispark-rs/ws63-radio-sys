//! Narrow WS63 FRW host-delivery ABI, not a producer-drain API.
//!
//! The SDK's `frw_rom_cb_rom.h` identifies callback 261 as RX_NETBUF;
//! `frw_dmac_rom.h` declares its two-word arguments and unsigned return.
//! The delivered profile registers `frw_rx_netbuf` at this slot. ROM
//! `hcc_slave_tx` invokes it before the host copy and optional MSG595 enqueue.
//! See the repository's `docs/abi/frw-host-delivery.md` for evidence and limits.
//!
//! Do not use the historical one-argument declaration in `port_frw.h`.
//! A callback return is not a receipt for downstream processing or native
//! RX/TX quiescence. In particular, the delivered receiver also returns zero
//! after some allocation/copy failures.

use core::ffi::c_void;

/// `FRW_ROM_CB_RX_NETBUF` in the pinned WS63 `frw_rom_cb_enum`.
pub const RX_NETBUF_CALLBACK_ID: u32 = 261;

/// Owns one vendor DMAC netbuf on entry, including its error/free paths.
///
/// The pointer is opaque: it is not an Ethernet payload or a Rust allocation.
/// `payload_len` and the return value are `osal_u32`, not `u16` or a C boolean.
pub type RxNetbufCallback = unsafe extern "C" fn(netbuf: *mut c_void, payload_len: u32) -> u32;

unsafe extern "C" {
    /// Replace one ROM callback slot. The ROM setter returns no status.
    ///
    /// # Safety
    /// The caller must own the framework registration lifecycle, use a valid
    /// slot, and provide a function with that slot's exact ABI and lifetime.
    /// Serialize replacement against other writers; verify the expected old
    /// owner before replacement and read the slot back afterwards. This does
    /// not stop callbacks already loaded by another execution context.
    pub fn frw_rom_cb_register(function_id: u32, callback: *mut c_void);

    /// Read one ROM callback slot without transferring ownership of it.
    ///
    /// # Safety
    /// The framework/ROM RAM must be initialized and `function_id` must name
    /// a valid slot. Synchronize with writers before using the result. Null or
    /// an unexpected pointer is not a callable fallback.
    pub fn frw_get_rom_cb(function_id: u32) -> *mut c_void;

    /// Delivered host receiver: copies the netbuf, frees the DMAC input, and
    /// dispatches the host copy. A zero return does not guarantee delivery.
    ///
    /// # Safety
    /// Transfer exactly one valid vendor DMAC netbuf with its original length
    /// under the initialized FRW runtime. Do not access or free it afterwards,
    /// including on failure. Forwarding observers must call this exactly once
    /// and must not reinterpret the pointer or retain its payload.
    pub fn frw_rx_netbuf(netbuf: *mut c_void, payload_len: u32) -> u32;
}

// Type-check the receiver against the SDK callback ABI without emitting an
// artificial reference that would pull the native archive into host tests.
const _: RxNetbufCallback = frw_rx_netbuf;

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::size_of::<RxNetbufCallback>() == 4);
    assert!(core::mem::size_of::<Option<RxNetbufCallback>>() == 4);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_preserves_full_width_arguments_and_return() {
        unsafe extern "C" fn echo(pointer: *mut c_void, length: u32) -> u32 {
            assert!(pointer.is_null());
            length
        }
        let callback: RxNetbufCallback = echo;
        for length in [0, 1, 65_535, 65_536, u32::MAX] {
            // SAFETY: this host oracle never dereferences the opaque pointer.
            assert_eq!(unsafe { callback(core::ptr::null_mut(), length) }, length);
        }
        assert_eq!(RX_NETBUF_CALLBACK_ID, 261);
    }
}
