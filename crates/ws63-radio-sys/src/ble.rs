//! Raw WS63 BLE persistence ABI.
//!
//! The pinned WS63 archives pass a 71-byte record through internal GAP event
//! 19 and accept a sequence of the same records in
//! [`sapi_ble_recover_smp_keys`]. The record remains opaque here: archive
//! disassembly proves its size and the peer-address fields, but does not prove
//! names or semantics for every secret field.

use core::fmt;
use zeroize::Zeroize;

/// Size of one record accepted by the pinned BLE restore entry point.
pub const SMP_RECORD_BYTES: usize = 71;
/// Maximum number of records in the vendor ACPU persistence table.
pub const SMP_RECORD_CAPACITY: usize = 8;
/// Internal GAP callback group used by the pinned BLE service manager.
pub const INTERNAL_GAP_CALLBACK_GROUP: u16 = 1;
/// Internal GAP event carrying the complete SMP record.
pub const INTERNAL_GAP_SMP_RECORD_EVENT: u16 = 19;

/// Vendor save-mode value.
///
/// This value is not a persistence-ownership capability. In the pinned
/// archives the backing byte is referenced only by its getter and setter,
/// while internal GAP event 19 still has an independently registered automatic
/// save callback. Consumers must not infer that [`Manual`](Self::Manual)
/// disables vendor persistence without separate silicon evidence.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmpSaveMode {
    Automatic = 0,
    Manual = 1,
}

/// Failure returned by the bounded SMP restore adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmpRestoreError {
    /// The vendor restore entry point requires at least one complete record.
    Empty,
    /// The request exceeds the pinned vendor persistence-table capacity.
    Capacity { requested: usize, capacity: usize },
    /// The vendor restore entry point rejected the records.
    Vendor(u32),
    /// Host builds can validate records but cannot invoke the WS63 archive.
    UnsupportedTarget,
}

/// Opaque, byte-exact SMP record owned by the WS63 vendor ABI.
///
/// The bytes contain secret key material. `Debug` is deliberately redacted and
/// this raw integration type exposes no field-level key accessors.
#[repr(transparent)]
#[derive(Eq, PartialEq)]
pub struct SmpRecord([u8; SMP_RECORD_BYTES]);

impl SmpRecord {
    /// Copy a callback-owned record before the callback returns.
    ///
    /// # Safety
    ///
    /// `record` must point to a readable vendor SMP record of exactly
    /// [`SMP_RECORD_BYTES`] bytes for the duration of this call.
    pub unsafe fn copy_from_ptr(record: *const u8) -> Option<Self> {
        if record.is_null() {
            return None;
        }
        let mut bytes = [0; SMP_RECORD_BYTES];
        // SAFETY: upheld by the caller; the destination is a distinct local
        // array with exactly the required length.
        unsafe {
            core::ptr::copy_nonoverlapping(record, bytes.as_mut_ptr(), SMP_RECORD_BYTES);
        }
        Some(Self(bytes))
    }

    /// Peer address copied by the vendor persistence conversion.
    pub const fn peer_address(&self) -> [u8; 6] {
        [
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5],
        ]
    }

    /// Vendor remote initial-address type stored at byte 70.
    pub const fn remote_initial_address_type(&self) -> u8 {
        self.0[70]
    }

    /// Borrow the complete secret record for an immediate vendor ABI call.
    ///
    /// This is intentionally not a general key-export API. Chip integration
    /// code may use it to persist or restore the same opaque vendor record.
    #[doc(hidden)]
    pub const fn as_bytes(&self) -> &[u8; SMP_RECORD_BYTES] {
        &self.0
    }

    /// Zero all copied secret bytes.
    pub fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SmpRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SmpRecord([REDACTED])")
    }
}

impl Drop for SmpRecord {
    fn drop(&mut self) {
        self.zeroize();
    }
}

fn restore_length(records: &[SmpRecord]) -> Result<u32, SmpRestoreError> {
    if records.is_empty() {
        return Err(SmpRestoreError::Empty);
    }
    if records.len() > SMP_RECORD_CAPACITY {
        return Err(SmpRestoreError::Capacity {
            requested: records.len(),
            capacity: SMP_RECORD_CAPACITY,
        });
    }
    u32::try_from(records.len() * SMP_RECORD_BYTES).map_err(|_| SmpRestoreError::Capacity {
        requested: records.len(),
        capacity: SMP_RECORD_CAPACITY,
    })
}

/// Restore a bounded list of complete, opaque records into the WS63 BLE host.
///
/// This only invokes the archive restore entry point. It does not change the
/// vendor save mode or transfer persistence ownership to Rust.
#[cfg(target_arch = "riscv32")]
pub fn restore_smp_records(records: &[SmpRecord]) -> Result<(), SmpRestoreError> {
    let length = restore_length(records)?;
    // SAFETY: SmpRecord is a byte-exact transparent 71-byte record, the slice
    // remains valid for the synchronous call, and restore_length bounds the
    // complete-record byte length accepted by the pinned ABI.
    let status = unsafe { sapi_ble_recover_smp_keys(records.as_ptr(), length) };
    if status == 0 {
        Ok(())
    } else {
        Err(SmpRestoreError::Vendor(status))
    }
}

/// Host-side counterpart that retains validation behavior without pretending
/// the target archive can run on the build host.
#[cfg(not(target_arch = "riscv32"))]
pub fn restore_smp_records(records: &[SmpRecord]) -> Result<(), SmpRestoreError> {
    restore_length(records)?;
    Err(SmpRestoreError::UnsupportedTarget)
}

/// Internal GAP callback used only by the chip integration layer.
pub type InternalGapCallback = unsafe extern "C" fn(event: u16, payload: *const SmpRecord);

unsafe extern "C" {
    /// Read all vendor-persisted records into `records` and write their count.
    pub fn ble_get_all_smp_keys(records: *mut SmpRecord, count: *mut u8);
    /// Read records matching the vendor-selected peer into `records`.
    pub fn ble_get_smp_keys(records: *mut SmpRecord, count: *mut u8);
    /// Restore `length` bytes containing a whole number of 71-byte records.
    pub fn sapi_ble_recover_smp_keys(records: *const SmpRecord, length: u32) -> u32;
    pub fn ble_get_save_smp_keys_mode() -> SmpSaveMode;
    pub fn ble_set_save_smp_keys_mode(mode: SmpSaveMode);
    /// Add a callback to the vendor internal GAP callback list.
    ///
    /// This registration is additive. Registering an observer for event 19
    /// does not remove the vendor service manager's automatic-save callback.
    pub fn ble_gap_internal_callback_regist(
        group: u16,
        event: u16,
        callback: Option<InternalGapCallback>,
    ) -> u32;
}

const _: () = assert!(core::mem::size_of::<SmpRecord>() == SMP_RECORD_BYTES);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::format;

    #[test]
    fn record_layout_and_proven_fields_are_stable() {
        let mut bytes = [0; SMP_RECORD_BYTES];
        bytes[..6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        bytes[70] = 9;
        let record = SmpRecord(bytes);
        assert_eq!(core::mem::size_of_val(&record), SMP_RECORD_BYTES);
        assert_eq!(record.peer_address(), [1, 2, 3, 4, 5, 6]);
        assert_eq!(record.remote_initial_address_type(), 9);
    }

    #[test]
    fn debug_and_zeroize_do_not_disclose_secret_bytes() {
        let mut record = SmpRecord([0xa5; SMP_RECORD_BYTES]);
        assert_eq!(format!("{record:?}"), "SmpRecord([REDACTED])");
        record.zeroize();
        assert_eq!(record.as_bytes(), &[0; SMP_RECORD_BYTES]);
    }

    #[test]
    fn null_callback_record_is_rejected() {
        // SAFETY: null is accepted specifically to exercise rejection.
        assert_eq!(unsafe { SmpRecord::copy_from_ptr(core::ptr::null()) }, None);
    }

    #[test]
    fn restore_rejects_empty_and_over_capacity_requests() {
        assert_eq!(restore_smp_records(&[]), Err(SmpRestoreError::Empty));

        let mut records = std::vec::Vec::new();
        for _ in 0..=SMP_RECORD_CAPACITY {
            // SAFETY: the local array is exactly one readable SMP record.
            records.push(
                unsafe { SmpRecord::copy_from_ptr([0u8; SMP_RECORD_BYTES].as_ptr()) }.unwrap(),
            );
        }
        assert_eq!(
            restore_smp_records(&records),
            Err(SmpRestoreError::Capacity {
                requested: SMP_RECORD_CAPACITY + 1,
                capacity: SMP_RECORD_CAPACITY,
            })
        );
    }

    #[test]
    fn host_restore_validates_then_reports_unsupported_target() {
        let bytes = [0u8; SMP_RECORD_BYTES];
        // SAFETY: the local array is exactly one readable SMP record.
        let record = unsafe { SmpRecord::copy_from_ptr(bytes.as_ptr()) }.unwrap();
        assert_eq!(
            restore_smp_records(core::slice::from_ref(&record)),
            Err(SmpRestoreError::UnsupportedTarget)
        );
    }
}
