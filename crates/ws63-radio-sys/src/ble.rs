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

/// Failure returned while reading the vendor-managed SMP table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmpSnapshotError {
    /// The vendor returned a count larger than the pinned table capacity.
    InvalidCount { reported: usize, capacity: usize },
    /// Host builds cannot inspect the target vendor table.
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

/// Fixed-capacity snapshot of the vendor-managed SMP table.
///
/// This chip integration type owns complete secret records and zeroizes every
/// slot on drop. It deliberately exposes only a bounded record slice for an
/// immediate restore call; ordinary applications should consume secret-free
/// peer/count observations from the safe radio facade instead.
pub struct SmpRecordSet {
    records: [SmpRecord; SMP_RECORD_CAPACITY],
    len: usize,
}

impl SmpRecordSet {
    #[cfg_attr(not(any(target_arch = "riscv32", test)), allow(dead_code))]
    fn empty() -> Self {
        Self {
            records: core::array::from_fn(|_| SmpRecord([0; SMP_RECORD_BYTES])),
            len: 0,
        }
    }

    /// Number of complete records in this snapshot.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the vendor table contained no records.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Borrow the initialized prefix for an immediate chip integration call.
    #[doc(hidden)]
    pub fn records(&self) -> &[SmpRecord] {
        &self.records[..self.len]
    }

    /// Move one initialized record out of this zeroizing snapshot.
    ///
    /// The vacated slot is replaced with a zero record so ownership of the
    /// secret bytes transfers exactly once to the caller.
    #[doc(hidden)]
    pub fn take(&mut self, index: usize) -> Option<SmpRecord> {
        if index >= self.len {
            return None;
        }
        Some(core::mem::replace(
            &mut self.records[index],
            SmpRecord([0; SMP_RECORD_BYTES]),
        ))
    }

    /// Restore this exact snapshot into the running vendor host.
    pub fn restore(&self) -> Result<(), SmpRestoreError> {
        restore_smp_records(self.records())
    }
}

impl fmt::Debug for SmpRecordSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SmpRecordSet")
            .field("len", &self.len)
            .field("records", &"[REDACTED]")
            .finish()
    }
}

#[cfg_attr(not(any(target_arch = "riscv32", test)), allow(dead_code))]
fn validate_snapshot_count(reported: u8) -> Result<usize, SmpSnapshotError> {
    let reported = usize::from(reported);
    if reported > SMP_RECORD_CAPACITY {
        return Err(SmpSnapshotError::InvalidCount {
            reported,
            capacity: SMP_RECORD_CAPACITY,
        });
    }
    Ok(reported)
}

/// Copy the complete vendor-managed SMP table into zeroizing bounded storage.
///
/// The pinned archive writes at most [`SMP_RECORD_CAPACITY`] records and reports
/// the initialized count through an out parameter. A count outside that ABI
/// envelope fails closed.
#[cfg(target_arch = "riscv32")]
pub fn snapshot_smp_records() -> Result<SmpRecordSet, SmpSnapshotError> {
    let mut snapshot = SmpRecordSet::empty();
    let mut count = 0;
    // SAFETY: the fixed output array holds exactly the eight 71-byte records
    // expected by the pinned archive, and count remains valid for the call.
    unsafe { ble_get_all_smp_keys(snapshot.records.as_mut_ptr(), &raw mut count) };
    snapshot.len = validate_snapshot_count(count)?;
    Ok(snapshot)
}

/// Host-side counterpart that does not pretend the target table is available.
#[cfg(not(target_arch = "riscv32"))]
pub fn snapshot_smp_records() -> Result<SmpRecordSet, SmpSnapshotError> {
    Err(SmpSnapshotError::UnsupportedTarget)
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
    /// Register one callback for a vendor internal GAP group/event pair.
    ///
    /// The pinned implementation replaces the callback pointer when the same
    /// group/event is registered again. It is not a multicast subscription;
    /// callers must not use event 19 to observe vendor persistence because that
    /// would replace the service manager's automatic-save callback.
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

    #[test]
    fn snapshot_count_and_debug_are_bounded_and_redacted() {
        assert_eq!(validate_snapshot_count(0), Ok(0));
        assert_eq!(validate_snapshot_count(8), Ok(8));
        assert_eq!(
            validate_snapshot_count(9),
            Err(SmpSnapshotError::InvalidCount {
                reported: 9,
                capacity: SMP_RECORD_CAPACITY,
            })
        );
        let snapshot = SmpRecordSet::empty();
        assert_eq!(
            format!("{snapshot:?}"),
            "SmpRecordSet { len: 0, records: \"[REDACTED]\" }"
        );
        assert!(matches!(
            snapshot_smp_records(),
            Err(SmpSnapshotError::UnsupportedTarget)
        ));
    }

    #[test]
    fn snapshot_record_can_be_taken_once() {
        let mut snapshot = SmpRecordSet::empty();
        snapshot.records[0].0[..6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        snapshot.len = 1;

        assert_eq!(snapshot.take(0).unwrap().peer_address(), [1, 2, 3, 4, 5, 6]);
        assert_eq!(snapshot.records[0].peer_address(), [0; 6]);
        assert_eq!(snapshot.take(1), None);
    }
}
