//! Hash-bound WS63 BLE archive and external-capability inventory.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use crate::normalize::{self, RelocationSummary};

#[derive(Debug, Deserialize)]
struct Profile {
    schema_version: u32,
    revision: String,
    target: TargetAbi,
    archives: Vec<ProfileArchive>,
    excluded_sibling_archives: Vec<ExcludedArchive>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
struct TargetAbi {
    class: String,
    endian: String,
    machine: String,
    e_flags: u32,
}

#[derive(Debug, Deserialize)]
struct ProfileArchive {
    archive: String,
    sha256: String,
    role: String,
}

#[derive(Debug, Deserialize)]
struct ExcludedArchive {
    archive: String,
    sha256: String,
    reason: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct Report {
    schema_version: u32,
    revision: String,
    target: TargetAbi,
    archives: Vec<ArchiveReport>,
    excluded_sibling_archives: Vec<ExcludedArchiveReport>,
    aggregate: AggregateReport,
    required_symbols: Vec<RequiredSymbol>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct ArchiveReport {
    archive: String,
    sha256: String,
    size: usize,
    role: String,
    members: usize,
    defined_global_symbols: usize,
    undefined_global_symbols: usize,
    vendor_relocations: usize,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct ExcludedArchiveReport {
    archive: String,
    sha256: String,
    size: usize,
    reason: String,
    vendor_relocations: usize,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct AggregateReport {
    defined_global_symbols: usize,
    undefined_global_symbols: usize,
    required_external_symbols: usize,
    vendor_relocations: RelocationCounts,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct RelocationCounts {
    total: usize,
    by_type: BTreeMap<String, usize>,
    branchi_same_section: usize,
    branchi_cross_section: usize,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct RequiredSymbol {
    name: String,
    owner: String,
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn archive_symbols(path: &Path) -> Result<(usize, BTreeSet<String>, BTreeSet<String>), String> {
    let symbols = normalize::inspect_archive_symbols(path).map_err(|error| error.to_string())?;
    Ok((
        symbols.members,
        symbols.defined_global,
        symbols.undefined_global,
    ))
}

fn parse_rom_symbols(path: &Path) -> Result<BTreeSet<String>, String> {
    let source = fs::read_to_string(path)
        .map_err(|error| format!("read ROM symbols {}: {error}", path.display()))?;
    Ok(source
        .lines()
        .filter_map(|line| line.split_once('=').map(|(name, _)| name.trim()))
        .filter(|name| !name.is_empty() && !name.starts_with("/*"))
        .map(str::to_owned)
        .collect())
}

fn owner(name: &str, rom_symbols: &BTreeSet<String>) -> Option<&'static str> {
    if rom_symbols.contains(name) {
        return Some("hisi-rom-sys-ws63");
    }
    if name.starts_with("LOS_")
        || name.starts_with("osal_kthread_")
        || name.starts_with("osal_msg_queue_")
        || name.starts_with("osal_mutex_")
        || name.starts_with("osal_sem_")
        || name.starts_with("osMessageQueue")
        || name.starts_with("osMutex")
        || name.starts_with("osTimer")
        || matches!(
            name,
            "osDelay" | "osal_msleep" | "osal_msecs_to_jiffies" | "g_osSwtmrCBArray"
        )
    {
        return Some("hisi-rf-rtos-driver");
    }
    if name.starts_with("oal_mem_")
        || matches!(name, "osal_vmalloc" | "osal_vfree" | "g_intheap_begin")
    {
        return Some("hisi-alloc");
    }
    if matches!(name, "uapi_nv_read" | "uapi_nv_write") {
        return Some("hisi-nvs");
    }
    if name.starts_with("uapi_drv_cipher_") {
        return Some("hisi-crypto-ws63");
    }
    if matches!(
        name,
        "api_h2c_write" | "g_dts_thread_chnl" | "hci_if_bth_init"
    ) {
        return Some("ws63-radio-controller-transport");
    }
    if name.starts_with("log_event_")
        || name.starts_with("massdata_")
        || name.starts_with("global_")
        || matches!(
            name,
            "panic" | "print_str" | "uapi_at_print" | "uapi_at_bt_register_cmd"
        )
    {
        return Some("platform-diagnostics");
    }
    if matches!(
        name,
        "__udivdi3"
            | "atoi"
            | "memcmp"
            | "memcpy"
            | "memset"
            | "strcmp"
            | "strlen"
            | "strnlen"
            | "tolower"
    ) {
        return Some("compiler-builtins-or-core");
    }
    if matches!(name, "enable_sle" | "disable_sle") {
        return Some("explicit-sle-boundary");
    }
    if matches!(
        name,
        "gap_create_connectiona"
            | "sapi_ble_hid_keyboard_input"
            | "sapi_ble_low_latency_set_em_data"
    ) {
        return Some("ble-application-hook");
    }
    None
}

fn counts(summary: RelocationSummary) -> RelocationCounts {
    RelocationCounts {
        total: summary.total,
        by_type: summary.by_type,
        branchi_same_section: summary.branchi_same_section,
        branchi_cross_section: summary.branchi_cross_section,
    }
}

fn generate(
    profile_path: &Path,
    archive_root: &Path,
    rom_symbols_path: &Path,
) -> Result<Report, String> {
    let profile: Profile = toml::from_str(
        &fs::read_to_string(profile_path)
            .map_err(|error| format!("read {}: {error}", profile_path.display()))?,
    )
    .map_err(|error| format!("parse {}: {error}", profile_path.display()))?;
    if profile.schema_version != 1 {
        return Err(format!(
            "unsupported schema version {}",
            profile.schema_version
        ));
    }
    if profile.target
        != (TargetAbi {
            class: "ELF32".to_owned(),
            endian: "little".to_owned(),
            machine: "RISC-V".to_owned(),
            e_flags: 3,
        })
    {
        return Err(
            "BLE profile target ABI must remain ELF32 little-endian RISC-V ilp32f+RVC".to_owned(),
        );
    }

    let rom_symbols = parse_rom_symbols(rom_symbols_path)?;
    let mut all_defined = BTreeSet::new();
    let mut all_undefined = BTreeSet::new();
    let mut inventories = Vec::new();
    let mut archives = Vec::new();
    for entry in &profile.archives {
        let path = archive_root.join(&entry.archive);
        let bytes = fs::read(&path).map_err(|error| format!("read {}: {error}", path.display()))?;
        let actual = sha256(&bytes);
        if actual != entry.sha256 {
            return Err(format!(
                "{} SHA-256 {actual}, expected {}",
                path.display(),
                entry.sha256
            ));
        }
        let (members, defined, undefined) = archive_symbols(&path)?;
        let inventory = normalize::inspect_archive(&path).map_err(|error| error.to_string())?;
        archives.push(ArchiveReport {
            archive: entry.archive.clone(),
            sha256: actual,
            size: bytes.len(),
            role: entry.role.clone(),
            members,
            defined_global_symbols: defined.len(),
            undefined_global_symbols: undefined.len(),
            vendor_relocations: inventory.vendor_relocations.len(),
        });
        all_defined.extend(defined);
        all_undefined.extend(undefined);
        inventories.push(inventory);
    }

    let mut excluded_sibling_archives = Vec::new();
    for entry in &profile.excluded_sibling_archives {
        let path = archive_root.join(&entry.archive);
        let bytes = fs::read(&path).map_err(|error| format!("read {}: {error}", path.display()))?;
        let actual = sha256(&bytes);
        if actual != entry.sha256 {
            return Err(format!(
                "{} SHA-256 {actual}, expected {}",
                path.display(),
                entry.sha256
            ));
        }
        let inventory = normalize::inspect_archive(&path).map_err(|error| error.to_string())?;
        excluded_sibling_archives.push(ExcludedArchiveReport {
            archive: entry.archive.clone(),
            sha256: actual,
            size: bytes.len(),
            reason: entry.reason.clone(),
            vendor_relocations: inventory.vendor_relocations.len(),
        });
    }

    let required = all_undefined
        .difference(&all_defined)
        .cloned()
        .collect::<Vec<_>>();
    let mut required_symbols = Vec::with_capacity(required.len());
    let mut unowned = Vec::new();
    for name in required {
        if let Some(symbol_owner) = owner(&name, &rom_symbols) {
            required_symbols.push(RequiredSymbol {
                name,
                owner: symbol_owner.to_owned(),
            });
        } else {
            unowned.push(name);
        }
    }
    if !unowned.is_empty() {
        return Err(format!(
            "unowned BLE external symbols: {}",
            unowned.join(", ")
        ));
    }
    let summary = normalize::summarize(&inventories);
    if summary.branchi_cross_section != 0 {
        return Err(format!(
            "BLE profile contains {} cross-section R_RISCV_BRANCHI relocations",
            summary.branchi_cross_section
        ));
    }
    Ok(Report {
        schema_version: 1,
        revision: profile.revision,
        target: profile.target,
        archives,
        excluded_sibling_archives,
        aggregate: AggregateReport {
            defined_global_symbols: all_defined.len(),
            undefined_global_symbols: all_undefined.len(),
            required_external_symbols: required_symbols.len(),
            vendor_relocations: counts(summary),
        },
        required_symbols,
    })
}

pub fn write_or_check(
    profile: &Path,
    archive_root: &Path,
    rom_symbols: &Path,
    output: &Path,
    check: bool,
) -> Result<(), String> {
    let report = generate(profile, archive_root, rom_symbols)?;
    let encoded = serde_json::to_vec_pretty(&report)
        .map_err(|error| format!("serialize BLE profile: {error}"))?;
    if check {
        let expected = fs::read(output)
            .map_err(|error| format!("read committed report {}: {error}", output.display()))?;
        if expected != encoded {
            return Err(format!(
                "{} drifted; regenerate it with the same command without --check",
                output.display()
            ));
        }
        return Ok(());
    }
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    fs::write(output, encoded).map_err(|error| format!("write {}: {error}", output.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ownership_is_explicit_and_fail_closed() {
        let rom_symbols = BTreeSet::from(["rom_ble_symbol".to_owned()]);

        assert_eq!(
            owner("rom_ble_symbol", &rom_symbols),
            Some("hisi-rom-sys-ws63")
        );
        assert_eq!(
            owner("LOS_SemPost", &rom_symbols),
            Some("hisi-rf-rtos-driver")
        );
        assert_eq!(
            owner("uapi_drv_cipher_trng_get_random", &rom_symbols),
            Some("hisi-crypto-ws63")
        );
        assert_eq!(owner("unexpected_external", &rom_symbols), None);
    }
}
