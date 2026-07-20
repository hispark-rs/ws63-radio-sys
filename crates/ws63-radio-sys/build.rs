use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
};

const ROM_START: u32 = 0x0010_9000;
const ROM_END: u32 = 0x0014_C000;
const PATCH_VMA: u32 = 0x0014_C000;
const REMAP_SIZE: usize = 0x610;
const COMPARE_SIZE: usize = 0x318;
const DATA_PATCH_ENTRY_COUNT: usize = 2;
const INSTRUCTION_COMPARE_COUNT: usize = 192;
const COMPARE_HEADER_WORDS: usize = 3;

#[derive(Deserialize)]
struct Profile {
    revision: String,
    normalized_artifact_revision: String,
    wifi_root_symbols: Vec<String>,
    rom_callback_root_symbols: Vec<String>,
    wifi_archives: Vec<WifiArchive>,
    wpa_archives: Vec<WpaArchive>,
}

#[derive(Deserialize)]
struct WifiArchive {
    name: String,
    #[serde(default)]
    whole_archive: bool,
    link_order: u16,
}

#[derive(Deserialize)]
struct WpaArchive {
    name: String,
    order: u16,
    profiles: Vec<String>,
}

#[derive(Deserialize)]
struct SchedulingProfile {
    revision: String,
    payload_revision: String,
    default_role: String,
    artifacts: Vec<ProfileArtifact>,
    tasks: Vec<TaskProfile>,
}

#[derive(Deserialize)]
struct ProfileArtifact {
    id: String,
    path: Option<String>,
    sha256: String,
}

#[derive(Deserialize)]
struct TaskProfile {
    entry_symbol: String,
    source: String,
    role: String,
    vendor_priority: u8,
    wpa_profile: Option<String>,
}

#[derive(Deserialize)]
struct RuntimeCompatibilityProfile {
    symbols: Vec<RuntimeCompatibilitySymbol>,
}

#[derive(Deserialize)]
struct RuntimeCompatibilitySymbol {
    name: String,
    classification: String,
}

#[derive(Deserialize)]
struct SupplicantBoundaryProfile {
    native_root_symbols: Vec<String>,
}

fn sha256(path: &std::path::Path) -> String {
    let digest = Sha256::digest(fs::read(path).unwrap_or_else(|error| {
        panic!(
            "read scheduling-profile artifact {}: {error}",
            path.display()
        )
    }));
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_rom_symbols(path: &Path) -> BTreeMap<String, u32> {
    let source = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read ROM symbols {}: {error}", path.display()));
    let mut symbols = BTreeMap::new();
    for line in source.lines() {
        let statement = line.split("/*").next().unwrap_or("").trim();
        let Some(statement) = statement.strip_suffix(';') else {
            continue;
        };
        let Some((name, value)) = statement.split_once('=') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        let Some(hex) = value.strip_prefix("0x") else {
            continue;
        };
        let Ok(address) = u32::from_str_radix(hex, 16) else {
            continue;
        };
        if (ROM_START..ROM_END).contains(&(address & !1)) {
            assert!(
                symbols.insert(name.to_owned(), address).is_none(),
                "duplicate ROM symbol: {name}"
            );
        }
    }
    symbols
}

fn parse_patch_names(path: &Path) -> Vec<String> {
    let source = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read ROM patch list {}: {error}", path.display()));
    let mut unique = BTreeSet::new();
    source
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|name| {
            assert!(
                unique.insert(name.to_owned()),
                "duplicate ROM patch: {name}"
            );
            name.to_owned()
        })
        .collect()
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_rom_patch_object(rom_symbols: &Path, patch_list: &Path, output: &Path) -> usize {
    use object::write::{Object, Relocation, Symbol, SymbolSection};
    use object::{
        Architecture, BinaryFormat, Endianness, FileFlags, RelocationFlags, SectionKind,
        SymbolFlags, SymbolKind, SymbolScope,
    };

    let symbols = parse_rom_symbols(rom_symbols);
    let mut patches = parse_patch_names(patch_list)
        .into_iter()
        .map(|name| {
            let address = symbols
                .get(&name)
                .copied()
                .unwrap_or_else(|| panic!("ROM patch source symbol is missing: {name}"));
            (name, address & !1)
        })
        .collect::<Vec<_>>();
    patches.sort_by(|left, right| (left.1, &left.0).cmp(&(right.1, &right.0)));
    assert!(
        patches.len() <= INSTRUCTION_COMPARE_COUNT,
        "{} ROM patches exceed the WS63 controller capacity",
        patches.len()
    );

    let mut object = Object::new(BinaryFormat::Elf, Architecture::Riscv32, Endianness::Little);
    object.flags = FileFlags::Elf {
        os_abi: 0,
        abi_version: 0,
        e_flags: 0x3,
    };
    let remap_section = object.add_section(Vec::new(), b".patch_remap".to_vec(), SectionKind::Data);
    let compare_section = object.add_section(Vec::new(), b".patch_cmp".to_vec(), SectionKind::Data);
    let mut remap = vec![0; REMAP_SIZE];
    let mut compare = vec![0; COMPARE_SIZE];
    write_u32(&mut compare, 4, PATCH_VMA);
    write_u32(&mut compare, 8, patches.len() as u32);

    for (index, (_, original)) in patches.iter().enumerate() {
        let offset = (DATA_PATCH_ENTRY_COUNT + index) * 8;
        // auipc t1, 0; jalr x0, t1, 0. The standard call relocation patches
        // this pair after rust-lld has chosen the replacement's final address.
        remap[offset..offset + 8]
            .copy_from_slice(&[0x17, 0x03, 0x00, 0x00, 0x67, 0x00, 0x03, 0x00]);
        write_u32(
            &mut compare,
            (COMPARE_HEADER_WORDS + index) * 4,
            original | 1,
        );
    }
    object.append_section_data(remap_section, &remap, 8);
    object.append_section_data(compare_section, &compare, 8);

    object.add_symbol(Symbol {
        name: b"__hisi_ws63_rom_patch_table".to_vec(),
        value: 0,
        size: (REMAP_SIZE + COMPARE_SIZE) as u64,
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(remap_section),
        flags: SymbolFlags::None,
    });
    for (index, (name, original)) in patches.iter().enumerate() {
        let offset = (DATA_PATCH_ENTRY_COUNT + index) * 8;
        let replacement = object.add_symbol(Symbol {
            name: format!("{name}_patch").into_bytes(),
            value: 0,
            size: 0,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Undefined,
            flags: SymbolFlags::None,
        });
        let slot_vma = PATCH_VMA + offset as u32;
        object
            .add_relocation(
                remap_section,
                Relocation {
                    offset: offset as u64,
                    symbol: replacement,
                    addend: i64::from(slot_vma) - i64::from(*original),
                    flags: RelocationFlags::Elf { r_type: 19 },
                },
            )
            .unwrap_or_else(|error| panic!("add {name} ROM patch relocation: {error}"));
    }
    fs::write(
        output,
        object.write().expect("serialize WS63 ROM patch object"),
    )
    .unwrap_or_else(|error| panic!("write ROM patch object {}: {error}", output.display()));
    patches.len()
}

fn validate_scheduling_profile(profile: &SchedulingProfile, oracle_root: Option<&Path>) {
    assert!(
        !profile.revision.is_empty(),
        "empty scheduling-profile revision"
    );
    assert!(
        !profile.payload_revision.is_empty(),
        "empty scheduling-profile payload revision"
    );
    assert_eq!(
        profile.default_role, "unknown",
        "unmatched task entries must remain unknown"
    );

    let mut artifacts = BTreeSet::new();
    for artifact in &profile.artifacts {
        assert!(
            artifacts.insert(artifact.id.as_str()),
            "duplicate artifact id"
        );
        assert!(
            artifact.sha256.len() == 64
                && artifact
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "invalid SHA-256 for {}",
            artifact.id
        );
        if let (Some(root), Some(relative)) = (oracle_root, &artifact.path) {
            let path = root.join(relative);
            assert_eq!(
                sha256(&path),
                artifact.sha256,
                "scheduling-profile artifact drift: {}",
                path.display()
            );
        }
    }

    let mut symbols = BTreeSet::new();
    for task in &profile.tasks {
        assert!(
            symbols.insert((task.entry_symbol.as_str(), task.wpa_profile.as_deref())),
            "duplicate task entry symbol/profile"
        );
        assert!(
            artifacts.contains(task.source.as_str()),
            "unknown task source"
        );
        assert!(
            matches!(
                task.role.as_str(),
                "critical" | "worker" | "background" | "unknown"
            ),
            "invalid task role"
        );
        assert!(task.vendor_priority < 32, "invalid vendor task priority");
        assert!(
            task.wpa_profile
                .as_deref()
                .is_none_or(|profile| matches!(profile, "wpa2-personal" | "wpa3-personal")),
            "invalid WPA task profile"
        );
    }
}

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let oracle_root = env::var_os("WS63_RF_ORACLE_ROOT").map(PathBuf::from);
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let packaged_lib = PathBuf::from(
        env::var_os("DEP_WS63_RADIO_BLOB_LIB_DIR")
            .expect("ws63-radio-blob did not export its normalized archive directory"),
    );
    let lib = env::var_os("WS63_RF_LIB_DIR")
        .map(PathBuf::from)
        .unwrap_or(packaged_lib);
    let profile_path = out_dir.join("ws63-archive-profile.toml");
    let runtime_compat_profile_path = out_dir.join("ws63-runtime-compat.toml");
    let supplicant_boundary_profile_path = out_dir.join("ws63-supplicant-boundary.toml");
    let scheduling_profile_path = out_dir.join("ws63-scheduling.toml");
    for (path, contents) in [
        (&profile_path, hisi_rf_link::WS63_ARCHIVE_PROFILE),
        (
            &runtime_compat_profile_path,
            hisi_rf_link::WS63_RUNTIME_COMPAT_PROFILE,
        ),
        (
            &supplicant_boundary_profile_path,
            hisi_rf_link::WS63_SUPPLICANT_BOUNDARY_PROFILE,
        ),
        (
            &scheduling_profile_path,
            hisi_rf_link::WS63_SCHEDULING_PROFILE,
        ),
    ] {
        fs::write(path, contents)
            .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
    }
    let nvs_linker = manifest.join("linker/ws63-nvs.x");
    let rom_symbols = PathBuf::from(
        env::var_os("DEP_HISI_ROM_SYS_WS63_ROM_SYMBOLS")
            .expect("hisi-rom-sys-ws63 did not export its ROM symbol table"),
    );
    let rom_patches = PathBuf::from(
        env::var_os("DEP_HISI_ROM_SYS_WS63_WIFI_PATCHES")
            .expect("hisi-rom-sys-ws63 did not export its Wi-Fi patch inventory"),
    );
    let rom_callbacks = PathBuf::from(
        env::var_os("DEP_HISI_ROM_SYS_WS63_ROM_CALLBACKS")
            .expect("hisi-rom-sys-ws63 did not export its callback inventory"),
    );
    let native_wpa3 = env::var_os("CARGO_FEATURE_UPSTREAM_SUPPLICANT_WPA3").is_some();
    let profile: Profile =
        toml::from_str(hisi_rf_link::WS63_ARCHIVE_PROFILE).expect("parse WS63 archive profile");
    let artifact_revision = env::var("DEP_WS63_RADIO_BLOB_PROFILE_REVISION")
        .expect("ws63-radio-blob did not export its profile revision");
    assert_eq!(
        artifact_revision, profile.normalized_artifact_revision,
        "WS63 normalized artifact/profile revision mismatch"
    );
    let mut wifi = profile.wifi_archives;
    wifi.sort_by_key(|archive| archive.link_order);
    let wpa2 = env::var_os("CARGO_FEATURE_WPA2_PERSONAL").is_some();
    let wpa3 = env::var_os("CARGO_FEATURE_WPA3_PERSONAL").is_some();
    assert!(!(wpa2 && wpa3), "select exactly one WS63 WPA profile");
    let selected_wpa_profile = if wpa3 {
        Some("wpa3-personal")
    } else if wpa2 {
        Some("wpa2-personal")
    } else {
        None
    };
    let mut wpa = profile
        .wpa_archives
        .into_iter()
        .filter(|archive| {
            selected_wpa_profile
                .is_some_and(|selected| archive.profiles.iter().any(|profile| profile == selected))
        })
        .collect::<Vec<_>>();
    wpa.sort_by_key(|archive| archive.order);
    let scheduling_profile: SchedulingProfile =
        toml::from_str(hisi_rf_link::WS63_SCHEDULING_PROFILE)
            .expect("parse WS63 task scheduling profile");
    validate_scheduling_profile(&scheduling_profile, oracle_root.as_deref());
    let runtime_compatibility: RuntimeCompatibilityProfile =
        toml::from_str(hisi_rf_link::WS63_RUNTIME_COMPAT_PROFILE)
            .expect("parse WS63 runtime compatibility profile");
    let supplicant_boundary: SupplicantBoundaryProfile =
        toml::from_str(hisi_rf_link::WS63_SUPPLICANT_BOUNDARY_PROFILE)
            .expect("parse WS63 supplicant boundary profile");

    let rom_callback_archive = PathBuf::from(
        env::var_os("DEP_WS63_RADIO_BLOB_ROM_CALLBACK_ARCHIVE")
            .expect("ws63-radio-blob did not export its ROM callback archive"),
    );

    for (key, path) in [
        ("lib_dir", lib.clone()),
        ("rom_symbols", rom_symbols.clone()),
        ("rom_callbacks", rom_callbacks),
        ("rom_patches", rom_patches.clone()),
        ("rom_callback_archive", rom_callback_archive),
        ("archive_profile", profile_path),
        ("runtime_compat_profile", runtime_compat_profile_path),
        (
            "supplicant_boundary_profile",
            supplicant_boundary_profile_path,
        ),
        ("task_profile", scheduling_profile_path),
        ("nvs_linker", nvs_linker),
    ] {
        if !path.exists() {
            panic!("WS63 radio payload is incomplete: {}", path.display());
        }
        println!("cargo:{key}={}", path.display());
        println!("cargo:rerun-if-changed={}", path.display());
    }
    let rom_patch_object = out_dir.join("ws63-rom-patches.o");
    let rom_patch_count = write_rom_patch_object(&rom_symbols, &rom_patches, &rom_patch_object);
    assert_eq!(rom_patch_count, 37, "WS63 ROM patch inventory drift");
    println!("cargo:rom_patch_object={}", rom_patch_object.display());
    println!("cargo:rom_patch_count={rom_patch_count}");
    println!("cargo:revision={}", profile.revision);
    println!(
        "cargo:task_profile_revision={}",
        scheduling_profile.revision
    );
    println!(
        "cargo:task_profile_payload_revision={}",
        scheduling_profile.payload_revision
    );
    println!(
        "cargo:wifi_archives={}",
        wifi.iter()
            .map(|archive| format!(
                "{}:{}",
                archive.name,
                if archive.whole_archive {
                    "whole"
                } else {
                    "normal"
                }
            ))
            .collect::<Vec<_>>()
            .join(",")
    );
    println!(
        "cargo:wifi_root_symbols={}",
        profile.wifi_root_symbols.join(",")
    );
    println!(
        "cargo:rom_callback_root_symbols={}",
        profile.rom_callback_root_symbols.join(",")
    );
    println!(
        "cargo:runtime_compat_symbols={}",
        runtime_compatibility
            .symbols
            .iter()
            .filter(|symbol| symbol.classification == "provided")
            .map(|symbol| symbol.name.as_str())
            .collect::<Vec<_>>()
            .join(",")
    );
    println!(
        "cargo:wpa_archives={}",
        wpa.iter()
            .map(|archive| archive.name.as_str())
            .collect::<Vec<_>>()
            .join(",")
    );
    println!("cargo:rerun-if-env-changed=WS63_RF_ORACLE_ROOT");
    println!("cargo:rerun-if-env-changed=WS63_RF_LIB_DIR");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_WPA2_PERSONAL");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_WPA3_PERSONAL");

    if env::var_os("CARGO_FEATURE_UPSTREAM_SUPPLICANT_PORT").is_some() {
        let (archive_variable, revision_variable, expected_revision) = if native_wpa3 {
            (
                "DEP_WS63_RADIO_BLOB_NATIVE_SUPPLICANT_WPA3_ARCHIVE",
                "DEP_WS63_RADIO_BLOB_NATIVE_SUPPLICANT_WPA3_REVISION",
                "hostap-2.11-security-2026-07-personal-wpa3-v2",
            )
        } else {
            (
                "DEP_WS63_RADIO_BLOB_NATIVE_SUPPLICANT_WPA2_ARCHIVE",
                "DEP_WS63_RADIO_BLOB_NATIVE_SUPPLICANT_WPA2_REVISION",
                "hostap-2.11-security-2026-07-personal-v2",
            )
        };
        let archive = PathBuf::from(
            env::var_os(archive_variable)
                .unwrap_or_else(|| panic!("ws63-radio-blob did not export {archive_variable}")),
        );
        let revision = env::var(revision_variable)
            .unwrap_or_else(|_| panic!("ws63-radio-blob did not export {revision_variable}"));
        assert_eq!(
            revision, expected_revision,
            "native supplicant artifact/profile revision mismatch"
        );
        let file_name = archive
            .file_name()
            .and_then(|name| name.to_str())
            .expect("native supplicant archive has a non-UTF-8 file name");
        let link_name = file_name
            .strip_prefix("lib")
            .and_then(|name| name.strip_suffix(".a"))
            .expect("native supplicant artifact must be named lib*.a");
        let _ = link_name;
        println!("cargo:native_supplicant_archive={}", archive.display());
        println!("cargo:native_supplicant_profile_revision={revision}");
        println!(
            "cargo:native_supplicant_root_symbols={}",
            supplicant_boundary.native_root_symbols.join(",")
        );
    }
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_UPSTREAM_SUPPLICANT_PORT");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_UPSTREAM_SUPPLICANT_WPA3");
}
