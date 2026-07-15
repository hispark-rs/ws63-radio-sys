use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, env, fs, path::PathBuf};

#[derive(Deserialize)]
struct Profile {
    revision: String,
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
struct NativeSupplicantProfile {
    revision: String,
    upstream_sources: Vec<String>,
    port_sources: Vec<String>,
    defines: Vec<String>,
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

fn environment_override_exists(names: &[&str]) -> bool {
    names.iter().any(|name| env::var_os(name).is_some())
}

fn validate_scheduling_profile(profile: &SchedulingProfile, root: &std::path::Path) {
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
        if let Some(relative) = &artifact.path {
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
    let default_root = manifest.join("../../ws63-RF");
    let root = env::var_os("WS63_RF_ROOT")
        .map(PathBuf::from)
        .unwrap_or(default_root);
    let root = root.canonicalize().unwrap_or(root);
    let lib = env::var_os("WS63_RF_LIB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("lib"));
    let profile_path = manifest.join("../hisi-rf-link/profiles/ws63.toml");
    let scheduling_profile_path = manifest.join("../hisi-rf-link/profiles/ws63-scheduling.toml");
    let nvs_linker = manifest.join("../../linker/ws63-nvs.x");
    let supplicant_header = manifest.join("../../include/hisi_wpa_supplicant.h");
    let supplicant_source = manifest.join("../../upstream/hostap-2.11.json");
    let upstream_hostap = manifest.join("../../third-party/hostap");
    let native_port = manifest.join("../../port/hostap");
    let native_wpa3 = env::var_os("CARGO_FEATURE_UPSTREAM_SUPPLICANT_WPA3").is_some();
    let native_profile_path = native_port.join(if native_wpa3 {
        "personal-wpa3.toml"
    } else {
        "personal.toml"
    });
    let profile: Profile =
        toml::from_str(&fs::read_to_string(&profile_path).expect("read WS63 archive profile"))
            .expect("parse WS63 archive profile");
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
    let scheduling_profile: SchedulingProfile = toml::from_str(
        &fs::read_to_string(&scheduling_profile_path).expect("read WS63 task scheduling profile"),
    )
    .expect("parse WS63 task scheduling profile");
    validate_scheduling_profile(&scheduling_profile, &root);

    for (key, path) in [
        ("root", root.clone()),
        ("lib_dir", lib.clone()),
        ("include_dir", root.join("include")),
        ("rom_symbols", root.join("rom/ws63_acore_rom.lds")),
        (
            "rom_callbacks",
            root.join("rom/ws63_acore_rom_callbacks.txt"),
        ),
        ("rom_patches", root.join("rom/ws63_acore_wifi_patches.txt")),
        // This archive is an ABI veneer/data payload, not an input to the
        // relocation transform. A patched `WS63_RF_LIB_DIR` therefore must not
        // redirect it away from the canonical delivery.
        ("rom_callback_archive", root.join("lib/librom_callback.a")),
        ("archive_profile", profile_path),
        ("task_profile", scheduling_profile_path),
        ("nvs_linker", nvs_linker),
        ("supplicant_header", supplicant_header),
        ("supplicant_source", supplicant_source),
        ("upstream_hostap", upstream_hostap.clone()),
        ("native_supplicant_port", native_port.clone()),
        ("native_supplicant_profile", native_profile_path.clone()),
    ] {
        if !path.exists() {
            panic!("WS63 radio payload is incomplete: {}", path.display());
        }
        println!("cargo:{key}={}", path.display());
        println!("cargo:rerun-if-changed={}", path.display());
    }
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
        "cargo:wpa_archives={}",
        wpa.iter()
            .map(|archive| archive.name.as_str())
            .collect::<Vec<_>>()
            .join(",")
    );
    println!("cargo:rerun-if-env-changed=WS63_RF_ROOT");
    println!("cargo:rerun-if-env-changed=WS63_RF_LIB_DIR");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_WPA2_PERSONAL");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_WPA3_PERSONAL");

    if env::var_os("CARGO_FEATURE_UPSTREAM_SUPPLICANT_PORT").is_some() {
        let native_profile: NativeSupplicantProfile = toml::from_str(
            &fs::read_to_string(&native_profile_path)
                .expect("read native supplicant source profile"),
        )
        .expect("parse native supplicant source profile");
        assert!(
            !native_profile.revision.is_empty(),
            "empty native supplicant profile revision"
        );
        let mut source_paths = Vec::new();
        let mut unique_sources = BTreeSet::new();
        for source in &native_profile.upstream_sources {
            assert!(
                unique_sources.insert(format!("upstream:{source}")),
                "duplicate native supplicant source: {source}"
            );
            let path = upstream_hostap.join(source);
            assert!(
                path.is_file(),
                "missing upstream source: {}",
                path.display()
            );
            println!("cargo:rerun-if-changed={}", path.display());
            source_paths.push(path);
        }
        for source in &native_profile.port_sources {
            assert!(
                unique_sources.insert(format!("port:{source}")),
                "duplicate native supplicant source: {source}"
            );
            let path = native_port.join(source);
            assert!(path.is_file(), "missing port source: {}", path.display());
            println!("cargo:rerun-if-changed={}", path.display());
            source_paths.push(path);
        }
        let mut build = cc::Build::new();
        build
            .files(source_paths)
            .include(manifest.join("../../include"))
            .include(&native_port)
            .include(upstream_hostap.join("wpa_supplicant"))
            .include(manifest.join("../../third-party/hostap/src/utils"))
            .include(manifest.join("../../third-party/hostap/src"))
            .flag("-include")
            .flag(native_port.join("hisi_wpa_hostap_compat.h"))
            .flag_if_supported("-std=c11")
            .flag_if_supported("-ffreestanding")
            .flag_if_supported("-fno-builtin")
            .flag("-Wno-unused-parameter")
            // CONFIG_NO_STDOUT_DEBUG compiles wpa_printf() arguments away;
            // a few upstream notification helpers then intentionally retain
            // values that are only consumed by logging.
            .flag_if_supported("-Wno-unused-but-set-variable")
            .flag_if_supported("-Wno-unused-variable")
            .flag_if_supported("-Wno-variadic-macros")
            .flag_if_supported("-Wno-zero-length-array")
            .flag_if_supported("-Wno-flexible-array-extensions")
            .warnings_into_errors(true);
        for definition in &native_profile.defines {
            if let Some((name, value)) = definition.split_once('=') {
                build.define(name, value);
            } else {
                build.define(definition, None);
            }
        }
        if env::var("TARGET").is_ok_and(|target| target.starts_with("riscv32imfc-")) {
            // cc-rs otherwise pairs an explicitly selected cross GCC with the
            // host archiver. On macOS, host ranlib cannot index RISC-V ELF and
            // leaves a deceptively successful empty archive. Keep compiler and
            // archiver from one toolchain unless the caller overrides either.
            if !environment_override_exists(&[
                "CC_riscv32imfc_unknown_none_elf",
                "CC_riscv32imfc-unknown-none-elf",
                "TARGET_CC",
                "CC",
            ]) {
                build.compiler("riscv64-unknown-elf-gcc");
            }
            if !environment_override_exists(&[
                "AR_riscv32imfc_unknown_none_elf",
                "AR_riscv32imfc-unknown-none-elf",
                "TARGET_AR",
                "AR",
            ]) {
                build.archiver("riscv64-unknown-elf-ar");
            }
            // Rust's official target is hardware-single-float ILP32F. Clang's
            // generic RISC-V default is soft-float ILP32, which produces ELF
            // attributes that rust-lld correctly refuses to mix with Rust.
            build.flag("-march=rv32imfc").flag("-mabi=ilp32f");
        }
        build.compile("hisi_wpa_native_port");
    }
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_UPSTREAM_SUPPLICANT_PORT");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_UPSTREAM_SUPPLICANT_WPA3");
}
