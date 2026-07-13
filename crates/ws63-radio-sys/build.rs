use serde::Deserialize;
use std::{env, fs, path::PathBuf};

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
    let nvs_linker = manifest.join("../../linker/ws63-nvs.x");
    let profile: Profile =
        toml::from_str(&fs::read_to_string(&profile_path).expect("read WS63 archive profile"))
            .expect("parse WS63 archive profile");
    let mut wifi = profile.wifi_archives;
    wifi.sort_by_key(|archive| archive.link_order);
    let mut wpa = profile.wpa_archives;
    wpa.sort_by_key(|archive| archive.order);

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
        ("nvs_linker", nvs_linker),
    ] {
        if !path.exists() {
            panic!("WS63 radio payload is incomplete: {}", path.display());
        }
        println!("cargo:{key}={}", path.display());
        println!("cargo:rerun-if-changed={}", path.display());
    }
    println!("cargo:revision={}", profile.revision);
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
}
