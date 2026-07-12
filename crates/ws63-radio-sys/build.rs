use std::{env, path::PathBuf};

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
        ("rom_callback_archive", lib.join("librom_callback.a")),
    ] {
        if !path.exists() {
            panic!("WS63 radio payload is incomplete: {}", path.display());
        }
        println!("cargo:{key}={}", path.display());
        println!("cargo:rerun-if-changed={}", path.display());
    }
    println!("cargo:rerun-if-env-changed=WS63_RF_ROOT");
    println!("cargo:rerun-if-env-changed=WS63_RF_LIB_DIR");
}
