use std::process::Command;

fn binary() -> std::path::PathBuf {
    let path = std::path::PathBuf::from(env!("CARGO_BIN_EXE_hisi-rf-link"));
    if path.is_absolute() {
        path
    } else {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(path)
    }
}

#[test]
fn embedded_tools_expose_help() {
    let cache = tempfile::tempdir().unwrap();
    for command in [
        "patch-reloc",
        "verify-layout",
        "generate-rom-patch",
        "patch-from-oracle",
    ] {
        let output = Command::new(binary())
            .args([command, "--help"])
            .env("UV_CACHE_DIR", cache.path())
            .output()
            .expect("run embedded post-link tool");
        assert!(
            output.status.success(),
            "{command} --help failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn task_profile_exposes_help() {
    let output = Command::new(binary())
        .args(["task-profile", "--help"])
        .output()
        .expect("run task-profile --help");
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("hash-bound scheduling profile")
    );
}

#[test]
fn inspect_summarizes_real_vendor_archive() {
    let archive = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../ws63-RF/lib/libwifi_alg_edca_opt.a");
    let output = Command::new(binary())
        .args(["inspect", "--summary"])
        .arg(archive)
        .output()
        .expect("inspect vendor archive");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["archives"], 1);
    assert!(summary["total"].as_u64().unwrap() > 0);
    assert!(summary["by_type"]["R_RISCV_48_LLUI"].as_u64().unwrap() > 0);
}

#[test]
fn normalize_is_deterministic_and_removes_vendor_relocations() {
    let archive = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../ws63-RF/lib/libwifi_alg_edca_opt.a");
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("first");
    let second = directory.path().join("second");
    let first_manifest = directory.path().join("first.json");
    let second_manifest = directory.path().join("second.json");

    for (output, manifest) in [(&first, &first_manifest), (&second, &second_manifest)] {
        let result = Command::new(binary())
            .args(["normalize", "--profile-revision", "test"])
            .arg("--out-dir")
            .arg(output)
            .arg("--manifest")
            .arg(manifest)
            .arg(&archive)
            .output()
            .expect("normalize vendor archive");
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    let file_name = archive.file_name().unwrap();
    assert_eq!(
        std::fs::read(first.join(file_name)).unwrap(),
        std::fs::read(second.join(file_name)).unwrap()
    );
    assert_eq!(
        std::fs::read(&first_manifest).unwrap(),
        std::fs::read(&second_manifest).unwrap()
    );

    let verify = Command::new(binary())
        .args(["verify-normalized", "--manifest"])
        .arg(&first_manifest)
        .arg("--archive-dir")
        .arg(&first)
        .output()
        .expect("verify normalized archive");
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );

    let inspect = Command::new(binary())
        .args(["inspect", "--summary"])
        .arg(first.join(file_name))
        .output()
        .expect("inspect normalized archive");
    assert!(inspect.status.success());
    let summary: serde_json::Value = serde_json::from_slice(&inspect.stdout).unwrap();
    assert_eq!(summary["total"], 0);
}

#[test]
fn machine_profile_resolves_wifi_archives() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ws63-RF");
    let output = Command::new(binary())
        .arg("archive-paths")
        .arg("wifi")
        .arg(root)
        .output()
        .expect("resolve archive profile");
    assert!(output.status.success());
    let paths = String::from_utf8(output.stdout).unwrap();
    assert_eq!(paths.lines().count(), 10);
    assert!(
        paths
            .lines()
            .next()
            .unwrap()
            .ends_with("libwifi_driver_hmac.a")
    );
}

#[test]
fn machine_profile_adds_mbedtls_crypto_archives_only_for_wpa3_personal() {
    let directory = tempfile::tempdir().unwrap();
    let sdk = directory.path().join("sdk");
    for relative in [
        "driver/security_unified/libdrv_security_unified.a",
        "hal/security_unified/libhal_security_unified.a",
        "libmbedtls_v3.6.0.a",
        "driver/security_unified/mbedtls_harden_adapt/libmbedtls_harden.a",
        "liteos/libs/libc.a",
        "liteos/libs/libm.a",
    ] {
        let path = sdk.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, []).unwrap();
    }
    let supplicant = directory.path().join("libwpa_supplicant.a");
    std::fs::write(&supplicant, []).unwrap();

    let resolve = |profile: &str| {
        let output = Command::new(binary())
            .args(["archive-paths", "wpa"])
            .arg(&sdk)
            .arg(&supplicant)
            .arg(profile)
            .output()
            .expect("resolve WPA archive profile");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    };

    let wpa2 = resolve("wpa2-personal");
    assert_eq!(wpa2.lines().count(), 5);
    assert!(!wpa2.contains("libmbedtls_v3.6.0.a"));
    assert!(!wpa2.contains("libmbedtls_harden.a"));

    let wpa3 = resolve("wpa3-personal");
    assert_eq!(wpa3.lines().count(), 7);
    assert!(wpa3.contains("libmbedtls_v3.6.0.a"));
    assert!(wpa3.contains("libmbedtls_harden.a"));
}
