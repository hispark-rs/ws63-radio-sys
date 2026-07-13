use std::process::Command;

#[test]
fn embedded_tools_expose_help() {
    for command in [
        "patch-reloc",
        "verify-layout",
        "generate-rom-patch",
        "patch-from-oracle",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_hisi-rf-link"))
            .args([command, "--help"])
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
fn machine_profile_resolves_wifi_archives() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ws63-RF");
    let output = Command::new(env!("CARGO_BIN_EXE_hisi-rf-link"))
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
