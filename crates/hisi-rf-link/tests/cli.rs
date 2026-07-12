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
