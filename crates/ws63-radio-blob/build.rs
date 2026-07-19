use ruzstd::decoding::StreamingDecoder;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    fs::File,
    io,
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
struct Manifest {
    schema_version: u32,
    profile_revision: String,
    artifacts: Vec<Artifact>,
    native_supplicant: NativeSupplicant,
}

#[derive(Deserialize)]
struct Artifact {
    archive: String,
    output_sha256: String,
    output_size: usize,
}

#[derive(Deserialize)]
struct NativeSupplicant {
    profiles: Vec<NativeSupplicantProfile>,
}

#[derive(Deserialize)]
struct NativeSupplicantProfile {
    id: String,
    revision: String,
    archive: String,
}

fn sha256(path: &Path) -> String {
    let bytes = fs::read(path).unwrap_or_else(|error| {
        panic!(
            "read expanded WS63 radio artifact {}: {error}",
            path.display()
        )
    });
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn expand(source: &Path, output: &Path) {
    let input =
        File::open(source).unwrap_or_else(|error| panic!("open {}: {error}", source.display()));
    let mut decoder = StreamingDecoder::new(input)
        .unwrap_or_else(|error| panic!("decode {}: {error}", source.display()));
    let mut destination =
        File::create(output).unwrap_or_else(|error| panic!("create {}: {error}", output.display()));
    io::copy(&mut decoder, &mut destination)
        .unwrap_or_else(|error| panic!("expand {}: {error}", source.display()));
}

fn main() {
    let package = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let artifacts = package.join("artifacts");
    let manifest_path = artifacts.join("manifest.json");
    let manifest: Manifest = serde_json::from_slice(
        &fs::read(&manifest_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", manifest_path.display())),
    )
    .unwrap_or_else(|error| panic!("parse {}: {error}", manifest_path.display()));
    assert_eq!(manifest.schema_version, 1, "unsupported manifest schema");

    let output = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR")).join("lib");
    fs::create_dir_all(&output)
        .unwrap_or_else(|error| panic!("create {}: {error}", output.display()));

    println!("cargo:rerun-if-changed={}", manifest_path.display());
    for artifact in &manifest.artifacts {
        let source = artifacts.join(format!("{}.zst", artifact.archive));
        let destination = output.join(&artifact.archive);
        println!("cargo:rerun-if-changed={}", source.display());
        expand(&source, &destination);
        let metadata = fs::metadata(&destination)
            .unwrap_or_else(|error| panic!("stat {}: {error}", destination.display()));
        assert_eq!(
            metadata.len(),
            artifact.output_size as u64,
            "expanded size mismatch for {}",
            artifact.archive
        );
        assert_eq!(
            sha256(&destination),
            artifact.output_sha256,
            "expanded SHA-256 mismatch for {}",
            artifact.archive
        );
    }

    println!("cargo:lib_dir={}", output.display());
    println!("cargo:manifest={}", manifest_path.display());
    println!("cargo:profile_revision={}", manifest.profile_revision);
    for profile in &manifest.native_supplicant.profiles {
        assert!(
            manifest
                .artifacts
                .iter()
                .any(|artifact| artifact.archive == profile.archive),
            "native supplicant profile {} references an unknown archive",
            profile.id
        );
        let archive = output.join(&profile.archive);
        println!(
            "cargo:native_supplicant_{}_archive={}",
            profile.id,
            archive.display()
        );
        println!(
            "cargo:native_supplicant_{}_revision={}",
            profile.id, profile.revision
        );
    }
}
