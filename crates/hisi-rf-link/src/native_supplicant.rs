//! Rebuild the pinned upstream hostap target archives for release verification.

use ruzstd::decoding::StreamingDecoder;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

const TARGET: &str = "riscv32imfc-unknown-none-elf";
const CC_RS_VERSION: &str = "1.2.67";

#[derive(Debug)]
pub struct Error(String);

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl Error {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

#[derive(Deserialize)]
struct SourceProfile {
    revision: String,
    upstream_sources: Vec<String>,
    port_sources: Vec<String>,
    defines: Vec<String>,
}

#[derive(Deserialize)]
struct ArtifactManifest {
    schema_version: u32,
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
    target: String,
    builder: NativeBuilder,
    profiles: Vec<NativeProfile>,
}

#[derive(Deserialize)]
struct NativeBuilder {
    cc_rs: String,
    compiler_first_line: String,
    archiver_first_line: String,
}

#[derive(Deserialize)]
struct NativeProfile {
    id: String,
    revision: String,
    archive: String,
}

struct CurrentDirectory(PathBuf);

impl CurrentDirectory {
    fn enter(path: &Path) -> Result<Self, Error> {
        let previous = env::current_dir()
            .map_err(|error| Error::new(format!("read current directory: {error}")))?;
        env::set_current_dir(path)
            .map_err(|error| Error::new(format!("enter {}: {error}", path.display())))?;
        Ok(Self(previous))
    }
}

impl Drop for CurrentDirectory {
    fn drop(&mut self) {
        let _ = env::set_current_dir(&self.0);
    }
}

fn option(arguments: &mut Vec<std::ffi::OsString>, name: &str) -> Result<PathBuf, Error> {
    let position = arguments
        .iter()
        .position(|argument| argument == name)
        .ok_or_else(|| Error::new(format!("missing required option {name}")))?;
    if position + 1 >= arguments.len() {
        return Err(Error::new(format!("missing value for {name}")));
    }
    arguments.remove(position);
    Ok(PathBuf::from(arguments.remove(position)))
}

fn command_first_line(path: &Path) -> Result<String, Error> {
    let output = Command::new(path)
        .arg("--version")
        .output()
        .map_err(|error| Error::new(format!("run {} --version: {error}", path.display())))?;
    if !output.status.success() {
        return Err(Error::new(format!(
            "{} --version exited with {}",
            path.display(),
            output.status
        )));
    }
    String::from_utf8(output.stdout)
        .map_err(|error| Error::new(format!("{} version is not UTF-8: {error}", path.display())))?
        .lines()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| Error::new(format!("{} returned an empty version", path.display())))
}

fn rustc_host() -> Result<String, Error> {
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = Command::new(&rustc)
        .arg("-vV")
        .output()
        .map_err(|error| Error::new(format!("run rustc -vV: {error}")))?;
    if !output.status.success() {
        return Err(Error::new(format!(
            "rustc -vV exited with {}",
            output.status
        )));
    }
    let version = String::from_utf8(output.stdout)
        .map_err(|error| Error::new(format!("rustc -vV is not UTF-8: {error}")))?;
    version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(str::to_owned)
        .ok_or_else(|| Error::new("rustc -vV did not report a host triple"))
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn expand_zstd(path: &Path) -> Result<Vec<u8>, Error> {
    let input = File::open(path)
        .map_err(|error| Error::new(format!("open {}: {error}", path.display())))?;
    let mut decoder = StreamingDecoder::new(input)
        .map_err(|error| Error::new(format!("decode {}: {error}", path.display())))?;
    let mut bytes = Vec::new();
    decoder
        .read_to_end(&mut bytes)
        .map_err(|error| Error::new(format!("expand {}: {error}", path.display())))?;
    Ok(bytes)
}

fn load_toml<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, Error> {
    let source = fs::read_to_string(path)
        .map_err(|error| Error::new(format!("read {}: {error}", path.display())))?;
    toml::from_str(&source)
        .map_err(|error| Error::new(format!("parse {}: {error}", path.display())))
}

fn load_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, Error> {
    let source =
        fs::read(path).map_err(|error| Error::new(format!("read {}: {error}", path.display())))?;
    serde_json::from_slice(&source)
        .map_err(|error| Error::new(format!("parse {}: {error}", path.display())))
}

fn build_profile(
    repository: &Path,
    output: &Path,
    compiler: &Path,
    archiver: &Path,
    profile: &NativeProfile,
) -> Result<PathBuf, Error> {
    let profile_name = match profile.id.as_str() {
        "wpa2" => "personal.toml",
        "wpa3" => "personal-wpa3.toml",
        other => return Err(Error::new(format!("unsupported native profile {other}"))),
    };
    let source_profile: SourceProfile =
        load_toml(&repository.join("port/hostap").join(profile_name))?;
    if source_profile.revision != profile.revision {
        return Err(Error::new(format!(
            "native profile {} revision drift: manifest={}, source={}",
            profile.id, profile.revision, source_profile.revision
        )));
    }

    let crate_dir = repository.join("crates/ws63-radio-sys");
    let upstream = PathBuf::from("../../third-party/hostap");
    let port = PathBuf::from("../../port/hostap");
    let mut sources = source_profile
        .upstream_sources
        .iter()
        .map(|source| upstream.join(source))
        .chain(
            source_profile
                .port_sources
                .iter()
                .map(|source| port.join(source)),
        )
        .collect::<Vec<_>>();
    for source in &sources {
        if !crate_dir.join(source).is_file() {
            return Err(Error::new(format!(
                "native profile source is missing: {}",
                crate_dir.join(source).display()
            )));
        }
    }

    let build_root = output.join(format!("{}-objects", profile.id));
    if build_root.exists() {
        fs::remove_dir_all(&build_root)
            .map_err(|error| Error::new(format!("clean {}: {error}", build_root.display())))?;
    }
    fs::create_dir_all(&build_root)
        .map_err(|error| Error::new(format!("create {}: {error}", build_root.display())))?;
    let host = rustc_host()?;
    let _directory = CurrentDirectory::enter(&crate_dir)?;

    let mut build = cc::Build::new();
    build
        .cargo_metadata(false)
        .files(sources.drain(..))
        .include("../../include")
        .include(&port)
        .include(upstream.join("wpa_supplicant"))
        .include(upstream.join("src/utils"))
        .include(upstream.join("src"))
        .flag("-include")
        .flag(port.join("hisi_wpa_hostap_compat.h"))
        // The release toolchain is version-locked below, so these are a fixed
        // archive-format contract rather than host capability probes.
        .flag("-std=c11")
        .flag("-ffreestanding")
        .flag("-fno-builtin")
        .flag("-g0")
        .flag("-ffile-prefix-map=../..=ws63-radio-sys")
        .flag("-fmacro-prefix-map=../..=ws63-radio-sys")
        .flag("-Wno-unused-parameter")
        .flag("-Wno-unused-but-set-variable")
        .flag("-Wno-unused-variable")
        .flag("-Wno-maybe-uninitialized")
        .flag("-Wno-variadic-macros")
        .flag("-Wno-zero-length-array")
        .flag("-Wno-flexible-array-extensions")
        .warnings_into_errors(true)
        .compiler(compiler)
        .archiver(archiver)
        .target(TARGET)
        .host(&host)
        .opt_level(3)
        .debug(false)
        .out_dir(&build_root)
        .flag("-march=rv32imfc")
        .flag("-mabi=ilp32f");
    for definition in &source_profile.defines {
        if let Some((name, value)) = definition.split_once('=') {
            build.define(name, value);
        } else {
            build.define(definition, None);
        }
    }
    build.compile("hisi_wpa_native_port");

    let built = build_root.join("libhisi_wpa_native_port.a");
    let destination = output.join(&profile.archive);
    fs::copy(&built, &destination).map_err(|error| {
        Error::new(format!(
            "copy {} to {}: {error}",
            built.display(),
            destination.display()
        ))
    })?;
    Ok(destination)
}

fn rebuild(
    repository: &Path,
    output: &Path,
    compiler: &Path,
    archiver: &Path,
) -> Result<(), Error> {
    let manifest_path = repository.join("crates/ws63-radio-blob/artifacts/manifest.json");
    let manifest: ArtifactManifest = load_json(&manifest_path)?;
    if manifest.schema_version != 1 {
        return Err(Error::new(format!(
            "unsupported artifact manifest schema {}",
            manifest.schema_version
        )));
    }
    if manifest.native_supplicant.target != TARGET {
        return Err(Error::new(format!(
            "native target drift: expected {TARGET}, got {}",
            manifest.native_supplicant.target
        )));
    }
    if manifest.native_supplicant.builder.cc_rs != CC_RS_VERSION {
        return Err(Error::new(format!(
            "cc-rs contract drift: expected {CC_RS_VERSION}, got {}",
            manifest.native_supplicant.builder.cc_rs
        )));
    }
    for (path, expected) in [
        (
            compiler,
            manifest
                .native_supplicant
                .builder
                .compiler_first_line
                .as_str(),
        ),
        (
            archiver,
            manifest
                .native_supplicant
                .builder
                .archiver_first_line
                .as_str(),
        ),
    ] {
        let actual = command_first_line(path)?;
        if actual != expected {
            return Err(Error::new(format!(
                "toolchain drift for {}: expected {expected:?}, got {actual:?}",
                path.display()
            )));
        }
    }
    fs::create_dir_all(output)
        .map_err(|error| Error::new(format!("create {}: {error}", output.display())))?;

    for profile in &manifest.native_supplicant.profiles {
        let artifact = manifest
            .artifacts
            .iter()
            .find(|artifact| artifact.archive == profile.archive)
            .ok_or_else(|| {
                Error::new(format!(
                    "native profile {} references missing artifact {}",
                    profile.id, profile.archive
                ))
            })?;
        let built_path = build_profile(repository, output, compiler, archiver, profile)?;
        let built = fs::read(&built_path)
            .map_err(|error| Error::new(format!("read {}: {error}", built_path.display())))?;
        let packaged_path = repository
            .join("crates/ws63-radio-blob/artifacts")
            .join(format!("{}.zst", profile.archive));
        let packaged = expand_zstd(&packaged_path)?;
        if built.len() != artifact.output_size || sha256(&built) != artifact.output_sha256 {
            return Err(Error::new(format!(
                "rebuilt {} differs from manifest: size={}, sha256={}",
                profile.archive,
                built.len(),
                sha256(&built)
            )));
        }
        if built != packaged {
            return Err(Error::new(format!(
                "rebuilt {} differs byte-for-byte from the Cargo payload",
                profile.archive
            )));
        }
        println!(
            "rebuilt {}: {} bytes, sha256={}, byte-for-byte Cargo payload match",
            profile.archive, artifact.output_size, artifact.output_sha256
        );
    }
    Ok(())
}

/// Run the maintainer-side native supplicant rebuild command.
pub fn run(arguments: impl Iterator<Item = std::ffi::OsString>) -> Result<(), Error> {
    let mut arguments = arguments.collect::<Vec<_>>();
    let repository = fs::canonicalize(option(&mut arguments, "--repository-root")?)
        .map_err(|error| Error::new(format!("resolve repository root: {error}")))?;
    let output = option(&mut arguments, "--output-dir")?;
    let output = if output.is_absolute() {
        output
    } else {
        env::current_dir()
            .map_err(|error| Error::new(format!("read current directory: {error}")))?
            .join(output)
    };
    let compiler = option(&mut arguments, "--compiler")?;
    let archiver = option(&mut arguments, "--archiver")?;
    if !arguments.is_empty() {
        return Err(Error::new(format!("unexpected arguments: {:?}", arguments)));
    }
    rebuild(&repository, &output, &compiler, &archiver)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_are_lowercase_sha256() {
        assert_eq!(
            sha256(b"hisi"),
            "099ea77597990f3cf85524018aa1eeb04dab3d83bbb9c11b16567b3fce71396f"
        );
    }

    #[test]
    fn zstd_payload_expands() {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let path =
            repository.join("crates/ws63-radio-blob/artifacts/libhisi_wpa_native_port_wpa2.a.zst");
        let bytes = expand_zstd(&path).unwrap();
        assert!(bytes.starts_with(b"!<arch>\n"));
    }
}
