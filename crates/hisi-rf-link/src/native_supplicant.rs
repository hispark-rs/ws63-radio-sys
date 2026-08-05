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
    #[serde(default)]
    extends: Option<String>,
    #[serde(default)]
    upstream_sources: Vec<String>,
    #[serde(default)]
    port_sources: Vec<String>,
    #[serde(default)]
    defines: Vec<String>,
}

#[derive(Deserialize)]
struct ArtifactManifest {
    schema_version: u32,
    artifacts: Vec<Artifact>,
    native_supplicant: NativeSupplicant,
    native_authenticator: NativeSupplicant,
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
    source_profile: Option<String>,
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

fn optional_string(
    arguments: &mut Vec<std::ffi::OsString>,
    name: &str,
) -> Result<Option<String>, Error> {
    let Some(position) = arguments.iter().position(|argument| argument == name) else {
        return Ok(None);
    };
    if position + 1 >= arguments.len() {
        return Err(Error::new(format!("missing value for {name}")));
    }
    arguments.remove(position);
    arguments
        .remove(position)
        .into_string()
        .map(Some)
        .map_err(|_| Error::new(format!("{name} must be valid UTF-8")))
}

fn flag(arguments: &mut Vec<std::ffi::OsString>, name: &str) -> bool {
    arguments
        .iter()
        .position(|argument| argument == name)
        .map(|position| {
            arguments.remove(position);
            true
        })
        .unwrap_or(false)
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

fn load_source_profile(repository: &Path, name: &str) -> Result<SourceProfile, Error> {
    let profile_path = repository.join("port/hostap").join(name);
    let mut profile: SourceProfile = load_toml(&profile_path)?;
    let Some(base_name) = profile.extends.take() else {
        return Ok(profile);
    };
    let mut base = load_source_profile(repository, &base_name)?;
    base.revision = profile.revision;
    base.upstream_sources.extend(profile.upstream_sources);
    base.port_sources.extend(profile.port_sources);
    base.defines.extend(profile.defines);
    Ok(base)
}

fn build_profile(
    repository: &Path,
    output: &Path,
    compiler: &Path,
    archiver: &Path,
    profile: &NativeProfile,
) -> Result<PathBuf, Error> {
    let profile_name = if let Some(source_profile) = profile.source_profile.as_deref() {
        source_profile
    } else {
        match profile.id.as_str() {
            "wpa2" => "personal.toml",
            "wpa3" => "personal-wpa3.toml",
            other => return Err(Error::new(format!("unsupported native profile {other}"))),
        }
    };
    let source_profile = load_source_profile(repository, profile_name)?;
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

fn validate_native_group(
    group_name: &str,
    group: &NativeSupplicant,
    compiler: &Path,
    archiver: &Path,
) -> Result<(), Error> {
    if group.target != TARGET {
        return Err(Error::new(format!(
            "{group_name} target drift: expected {TARGET}, got {}",
            group.target
        )));
    }
    if group.builder.cc_rs != CC_RS_VERSION {
        return Err(Error::new(format!(
            "{group_name} cc-rs contract drift: expected {CC_RS_VERSION}, got {}",
            group.builder.cc_rs
        )));
    }
    for (path, expected) in [
        (compiler, group.builder.compiler_first_line.as_str()),
        (archiver, group.builder.archiver_first_line.as_str()),
    ] {
        let actual = command_first_line(path)?;
        if actual != expected {
            return Err(Error::new(format!(
                "{group_name} toolchain drift for {}: expected {expected:?}, got {actual:?}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn rebuild_group(
    repository: &Path,
    output: &Path,
    compiler: &Path,
    archiver: &Path,
    artifacts: &[Artifact],
    group_name: &str,
    group: &NativeSupplicant,
    update_artifacts: bool,
) -> Result<(), Error> {
    validate_native_group(group_name, group, compiler, archiver)?;
    for profile in &group.profiles {
        let artifact = artifacts
            .iter()
            .find(|artifact| artifact.archive == profile.archive)
            .ok_or_else(|| {
                Error::new(format!(
                    "{group_name} profile {} references missing artifact {}",
                    profile.id, profile.archive
                ))
            })?;
        let built_path = build_profile(repository, output, compiler, archiver, profile)?;
        let built = fs::read(&built_path)
            .map_err(|error| Error::new(format!("read {}: {error}", built_path.display())))?;
        if update_artifacts {
            continue;
        }
        let packaged_path = repository
            .join("crates/ws63-radio-blob/artifacts")
            .join(format!("{}.zst", profile.archive));
        if built.len() != artifact.output_size || sha256(&built) != artifact.output_sha256 {
            return Err(Error::new(format!(
                "rebuilt {} differs from manifest: size={}, sha256={}",
                profile.archive,
                built.len(),
                sha256(&built)
            )));
        }
        let packaged = expand_zstd(&packaged_path)?;
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

fn rebuild(
    repository: &Path,
    output: &Path,
    compiler: &Path,
    archiver: &Path,
    update_artifacts: bool,
    selected_group: Option<&str>,
) -> Result<(), Error> {
    let manifest_path = repository.join("crates/ws63-radio-blob/artifacts/manifest.json");
    let mut manifest_value: serde_json::Value = load_json(&manifest_path)?;
    let manifest: ArtifactManifest = serde_json::from_value(manifest_value.clone())
        .map_err(|error| Error::new(format!("parse {}: {error}", manifest_path.display())))?;
    if manifest.schema_version != 1 {
        return Err(Error::new(format!(
            "unsupported artifact manifest schema {}",
            manifest.schema_version
        )));
    }
    fs::create_dir_all(output)
        .map_err(|error| Error::new(format!("create {}: {error}", output.display())))?;
    if selected_group.is_none_or(|group| group == "supplicant") {
        rebuild_group(
            repository,
            output,
            compiler,
            archiver,
            &manifest.artifacts,
            "native supplicant",
            &manifest.native_supplicant,
            update_artifacts,
        )?;
    }
    if selected_group.is_none_or(|group| group == "authenticator") {
        rebuild_group(
            repository,
            output,
            compiler,
            archiver,
            &manifest.artifacts,
            "native authenticator",
            &manifest.native_authenticator,
            update_artifacts,
        )?;
    }
    if update_artifacts {
        let artifacts = manifest_value["artifacts"]
            .as_array_mut()
            .ok_or_else(|| Error::new("artifact manifest artifacts is not an array"))?;
        let groups = [
            ("supplicant", &manifest.native_supplicant),
            ("authenticator", &manifest.native_authenticator),
        ];
        for (_, group) in groups
            .into_iter()
            .filter(|(name, _)| selected_group.is_none_or(|selected| selected == *name))
        {
            for profile in &group.profiles {
                let built_path = output.join(&profile.archive);
                let built = fs::read(&built_path).map_err(|error| {
                    Error::new(format!("read {}: {error}", built_path.display()))
                })?;
                let packaged_path = repository
                    .join("crates/ws63-radio-blob/artifacts")
                    .join(format!("{}.zst", profile.archive));
                let compressed = ruzstd::encoding::compress_to_vec(
                    built.as_slice(),
                    ruzstd::encoding::CompressionLevel::Fastest,
                );
                fs::write(&packaged_path, compressed).map_err(|error| {
                    Error::new(format!("write {}: {error}", packaged_path.display()))
                })?;
                let artifact = artifacts
                    .iter_mut()
                    .find(|artifact| artifact["archive"] == profile.archive)
                    .ok_or_else(|| {
                        Error::new(format!("manifest is missing {}", profile.archive))
                    })?;
                artifact["output_size"] = serde_json::Value::from(built.len());
                artifact["output_sha256"] = serde_json::Value::from(sha256(&built));
                println!(
                    "updated {}: {} bytes, sha256={}",
                    profile.archive,
                    built.len(),
                    sha256(&built)
                );
            }
        }
        let mut serialized = serde_json::to_string_pretty(&manifest_value)
            .map_err(|error| Error::new(format!("serialize artifact manifest: {error}")))?;
        serialized.push('\n');
        fs::write(&manifest_path, serialized)
            .map_err(|error| Error::new(format!("write {}: {error}", manifest_path.display())))?;
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
    let update_artifacts = flag(&mut arguments, "--update-artifacts");
    let selected_group = optional_string(&mut arguments, "--group")?;
    if selected_group
        .as_deref()
        .is_some_and(|group| !matches!(group, "supplicant" | "authenticator"))
    {
        return Err(Error::new(
            "--group must be either supplicant or authenticator",
        ));
    }
    if !arguments.is_empty() {
        return Err(Error::new(format!("unexpected arguments: {:?}", arguments)));
    }
    rebuild(
        &repository,
        &output,
        &compiler,
        &archiver,
        update_artifacts,
        selected_group.as_deref(),
    )
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

    #[test]
    fn pure_rust_zstd_encoder_round_trips() {
        let source = b"!<arch>\nreproducible target archive";
        let compressed = ruzstd::encoding::compress_to_vec(
            source.as_slice(),
            ruzstd::encoding::CompressionLevel::Fastest,
        );
        let mut decoder = StreamingDecoder::new(compressed.as_slice()).unwrap();
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, source);
    }
}
