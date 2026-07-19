use serde::Deserialize;
use std::{env, fs, path::PathBuf, process::Command};

mod task_profile;

const PROFILE: &str = include_str!("../profiles/ws63.toml");

#[derive(Deserialize)]
struct Profile {
    wifi_archives: Vec<WifiArchive>,
    wpa_archives: Vec<WpaArchive>,
}

#[derive(Deserialize)]
struct WifiArchive {
    name: String,
    transform_order: u16,
}

#[derive(Deserialize)]
struct WpaArchive {
    source: String,
    relative: String,
    order: u16,
    profiles: Vec<String>,
}

const COMMANDS: &[(&str, &str)] = &[
    ("patch-reloc", include_str!("../python/patch-reloc.py")),
    ("verify-layout", include_str!("../python/verify-layout.py")),
    (
        "generate-rom-patch",
        include_str!("../python/generate-rom-patch.py"),
    ),
    (
        "patch-from-oracle",
        include_str!("../python/patch-from-oracle.py"),
    ),
];

fn usage() -> ! {
    eprintln!(
        "usage: hisi-rf-link <inspect|normalize|verify-normalized|verify-guarded-sites|archive-paths|task-profile|{}> [arguments...]",
        COMMANDS
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>()
            .join("|")
    );
    std::process::exit(2);
}

fn required_option(arguments: &mut Vec<std::ffi::OsString>, name: &str) -> std::ffi::OsString {
    let position = arguments
        .iter()
        .position(|argument| argument == name)
        .unwrap_or_else(|| usage());
    if position + 1 >= arguments.len() {
        usage();
    }
    arguments.remove(position);
    arguments.remove(position)
}

fn normalize(args: impl Iterator<Item = std::ffi::OsString>) {
    let mut arguments = args.collect::<Vec<_>>();
    let profile_revision = required_option(&mut arguments, "--profile-revision")
        .into_string()
        .unwrap_or_else(|_| usage());
    let output_directory = PathBuf::from(required_option(&mut arguments, "--out-dir"));
    let manifest_path = PathBuf::from(required_option(&mut arguments, "--manifest"));
    if arguments.is_empty() {
        usage();
    }
    let mut artifacts = Vec::new();
    for argument in arguments {
        let input = PathBuf::from(argument);
        let file_name = input.file_name().unwrap_or_else(|| usage());
        let output = output_directory.join(file_name);
        let artifact =
            hisi_rf_link::normalize::normalize_archive(&input, &output).unwrap_or_else(|error| {
                eprintln!("normalize {}: {error}", input.display());
                std::process::exit(1);
            });
        println!(
            "{}: R58={} R59={} R59-section RELAX={} R61={} -> {}",
            artifact.archive,
            artifact.transformations.llui48_to_riscv32,
            artifact.transformations.branchi_same_section_encoded,
            artifact
                .transformations
                .relax_markers_removed_from_branchi_sections,
            artifact.transformations.llui_rep_markers_removed,
            output.display()
        );
        artifacts.push(artifact);
    }
    let manifest = hisi_rf_link::normalize::NormalizationManifest {
        schema_version: 1,
        normalizer: format!("hisi-rf-link {}", env!("CARGO_PKG_VERSION")),
        profile_revision,
        artifacts,
    };
    if let Some(parent) = manifest_path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|error| {
            panic!("create manifest directory {}: {error}", parent.display())
        });
    }
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("serialize normalization manifest"),
    )
    .unwrap_or_else(|error| panic!("write {}: {error}", manifest_path.display()));
}

fn verify_normalized(args: impl Iterator<Item = std::ffi::OsString>) {
    let mut arguments = args.collect::<Vec<_>>();
    let manifest_path = PathBuf::from(required_option(&mut arguments, "--manifest"));
    let archive_directory = PathBuf::from(required_option(&mut arguments, "--archive-dir"));
    if !arguments.is_empty() {
        usage();
    }
    let manifest: hisi_rf_link::normalize::NormalizationManifest = serde_json::from_slice(
        &fs::read(&manifest_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", manifest_path.display())),
    )
    .unwrap_or_else(|error| panic!("parse {}: {error}", manifest_path.display()));
    if manifest.schema_version != 1 {
        eprintln!(
            "unsupported normalization manifest schema {}",
            manifest.schema_version
        );
        std::process::exit(1);
    }
    for artifact in &manifest.artifacts {
        let path = archive_directory.join(&artifact.archive);
        hisi_rf_link::normalize::verify_normalized_archive(&path, artifact).unwrap_or_else(
            |error| {
                eprintln!("verify {}: {error}", path.display());
                std::process::exit(1);
            },
        );
        println!("verified {}", path.display());
    }
}

fn verify_guarded_sites(args: impl Iterator<Item = std::ffi::OsString>) {
    let mut arguments = args.collect::<Vec<_>>();
    let manifest = PathBuf::from(required_option(&mut arguments, "--manifest"));
    let final_elf = PathBuf::from(required_option(&mut arguments, "--final-elf"));
    let archive_directory = PathBuf::from(required_option(&mut arguments, "--archive-dir"));
    if !arguments.is_empty() {
        usage();
    }
    let parity =
        hisi_rf_link::normalize::verify_guarded_sites(&manifest, &final_elf, &archive_directory)
            .unwrap_or_else(|error| {
                eprintln!("verify guarded sites: {error}");
                std::process::exit(1);
            });
    println!(
        "verified normalized bytes against guarded lane: R58 exact={}, merged-equivalent={}, legacy-merged-string-corrections={}; R59 exact={}",
        parity.llui48_exact,
        parity.llui48_merged_string_equivalent,
        parity.llui48_legacy_merged_string_corrections,
        parity.branchi_exact,
    );
}

fn inspect(mut args: impl Iterator<Item = std::ffi::OsString>) {
    let mut arguments = args.by_ref().collect::<Vec<_>>();
    let summary = arguments
        .first()
        .is_some_and(|argument| argument == "--summary");
    if summary {
        arguments.remove(0);
    }
    let mut inventories = Vec::new();
    for argument in arguments {
        let path = PathBuf::from(argument);
        let inventory = hisi_rf_link::normalize::inspect_archive(&path).unwrap_or_else(|error| {
            eprintln!("inspect {}: {error}", path.display());
            std::process::exit(1);
        });
        inventories.push(inventory);
    }
    if inventories.is_empty() {
        usage();
    }
    if summary {
        serde_json::to_writer_pretty(
            std::io::stdout(),
            &hisi_rf_link::normalize::summarize(&inventories),
        )
        .expect("write relocation summary");
    } else {
        serde_json::to_writer_pretty(std::io::stdout(), &inventories)
            .expect("write relocation inventory");
    }
    println!();
}

fn print_path(path: PathBuf) {
    if !path.is_file() {
        eprintln!("radio archive is missing: {}", path.display());
        std::process::exit(2);
    }
    println!("{}", path.display());
}

fn archive_paths(mut args: impl Iterator<Item = std::ffi::OsString>) {
    let profile: Profile = toml::from_str(PROFILE).expect("parse embedded WS63 profile");
    match args
        .next()
        .and_then(|arg| arg.into_string().ok())
        .as_deref()
    {
        Some("wifi") => {
            let root = args.next().map(PathBuf::from).unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let mut archives = profile.wifi_archives;
            archives.sort_by_key(|archive| archive.transform_order);
            for archive in archives {
                print_path(root.join("lib").join(format!("lib{}.a", archive.name)));
            }
        }
        Some("wpa") => {
            let sdk = args.next().map(PathBuf::from).unwrap_or_else(|| usage());
            let override_archive = args.next().map(PathBuf::from).unwrap_or_else(|| usage());
            let selected_profile = args
                .next()
                .and_then(|argument| argument.into_string().ok())
                .unwrap_or_else(|| "wpa2-personal".to_owned());
            if args.next().is_some() {
                usage();
            }
            let mut archives = profile.wpa_archives;
            archives.sort_by_key(|archive| archive.order);
            let mut selected = 0;
            for archive in archives.into_iter().filter(|archive| {
                archive
                    .profiles
                    .iter()
                    .any(|name| name == &selected_profile)
            }) {
                selected += 1;
                match archive.source.as_str() {
                    "override" => print_path(override_archive.clone()),
                    "sdk" => print_path(sdk.join(archive.relative)),
                    source => panic!("unsupported archive source {source}"),
                }
            }
            if selected == 0 {
                eprintln!("unsupported WS63 WPA archive profile: {selected_profile}");
                std::process::exit(2);
            }
        }
        _ => usage(),
    }
}

fn main() {
    let mut args = env::args_os();
    let _program = args.next();
    let Some(command) = args.next().and_then(|arg| arg.into_string().ok()) else {
        usage();
    };
    if command == "archive-paths" {
        archive_paths(args);
        return;
    }
    if command == "inspect" {
        inspect(args);
        return;
    }
    if command == "normalize" {
        normalize(args);
        return;
    }
    if command == "verify-normalized" {
        verify_normalized(args);
        return;
    }
    if command == "verify-guarded-sites" {
        verify_guarded_sites(args);
        return;
    }
    if command == "task-profile" {
        task_profile::run(args);
        return;
    }
    let Some((_, script)) = COMMANDS.iter().find(|(name, _)| *name == command) else {
        usage();
    };

    let directory = tempfile::Builder::new()
        .prefix("hisi-rf-link-")
        .tempdir()
        .expect("create temporary script directory");
    let path = directory.path().join(format!("{command}.py"));
    fs::write(&path, script).expect("write embedded post-link tool");

    let status = Command::new("uv")
        .args(["run", "--script"])
        .arg(path)
        .args(args)
        .status()
        .expect("execute legacy post-link oracle through uv");
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
}
