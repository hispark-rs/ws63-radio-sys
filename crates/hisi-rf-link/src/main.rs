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
        "usage: hisi-rf-link <archive-paths|task-profile|{}> [arguments...]",
        COMMANDS
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>()
            .join("|")
    );
    std::process::exit(2);
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
            if args.next().is_some() {
                usage();
            }
            let mut archives = profile.wpa_archives;
            archives.sort_by_key(|archive| archive.order);
            for archive in archives {
                match archive.source.as_str() {
                    "override" => print_path(override_archive.clone()),
                    "sdk" => print_path(sdk.join(archive.relative)),
                    source => panic!("unsupported archive source {source}"),
                }
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

    let status = Command::new(env::var_os("PYTHON").unwrap_or_else(|| "python3".into()))
        .arg(path)
        .args(args)
        .status()
        .expect("execute Python post-link tool");
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
}
