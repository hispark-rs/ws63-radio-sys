use std::{env, fs, process::Command};

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
        "usage: hisi-rf-link <{}> [arguments...]",
        COMMANDS
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>()
            .join("|")
    );
    std::process::exit(2);
}

fn main() {
    let mut args = env::args_os();
    let _program = args.next();
    let Some(command) = args.next().and_then(|arg| arg.into_string().ok()) else {
        usage();
    };
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
