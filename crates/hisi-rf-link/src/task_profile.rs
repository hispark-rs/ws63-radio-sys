use object::{Object, ObjectSymbol};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
};

const SCHEDULING_PROFILE: &str = include_str!("../profiles/ws63-scheduling.toml");

#[derive(Debug, Deserialize)]
struct SchedulingProfile {
    revision: String,
    payload_revision: String,
    default_role: String,
    tasks: Vec<ProfileTask>,
}

#[derive(Clone, Debug, Deserialize)]
struct ProfileTask {
    entry_symbol: String,
    entry_address: Option<u64>,
    source: String,
    role: String,
    vendor_priority: u8,
}

#[derive(Debug, Default)]
struct Arguments {
    elf: Option<PathBuf>,
    log: Option<PathBuf>,
    entries: Vec<u64>,
}

#[derive(Debug, Default)]
struct ObservedTaskInput {
    task_id: Option<u32>,
    entry: u64,
    runtime: BTreeMap<String, u64>,
}

struct ElfSymbols {
    sha256: String,
    by_name: BTreeMap<String, u64>,
    by_address: BTreeMap<u64, String>,
}

#[derive(Debug, Serialize)]
struct Report {
    schema: &'static str,
    profile_revision: String,
    payload_revision: String,
    elf: String,
    elf_sha256: String,
    profile_tasks: Vec<ResolvedProfileTask>,
    observed_tasks: Vec<ObservedTask>,
}

#[derive(Debug, Serialize)]
struct ResolvedProfileTask {
    entry_symbol: String,
    address: Option<String>,
    source: String,
    role: String,
    vendor_priority: u8,
}

#[derive(Debug, Serialize)]
struct ObservedTask {
    task_id: Option<u32>,
    entry: String,
    symbol: Option<String>,
    source: Option<String>,
    role: String,
    vendor_priority: Option<u8>,
    runtime: BTreeMap<String, u64>,
}

fn usage() -> ! {
    eprintln!(
        "usage: hisi-rf-link task-profile --elf <ELF> [--log <UART_LOG>] [--entry <ADDR>]..."
    );
    std::process::exit(2);
}

fn parse_u64(value: &str) -> Result<u64, String> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).map_err(|error| format!("invalid address {value}: {error}"))
    } else {
        value
            .parse()
            .map_err(|error| format!("invalid address {value}: {error}"))
    }
}

fn parse_args(mut args: impl Iterator<Item = OsString>) -> Arguments {
    let mut parsed = Arguments::default();
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--help" | "-h") => {
                println!(
                    "Classify observed WS63 RF tasks using the hash-bound scheduling profile.\n\n\
                     usage: hisi-rf-link task-profile --elf <ELF> \
                     [--log <UART_LOG>] [--entry <ADDR>]..."
                );
                std::process::exit(0);
            }
            Some("--elf") => parsed.elf = args.next().map(PathBuf::from),
            Some("--log") => parsed.log = args.next().map(PathBuf::from),
            Some("--entry") => {
                let value = args
                    .next()
                    .and_then(|value| value.into_string().ok())
                    .unwrap_or_else(|| usage());
                parsed
                    .entries
                    .push(parse_u64(&value).unwrap_or_else(|error| {
                        eprintln!("{error}");
                        usage()
                    }));
            }
            _ => usage(),
        }
    }
    if parsed.elf.is_none() {
        usage();
    }
    parsed
}

fn parse_fields(line: &str) -> BTreeMap<String, u64> {
    line.split_ascii_whitespace()
        .filter_map(|field| {
            let (key, value) = field.split_once('=')?;
            parse_u64(value).ok().map(|value| (key.to_owned(), value))
        })
        .collect()
}

fn parse_log(contents: &str) -> Vec<ObservedTaskInput> {
    let mut tasks = BTreeMap::<u32, ObservedTaskInput>::new();
    for line in contents.lines() {
        if let Some(fields) = line.strip_prefix("RFDBG_TASK ").map(parse_fields) {
            let Some(task_id) = fields.get("id").copied().map(|id| id as u32) else {
                continue;
            };
            let Some(entry) = fields.get("entry").copied() else {
                continue;
            };
            tasks.insert(
                task_id,
                ObservedTaskInput {
                    task_id: Some(task_id),
                    entry,
                    runtime: fields,
                },
            );
        } else if let Some(fields) = line.strip_prefix("RFDBG_TASK_METRIC ").map(parse_fields) {
            let Some(task_id) = fields.get("id").copied().map(|id| id as u32) else {
                continue;
            };
            if let Some(task) = tasks.get_mut(&task_id) {
                task.runtime.extend(fields);
            }
        }
    }
    tasks.into_values().collect()
}

fn elf_symbols(path: &Path) -> Result<ElfSymbols, String> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let file = object::File::parse(bytes.as_slice())
        .map_err(|error| format!("parse {}: {error}", path.display()))?;
    let sha256 = format!("{:x}", Sha256::digest(&bytes));
    let mut by_name = BTreeMap::new();
    let mut by_address = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        if symbol.address() == 0 || !symbol.is_definition() {
            continue;
        }
        let Ok(name) = symbol.name() else {
            continue;
        };
        if !seen.insert((symbol.address(), name.to_owned())) {
            continue;
        }
        by_name.entry(name.to_owned()).or_insert(symbol.address());
        by_address
            .entry(symbol.address())
            .or_insert_with(|| name.to_owned());
    }
    Ok(ElfSymbols {
        sha256,
        by_name,
        by_address,
    })
}

fn hex_address(address: u64) -> String {
    format!("0x{address:08x}")
}

fn match_profile_task<'a>(
    symbol: Option<&str>,
    tasks_by_symbol: &'a BTreeMap<String, ProfileTask>,
) -> Option<&'a ProfileTask> {
    symbol.and_then(|symbol| tasks_by_symbol.get(symbol))
}

fn build_report(
    profile: SchedulingProfile,
    elf: &Path,
    mut observed: Vec<ObservedTaskInput>,
) -> Result<Report, String> {
    let symbols = elf_symbols(elf)?;
    let mut tasks_by_symbol = BTreeMap::new();
    let mut profile_symbols_by_address = BTreeMap::new();
    let profile_tasks = profile
        .tasks
        .into_iter()
        .map(|task| {
            let address = symbols
                .by_name
                .get(&task.entry_symbol)
                .copied()
                .or(task.entry_address);
            if let Some(address) = address {
                profile_symbols_by_address.insert(address, task.entry_symbol.clone());
            }
            tasks_by_symbol.insert(task.entry_symbol.clone(), task.clone());
            ResolvedProfileTask {
                entry_symbol: task.entry_symbol,
                address: address.map(hex_address),
                source: task.source,
                role: task.role,
                vendor_priority: task.vendor_priority,
            }
        })
        .collect();

    observed.sort_by_key(|task| (task.task_id.unwrap_or(u32::MAX), task.entry));
    let observed_tasks = observed
        .into_iter()
        .map(|task| {
            let symbol = symbols
                .by_address
                .get(&task.entry)
                .or_else(|| profile_symbols_by_address.get(&task.entry))
                .cloned();
            let matched = match_profile_task(symbol.as_deref(), &tasks_by_symbol);
            ObservedTask {
                task_id: task.task_id,
                entry: hex_address(task.entry),
                symbol,
                source: matched.map(|task| task.source.clone()),
                role: matched
                    .map(|task| task.role.clone())
                    .unwrap_or_else(|| profile.default_role.clone()),
                vendor_priority: matched.map(|task| task.vendor_priority),
                runtime: task.runtime,
            }
        })
        .collect();

    Ok(Report {
        schema: "hisi-rf-link/ws63-task-profile-report/v1",
        profile_revision: profile.revision,
        payload_revision: profile.payload_revision,
        elf: elf.display().to_string(),
        elf_sha256: symbols.sha256,
        profile_tasks,
        observed_tasks,
    })
}

pub(crate) fn run(args: impl Iterator<Item = OsString>) {
    let arguments = parse_args(args);
    let elf = arguments.elf.expect("--elf checked by parse_args");
    let mut observed = arguments
        .entries
        .into_iter()
        .map(|entry| ObservedTaskInput {
            entry,
            ..ObservedTaskInput::default()
        })
        .collect::<Vec<_>>();
    if let Some(log) = arguments.log {
        let contents = fs::read_to_string(&log).unwrap_or_else(|error| {
            eprintln!("read {}: {error}", log.display());
            std::process::exit(1)
        });
        observed.extend(parse_log(&contents));
    }

    let profile: SchedulingProfile =
        toml::from_str(SCHEDULING_PROFILE).expect("parse embedded WS63 scheduling profile");
    let report = build_report(profile, &elf, observed).unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(1)
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize task profile report")
    );
}

#[cfg(test)]
mod tests {
    use super::{ProfileTask, match_profile_task, parse_fields, parse_log, parse_u64};
    use std::collections::BTreeMap;

    #[test]
    fn parses_decimal_and_hex_addresses() {
        assert_eq!(parse_u64("42").unwrap(), 42);
        assert_eq!(parse_u64("0x2a").unwrap(), 42);
    }

    #[test]
    fn parses_task_and_metric_lines() {
        let tasks = parse_log(
            "RFDBG_TASK id=0x00000005 state=0x1 entry=0x00128d4a base_priority=0x5\n\
             RFDBG_TASK_METRIC id=0x00000005 policy=0x0 cpu_ms=0x2a dispatches=0x10\n",
        );
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].task_id, Some(5));
        assert_eq!(tasks[0].entry, 0x0012_8d4a);
        assert_eq!(tasks[0].runtime["cpu_ms"], 42);
        assert_eq!(tasks[0].runtime["dispatches"], 16);
    }

    #[test]
    fn ignores_non_numeric_log_fields() {
        let fields = parse_fields("id=0x2 role=critical broken");
        assert_eq!(fields.len(), 1);
        assert_eq!(fields["id"], 2);
    }

    #[test]
    fn unmatched_symbols_have_no_profile_row() {
        let mut tasks = BTreeMap::new();
        tasks.insert(
            "known".to_owned(),
            ProfileTask {
                entry_symbol: "known".to_owned(),
                entry_address: None,
                source: "fixture".to_owned(),
                role: "worker".to_owned(),
                vendor_priority: 4,
            },
        );
        assert!(match_profile_task(Some("unknown"), &tasks).is_none());
        assert!(match_profile_task(None, &tasks).is_none());
    }
}
