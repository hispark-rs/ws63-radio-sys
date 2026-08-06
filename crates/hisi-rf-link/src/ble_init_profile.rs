//! Rooted WS63 BLE controller/host initialization closure.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    path::Path,
};

use crate::{ble_profile::owner, normalize};

#[derive(Debug, Deserialize)]
struct InitProfile {
    schema_version: u32,
    revision: String,
    b0_profile_revision: String,
    roots: Vec<String>,
    controller_archives: Vec<ControllerArchive>,
    #[serde(default)]
    external_roots: Vec<ExternalRoot>,
    tasks: Vec<Task>,
}

#[derive(Debug, Deserialize)]
struct B0Profile {
    revision: String,
    archives: Vec<B0Archive>,
}

#[derive(Debug, Deserialize)]
struct B0Archive {
    archive: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
struct ControllerArchive {
    archive: String,
    sha256: String,
    role: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
struct ExternalRoot {
    name: String,
    owner: String,
    reason: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
struct Task {
    name: String,
    entry: String,
    stack_bytes: u32,
    vendor_priority: u8,
    owner: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct SelectedMember {
    archive: String,
    member: String,
    selected_by: String,
    defined_symbols: usize,
    undefined_symbols: usize,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct RequiredSymbol {
    name: String,
    owner: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct TaskResources {
    task_count: usize,
    stack_bytes: u32,
    tasks: Vec<Task>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct Report {
    schema_version: u32,
    revision: String,
    b0_profile_revision: String,
    roots: Vec<String>,
    controller_archives: Vec<ControllerArchive>,
    external_roots: Vec<ExternalRoot>,
    selected_members: Vec<SelectedMember>,
    required_symbols: Vec<RequiredSymbol>,
    resources: TaskResources,
}

fn parse_rom_symbols(path: &Path) -> Result<BTreeSet<String>, String> {
    let source = fs::read_to_string(path)
        .map_err(|error| format!("read ROM symbols {}: {error}", path.display()))?;
    Ok(source
        .lines()
        .filter_map(|line| line.split_once('=').map(|(name, _)| name.trim()))
        .filter(|name| !name.is_empty() && !name.starts_with("/*"))
        .map(str::to_owned)
        .collect())
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn generate(
    init_profile_path: &Path,
    b0_profile_path: &Path,
    archive_root: &Path,
    rom_symbols_path: &Path,
) -> Result<Report, String> {
    let init: InitProfile = toml::from_str(
        &fs::read_to_string(init_profile_path)
            .map_err(|error| format!("read {}: {error}", init_profile_path.display()))?,
    )
    .map_err(|error| format!("parse {}: {error}", init_profile_path.display()))?;
    if init.schema_version != 1 {
        return Err(format!(
            "unsupported BLE init schema {}",
            init.schema_version
        ));
    }
    let b0: B0Profile = toml::from_str(
        &fs::read_to_string(b0_profile_path)
            .map_err(|error| format!("read {}: {error}", b0_profile_path.display()))?,
    )
    .map_err(|error| format!("parse {}: {error}", b0_profile_path.display()))?;
    if init.b0_profile_revision != b0.revision {
        return Err(format!(
            "BLE init profile expects B0 {}, found {}",
            init.b0_profile_revision, b0.revision
        ));
    }

    let mut members = Vec::new();
    for archive in &b0.archives {
        members.extend(
            normalize::inspect_archive_member_symbols(&archive_root.join(&archive.archive))
                .map_err(|error| error.to_string())?,
        );
    }
    for archive in &init.controller_archives {
        let path = archive_root.join(&archive.archive);
        let bytes = fs::read(&path).map_err(|error| format!("read {}: {error}", path.display()))?;
        let actual = sha256(&bytes);
        if actual != archive.sha256 {
            return Err(format!(
                "{} SHA-256 {actual}, expected {}",
                path.display(),
                archive.sha256
            ));
        }
        members.extend(
            normalize::inspect_archive_member_symbols(&path).map_err(|error| error.to_string())?,
        );
    }
    let mut providers: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (index, member) in members.iter().enumerate() {
        for symbol in &member.defined_global {
            providers.entry(symbol.clone()).or_default().push(index);
        }
    }

    let external_root_names = init
        .external_roots
        .iter()
        .map(|root| root.name.clone())
        .collect::<BTreeSet<_>>();
    let mut pending = init.roots.iter().cloned().collect::<VecDeque<_>>();
    let mut resolved = BTreeSet::new();
    let mut selected = BTreeSet::new();
    let mut selected_members = Vec::new();
    let mut unresolved = BTreeSet::new();
    while let Some(symbol) = pending.pop_front() {
        if resolved.contains(&symbol) || external_root_names.contains(&symbol) {
            continue;
        }
        let Some(provider) = providers
            .get(&symbol)
            .and_then(|entries| entries.first())
            .copied()
        else {
            unresolved.insert(symbol);
            continue;
        };
        resolved.insert(symbol.clone());
        if !selected.insert(provider) {
            continue;
        }
        let member = &members[provider];
        resolved.extend(member.defined_global.iter().cloned());
        for dependency in &member.undefined_global {
            if !resolved.contains(dependency) && !external_root_names.contains(dependency) {
                pending.push_back(dependency.clone());
            }
        }
        selected_members.push(SelectedMember {
            archive: member.archive.clone(),
            member: member.member.clone(),
            selected_by: symbol,
            defined_symbols: member.defined_global.len(),
            undefined_symbols: member.undefined_global.len(),
        });
    }

    let rom_symbols = parse_rom_symbols(rom_symbols_path)?;
    let mut required_symbols = Vec::new();
    let mut unowned = Vec::new();
    for name in unresolved {
        if let Some(symbol_owner) = owner(&name, &rom_symbols) {
            required_symbols.push(RequiredSymbol {
                name,
                owner: symbol_owner.to_owned(),
            });
        } else {
            unowned.push(name);
        }
    }
    if !unowned.is_empty() {
        return Err(format!(
            "unowned rooted BLE init symbols: {}",
            unowned.join(", ")
        ));
    }

    let task_entries = init
        .tasks
        .iter()
        .map(|task| task.entry.as_str())
        .collect::<BTreeSet<_>>();
    let declared_entries = init
        .roots
        .iter()
        .chain(init.external_roots.iter().map(|root| &root.name))
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if !task_entries.is_subset(&declared_entries) {
        return Err("every BLE task entry must be a rooted or external-root symbol".to_owned());
    }
    let stack_bytes = init.tasks.iter().try_fold(0_u32, |total, task| {
        total
            .checked_add(task.stack_bytes)
            .ok_or_else(|| "BLE task stack budget overflow".to_owned())
    })?;

    Ok(Report {
        schema_version: 1,
        revision: init.revision,
        b0_profile_revision: b0.revision,
        roots: init.roots,
        controller_archives: init.controller_archives,
        external_roots: init.external_roots,
        selected_members,
        required_symbols,
        resources: TaskResources {
            task_count: init.tasks.len(),
            stack_bytes,
            tasks: init.tasks,
        },
    })
}

pub fn write_or_check(
    profile: &Path,
    b0_profile: &Path,
    archive_root: &Path,
    rom_symbols: &Path,
    output: &Path,
    check: bool,
) -> Result<(), String> {
    let report = generate(profile, b0_profile, archive_root, rom_symbols)?;
    let encoded = serde_json::to_vec_pretty(&report)
        .map_err(|error| format!("serialize BLE init profile: {error}"))?;
    if check {
        let expected = fs::read(output)
            .map_err(|error| format!("read committed report {}: {error}", output.display()))?;
        if expected != encoded {
            return Err(format!(
                "{} drifted; regenerate it with the same command without --check",
                output.display()
            ));
        }
        return Ok(());
    }
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    fs::write(output, encoded).map_err(|error| format!("write {}: {error}", output.display()))
}
