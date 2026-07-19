use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::Path,
};

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const AR_MAGIC: &[u8; 8] = b"!<arch>\n";
const AR_HEADER_SIZE: usize = 60;
const SHT_SYMTAB: u32 = 2;
const SHT_RELA: u32 = 4;
const SHF_MERGE: u32 = 0x10;
const SHF_STRINGS: u32 = 0x20;
const SHN_UNDEF: u16 = 0;
const R_RISCV_NONE: u32 = 0;
const R_RISCV_32: u32 = 1;
const R_RISCV_RELAX: u32 = 51;

pub const R_RISCV_48_LLUI: u32 = 58;
pub const R_RISCV_BRANCHI: u32 = 59;
pub const R_RISCV_LLUI_REP: u32 = 61;

#[derive(Debug)]
pub struct Error(String);

impl Error {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone)]
struct Section {
    name: String,
    section_type: u32,
    flags: u32,
    address: u32,
    offset: usize,
    size: usize,
    entry_size: usize,
    link: usize,
    info: usize,
}

#[derive(Debug, Clone)]
struct Symbol {
    name: String,
    value: u32,
    section_index: u16,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RelocationRecord {
    pub archive: String,
    pub member: String,
    pub relocation_section: String,
    pub target_section: String,
    pub offset: u32,
    pub relocation_type: u32,
    pub relocation_name: String,
    pub symbol: String,
    pub symbol_section: String,
    pub symbol_value: u32,
    pub addend: i32,
    pub same_section: bool,
    pub debug_section: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveInventory {
    pub schema_version: u32,
    pub archive: String,
    pub input_sha256: String,
    pub vendor_relocations: Vec<RelocationRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelocationSummary {
    pub schema_version: u32,
    pub archives: usize,
    pub total: usize,
    pub by_type: BTreeMap<String, usize>,
    pub branchi_same_section: usize,
    pub branchi_cross_section: usize,
    pub debug: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransformationCounts {
    pub llui48_to_riscv32: usize,
    pub branchi_same_section_encoded: usize,
    pub relax_markers_removed_from_branchi_sections: usize,
    pub llui_rep_markers_removed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedArtifact {
    pub archive: String,
    pub input_sha256: String,
    pub output_sha256: String,
    pub input_size: usize,
    pub output_size: usize,
    pub transformations: TransformationCounts,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizationManifest {
    pub schema_version: u32,
    pub normalizer: String,
    pub profile_revision: String,
    pub artifacts: Vec<NormalizedArtifact>,
}

pub fn summarize(inventories: &[ArchiveInventory]) -> RelocationSummary {
    let mut by_type = BTreeMap::new();
    let mut total = 0;
    let mut branchi_same_section = 0;
    let mut branchi_cross_section = 0;
    let mut debug = 0;
    for relocation in inventories
        .iter()
        .flat_map(|inventory| &inventory.vendor_relocations)
    {
        total += 1;
        *by_type
            .entry(relocation.relocation_name.clone())
            .or_insert(0) += 1;
        if relocation.relocation_type == R_RISCV_BRANCHI {
            if relocation.same_section {
                branchi_same_section += 1;
            } else {
                branchi_cross_section += 1;
            }
        }
        debug += usize::from(relocation.debug_section);
    }
    RelocationSummary {
        schema_version: 1,
        archives: inventories.len(),
        total,
        by_type,
        branchi_same_section,
        branchi_cross_section,
        debug,
    }
}

fn checked_range(
    data: &[u8],
    offset: usize,
    length: usize,
    context: &str,
) -> Result<std::ops::Range<usize>, Error> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| Error::new(format!("{context}: range overflow")))?;
    if end > data.len() {
        return Err(Error::new(format!(
            "{context}: range 0x{offset:x}..0x{end:x} exceeds 0x{:x} bytes",
            data.len()
        )));
    }
    Ok(offset..end)
}

fn u16(data: &[u8], offset: usize, context: &str) -> Result<u16, Error> {
    let range = checked_range(data, offset, 2, context)?;
    Ok(u16::from_le_bytes(data[range].try_into().unwrap()))
}

fn u32(data: &[u8], offset: usize, context: &str) -> Result<u32, Error> {
    let range = checked_range(data, offset, 4, context)?;
    Ok(u32::from_le_bytes(data[range].try_into().unwrap()))
}

fn i32(data: &[u8], offset: usize, context: &str) -> Result<i32, Error> {
    let range = checked_range(data, offset, 4, context)?;
    Ok(i32::from_le_bytes(data[range].try_into().unwrap()))
}

fn put_u32(data: &mut [u8], offset: usize, value: u32, context: &str) -> Result<(), Error> {
    let range = checked_range(data, offset, 4, context)?;
    data[range].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn c_string(data: &[u8], offset: usize, context: &str) -> Result<String, Error> {
    if offset >= data.len() {
        return Err(Error::new(format!(
            "{context}: string offset 0x{offset:x} exceeds table"
        )));
    }
    let end = data[offset..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|relative| offset + relative)
        .unwrap_or(data.len());
    Ok(String::from_utf8_lossy(&data[offset..end]).into_owned())
}

fn parse_sections(data: &[u8], context: &str) -> Result<Vec<Section>, Error> {
    if data.get(..4) != Some(ELF_MAGIC) || data.get(4) != Some(&1) || data.get(5) != Some(&1) {
        return Err(Error::new(format!(
            "{context}: expected ELF32 little-endian object"
        )));
    }

    let section_offset = u32(data, 0x20, context)? as usize;
    let section_entry_size = u16(data, 0x2e, context)? as usize;
    let section_count = u16(data, 0x30, context)? as usize;
    let names_index = u16(data, 0x32, context)? as usize;
    if section_entry_size < 40 {
        return Err(Error::new(format!(
            "{context}: section header is only {section_entry_size} bytes"
        )));
    }
    if names_index >= section_count {
        return Err(Error::new(format!(
            "{context}: section-name table index {names_index} is invalid"
        )));
    }

    let mut raw = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let header =
            section_offset
                .checked_add(index.checked_mul(section_entry_size).ok_or_else(|| {
                    Error::new(format!("{context}: section header offset overflow"))
                })?)
                .ok_or_else(|| Error::new(format!("{context}: section header offset overflow")))?;
        checked_range(data, header, 40, context)?;
        raw.push((
            u32(data, header, context)? as usize,
            u32(data, header + 4, context)?,
            u32(data, header + 8, context)?,
            u32(data, header + 12, context)?,
            u32(data, header + 16, context)? as usize,
            u32(data, header + 20, context)? as usize,
            u32(data, header + 24, context)? as usize,
            u32(data, header + 28, context)? as usize,
            u32(data, header + 36, context)? as usize,
        ));
    }

    let names = raw[names_index];
    let names_range = checked_range(data, names.4, names.5, context)?;
    let names_data = &data[names_range];
    raw.into_iter()
        .map(
            |(name, section_type, flags, address, offset, size, link, info, entry_size)| {
                Ok(Section {
                    name: c_string(names_data, name, context)?,
                    section_type,
                    flags,
                    address,
                    offset,
                    size,
                    entry_size,
                    link,
                    info,
                })
            },
        )
        .collect()
}

fn parse_symbols(
    data: &[u8],
    sections: &[Section],
    symtab_index: usize,
    context: &str,
) -> Result<Vec<Symbol>, Error> {
    let symtab = sections
        .get(symtab_index)
        .ok_or_else(|| Error::new(format!("{context}: invalid symbol table index")))?;
    if symtab.section_type != SHT_SYMTAB || symtab.entry_size < 16 {
        return Err(Error::new(format!(
            "{context}: relocation does not reference an ELF32 symbol table"
        )));
    }
    let strings = sections
        .get(symtab.link)
        .ok_or_else(|| Error::new(format!("{context}: invalid symbol string table")))?;
    let strings_range = checked_range(data, strings.offset, strings.size, context)?;
    let strings_data = &data[strings_range];
    checked_range(data, symtab.offset, symtab.size, context)?;

    let count = symtab.size / symtab.entry_size;
    let mut symbols = Vec::with_capacity(count);
    for index in 0..count {
        let offset = symtab.offset + index * symtab.entry_size;
        symbols.push(Symbol {
            name: c_string(strings_data, u32(data, offset, context)? as usize, context)?,
            value: u32(data, offset + 4, context)?,
            section_index: u16(data, offset + 14, context)?,
        });
    }
    Ok(symbols)
}

fn relocation_name(relocation_type: u32) -> String {
    match relocation_type {
        R_RISCV_48_LLUI => "R_RISCV_48_LLUI".to_owned(),
        R_RISCV_BRANCHI => "R_RISCV_BRANCHI".to_owned(),
        R_RISCV_LLUI_REP => "R_RISCV_LLUI_REP".to_owned(),
        other => format!("R_RISCV_VENDOR_{other}"),
    }
}

fn inspect_object(
    data: &[u8],
    archive: &str,
    member: &str,
) -> Result<Vec<RelocationRecord>, Error> {
    let context = format!("{archive}({member})");
    let sections = parse_sections(data, &context)?;
    let mut records = Vec::new();
    for relocation_section in sections
        .iter()
        .filter(|section| section.section_type == SHT_RELA)
    {
        let target = sections.get(relocation_section.info).ok_or_else(|| {
            Error::new(format!(
                "{context}: {} has invalid target section",
                relocation_section.name
            ))
        })?;
        let symbols = parse_symbols(data, &sections, relocation_section.link, &context)?;
        let entry_size = if relocation_section.entry_size == 0 {
            12
        } else {
            relocation_section.entry_size
        };
        if entry_size < 12 || relocation_section.size % entry_size != 0 {
            return Err(Error::new(format!(
                "{context}: {} has invalid RELA entry size",
                relocation_section.name
            )));
        }
        checked_range(
            data,
            relocation_section.offset,
            relocation_section.size,
            &context,
        )?;
        for index in 0..relocation_section.size / entry_size {
            let entry = relocation_section.offset + index * entry_size;
            let info = u32(data, entry + 4, &context)?;
            let relocation_type = info & 0xff;
            if !matches!(
                relocation_type,
                R_RISCV_48_LLUI | R_RISCV_BRANCHI | R_RISCV_LLUI_REP
            ) && relocation_type < 58
            {
                continue;
            }
            let symbol_index = (info >> 8) as usize;
            let symbol = symbols.get(symbol_index).ok_or_else(|| {
                Error::new(format!(
                    "{context}: {} relocation references symbol {symbol_index}",
                    relocation_section.name
                ))
            })?;
            let symbol_section = if symbol.section_index == SHN_UNDEF {
                "UND".to_owned()
            } else {
                sections
                    .get(symbol.section_index as usize)
                    .map(|section| section.name.clone())
                    .unwrap_or_else(|| format!("SHN_{:x}", symbol.section_index))
            };
            records.push(RelocationRecord {
                archive: archive.to_owned(),
                member: member.to_owned(),
                relocation_section: relocation_section.name.clone(),
                target_section: target.name.clone(),
                offset: u32(data, entry, &context)?,
                relocation_type,
                relocation_name: relocation_name(relocation_type),
                symbol: symbol.name.clone(),
                symbol_section: symbol_section.clone(),
                symbol_value: symbol.value,
                addend: i32(data, entry + 8, &context)?,
                same_section: symbol_section == target.name,
                debug_section: target.name.starts_with(".debug"),
            });
        }
    }
    Ok(records)
}

fn encode_branchi(word: u32, offset: i64, context: &str) -> Result<u32, Error> {
    if offset & 1 != 0 {
        return Err(Error::new(format!(
            "{context}: R_RISCV_BRANCHI displacement {offset} is not halfword aligned"
        )));
    }
    if !(-0x200..=0x1fe).contains(&offset) {
        return Err(Error::new(format!(
            "{context}: R_RISCV_BRANCHI displacement {offset} is out of range"
        )));
    }
    let encoded = (offset as i32 as u32) & 0x3ff;
    let immediate_mask = 0x00f0_0f80;
    let immediate = ((encoded & 0x03e) << 6) | ((encoded & 0x3c0) << 14);
    Ok((word & !immediate_mask) | immediate)
}

fn normalize_object(
    data: &mut [u8],
    archive: &str,
    member: &str,
) -> Result<TransformationCounts, Error> {
    let context = format!("{archive}({member})");
    let sections = parse_sections(data, &context)?;
    let mut branchi_sections = BTreeSet::new();
    for relocation_section in sections
        .iter()
        .filter(|section| section.section_type == SHT_RELA)
    {
        let entry_size = if relocation_section.entry_size == 0 {
            12
        } else {
            relocation_section.entry_size
        };
        if entry_size < 12 || relocation_section.size % entry_size != 0 {
            return Err(Error::new(format!(
                "{context}: {} has invalid RELA entry size",
                relocation_section.name
            )));
        }
        for index in 0..relocation_section.size / entry_size {
            let entry = relocation_section.offset + index * entry_size;
            if u32(data, entry + 4, &context)? & 0xff == R_RISCV_BRANCHI {
                branchi_sections.insert(relocation_section.info);
            }
        }
    }
    let mut counts = TransformationCounts {
        llui48_to_riscv32: 0,
        branchi_same_section_encoded: 0,
        relax_markers_removed_from_branchi_sections: 0,
        llui_rep_markers_removed: 0,
    };
    for relocation_section in sections
        .iter()
        .filter(|section| section.section_type == SHT_RELA)
    {
        let target = sections.get(relocation_section.info).ok_or_else(|| {
            Error::new(format!(
                "{context}: {} has invalid target section",
                relocation_section.name
            ))
        })?;
        let symbols = parse_symbols(data, &sections, relocation_section.link, &context)?;
        let entry_size = if relocation_section.entry_size == 0 {
            12
        } else {
            relocation_section.entry_size
        };
        if entry_size < 12 || relocation_section.size % entry_size != 0 {
            return Err(Error::new(format!(
                "{context}: {} has invalid RELA entry size",
                relocation_section.name
            )));
        }
        for index in 0..relocation_section.size / entry_size {
            let entry = relocation_section.offset + index * entry_size;
            let relocation_offset = u32(data, entry, &context)?;
            let info = u32(data, entry + 4, &context)?;
            let relocation_type = info & 0xff;
            let symbol_index = (info >> 8) as usize;
            let addend = i32(data, entry + 8, &context)?;

            match relocation_type {
                R_RISCV_48_LLUI => {
                    let relocated_offset = relocation_offset.checked_add(2).ok_or_else(|| {
                        Error::new(format!("{context}: R_RISCV_48_LLUI offset overflow"))
                    })?;
                    let write_end = relocated_offset.checked_add(4).ok_or_else(|| {
                        Error::new(format!("{context}: R_RISCV_48_LLUI range overflow"))
                    })?;
                    if write_end as usize > target.size {
                        return Err(Error::new(format!(
                            "{context}: R_RISCV_48_LLUI at {}+0x{relocation_offset:x} exceeds its target section",
                            target.name
                        )));
                    }
                    put_u32(data, entry, relocated_offset, &context)?;
                    put_u32(data, entry + 4, (info & !0xff) | R_RISCV_32, &context)?;
                    counts.llui48_to_riscv32 += 1;
                }
                R_RISCV_BRANCHI => {
                    let symbol = symbols.get(symbol_index).ok_or_else(|| {
                        Error::new(format!(
                            "{context}: R_RISCV_BRANCHI references symbol {symbol_index}"
                        ))
                    })?;
                    if symbol.section_index as usize != relocation_section.info {
                        let symbol_section = if symbol.section_index == SHN_UNDEF {
                            "UND".to_owned()
                        } else {
                            sections
                                .get(symbol.section_index as usize)
                                .map(|section| section.name.clone())
                                .unwrap_or_else(|| format!("SHN_{:x}", symbol.section_index))
                        };
                        return Err(Error::new(format!(
                            "{context}: cross-section R_RISCV_BRANCHI at {}+0x{relocation_offset:x} targets {} ({symbol_section}); no standard fixed-size conversion is declared",
                            target.name, symbol.name
                        )));
                    }
                    let instruction_offset = target
                        .offset
                        .checked_add(relocation_offset as usize)
                        .ok_or_else(|| Error::new(format!("{context}: branch offset overflow")))?;
                    let word = u32(data, instruction_offset, &context)?;
                    let displacement =
                        i64::from(symbol.value) + i64::from(addend) - i64::from(relocation_offset);
                    let encoded = encode_branchi(word, displacement, &context)?;
                    put_u32(data, instruction_offset, encoded, &context)?;
                    put_u32(data, entry + 4, (info & !0xff) | R_RISCV_NONE, &context)?;
                    counts.branchi_same_section_encoded += 1;
                }
                R_RISCV_LLUI_REP => {
                    if symbol_index != 0 || addend != 0 {
                        return Err(Error::new(format!(
                            "{context}: R_RISCV_LLUI_REP at {}+0x{relocation_offset:x} is not the proven zero-symbol/zero-addend marker form",
                            target.name
                        )));
                    }
                    let instruction_end = relocation_offset.checked_add(6).ok_or_else(|| {
                        Error::new(format!("{context}: R_RISCV_LLUI_REP range overflow"))
                    })?;
                    if instruction_end as usize > target.size {
                        return Err(Error::new(format!(
                            "{context}: R_RISCV_LLUI_REP at {}+0x{relocation_offset:x} exceeds its target section",
                            target.name
                        )));
                    }
                    put_u32(data, entry + 4, (info & !0xff) | R_RISCV_NONE, &context)?;
                    counts.llui_rep_markers_removed += 1;
                }
                R_RISCV_RELAX if branchi_sections.contains(&relocation_section.info) => {
                    put_u32(data, entry + 4, (info & !0xff) | R_RISCV_NONE, &context)?;
                    counts.relax_markers_removed_from_branchi_sections += 1;
                }
                60 => {
                    return Err(Error::new(format!(
                        "{context}: undeclared vendor relocation type 60 at {}+0x{relocation_offset:x}",
                        target.name
                    )));
                }
                _ => {}
            }
        }
    }
    Ok(counts)
}

fn parse_decimal(field: &[u8], context: &str) -> Result<usize, Error> {
    let text = std::str::from_utf8(field)
        .map_err(|_| Error::new(format!("{context}: invalid archive decimal field")))?
        .trim();
    text.parse()
        .map_err(|_| Error::new(format!("{context}: invalid archive decimal value {text:?}")))
}

fn archive_member_name(field: &[u8], long_names: &[u8], context: &str) -> Result<String, Error> {
    let raw = String::from_utf8_lossy(field).trim().to_owned();
    if raw == "/" || raw == "//" || raw.starts_with("#1/") {
        return Ok(raw);
    }
    if let Some(offset) = raw.strip_prefix('/') {
        let offset = offset
            .parse::<usize>()
            .map_err(|_| Error::new(format!("{context}: invalid GNU long name {raw}")))?;
        if offset >= long_names.len() {
            return Err(Error::new(format!(
                "{context}: GNU long-name offset {offset} is invalid"
            )));
        }
        let end = long_names[offset..]
            .windows(2)
            .position(|window| window == b"/\n")
            .map(|relative| offset + relative)
            .unwrap_or(long_names.len());
        return Ok(String::from_utf8_lossy(&long_names[offset..end]).into_owned());
    }
    Ok(raw.strip_suffix('/').unwrap_or(&raw).to_owned())
}

fn archive_members(data: &[u8], archive: &str) -> Result<Vec<(String, usize, usize)>, Error> {
    if data.get(..AR_MAGIC.len()) != Some(AR_MAGIC) {
        return Err(Error::new(format!("{archive}: expected GNU ar archive")));
    }
    let mut offset = AR_MAGIC.len();
    let mut long_names = Vec::new();
    let mut members = Vec::new();
    while offset < data.len() {
        let header_range = checked_range(data, offset, AR_HEADER_SIZE, archive)?;
        let header = &data[header_range];
        if &header[58..60] != b"`\n" {
            return Err(Error::new(format!(
                "{archive}: invalid member header at 0x{offset:x}"
            )));
        }
        let size = parse_decimal(&header[48..58], archive)?;
        let member_start = offset + AR_HEADER_SIZE;
        let member_range = checked_range(data, member_start, size, archive)?;
        let raw_name = String::from_utf8_lossy(&header[..16]).trim().to_owned();
        if raw_name == "//" {
            long_names = data[member_range.clone()].to_vec();
        }
        let member = archive_member_name(&header[..16], &long_names, archive)?;
        members.push((member, member_range.start, member_range.end));
        offset = member_start + size + (size & 1);
    }
    Ok(members)
}

fn sha256(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn inspect_archive(path: &Path) -> Result<ArchiveInventory, Error> {
    let data =
        fs::read(path).map_err(|error| Error::new(format!("read {}: {error}", path.display())))?;
    let archive = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("<archive>")
        .to_owned();
    let mut records = Vec::new();
    for (member, start, end) in archive_members(&data, &archive)? {
        let member_data = &data[start..end];
        if member_data.get(..4) == Some(ELF_MAGIC) {
            records.extend(inspect_object(member_data, &archive, &member)?);
        }
    }
    Ok(ArchiveInventory {
        schema_version: 1,
        archive,
        input_sha256: sha256(&data),
        vendor_relocations: records,
    })
}

pub fn normalize_archive(input: &Path, output: &Path) -> Result<NormalizedArtifact, Error> {
    let mut data = fs::read(input)
        .map_err(|error| Error::new(format!("read {}: {error}", input.display())))?;
    let input_sha256 = sha256(&data);
    let input_size = data.len();
    let archive = input
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::new(format!("{}: archive name is not UTF-8", input.display())))?
        .to_owned();
    let members = archive_members(&data, &archive)?;
    let mut transformations = TransformationCounts {
        llui48_to_riscv32: 0,
        branchi_same_section_encoded: 0,
        relax_markers_removed_from_branchi_sections: 0,
        llui_rep_markers_removed: 0,
    };
    for (member, start, end) in members {
        if data[start..end].get(..4) != Some(ELF_MAGIC) {
            continue;
        }
        let counts = normalize_object(&mut data[start..end], &archive, &member)?;
        transformations.llui48_to_riscv32 += counts.llui48_to_riscv32;
        transformations.branchi_same_section_encoded += counts.branchi_same_section_encoded;
        transformations.relax_markers_removed_from_branchi_sections +=
            counts.relax_markers_removed_from_branchi_sections;
        transformations.llui_rep_markers_removed += counts.llui_rep_markers_removed;
    }
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| Error::new(format!("create {}: {error}", parent.display())))?;
    }
    fs::write(output, &data)
        .map_err(|error| Error::new(format!("write {}: {error}", output.display())))?;
    Ok(NormalizedArtifact {
        archive,
        input_sha256,
        output_sha256: sha256(&data),
        input_size,
        output_size: data.len(),
        transformations,
    })
}

pub fn verify_normalized_archive(path: &Path, expected: &NormalizedArtifact) -> Result<(), Error> {
    let data =
        fs::read(path).map_err(|error| Error::new(format!("read {}: {error}", path.display())))?;
    if data.len() != expected.output_size {
        return Err(Error::new(format!(
            "{}: size {}, expected {}",
            path.display(),
            data.len(),
            expected.output_size
        )));
    }
    let actual_hash = sha256(&data);
    if actual_hash != expected.output_sha256 {
        return Err(Error::new(format!(
            "{}: SHA-256 {}, expected {}",
            path.display(),
            actual_hash,
            expected.output_sha256
        )));
    }
    let inventory = inspect_archive(path)?;
    if let Some(relocation) = inventory.vendor_relocations.first() {
        return Err(Error::new(format!(
            "{}: vendor relocation {} remains in {}({}) {}+0x{:x}",
            path.display(),
            relocation.relocation_name,
            relocation.archive,
            relocation.member,
            relocation.target_section,
            relocation.offset
        )));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct GuardedSite {
    relocation: String,
    rel_vma: u32,
    imm32: Option<u32>,
    instruction: Option<u32>,
    archive: String,
    member: String,
    section: String,
    symbol: String,
    symbol_shndx: u16,
    symbol_value: u32,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GuardedParity {
    pub llui48_exact: usize,
    pub llui48_merged_string_equivalent: usize,
    pub llui48_legacy_merged_string_corrections: usize,
    pub branchi_exact: usize,
}

fn bytes_at_vma<'a>(
    elf: &'a [u8],
    sections: &[Section],
    address: u32,
    length: usize,
    context: &str,
) -> Result<&'a [u8], Error> {
    for section in sections.iter().filter(|section| section.flags & 0x2 != 0) {
        let Some(relative) = address.checked_sub(section.address) else {
            continue;
        };
        let Some(relative_end) = relative.checked_add(length as u32) else {
            continue;
        };
        if relative_end as usize > section.size {
            continue;
        }
        let offset = section
            .offset
            .checked_add(relative as usize)
            .ok_or_else(|| Error::new(format!("{context}: ELF offset overflow")))?;
        let range = checked_range(elf, offset, length, context)?;
        return Ok(&elf[range]);
    }
    Err(Error::new(format!(
        "{context}: address 0x{address:08x} is not in an allocated ELF section"
    )))
}

fn source_merged_string(
    archive_directory: &Path,
    site: &GuardedSite,
    context: &str,
) -> Result<Vec<u8>, Error> {
    let archive_path = archive_directory.join(&site.archive);
    let archive = fs::read(&archive_path)
        .map_err(|error| Error::new(format!("read {}: {error}", archive_path.display())))?;
    let members = archive_members(&archive, &site.archive)?;
    let (_, start, end) = members
        .into_iter()
        .find(|(member, _, _)| member == &site.member)
        .ok_or_else(|| {
            Error::new(format!(
                "{context}: member {} is missing from {}",
                site.member,
                archive_path.display()
            ))
        })?;
    let object = &archive[start..end];
    let sections = parse_sections(object, context)?;
    let section = sections
        .get(site.symbol_shndx as usize)
        .ok_or_else(|| Error::new(format!("{context}: invalid symbol section index")))?;
    if section.flags & (SHF_MERGE | SHF_STRINGS) != SHF_MERGE | SHF_STRINGS {
        return Err(Error::new(format!(
            "{context}: {} points to {}, which is not a mergeable string section",
            site.symbol, section.name
        )));
    }
    let value = site.symbol_value as usize;
    if value >= section.size {
        return Err(Error::new(format!(
            "{context}: {} value 0x{value:x} exceeds {}",
            site.symbol, section.name
        )));
    }
    let source_offset = section
        .offset
        .checked_add(value)
        .ok_or_else(|| Error::new(format!("{context}: source string offset overflow")))?;
    let source = &object[checked_range(object, source_offset, section.size - value, context)?];
    let length = source
        .iter()
        .position(|byte| *byte == 0)
        .map(|index| index + 1)
        .ok_or_else(|| Error::new(format!("{context}: {} is not NUL terminated", site.symbol)))?;
    Ok(source[..length].to_vec())
}

pub fn verify_guarded_sites(
    manifest: &Path,
    final_elf: &Path,
    archive_directory: &Path,
) -> Result<GuardedParity, Error> {
    let elf = fs::read(final_elf)
        .map_err(|error| Error::new(format!("read {}: {error}", final_elf.display())))?;
    let sections = parse_sections(&elf, &final_elf.display().to_string())?;
    let manifest_text = fs::read_to_string(manifest)
        .map_err(|error| Error::new(format!("read {}: {error}", manifest.display())))?;
    let mut parity = GuardedParity {
        llui48_exact: 0,
        llui48_merged_string_equivalent: 0,
        llui48_legacy_merged_string_corrections: 0,
        branchi_exact: 0,
    };
    for (line_index, line) in manifest_text.lines().enumerate() {
        let site: GuardedSite = serde_json::from_str(line).map_err(|error| {
            Error::new(format!(
                "parse {} line {}: {error}",
                manifest.display(),
                line_index + 1
            ))
        })?;
        let context = format!(
            "{} line {} {}({}) {}",
            manifest.display(),
            line_index + 1,
            site.archive,
            site.member,
            site.section
        );
        match site.relocation.as_str() {
            "R_RISCV_48_LLUI" => {
                let expected = site
                    .imm32
                    .ok_or_else(|| Error::new(format!("{context}: missing imm32")))?;
                let address = site
                    .rel_vma
                    .checked_add(2)
                    .ok_or_else(|| Error::new(format!("{context}: relocation address overflow")))?;
                let actual = u32::from_le_bytes(
                    bytes_at_vma(&elf, &sections, address, 4, &context)?
                        .try_into()
                        .unwrap(),
                );
                if actual == expected {
                    parity.llui48_exact += 1;
                    continue;
                }
                let source = source_merged_string(archive_directory, &site, &context)?;
                let normalized = bytes_at_vma(&elf, &sections, actual, source.len(), &context)?;
                if normalized != source {
                    return Err(Error::new(format!(
                        "{context}: normalized R58 target 0x{actual:08x} does not contain the source mergeable string"
                    )));
                }
                let guarded = bytes_at_vma(&elf, &sections, expected, source.len(), &context)?;
                if guarded == source {
                    parity.llui48_merged_string_equivalent += 1;
                } else {
                    parity.llui48_legacy_merged_string_corrections += 1;
                }
            }
            "R_RISCV_BRANCHI" => {
                let expected = site
                    .instruction
                    .ok_or_else(|| Error::new(format!("{context}: missing branch instruction")))?;
                let actual = u32::from_le_bytes(
                    bytes_at_vma(&elf, &sections, site.rel_vma, 4, &context)?
                        .try_into()
                        .unwrap(),
                );
                if actual != expected {
                    return Err(Error::new(format!(
                        "{context}: normalized R59 encoded 0x{actual:08x}, guarded lane encoded 0x{expected:08x}"
                    )));
                }
                parity.branchi_exact += 1;
            }
            relocation => {
                return Err(Error::new(format!(
                    "{context}: undeclared guarded relocation {relocation}"
                )));
            }
        }
    }
    let llui48 = parity.llui48_exact
        + parity.llui48_merged_string_equivalent
        + parity.llui48_legacy_merged_string_corrections;
    if llui48 == 0 || parity.branchi_exact == 0 {
        return Err(Error::new(format!(
            "{}: expected both R58 and R59 guarded sites, found R58={llui48} R59={}",
            manifest.display(),
            parity.branchi_exact
        )));
    }
    Ok(parity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_name_constants_are_stable() {
        assert_eq!(relocation_name(R_RISCV_48_LLUI), "R_RISCV_48_LLUI");
        assert_eq!(relocation_name(R_RISCV_BRANCHI), "R_RISCV_BRANCHI");
        assert_eq!(relocation_name(R_RISCV_LLUI_REP), "R_RISCV_LLUI_REP");
    }

    #[test]
    fn summary_distinguishes_branch_scope() {
        let relocation = |same_section| RelocationRecord {
            archive: "lib.a".to_owned(),
            member: "a.o".to_owned(),
            relocation_section: ".rela.text".to_owned(),
            target_section: ".text".to_owned(),
            offset: 0,
            relocation_type: R_RISCV_BRANCHI,
            relocation_name: relocation_name(R_RISCV_BRANCHI),
            symbol: ".L1".to_owned(),
            symbol_section: if same_section { ".text" } else { ".other" }.to_owned(),
            symbol_value: 4,
            addend: 0,
            same_section,
            debug_section: false,
        };
        let inventory = ArchiveInventory {
            schema_version: 1,
            archive: "lib.a".to_owned(),
            input_sha256: "00".repeat(32),
            vendor_relocations: vec![relocation(true), relocation(false)],
        };
        let summary = summarize(&[inventory]);
        assert_eq!(summary.branchi_same_section, 1);
        assert_eq!(summary.branchi_cross_section, 1);
    }

    #[test]
    fn branchi_encoding_checks_range_and_alignment() {
        let instruction = 0x0105_89bb;
        assert_eq!(
            encode_branchi(instruction, 0, "test").unwrap(),
            instruction & !0x00f0_0f80
        );
        assert!(encode_branchi(instruction, 1, "test").is_err());
        assert!(encode_branchi(instruction, 0x200, "test").is_err());
        assert!(encode_branchi(instruction, -0x202, "test").is_err());
    }
}
