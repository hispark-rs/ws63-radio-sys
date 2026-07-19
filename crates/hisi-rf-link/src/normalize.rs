use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt, fs, path::Path};

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const AR_MAGIC: &[u8; 8] = b"!<arch>\n";
const AR_HEADER_SIZE: usize = 60;
const SHT_SYMTAB: u32 = 2;
const SHT_RELA: u32 = 4;
const SHN_UNDEF: u16 = 0;

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
            u32(data, header + 16, context)? as usize,
            u32(data, header + 20, context)? as usize,
            u32(data, header + 24, context)? as usize,
            u32(data, header + 28, context)? as usize,
            u32(data, header + 36, context)? as usize,
        ));
    }

    let names = raw[names_index];
    let names_range = checked_range(data, names.2, names.3, context)?;
    let names_data = &data[names_range];
    raw.into_iter()
        .map(
            |(name, section_type, offset, size, link, info, entry_size)| {
                Ok(Section {
                    name: c_string(names_data, name, context)?,
                    section_type,
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

pub fn inspect_archive(path: &Path) -> Result<ArchiveInventory, Error> {
    let data =
        fs::read(path).map_err(|error| Error::new(format!("read {}: {error}", path.display())))?;
    if data.get(..AR_MAGIC.len()) != Some(AR_MAGIC) {
        return Err(Error::new(format!(
            "{}: expected GNU ar archive",
            path.display()
        )));
    }
    let archive = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("<archive>")
        .to_owned();
    let mut offset = AR_MAGIC.len();
    let mut long_names = Vec::new();
    let mut records = Vec::new();
    while offset < data.len() {
        let header_range = checked_range(&data, offset, AR_HEADER_SIZE, &archive)?;
        let header = &data[header_range];
        if &header[58..60] != b"`\n" {
            return Err(Error::new(format!(
                "{archive}: invalid member header at 0x{offset:x}"
            )));
        }
        let size = parse_decimal(&header[48..58], &archive)?;
        let member_start = offset + AR_HEADER_SIZE;
        let member_range = checked_range(&data, member_start, size, &archive)?;
        let raw_name = String::from_utf8_lossy(&header[..16]).trim().to_owned();
        if raw_name == "//" {
            long_names = data[member_range.clone()].to_vec();
        }
        let member = archive_member_name(&header[..16], &long_names, &archive)?;
        let member_data = &data[member_range];
        if member_data.get(..4) == Some(ELF_MAGIC) {
            records.extend(inspect_object(member_data, &archive, &member)?);
        }
        offset = member_start + size + (size & 1);
    }

    let input_sha256 = Sha256::digest(&data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(ArchiveInventory {
        schema_version: 1,
        archive,
        input_sha256,
        vendor_relocations: records,
    })
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
}
