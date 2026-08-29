//! Deterministic offline generation from vendored Unicode 16.0.0 inputs.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::protocol::write_atomic_if_changed;

const INPUT_ROOT: &str = "third_party/unicode/16.0.0";
const OUTPUT_PATH: &str = "crates/gantry-core/src/generated/unicode.rs";

const DATA_FILES: &[&str] = &[
    "security/IdentifierStatus.txt",
    "security/IdentifierType.txt",
    "security/confusables.txt",
    "ucd/CompositionExclusions.txt",
    "ucd/DerivedAge.txt",
    "ucd/DerivedCoreProperties.txt",
    "ucd/DerivedNormalizationProps.txt",
    "ucd/NormalizationTest.txt",
    "ucd/PropList.txt",
    "ucd/PropertyValueAliases.txt",
    "ucd/ReadMe.txt",
    "ucd/ScriptExtensions.txt",
    "ucd/Scripts.txt",
    "ucd/SpecialCasing.txt",
    "ucd/UnicodeData.txt",
];

const ALL_FILES: &[&str] = &[
    "LICENSE",
    "SHA256SUMS",
    "SOURCES",
    "security/IdentifierStatus.txt",
    "security/IdentifierType.txt",
    "security/confusables.txt",
    "ucd/CompositionExclusions.txt",
    "ucd/DerivedAge.txt",
    "ucd/DerivedCoreProperties.txt",
    "ucd/DerivedNormalizationProps.txt",
    "ucd/NormalizationTest.txt",
    "ucd/PropList.txt",
    "ucd/PropertyValueAliases.txt",
    "ucd/ReadMe.txt",
    "ucd/ScriptExtensions.txt",
    "ucd/Scripts.txt",
    "ucd/SpecialCasing.txt",
    "ucd/UnicodeData.txt",
];

#[derive(Clone, Debug)]
struct UnicodeTables {
    xid_start: Vec<(u32, u32)>,
    xid_continue: Vec<(u32, u32)>,
    cased: Vec<(u32, u32)>,
    case_ignorable: Vec<(u32, u32)>,
    default_ignorable: Vec<(u32, u32)>,
    white_space: Vec<(u32, u32)>,
    join_control: Vec<(u32, u32)>,
    variation_selector: Vec<(u32, u32)>,
    bidi_control: Vec<(u32, u32)>,
    identifier_allowed: Vec<(u32, u32)>,
    identifier_recommended: Vec<(u32, u32)>,
    combining_classes: Vec<(u32, u32, u8)>,
    decompositions: Vec<(u32, Vec<u32>)>,
    compositions: Vec<(u32, u32, u32)>,
    lower: Vec<(u32, Vec<u32>)>,
    upper: Vec<(u32, Vec<u32>)>,
    scripts: Vec<(String, String)>,
    script_ranges: Vec<(u32, u32, u16)>,
    script_extensions: Vec<(u32, u32, Vec<u16>)>,
    confusables: Vec<(u32, Vec<u32>)>,
}

/// Generates the checked-in Unicode 16 runtime tables.
pub(crate) fn generate(root: &Path) -> Result<(), String> {
    let output = build_output(root)?;
    let changed = write_atomic_if_changed(&root.join(OUTPUT_PATH), output.as_bytes())?;
    if changed {
        println!("generated {OUTPUT_PATH}");
    } else {
        println!("Unicode tables are already current");
    }
    Ok(())
}

/// Checks the vendored input set, hashes, and generated output without writing.
pub(crate) fn check_generated(root: &Path) -> Result<(), String> {
    let expected = build_output(root)?;
    let path = root.join(OUTPUT_PATH);
    let actual =
        fs::read(&path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    if actual != expected.as_bytes() {
        return Err(format!(
            "{OUTPUT_PATH} is stale; run `cargo run --locked -p xtask -- generate unicode`"
        ));
    }
    println!("generated Unicode tables are current");
    Ok(())
}

fn build_output(root: &Path) -> Result<String, String> {
    let input_root = root.join(INPUT_ROOT);
    verify_input_set(&input_root)?;
    verify_hashes(&input_root)?;
    verify_versions(&input_root)?;
    let tables = load_tables(&input_root)?;
    render(&tables)
}

fn verify_input_set(root: &Path) -> Result<(), String> {
    let mut actual = Vec::new();
    collect_files(root, root, &mut actual)?;
    actual.sort();
    let expected = ALL_FILES
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    if actual != expected {
        return Err(format!(
            "Unicode input set differs: expected {expected:?}, found {actual:?}"
        ));
    }
    Ok(())
}

fn collect_files(root: &Path, directory: &Path, output: &mut Vec<String>) -> Result<(), String> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("could not read {}: {error}", directory.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("could not read directory entry: {error}"))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("could not inspect {}: {error}", path.display()))?;
        if file_type.is_dir() {
            collect_files(root, &path, output)?;
        } else if file_type.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| format!("{} is outside Unicode root", path.display()))?;
            output.push(relative.to_string_lossy().replace('\\', "/"));
        } else {
            return Err(format!(
                "unexpected non-file Unicode input {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn verify_hashes(root: &Path) -> Result<(), String> {
    let manifest = read_text(&root.join("SHA256SUMS"))?;
    let mut entries = BTreeMap::new();
    for (index, line) in manifest.lines().enumerate() {
        let (digest, path) = line
            .split_once("  ")
            .ok_or_else(|| format!("malformed SHA256SUMS line {}", index + 1))?;
        validate_digest(digest)?;
        if entries.insert(path, digest).is_some() {
            return Err(format!("duplicate Unicode checksum entry {path}"));
        }
    }
    let expected = DATA_FILES.iter().copied().collect::<BTreeSet<_>>();
    let actual = entries.keys().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(format!(
            "Unicode checksum entries differ: expected {expected:?}, found {actual:?}"
        ));
    }
    for (relative, expected_digest) in entries {
        let bytes = fs::read(root.join(relative))
            .map_err(|error| format!("could not read Unicode input {relative}: {error}"))?;
        let actual_digest = format!("{:x}", Sha256::digest(bytes));
        if actual_digest != expected_digest {
            return Err(format!("Unicode input hash mismatch for {relative}"));
        }
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(format!("invalid lowercase SHA-256 {value:?}"));
    }
    Ok(())
}

fn verify_versions(root: &Path) -> Result<(), String> {
    let readme = read_text(&root.join("ucd/ReadMe.txt"))?;
    if !readme.contains("Version 16.0.0 of the Unicode Standard") {
        return Err("Unicode UCD ReadMe does not identify version 16.0.0".to_owned());
    }
    for relative in [
        "security/confusables.txt",
        "security/IdentifierStatus.txt",
        "security/IdentifierType.txt",
    ] {
        let text = read_text(&root.join(relative))?;
        if !text.contains("# Version: 16.0.0") {
            return Err(format!("{relative} does not identify version 16.0.0"));
        }
    }
    Ok(())
}

fn load_tables(root: &Path) -> Result<UnicodeTables, String> {
    let core = read_text(&root.join("ucd/DerivedCoreProperties.txt"))?;
    let props = read_text(&root.join("ucd/PropList.txt"))?;
    let status = read_text(&root.join("security/IdentifierStatus.txt"))?;
    let identifier_type = read_text(&root.join("security/IdentifierType.txt"))?;
    let aliases = parse_script_aliases(&read_text(&root.join("ucd/PropertyValueAliases.txt"))?)?;
    let script_index = aliases
        .iter()
        .enumerate()
        .flat_map(|(index, (short, long))| {
            [(short.clone(), index as u16), (long.clone(), index as u16)]
        })
        .collect::<BTreeMap<_, _>>();
    let unicode_data = parse_unicode_data(&read_text(&root.join("ucd/UnicodeData.txt"))?)?;
    let exclusions = parse_property(
        &read_text(&root.join("ucd/DerivedNormalizationProps.txt"))?,
        "Full_Composition_Exclusion",
    )?;
    let exclusion_set = expand_ranges(&exclusions);
    let mut lower = unicode_data.lower;
    let mut upper = unicode_data.upper;
    apply_special_casing(
        &read_text(&root.join("ucd/SpecialCasing.txt"))?,
        &mut lower,
        &mut upper,
    )?;
    let compositions = build_compositions(&unicode_data.decompositions, &exclusion_set);
    Ok(UnicodeTables {
        xid_start: parse_property(&core, "XID_Start")?,
        xid_continue: parse_property(&core, "XID_Continue")?,
        cased: parse_property(&core, "Cased")?,
        case_ignorable: parse_property(&core, "Case_Ignorable")?,
        default_ignorable: parse_property(&core, "Default_Ignorable_Code_Point")?,
        white_space: parse_property(&props, "White_Space")?,
        join_control: parse_property(&props, "Join_Control")?,
        variation_selector: parse_property(&props, "Variation_Selector")?,
        bidi_control: parse_property(&props, "Bidi_Control")?,
        identifier_allowed: parse_property(&status, "Allowed")?,
        identifier_recommended: parse_property(&identifier_type, "Recommended")?,
        combining_classes: compress_values(unicode_data.combining_classes),
        decompositions: unicode_data.decompositions.into_iter().collect(),
        compositions,
        lower: lower.into_iter().collect(),
        upper: upper.into_iter().collect(),
        scripts: aliases,
        script_ranges: parse_script_ranges(
            &read_text(&root.join("ucd/Scripts.txt"))?,
            &script_index,
        )?,
        script_extensions: parse_script_extensions(
            &read_text(&root.join("ucd/ScriptExtensions.txt"))?,
            &script_index,
        )?,
        confusables: parse_confusables(&read_text(&root.join("security/confusables.txt"))?)?,
    })
}

struct UnicodeData {
    combining_classes: Vec<(u32, u8)>,
    decompositions: BTreeMap<u32, Vec<u32>>,
    lower: BTreeMap<u32, Vec<u32>>,
    upper: BTreeMap<u32, Vec<u32>>,
}

fn parse_unicode_data(text: &str) -> Result<UnicodeData, String> {
    let mut combining_classes = Vec::new();
    let mut decompositions = BTreeMap::new();
    let mut lower = BTreeMap::new();
    let mut upper = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let fields = line.split(';').collect::<Vec<_>>();
        if fields.len() != 15 {
            return Err(format!(
                "UnicodeData line {} has {} fields",
                index + 1,
                fields.len()
            ));
        }
        let code = parse_hex(fields[0])?;
        let ccc = fields[3]
            .parse::<u8>()
            .map_err(|_| format!("invalid combining class on UnicodeData line {}", index + 1))?;
        if ccc != 0 {
            combining_classes.push((code, ccc));
        }
        let decomposition = fields[5].trim();
        if !decomposition.is_empty() && !decomposition.starts_with('<') {
            decompositions.insert(code, parse_code_points(decomposition)?);
        }
        if !fields[13].is_empty() {
            lower.insert(code, vec![parse_hex(fields[13])?]);
        }
        if !fields[12].is_empty() {
            upper.insert(code, vec![parse_hex(fields[12])?]);
        }
    }
    Ok(UnicodeData {
        combining_classes,
        decompositions,
        lower,
        upper,
    })
}

fn apply_special_casing(
    text: &str,
    lower: &mut BTreeMap<u32, Vec<u32>>,
    upper: &mut BTreeMap<u32, Vec<u32>>,
) -> Result<(), String> {
    for line in data_lines(text) {
        let fields = line.split(';').map(str::trim).collect::<Vec<_>>();
        if fields.len() < 5 {
            return Err(format!("malformed SpecialCasing row {line:?}"));
        }
        if !fields[4].is_empty() {
            continue;
        }
        let code = parse_hex(fields[0])?;
        let lower_mapping = parse_code_points(fields[1])?;
        let upper_mapping = parse_code_points(fields[3])?;
        if lower_mapping != [code] {
            lower.insert(code, lower_mapping);
        }
        if upper_mapping != [code] {
            upper.insert(code, upper_mapping);
        }
    }
    Ok(())
}

fn build_compositions(
    decompositions: &BTreeMap<u32, Vec<u32>>,
    exclusions: &BTreeSet<u32>,
) -> Vec<(u32, u32, u32)> {
    let mut output = decompositions
        .iter()
        .filter(|(composed, parts)| parts.len() == 2 && !exclusions.contains(composed))
        .map(|(composed, parts)| (parts[0], parts[1], *composed))
        .collect::<Vec<_>>();
    output.sort_by_key(|(first, second, _)| (*first, *second));
    output
}

fn parse_property(text: &str, name: &str) -> Result<Vec<(u32, u32)>, String> {
    let mut ranges = Vec::new();
    for line in data_lines(text) {
        let Some((range, property_and_more)) = line.split_once(';') else {
            return Err(format!("malformed property row {line:?}"));
        };
        let property = property_and_more
            .split(';')
            .next()
            .map(str::trim)
            .unwrap_or_default();
        if property == name {
            ranges.push(parse_range(range.trim())?);
        }
    }
    merge_ranges(ranges)
}

fn parse_script_aliases(text: &str) -> Result<Vec<(String, String)>, String> {
    let mut output = Vec::new();
    for line in data_lines(text) {
        let fields = line.split(';').map(str::trim).collect::<Vec<_>>();
        if fields.first() == Some(&"sc") {
            if fields.len() < 3 {
                return Err(format!("malformed script alias row {line:?}"));
            }
            output.push((fields[1].to_owned(), fields[2].to_owned()));
        }
    }
    output.sort_by(|left, right| left.0.cmp(&right.0));
    if output.is_empty() {
        return Err("script alias table is empty".to_owned());
    }
    Ok(output)
}

fn parse_script_ranges(
    text: &str,
    scripts: &BTreeMap<String, u16>,
) -> Result<Vec<(u32, u32, u16)>, String> {
    let mut output = Vec::new();
    for line in data_lines(text) {
        let (range, script) = line
            .split_once(';')
            .ok_or_else(|| format!("malformed Scripts row {line:?}"))?;
        let script = script.trim();
        let index = scripts
            .get(script)
            .copied()
            .ok_or_else(|| format!("unknown script {script}"))?;
        let (start, end) = parse_range(range.trim())?;
        output.push((start, end, index));
    }
    output.sort_by_key(|(start, end, _)| (*start, *end));
    Ok(output)
}

fn parse_script_extensions(
    text: &str,
    scripts: &BTreeMap<String, u16>,
) -> Result<Vec<(u32, u32, Vec<u16>)>, String> {
    let mut output = Vec::new();
    for line in data_lines(text) {
        let (range, values) = line
            .split_once(';')
            .ok_or_else(|| format!("malformed ScriptExtensions row {line:?}"))?;
        let mut indices = values
            .split_whitespace()
            .map(|script| {
                scripts
                    .get(script)
                    .copied()
                    .ok_or_else(|| format!("unknown script extension {script}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        indices.sort_unstable();
        indices.dedup();
        let (start, end) = parse_range(range.trim())?;
        output.push((start, end, indices));
    }
    Ok(output)
}

fn parse_confusables(text: &str) -> Result<Vec<(u32, Vec<u32>)>, String> {
    let mut output = BTreeMap::new();
    for line in data_lines(text) {
        let fields = line.split(';').map(str::trim).collect::<Vec<_>>();
        if fields.len() < 3 {
            return Err(format!("malformed confusable row {line:?}"));
        }
        let source = parse_code_points(fields[0])?;
        if source.len() != 1 {
            return Err(format!("non-scalar confusable source {line:?}"));
        }
        if output
            .insert(source[0], parse_code_points(fields[1])?)
            .is_some()
        {
            return Err(format!("duplicate confusable source {:X}", source[0]));
        }
    }
    Ok(output.into_iter().collect())
}

fn compress_values(mut values: Vec<(u32, u8)>) -> Vec<(u32, u32, u8)> {
    values.sort_unstable();
    let mut output: Vec<(u32, u32, u8)> = Vec::new();
    for (code, value) in values {
        if let Some((_, end, prior)) = output.last_mut()
            && *prior == value
            && end.checked_add(1) == Some(code)
        {
            *end = code;
        } else {
            output.push((code, code, value));
        }
    }
    output
}

fn merge_ranges(mut ranges: Vec<(u32, u32)>) -> Result<Vec<(u32, u32)>, String> {
    ranges.sort_unstable();
    let mut output: Vec<(u32, u32)> = Vec::new();
    for (start, end) in ranges {
        if start > end || end > 0x10_FFFF {
            return Err(format!("invalid Unicode range {start:X}..{end:X}"));
        }
        if let Some((_, prior_end)) = output.last_mut()
            && start <= prior_end.saturating_add(1)
        {
            *prior_end = (*prior_end).max(end);
        } else {
            output.push((start, end));
        }
    }
    Ok(output)
}

fn expand_ranges(ranges: &[(u32, u32)]) -> BTreeSet<u32> {
    ranges
        .iter()
        .flat_map(|(start, end)| *start..=*end)
        .collect()
}

fn parse_range(value: &str) -> Result<(u32, u32), String> {
    if let Some((start, end)) = value.split_once("..") {
        Ok((parse_hex(start)?, parse_hex(end)?))
    } else {
        let code = parse_hex(value)?;
        Ok((code, code))
    }
}

fn parse_code_points(value: &str) -> Result<Vec<u32>, String> {
    value
        .split_whitespace()
        .map(parse_hex)
        .collect::<Result<Vec<_>, _>>()
}

fn parse_hex(value: &str) -> Result<u32, String> {
    let code =
        u32::from_str_radix(value, 16).map_err(|_| format!("invalid Unicode scalar {value:?}"))?;
    if code > 0x10_FFFF {
        return Err(format!("invalid Unicode code point U+{code:04X}"));
    }
    Ok(code)
}

fn data_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(|line| line.split('#').next().unwrap_or_default().trim())
        .filter(|line| !line.is_empty() && !line.starts_with('@'))
}

fn read_text(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|error| format!("could not read {}: {error}", path.display()))
}

fn render(tables: &UnicodeTables) -> Result<String, String> {
    let mut output = String::from(
        "// @generated by `cargo run --locked -p xtask -- generate unicode`.\n\
// Source: third_party/unicode/16.0.0. Do not edit manually.\n\n\
/// Exact Unicode Standard version implemented by these tables.\n\
pub const UNICODE_VERSION: (u8, u8, u8) = (16, 0, 0);\n",
    );
    render_ranges(&mut output, "XID_START", &tables.xid_start);
    render_ranges(&mut output, "XID_CONTINUE", &tables.xid_continue);
    render_ranges(&mut output, "CASED", &tables.cased);
    render_ranges(&mut output, "CASE_IGNORABLE", &tables.case_ignorable);
    render_ranges(&mut output, "DEFAULT_IGNORABLE", &tables.default_ignorable);
    render_ranges(&mut output, "WHITE_SPACE", &tables.white_space);
    render_ranges(&mut output, "JOIN_CONTROL", &tables.join_control);
    render_ranges(
        &mut output,
        "VARIATION_SELECTOR",
        &tables.variation_selector,
    );
    render_ranges(&mut output, "BIDI_CONTROL", &tables.bidi_control);
    render_ranges(
        &mut output,
        "IDENTIFIER_ALLOWED",
        &tables.identifier_allowed,
    );
    render_ranges(
        &mut output,
        "IDENTIFIER_RECOMMENDED",
        &tables.identifier_recommended,
    );
    render_value_ranges(&mut output, "COMBINING_CLASSES", &tables.combining_classes);
    render_mappings(
        &mut output,
        "CANONICAL_DECOMPOSITIONS",
        &tables.decompositions,
    );
    render_triples(&mut output, "CANONICAL_COMPOSITIONS", &tables.compositions);
    render_mappings(&mut output, "FULL_LOWERCASE", &tables.lower);
    render_mappings(&mut output, "FULL_UPPERCASE", &tables.upper);
    render_scripts(&mut output, &tables.scripts)?;
    render_script_ranges(&mut output, "SCRIPT_RANGES", &tables.script_ranges);
    render_script_extensions(&mut output, &tables.script_extensions);
    render_mappings(&mut output, "CONFUSABLES", &tables.confusables);
    Ok(output)
}

fn render_ranges(output: &mut String, name: &str, values: &[(u32, u32)]) {
    output.push_str(&format!("\npub(crate) const {name}: &[(u32, u32)] = &[\n"));
    for (start, end) in values {
        output.push_str(&format!("    (0x{start:X}, 0x{end:X}),\n"));
    }
    output.push_str("];\n");
}

fn render_value_ranges(output: &mut String, name: &str, values: &[(u32, u32, u8)]) {
    output.push_str(&format!(
        "\npub(crate) const {name}: &[(u32, u32, u8)] = &[\n"
    ));
    for (start, end, value) in values {
        output.push_str(&format!("    (0x{start:X}, 0x{end:X}, {value}),\n"));
    }
    output.push_str("];\n");
}

fn render_mappings(output: &mut String, name: &str, values: &[(u32, Vec<u32>)]) {
    output.push_str(&format!(
        "\npub(crate) const {name}: &[(u32, &[u32])] = &[\n"
    ));
    for (source, target) in values {
        output.push_str(&format!("    (0x{source:X}, &[{}]),\n", code_list(target)));
    }
    output.push_str("];\n");
}

fn render_triples(output: &mut String, name: &str, values: &[(u32, u32, u32)]) {
    output.push_str(&format!(
        "\npub(crate) const {name}: &[(u32, u32, u32)] = &[\n"
    ));
    for (first, second, result) in values {
        output.push_str(&format!("    (0x{first:X}, 0x{second:X}, 0x{result:X}),\n"));
    }
    output.push_str("];\n");
}

fn render_scripts(output: &mut String, scripts: &[(String, String)]) -> Result<(), String> {
    if scripts.len() > usize::from(u16::MAX) {
        return Err("too many Unicode scripts".to_owned());
    }
    output.push_str("\npub(crate) const SCRIPTS: &[(&str, &str)] = &[\n");
    for (short, long) in scripts {
        output.push_str(&format!("    ({short:?}, {long:?}),\n"));
    }
    output.push_str("];\n");
    Ok(())
}

fn render_script_ranges(output: &mut String, name: &str, values: &[(u32, u32, u16)]) {
    output.push_str(&format!(
        "\npub(crate) const {name}: &[(u32, u32, u16)] = &[\n"
    ));
    for (start, end, script) in values {
        output.push_str(&format!("    (0x{start:X}, 0x{end:X}, {script}),\n"));
    }
    output.push_str("];\n");
}

fn render_script_extensions(output: &mut String, values: &[(u32, u32, Vec<u16>)]) {
    output.push_str("\npub(crate) const SCRIPT_EXTENSIONS: &[(u32, u32, &[u16])] = &[\n");
    for (start, end, scripts) in values {
        let values = scripts
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        output.push_str(&format!("    (0x{start:X}, 0x{end:X}, &[{values}]),\n"));
    }
    output.push_str("];\n");
}

fn code_list(values: &[u32]) -> String {
    values
        .iter()
        .map(|value| format!("0x{value:X}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::{merge_ranges, parse_range, validate_digest};

    #[test]
    fn parses_and_merges_unicode_ranges() {
        assert_eq!(parse_range("0041"), Ok((0x41, 0x41)));
        assert_eq!(parse_range("0041..005A"), Ok((0x41, 0x5A)));
        assert_eq!(
            merge_ranges(vec![(3, 5), (1, 2), (8, 9), (5, 7)]),
            Ok(vec![(1, 9)])
        );
    }

    #[test]
    fn rejects_invalid_ranges_and_hashes() {
        assert!(parse_range("110000").is_err());
        assert!(parse_range("not-hex").is_err());
        assert!(validate_digest("AA").is_err());
        assert_eq!(validate_digest(&"ab".repeat(32)), Ok(()));
    }
}
