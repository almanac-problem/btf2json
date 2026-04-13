use std::{
    cmp::{self, min},
    sync::LazyLock,
};

use anyhow::{bail, Context, Result};
use log::{debug, error, warn};
use memchr::memmem::{self, rfind};
use regex::bytes::Regex;

use crate::{
    banner::{banner_scan, KernelVersion, BITNESS_REGEX},
    btf::Endian,
    image::traits::{ImageRead, MemoryImage},
};

// Reference: linux/scripts/kallsyms.c
pub static KALLSYMS_TOKEN_TABLE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        // Unmatched 48 tokens (not matched in Regex for speed)
        r"0\x001\x002\x003\x004\x005\x006\x007\x008\x009\x00", // 0-9 ASCII (10 tokens)
        r"(?:[0-9A-Za-z_.]{1,16}\x00){7}", // 7 more tokens before upper-case alphabet
        r"A\x00B\x00C\x00D\x00E\x00F\x00G\x00H\x00I\x00J\x00K\x00L\x00M\x00N\x00O\x00P\x00Q\x00R\x00S\x00T\x00U\x00V\x00W\x00X\x00Y\x00Z\x00", // 26 tokens
        r"(?:[0-9A-Za-z_.]{1,16}\x00){6}", // 6 more tokens before lower-case alphabet
        r"a\x00b\x00c\x00d\x00e\x00f\x00g\x00h\x00i\x00j\x00k\x00l\x00m\x00n\x00o\x00p\x00q\x00r\x00s\x00t\x00u\x00v\x00w\x00x\x00y\x00z\x00", // 26 tokens
                                                                                                                                               // r"(?:[0-9A-Za-z_.]{1,16}\x00){133}",
    ))
    .unwrap()
});

static WINDOW_SIZE: usize = 30 * 1024 * 1024;
static MAX_ALIGNMENT: usize = 256;
static KALLSYMS_SYMBOL_TYPES: [char; 30] = [
    'A', 'B', 'D', 'R', 'T', 'V', 'W', 'G', 'I', 'N', 'P', 'C', 'S', 'U', 'a', 'b', 'c', 'd', 'g',
    'i', 'n', 'p', 'r', 's', 't', 'u', 'v', 'w', '-', '?',
];

#[derive(Debug, Clone)]
pub struct Kallsyms {
    pub kallsyms_token_table: usize,
    pub kallsyms_token_index: usize,
    pub kallsyms_markers: usize,
    pub kallsyms_names: usize,
    pub kallsyms_num_syms: usize,
    pub kallsyms_relative_base: usize,
    pub kallsyms_offsets: usize,
    pub num_syms: u64,
    pub relative_base_address: u64,
    pub symbol_offsets: Vec<u64>,
    pub symbol_names: Vec<String>,
}

// Reference: https://github.com/marin-m/vmlinux-to-elf/blob/33ac512b93672073e480066d829778f5be8fb5c2/vmlinux_to_elf/core/kallsyms.py#L598
pub fn carve_kallsyms<I: MemoryImage + ImageRead>(image: &I) -> Result<Kallsyms> {
    let image_data = image.as_ref();

    let token_table_candidates = find_kallsyms_token_table(image)?;

    for (kallsyms_token_table, token_table_size) in token_table_candidates {
        debug!("------------------------------------------------------------");
        debug!("Attempting to process the kallsyms with token_table at 0x{kallsyms_token_table:x}");

        let token_table = build_token_table(&image_data, kallsyms_token_table);

        // Build window to search across as full image scans could be prohibitively expensive
        let window_start = kallsyms_token_table.saturating_sub(WINDOW_SIZE);
        let window_end = kallsyms_token_table
            .saturating_add(WINDOW_SIZE)
            .min(image_data.len());
        let window_data = &image_data[window_start..window_end];

        // Look for kallsyms_token_index based on guaranteed structure
        let (mut kallsyms_token_index, endian) = match find_kallsyms_token_index(
            window_data,
            kallsyms_token_table - window_start,
            token_table_size,
        ) {
            Ok(t) => t,
            Err(_) => continue,
        };

        kallsyms_token_index += window_start; // Adjust for window scan

        debug!("    [+] Found kallsyms_token_index at file offset 0x{kallsyms_token_index:x}");

        // Scan for markers table
        let (mut kallsyms_markers, marker_entries, marker_entry_size) =
            match find_kallsyms_markers(&window_data, kallsyms_token_table - window_start, &endian)
            {
                Ok(m) => m,
                Err(_) => continue,
            };

        kallsyms_markers += window_start; // Adjust for window scan

        debug!(
            "    [+] Found kallsyms_markers at file offset 0x{kallsyms_markers:x} ({} entries)",
            marker_entries.len()
        );

        // This is an optimization to increase the speed of validating potential kallsyms_names candidates
        let valid_first_token_index = build_valid_first_tokens(
            &image_data,
            kallsyms_token_table,
            kallsyms_token_index,
            &endian,
        );

        // Find names by scanning window and validating with markers
        let mut kallsyms_names =
            match find_kallsyms_names(window_data, &marker_entries, valid_first_token_index) {
                Ok(n) => n,
                Err(_) => continue,
            };

        kallsyms_names += window_start; // Adjust for window scan

        // Calculate  - TODO: Validate by searching for the actual presence of kallsyms_num_syms
        let num_syms =
            match count_num_symbols(&image_data, kallsyms_names as usize, &marker_entries) {
                Ok(m) => m,
                Err(_) => continue,
            };
        debug!(
            "    [+] Found kallsyms_names at file offset 0x{kallsyms_names:x} ({num_syms} symbols)"
        );

        let kallsyms_num_syms = match find_kallsyms_num_syms(
            image_data,
            kallsyms_names as usize,
            marker_entry_size,
            &endian,
            num_syms,
        ) {
            Ok(n) => n,
            Err(e) => {
                error!("{:?}", e);
                continue;
            }
        };

        debug!("    [+] Found kallsyms_num_syms at file offset 0x{kallsyms_num_syms:x}");

        let banner = banner_scan(image).context("Unable to find banner!")?;

        let kernel_version =
            KernelVersion::try_from(banner.as_str()).context("Unable to find kernel version!")?;

        // Find kallsyms_offsets - Assuming offsets based on requirements of BTF-enabled image (TODO: research further)
        let (kallsyms_relative_base, kallsyms_offsets, relative_base_address, symbol_offsets) =
            match find_kallsyms_offsets(
                image_data,
                num_syms as usize,
                kernel_version,
                marker_entry_size,
                kallsyms_token_index + (2 * 256),
                kallsyms_num_syms,
                endian,
            ) {
                Ok(o) => o,
                Err(e) => {
                    error!("{:?}", e);
                    continue;
                }
            };

        let symbol_names = extract_symbol_names(image_data, kallsyms_names, &token_table)?;

        // TODO: Add the actual kallsyms symbols (token_table, markers, etc.)
        // This will need to rely on architecture-specific load addresses as
        // we only have physical currently

        return Ok(Kallsyms {
            kallsyms_token_table,
            kallsyms_token_index,
            kallsyms_markers,
            kallsyms_names,
            kallsyms_num_syms,
            kallsyms_relative_base,
            kallsyms_offsets,
            num_syms,
            relative_base_address,
            symbol_offsets,
            symbol_names,
        });
    }

    bail!("Could not find valid kallsyms structure in provided image")
}

// Scan for the kallsyms token table
pub fn find_kallsyms_token_table<I: MemoryImage>(image: &I) -> Result<Vec<(usize, usize)>> {
    let data = image.as_ref();

    let candidates = image.scan_regex(&KALLSYMS_TOKEN_TABLE_REGEX);

    debug!(
        "[*] Found {} candidates for kallsyms_token_table",
        candidates.len()
    );

    // For each candidate, walk the token table backward and ensure
    // That they are composed of valid tokens
    let mut token_table_candidates: Vec<(usize, usize)> = vec![];

    'candidate_loop: for candidate in &candidates {
        let candidate_start = candidate.start();
        let candidate_size = candidate.len();

        if candidate_start == 0 {
            continue;
        }

        let mut position = candidate_start - 1;

        // Sanity check
        if data[position] != 0 {
            continue;
        }

        for _token_index in 0..'0' as u32 {
            for _chars_in_token in 0..50 {
                position -= 1;

                if data[position] == 0 || data[position] > 'z' as u8 {
                    break;
                }
            }

            if data[position] != 0 {
                continue 'candidate_loop;
            }
        }

        // Get back to first character of first symbol
        position += 1;

        // Fix alignment, if necessary (I looked into this and it appears that the alignment
        // is 4 bytes, regardless of architecture type)
        if position % 4 != 0 {
            position -= position % 4;
        }

        let token_table_start = position;
        let token_table_size = candidate_size + (candidate_start - position);
        token_table_candidates.push((token_table_start, token_table_size));
    }

    if token_table_candidates.is_empty() {
        bail!("Couldn't find offset to token table");
    } else {
        for (candidate, _) in &token_table_candidates {
            debug!("Candidate for kallsyms_token_table: 0x{candidate:x}");
        }
        return Ok(token_table_candidates);
    }
}

pub fn find_kallsyms_token_index(
    data: &[u8],
    token_table_start: usize,
    token_table_size: usize,
) -> Result<(usize, Endian)> {
    let mut token_indexes: Vec<usize> = vec![0];

    // Build the index list to search for
    for position in token_table_start..(token_table_start + token_table_size) - 1 {
        if data[position] == 0 {
            token_indexes.push(position + 1 - token_table_start);
        }
    }

    let le_pattern = token_indexes
        .iter()
        .map(|m| (*m as u16).to_le_bytes())
        .collect::<Vec<[u8; 2]>>()
        .concat();

    let be_pattern = token_indexes
        .iter()
        .map(|m| (*m as u16).to_be_bytes())
        .collect::<Vec<[u8; 2]>>()
        .concat();

    let le_candidates: Vec<usize> = memmem::find_iter(data, le_pattern.as_slice()).collect();
    let be_candidates: Vec<usize> = memmem::find_iter(data, be_pattern.as_slice()).collect();

    if le_candidates.len() == 0 && be_candidates.len() == 0 {
        bail!("The value of kallsyms_token_index was not found");
    }

    if le_candidates.len() > be_candidates.len() {
        return Ok((le_candidates[0], Endian::Little));
    } else {
        return Ok((be_candidates[0], Endian::Big));
    }
}

pub fn build_valid_first_tokens(
    data: &[u8],
    token_table_offset: usize,
    token_index_offset: usize,
    endian: &Endian,
) -> Vec<u8> {
    (0..256)
        .filter(|&index| {
            let off = token_index_offset + 2 * index as usize;
            let bytes: [u8; 2] = data[off..off + 2].try_into().unwrap(); // TODO: Error checking
            let token_off = match endian {
                Endian::Little => u16::from_le_bytes(bytes),
                Endian::Big => u16::from_be_bytes(bytes),
            } as usize;
            let first_byte = data[token_table_offset + token_off];
            KALLSYMS_SYMBOL_TYPES.contains(&(first_byte as char))
        })
        .map(|i| i as u8)
        .collect()
}

pub fn build_token_table(data: &[u8], token_table_offset: usize) -> Vec<String> {
    // The String::from_utf8_lossy is acceptable since the token table will only have ASCII
    data[token_table_offset..]
        .split(|&b| b == 0)
        .take(256)
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

pub fn find_kallsyms_markers(
    data: &[u8],
    token_table_offset: usize,
    endian: &Endian,
) -> Result<(usize, Vec<u64>, usize)> {
    let mut marker_offset: Option<usize> = None;
    let mut marker_entry_size: Option<usize> = None;

    // TODO: Research if this needs to be completed since we are limited to BTF-enabled kernels (4.18+)
    'table_element_size_loop: for table_element_size in [8, 4, 2] {
        let mut position = token_table_offset;

        'zero_matches_loop: for _ in 0..32 {
            position = rfind(&data[..position], &vec![0; table_element_size])
                .context("Unable to find beginning of marker table")?;

            // Spot check 4 entries (assuming there are > 3 * 256 symbols)
            const SPOT_CHECK_SIZE: usize = 4;
            let mut entries = [0u64; SPOT_CHECK_SIZE];
            for i in 0..SPOT_CHECK_SIZE {
                entries[i] = read_entry_unsigned(
                    data,
                    position + i * table_element_size,
                    endian,
                    table_element_size,
                )?;
            }

            if entries[0] != 0 {
                continue;
            }

            for i in 1..SPOT_CHECK_SIZE {
                if entries[i - 1] + 0x200 >= entries[i] || entries[i - 1] + 0x40000 < entries[i] {
                    continue 'zero_matches_loop;
                }
            }

            marker_offset = Some(position);
            marker_entry_size = Some(table_element_size);
            break 'table_element_size_loop;
        }
    }

    if marker_offset == None || marker_entry_size == None {
        bail!("[-] Could not find kallsyms_markers");
    }

    // Estimate kallsyms_markers length. Limit to 3000 for kernels with kallsyms_seqs_of_names
    // TODO: This is position dependent, should this be altered?
    let num_marker_entries = cmp::min(
        (token_table_offset - marker_offset.unwrap()) / marker_entry_size.unwrap(),
        3000,
    );

    let mut entries: Vec<u64> = vec![];

    // Read elements, stopping when the difference between offsets is outside of bounds
    // Initialize with first element
    entries.push(read_entry_unsigned(
        data,
        marker_offset.unwrap(),
        endian,
        marker_entry_size.unwrap(),
    )?);

    for i in 1..num_marker_entries {
        let new_entry = read_entry_unsigned(
            data,
            marker_offset.unwrap() + i * marker_entry_size.unwrap(),
            endian,
            marker_entry_size.unwrap(),
        )?;

        let last_entry = entries[i - 1];

        if last_entry + 0x200 >= new_entry || last_entry + 0x40000 < new_entry {
            break;
        } else {
            entries.push(new_entry);
        }
    }

    Ok((marker_offset.unwrap(), entries, marker_entry_size.unwrap()))
}

pub fn find_kallsyms_names(
    data: &[u8],
    marker_entries: &[u64],
    valid_first_token_indexes: Vec<u8>,
) -> Result<usize> {
    let mut lookup = [false; 256];
    for &i in &valid_first_token_indexes {
        lookup[i as usize] = true;
    }

    let mut candidates = vec![];

    for candidate in 0..data.len() {
        let passed = validate_names_candidate(data, candidate, marker_entries, &lookup);
        if passed {
            candidates.push(candidate);
        }
    }

    debug!("[*] Found {} kallsyms_names candidates", candidates.len());

    if candidates.len() != 1 {
        bail!("Unable to find kallsyms_names");
    }

    // TODO: Get the number of symbols from walking the final symbols
    // and checkign for the presence of kallsyms_num_symbols near the top of the table

    Ok(candidates[0])
}

// This function checks to see if a candidate value for kallsyms_names
// is valid based on the values of kallsyms_markers. For each marker,
// it checks to see if the bytes at that offset from the candidate
// look like a valid first token for a symbol
fn validate_names_candidate(
    data: &[u8],
    candidate: usize,
    markers: &[u64],
    valid_first_token_indexes: &[bool; 256],
) -> bool {
    for &marker in markers.iter() {
        let pos = candidate + marker as usize;
        if pos + 1 >= data.len() {
            return false;
        }
        let len = data[pos] as usize;

        if len == 0 || len > 127 {
            return false;
        }
        let token_idx = data[pos + 1];

        if !valid_first_token_indexes[token_idx as usize] {
            return false;
        }
    }

    true
}

pub fn count_num_symbols(data: &[u8], names_offset: usize, markers: &[u64]) -> Result<u64> {
    // Jump to last marker
    let last_marker = markers.last().context("Markers table is empty!")?;
    let mut count: u64 = (markers.len() as u64 - 1) * 256;
    let mut pos = names_offset + *last_marker as usize;

    for _ in 0..256 {
        if pos >= data.len() {
            bail!("Unable to count number of symbols in kallsyms_names - Ran out of data");
        }

        let len = data[pos];

        if len == 0 {
            return Ok(count);
        }

        count += 1;
        pos += len as usize + 1;
    }

    bail!("Invalid kallsyms_names candidate provided to count_num_symbols");
}

pub fn find_kallsyms_num_syms(
    data: &[u8],
    kallsyms_names: usize,
    kallsyms_marker_entry_size: usize,
    endian: &Endian,
    num_syms: u64,
) -> Result<usize> {
    // Search backwards from kallsyms_names looking for the binary represetnation of num_syms
    let start = kallsyms_names
        .checked_sub(MAX_ALIGNMENT)
        .context("Unable to find kallsyms_num_syms - Ran out of data")?;
    if kallsyms_names >= data.len() {
        bail!("Unable to find kallsyms_num_syms - Ran out of data");
    }

    let needle: Vec<u8> = match (kallsyms_marker_entry_size, endian) {
        (8, Endian::Big) => num_syms.to_be_bytes().to_vec(),
        (8, Endian::Little) => num_syms.to_le_bytes().to_vec(),
        (4, Endian::Big) => u32::try_from(num_syms)
            .context("num_syms too large for 32-bit system!")?
            .to_be_bytes()
            .to_vec(),
        (4, Endian::Little) => u32::try_from(num_syms)
            .context("num_syms too large for 32-bit system!")?
            .to_le_bytes()
            .to_vec(),
        (2, Endian::Big) => u16::try_from(num_syms)
            .context("num_syms too large for 16-bit system!")?
            .to_be_bytes()
            .to_vec(),
        (2, Endian::Little) => u16::try_from(num_syms)
            .context("num_syms too large for 16-bit system!")?
            .to_le_bytes()
            .to_vec(),
        _ => bail!("Invalid kallsyms_marker_entry_size!"),
    };

    let haystack = &data[start..kallsyms_names];
    let position = rfind(haystack, &needle).context("Unable to find kallsyms_num_syms")?;
    Ok(kallsyms_names - MAX_ALIGNMENT + position)
}

// For now, only implement a search for kallsyms_relative_base and kallsyms_offsets
// since this is the default since 4.6 for all platforms except itanium (TODO: Double check this)
// and BTF wasn't introduced until 4.18
pub fn find_kallsyms_offsets(
    data: &[u8],
    num_syms: usize,
    kernel_version: KernelVersion,
    kallsyms_marker_entry_size: usize,
    kallsyms_token_index_end: usize,
    kallsyms_num_syms_offset: usize,
    endian: Endian,
) -> Result<(usize, usize, u64, Vec<u64>)> {
    // Check banner string and previous information to identify likely structure
    if kernel_version
        .banner_string
        .to_lowercase()
        .contains("itanium")
        || kernel_version.banner_string.to_lowercase().contains("ia64")
    {
        bail!("Itanium platform not currently supported!");
    }

    let is_64_bit =
        kallsyms_marker_entry_size >= 8 || BITNESS_REGEX.is_match(&kernel_version.banner_string); // TODO: Research this line from vmlinux (>=?)

    let address_byte_size = match is_64_bit {
        true => 8,
        false => kallsyms_marker_entry_size,
    };

    let offset_byte_size = min(4, kallsyms_marker_entry_size);

    debug!("Address Byte Size: {address_byte_size}");
    debug!("Offset Byte Size: {offset_byte_size}");

    // Place position at the starting place (should be near kallsyms_relative_base)
    // Later kernel versions re-ordered the structures, so adjust for this
    let mut position: usize;
    if kernel_version.major > 6 || (kernel_version.major == 6 && kernel_version.minor >= 4) {
        let align_size = match is_64_bit {
            true => 8,
            false => 4,
        };

        position = kallsyms_token_index_end;
        position = position.next_multiple_of(align_size);
        position += num_syms * offset_byte_size;
        position = position.next_multiple_of(align_size);
        position += address_byte_size;
    } else {
        position = kallsyms_num_syms_offset;
    }

    loop {
        let start = position
            .checked_sub(address_byte_size)
            .context("Unable to find kallsyms_relative_base - Ran out of data")?;
        let previous_word = &data[start..position];

        if previous_word.iter().any(|&b| b != 0) {
            break;
        }
        position -= address_byte_size;
    }

    position = position
        .checked_sub(address_byte_size)
        .context("Unable to find kallsyms_relative_base - Ran out of data")?;

    let kallsyms_relative_base = position;

    debug!("[+] Found kallsyms_relative_base at file offset 0x{position:x}");
    let relative_base_address = read_entry_unsigned(data, position, &endian, address_byte_size)
        .context("Unable to read kallsyms_relative_base")?;

    debug!("[+] Found kallsyms_relative_base: 0x{relative_base_address:x}");

    loop {
        let start = position
            .checked_sub(offset_byte_size)
            .context("Unable to find kallsyms_offset - Ran out of data")?;

        let previous_word = &data[start..position];

        if previous_word.iter().any(|&b| b != 0) {
            break;
        }
        position -= offset_byte_size;
    }

    position -= offset_byte_size
        .checked_mul(num_syms)
        .context("Unable to find kallsyms_offset - num_syms too large")?;
    let kallsyms_offsets = position;

    debug!("[+] Found kallsyms_offsets at 0x{kallsyms_offsets:x}");

    let offsets = (0..num_syms)
        .map(|i| {
            read_entry_signed(
                data,
                kallsyms_offsets + i * offset_byte_size,
                &endian,
                offset_byte_size,
            )
        })
        .collect::<Result<Vec<i64>>>()
        .context("Unable to read offsets!")?;

    // Count the positive and negative values
    let mut positive_count = 0;
    let mut negative_count = 0;

    offsets.iter().for_each(|offset| {
        if *offset < 0 {
            negative_count += 1;
        } else {
            positive_count += 1;
        }
    });

    let negative_percent = negative_count as f64 / offsets.len() as f64;

    // Follow heuristic from vmlinux-to-elf
    let bits = match is_64_bit {
        true => 64,
        false => 32,
    };

    let negative_heuristic_mask = 0xFFF << (bits - 12);
    let absolute_heuristic_mask = 0x3F << (bits - 8);

    let mut negative_heuristic_count = 0;
    let mut absolute_heuristic_count = 0;

    offsets.iter().for_each(|offset| {
        if offset & negative_heuristic_mask == negative_heuristic_mask {
            negative_heuristic_count += 1;
        }
        if offset & absolute_heuristic_mask == 0 {
            absolute_heuristic_count += 1;
        }
    });

    let negative_heuristic_percent = negative_heuristic_count as f64 / offsets.len() as f64;
    let absolute_heuristic_percent = absolute_heuristic_count as f64 / offsets.len() as f64;

    debug!(
        "Heuristically Negative Offsets: {:.2}%",
        negative_heuristic_percent * 100f64
    );
    debug!(
        "Heuristically Absolute Offsets: {:.2}%",
        absolute_heuristic_percent * 100f64
    );

    if negative_heuristic_percent < 0.5 {
        warn!("[!] WARNING: Less than half ({:.2}%) of offsets are negative. If the resulting ISF profile is not functional, consider opening an issue on the btf2json Github project (https://github.com/vobst/btf2json)", negative_heuristic_percent);
    }

    if absolute_heuristic_percent > 0.5 {
        warn!("[!] WARNING: More than half ({:.2}%) of offsets appear to be absolute. If the resulting ISF profile is not functional, consider opening an issue on the btf2json Github project (https://github.com/vobst/btf2json)", negative_heuristic_percent);
    }

    // If negative percentage is > 50%, then assume CONFIG_KALLSYMS_ABSOLUTE_PERCPU is set
    let offsets_adjusted: Vec<u64>;
    if negative_percent >= 0.5 {
        offsets_adjusted = offsets
            .iter()
            .map(|offset| {
                if *offset < 0i64 {
                    (relative_base_address as i64 - 1 - offset) as u64
                } else {
                    *offset as u64
                }
            })
            .collect();
    } else {
        offsets_adjusted = offsets
            .iter()
            .map(|offset| (offset + relative_base_address as i64) as u64)
            .collect();
    }

    Ok((
        kallsyms_relative_base,
        kallsyms_offsets,
        relative_base_address,
        offsets_adjusted,
    ))
}

pub fn extract_symbol_names(
    data: &[u8],
    kallsyms_names_offset: usize,
    token_table: &Vec<String>,
) -> Result<Vec<String>> {
    let mut symbol_names = vec![];

    let mut current_symbol = kallsyms_names_offset;

    loop {
        let symbol_len = data[current_symbol] as usize;

        if symbol_len == 0 {
            break;
        }

        let token_indexes = &data[current_symbol + 1..current_symbol + 1 + symbol_len];
        let symbol: String = token_indexes
            .iter()
            .map(|&i| token_table[i as usize].as_str())
            .collect();
        symbol_names.push(symbol);

        current_symbol += symbol_len + 1;
    }

    Ok(symbol_names)
}

pub fn search_symbol_names(
    data: &[u8],
    kallsyms_names_offset: usize,
    token_table: &Vec<String>,
    search_list: &Vec<String>,
) -> Result<()> {
    let mut current_symbol = kallsyms_names_offset;

    loop {
        let symbol_len = data[current_symbol] as usize;

        if symbol_len == 0 {
            break;
        }

        let token_indexes = &data[current_symbol + 1..current_symbol + 1 + symbol_len];
        let symbol: String = token_indexes
            .iter()
            .map(|&i| token_table[i as usize].as_str())
            .collect();

        // Drop type char
        let x = &symbol[1..];
        println!("{x}");

        if search_list.contains(&String::from(x)) {
            println!("Found {symbol}!");
        }

        current_symbol += symbol_len + 1;
    }

    Ok(())
}

fn read_entry_unsigned(
    data: &[u8],
    offset: usize,
    endian: &Endian,
    table_element_size: usize,
) -> Result<u64> {
    let bytes = data
        .get(offset..offset + table_element_size)
        .context("Unable to read entry - Invalid bounds")?;

    let entry = match (endian, table_element_size) {
        (Endian::Big, 8) => {
            u64::from_be_bytes(bytes.try_into().context("Unable to build u64 from bytes")?)
        }
        (Endian::Big, 4) => {
            u32::from_be_bytes(bytes.try_into().context("Unable to build u32 from bytes")?) as u64
        }
        (Endian::Big, 2) => {
            u16::from_be_bytes(bytes.try_into().context("Unable to build u16 from bytes")?) as u64
        }
        (Endian::Little, 8) => {
            u64::from_le_bytes(bytes.try_into().context("Unable to build u64 from bytes")?)
        }
        (Endian::Little, 4) => {
            u32::from_le_bytes(bytes.try_into().context("Unable to build u32 from bytes")?) as u64
        }
        (Endian::Little, 2) => {
            u16::from_le_bytes(bytes.try_into().context("Unable to build u16 from bytes")?) as u64
        }
        _ => bail!("Unable to read entry (0x{offset:x}, {endian:?}, {table_element_size}"),
    };

    Ok(entry)
}

fn read_entry_signed(
    data: &[u8],
    offset: usize,
    endian: &Endian,
    table_element_size: usize,
) -> Result<i64> {
    let bytes = data
        .get(offset..offset + table_element_size)
        .context("Unable to read entry - Invalid bounds")?;

    let entry = match (endian, table_element_size) {
        (Endian::Big, 8) => {
            i64::from_be_bytes(bytes.try_into().context("Unable to build u64 from bytes")?)
        }
        (Endian::Big, 4) => {
            i32::from_be_bytes(bytes.try_into().context("Unable to build u32 from bytes")?) as i64
        }
        (Endian::Big, 2) => {
            i16::from_be_bytes(bytes.try_into().context("Unable to build u16 from bytes")?) as i64
        }
        (Endian::Little, 8) => {
            i64::from_le_bytes(bytes.try_into().context("Unable to build u64 from bytes")?)
        }
        (Endian::Little, 4) => {
            i32::from_le_bytes(bytes.try_into().context("Unable to build u32 from bytes")?) as i64
        }
        (Endian::Little, 2) => {
            i16::from_le_bytes(bytes.try_into().context("Unable to build u16 from bytes")?) as i64
        }
        _ => bail!("Unable to read entry (0x{offset:x}, {endian:?}, {table_element_size}"),
    };

    Ok(entry)
}
