use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use jni::objects::{JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jint, jobject};
use jni::JNIEnv;

// ELF header constants (from ELF specification)
const HASH_HEADER_SIZE: usize = 36;                // fixed size of the HASH segment header

// Default values for configurable scan parameters (empirically derived from firmware samples)
const DEFAULT_MAX_SCAN_OFFSET: usize = 0x1000;      // scan at most 4KB into a segment
const DEFAULT_MAX_SEGMENT_BYTES: u64 = 20 * 1024 * 1024; // 20 MB safety cap
const DEFAULT_VERSION_MIN: u32 = 1;
const DEFAULT_VERSION_MAX: u32 = 1000;
const DEFAULT_COMMON_SIZE_MAX: usize = 0x1000;
const DEFAULT_QTI_SIZE_MAX: usize = 0x1000;
const DEFAULT_OEM_SIZE_MAX: usize = 0x4000;
const DEFAULT_HASH_TABLE_SIZE_MAX: usize = 0x10000; // 64KB upper bound
const DEFAULT_ARB_VALUE_MAX: u32 = 127;              // ARB values are typically small (<128)

// Configuration structure passed from Java (field names must match Java class)
#[derive(Clone, Copy)]
struct Config {
    hash_scan_max: usize,
    max_segment_size: u64,
    min_version: u32,
    max_version: u32,
    max_common_sz: usize,
    max_qti_sz: usize,
    max_oem_sz: usize,
    max_hash_tbl_sz: usize,
    max_arb: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            hash_scan_max: DEFAULT_MAX_SCAN_OFFSET,
            max_segment_size: DEFAULT_MAX_SEGMENT_BYTES,
            min_version: DEFAULT_VERSION_MIN,
            max_version: DEFAULT_VERSION_MAX,
            max_common_sz: DEFAULT_COMMON_SIZE_MAX,
            max_qti_sz: DEFAULT_QTI_SIZE_MAX,
            max_oem_sz: DEFAULT_OEM_SIZE_MAX,
            max_hash_tbl_sz: DEFAULT_HASH_TABLE_SIZE_MAX,
            max_arb: DEFAULT_ARB_VALUE_MAX,
        }
    }
}

// Helper: read little‑endian values from a byte slice
fn read_le_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(buf[off..off + 2].try_into().unwrap())
}
fn read_le_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}
fn read_le_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
}

// Scan a segment for a plausible HASH header.
// Returns the offset of the header if found, and appends debug messages when enabled.
fn find_hash_header(
    seg: &[u8],
    debug: bool,
    _seg_idx: usize,
    seg_off: u64,
    debug_msgs: &mut Vec<String>,
    config: &Config,
) -> Option<usize> {
    let seg_len = seg.len();
    // Only scan up to the user‑specified limit, because valid headers are always early.
    let scan_max = config.hash_scan_max.min(seg_len);
    // Step by 4 because header fields are 32‑bit aligned.
    for off in (0..scan_max).step_by(4) {
        if off + HASH_HEADER_SIZE > seg_len {
            break;
        }

        let version = read_le_u32(seg, off);
        let common_sz = read_le_u32(seg, off + 4) as usize;
        let qti_sz = read_le_u32(seg, off + 8) as usize;
        let oem_sz = read_le_u32(seg, off + 12) as usize;
        let hash_tbl_sz = read_le_u32(seg, off + 16) as usize;

        // Version must be within the range observed in real firmware.
        if !(config.min_version..=config.max_version).contains(&version) {
            continue;
        }
        // Region sizes must be reasonable; otherwise it's likely random data.
        if common_sz > config.max_common_sz || qti_sz > config.max_qti_sz || oem_sz > config.max_oem_sz {
            continue;
        }
        // Hash table must exist and not be implausibly large.
        if hash_tbl_sz == 0 || hash_tbl_sz > config.max_hash_tbl_sz {
            continue;
        }
        // The total area described by the header must fit inside the segment.
        if off + HASH_HEADER_SIZE + common_sz + qti_sz + oem_sz > seg_len {
            continue;
        }

        if debug {
            debug_msgs.push(format!(
                "[DEBUG] Segment at file offset 0x{:x}: possible header at offset +0x{:x} (file 0x{:x})",
                seg_off, off, seg_off + off as u64
            ));
        }

        return Some(off);
    }
    None
}

// Holds the extracted OEM metadata.
struct OemInfo {
    major: u32,
    minor: u32,
    arb: u32,
    used_seg_off: u64,
    used_header_off: usize,
}

// Attempt to extract OEM metadata from a segment that already passed the header sanity checks.
fn try_extract_hash_info(
    seg_data: &[u8],
    seg_off: u64,
    debug: bool,
    seg_idx: usize,
    debug_msgs: &mut Vec<String>,
    config: &Config,
) -> Option<OemInfo> {
    let header_off = find_hash_header(seg_data, debug, seg_idx, seg_off, debug_msgs, config)?;

    let common_sz = read_le_u32(seg_data, header_off + 4) as usize;
    let qti_sz = read_le_u32(seg_data, header_off + 8) as usize;

    // OEM metadata begins immediately after the common and QTI regions.
    let oem_off = header_off + HASH_HEADER_SIZE + common_sz + qti_sz;
    if oem_off + 12 > seg_data.len() {
        return None;
    }

    let major = read_le_u32(seg_data, oem_off);
    let minor = read_le_u32(seg_data, oem_off + 4);
    let arb = read_le_u32(seg_data, oem_off + 8);

    // Reject values that are clearly outside expected ranges.
    if major > config.max_version || minor > config.max_version || arb > config.max_arb {
        return None;
    }

    if debug {
        debug_msgs.push(format!(
            "[DEBUG]  -> OEM at +0x{:x} (file 0x{:x}): major={}, minor={}, arb={}",
            oem_off,
            seg_off + oem_off as u64,
            major,
            minor,
            arb
        ));
    }

    Some(OemInfo {
        major,
        minor,
        arb,
        used_seg_off: seg_off,
        used_header_off: header_off,
    })
}

// Scan a list of candidate segments (offset, size, index) and return the first valid OemInfo.
fn scan_candidates(
    file: &mut File,
    candidates: &[(u64, u64, usize)],
    debug: bool,
    debug_msgs: &mut Vec<String>,
    config: &Config,
) -> Result<Option<OemInfo>, std::io::Error> {
    for &(off, size, idx) in candidates {
        if debug {
            debug_msgs.push(format!(
                "[DEBUG] Scanning segment {} at file offset 0x{:x} (size 0x{:x})",
                idx, off, size
            ));
        }
        let mut seg_data = vec![0u8; size as usize];
        file.seek(SeekFrom::Start(off))?;
        file.read_exact(&mut seg_data)?;

        if let Some(info) = try_extract_hash_info(&seg_data, off, debug, idx, debug_msgs, config) {
            if debug {
                debug_msgs.push(format!(
                    "[DEBUG] >>> SELECTED segment {} (offset 0x{:x}) with header at +0x{:x}",
                    idx, info.used_seg_off, info.used_header_off
                ));
            }
            return Ok(Some(info));
        }
    }
    Ok(None)
}

// Core extraction function – opens the file, parses ELF, scans candidates, returns metadata or error.
fn extract_metadata(
    path: &str,
    debug: bool,
    block_mode: bool,
    config: &Config,
) -> Result<(u32, u32, u32, Vec<String>), String> {
    let mut debug_msgs = Vec::new();

    let mut file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
    let file_size = file.metadata().map_err(|e| format!("Failed to get metadata: {}", e))?.len();

    // Read and validate ELF header
    let mut ehdr = [0u8; 64];
    file.read_exact(&mut ehdr).map_err(|e| format!("Failed to read ELF header: {}", e))?;

    if &ehdr[0..4] != b"\x7fELF" {
        return Err("Not an ELF file".into());
    }
    if ehdr[4] != 2 {
        return Err("Not a 64‑bit ELF file".into());
    }
    if ehdr[5] != 1 {
        return Err("Not a little‑endian ELF file".into());
    }

    let e_phoff = read_le_u64(&ehdr, 0x20);
    let e_phentsz = read_le_u16(&ehdr, 0x36) as usize;
    let e_phnum = read_le_u16(&ehdr, 0x38) as usize;

    if e_phentsz < 56 || e_phnum == 0 {
        return Err("Invalid program header table".into());
    }

    // Collect candidate segments: PT_NULL (type 0) are most likely to contain the HASH segment.
    let mut null_candidates = Vec::new();
    let mut other_candidates = Vec::new();

    for i in 0..e_phnum {
        let ph_offset = e_phoff + (i as u64) * e_phentsz as u64;
        file.seek(SeekFrom::Start(ph_offset)).map_err(|e| format!("Seek error: {}", e))?;
        let mut ph_buf = [0u8; 56];
        file.read_exact(&mut ph_buf).map_err(|e| format!("Read program header error: {}", e))?;

        let p_type = read_le_u32(&ph_buf, 0);
        let p_offset = read_le_u64(&ph_buf, 8);
        let p_filesz = read_le_u64(&ph_buf, 32);

        if p_filesz == 0 {
            continue;
        }
        // In normal mode, skip segments that extend beyond the file.
        // Skip file size check in block mode because block devices do not have a reliable file size.
        if !block_mode && p_offset + p_filesz > file_size {
            debug_msgs.push(format!("Warning: segment {} exceeds file size, skipping", i));
            continue;
        }
        if p_filesz > config.max_segment_size {
            debug_msgs.push(format!("Warning: segment {} too large ({} bytes), skipping", i, p_filesz));
            continue;
        }

        let candidate = (p_offset, p_filesz, i);
        if p_type == 0 {
            null_candidates.push(candidate);
        } else {
            other_candidates.push(candidate);
        }
    }

    // First try PT_NULL segments, then fall back to other types.
    let oem_info = if let Some(info) = scan_candidates(&mut file, &null_candidates, debug, &mut debug_msgs, config)
        .map_err(|e| format!("IO error while scanning: {}", e))?
    {
        info
    } else if let Some(info) = scan_candidates(&mut file, &other_candidates, debug, &mut debug_msgs, config)
        .map_err(|e| format!("IO error while scanning: {}", e))?
    {
        info
    } else {
        return Err("No valid HASH segment with OEM metadata found".into());
    };

    Ok((oem_info.major, oem_info.minor, oem_info.arb, debug_msgs))
}

// Helper: get an int field from a Java object using its field name.
fn get_int_field(env: &mut JNIEnv, obj: &JObject, field_name: &str) -> i32 {
    env.get_field(obj, field_name, "I")
        .expect("Failed to get int field")
        .i()
        .expect("Field is not an int")
}

// Helper: get a long field from a Java object using its field name.
fn get_long_field(env: &mut JNIEnv, obj: &JObject, field_name: &str) -> i64 {
    env.get_field(obj, field_name, "J")
        .expect("Failed to get long field")
        .j()
        .expect("Field is not a long")
}

// JNI entry point for extractWithConfig (accepts custom config object, may be null).
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_dere3046_arbinspector_ArbInspector_extractWithConfig(
    mut env: JNIEnv,
    _class: JClass,
    path: JString,
    debug: jboolean,
    block_mode: jboolean,
    config: JObject,  // may be null
) -> jobject {
    // Convert Java parameters to Rust types.
    let path_str: String = env
        .get_string(&path)
        .expect("Couldn't get Java string")
        .into();
    let debug = debug != 0;
    let block_mode = block_mode != 0;

    // Build Rust Config from Java object, or use defaults if config is null.
    let rust_config = if config.is_null() {
        Config::default()
    } else {
        Config {
            hash_scan_max: get_int_field(&mut env, &config, "hashScanMax") as usize,
            max_segment_size: get_long_field(&mut env, &config, "maxSegmentSize") as u64,
            min_version: get_int_field(&mut env, &config, "minVersion") as u32,
            max_version: get_int_field(&mut env, &config, "maxVersion") as u32,
            max_common_sz: get_int_field(&mut env, &config, "maxCommonSz") as usize,
            max_qti_sz: get_int_field(&mut env, &config, "maxQtiSz") as usize,
            max_oem_sz: get_int_field(&mut env, &config, "maxOemSz") as usize,
            max_hash_tbl_sz: get_int_field(&mut env, &config, "maxHashTblSz") as usize,
            max_arb: get_int_field(&mut env, &config, "maxArb") as u32,
        }
    };

    // Perform the extraction.
    let result = extract_metadata(&path_str, debug, block_mode, &rust_config);

    // Locate the ArbResult Java class.
    let arb_result_class = env
        .find_class("com/dere3046/arbinspector/ArbResult")
        .expect("Failed to find ArbResult class");

    // Create a new ArbResult object.
    let arb_result = env
        .new_object(arb_result_class, "()V", &[])
        .expect("Failed to create ArbResult object");

    // Macros to simplify field setting.
    macro_rules! set_int_field {
        ($obj:expr, $name:expr, $value:expr) => {{
            env.set_field(
                $obj,
                $name,
                "I",
                JValue::Int($value as jint),
            ).unwrap();
        }};
    }

    macro_rules! set_object_field {
        ($obj:expr, $name:expr, $sig:expr, $value:expr) => {{
            env.set_field(
                $obj,
                $name,
                $sig,
                JValue::Object($value),
            ).unwrap();
        }};
    }

    match result {
        Ok((major, minor, arb, debug_msgs)) => {
            // Fill integer fields.
            set_int_field!(&arb_result, "major", major);
            set_int_field!(&arb_result, "minor", minor);
            set_int_field!(&arb_result, "arb", arb);

            // Create an ArrayList<String> and populate with debug messages.
            let array_list_class = env
                .find_class("java/util/ArrayList")
                .expect("Failed to find ArrayList class");
            let array_list = env
                .new_object(array_list_class, "()V", &[])
                .expect("Failed to create ArrayList");

            for msg in debug_msgs {
                let jmsg = env.new_string(msg).expect("Failed to create Java string");
                env.call_method(
                    &array_list,
                    "add",
                    "(Ljava/lang/Object;)Z",
                    &[JValue::Object(&*jmsg)],
                )
                .expect("Failed to add debug message");
            }

            // Set debugMessages field (List<String>).
            set_object_field!(&arb_result, "debugMessages", "Ljava/util/List;", &array_list);
            // Set error field to null.
            set_object_field!(&arb_result, "error", "Ljava/lang/String;", &JObject::null());
        }
        Err(err_msg) => {
            // Set error field with the error message.
            let jerr = env
                .new_string(err_msg)
                .expect("Failed to create error string");
            set_object_field!(&arb_result, "error", "Ljava/lang/String;", &*jerr);

            // Set debugMessages to an empty list.
            let array_list_class = env
                .find_class("java/util/ArrayList")
                .expect("Failed to find ArrayList class");
            let array_list = env
                .new_object(array_list_class, "()V", &[])
                .expect("Failed to create ArrayList");
            set_object_field!(&arb_result, "debugMessages", "Ljava/util/List;", &array_list);
        }
    }

    *arb_result
}

// Original JNI function for backward compatibility – delegates to extractWithConfig with null config.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_dere3046_arbinspector_ArbInspector_extract(
    env: JNIEnv,
    class: JClass,
    path: JString,
    debug: jboolean,
    block_mode: jboolean,
) -> jobject {
    Java_com_dere3046_arbinspector_ArbInspector_extractWithConfig(
        env, class, path, debug, block_mode, JObject::null()
    )
}
