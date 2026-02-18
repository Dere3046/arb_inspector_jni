use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use jni::objects::{JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jint, jobject};
use jni::JNIEnv;

// Default configuration values (mirrored in Java's ArbConfig)
const DEFAULT_HASH_SCAN_MAX: usize = 0x1000;
const DEFAULT_MAX_SEGMENT_SIZE: u64 = 20 * 1024 * 1024;
const DEFAULT_MIN_VERSION: u32 = 1;
const DEFAULT_MAX_VERSION: u32 = 1000;
const DEFAULT_MAX_COMMON_SZ: usize = 0x1000;
const DEFAULT_MAX_QTI_SZ: usize = 0x1000;
const DEFAULT_MAX_OEM_SZ: usize = 0x4000;
const DEFAULT_MAX_HASH_TBL_SZ: usize = 0x10000;
const DEFAULT_MAX_ARB: u32 = 127;

// Configuration structure that can be passed from Java
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
            hash_scan_max: DEFAULT_HASH_SCAN_MAX,
            max_segment_size: DEFAULT_MAX_SEGMENT_SIZE,
            min_version: DEFAULT_MIN_VERSION,
            max_version: DEFAULT_MAX_VERSION,
            max_common_sz: DEFAULT_MAX_COMMON_SZ,
            max_qti_sz: DEFAULT_MAX_QTI_SZ,
            max_oem_sz: DEFAULT_MAX_OEM_SZ,
            max_hash_tbl_sz: DEFAULT_MAX_HASH_TBL_SZ,
            max_arb: DEFAULT_MAX_ARB,
        }
    }
}

// Helper functions to read little-endian values
fn read_le_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(buf[off..off + 2].try_into().unwrap())
}

fn read_le_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

fn read_le_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
}

fn find_hash_header(
    seg: &[u8],
    debug: bool,
    _seg_idx: usize,
    seg_off: u64,
    debug_msgs: &mut Vec<String>,
    config: &Config,
) -> Option<usize> {
    let seg_len = seg.len();
    let scan_max = config.hash_scan_max.min(seg_len);
    for off in (0..scan_max).step_by(4) {
        if off + 36 > seg_len {
            break;
        }

        let version = read_le_u32(seg, off);
        let common_sz = read_le_u32(seg, off + 4) as usize;
        let qti_sz = read_le_u32(seg, off + 8) as usize;
        let oem_sz = read_le_u32(seg, off + 12) as usize;
        let hash_tbl_sz = read_le_u32(seg, off + 16) as usize;

        if !(config.min_version..=config.max_version).contains(&version) {
            continue;
        }
        if common_sz > config.max_common_sz || qti_sz > config.max_qti_sz || oem_sz > config.max_oem_sz {
            continue;
        }
        if hash_tbl_sz == 0 || hash_tbl_sz > config.max_hash_tbl_sz {
            continue;
        }
        if off + 36 + common_sz + qti_sz + oem_sz > seg_len {
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

struct OemInfo {
    major: u32,
    minor: u32,
    arb: u32,
    used_seg_off: u64,
    used_header_off: usize,
}

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

    let oem_off = header_off + 36 + common_sz + qti_sz;
    if oem_off + 12 > seg_data.len() {
        return None;
    }

    let major = read_le_u32(seg_data, oem_off);
    let minor = read_le_u32(seg_data, oem_off + 4);
    let arb = read_le_u32(seg_data, oem_off + 8);

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

fn extract_metadata(
    path: &str,
    debug: bool,
    block_mode: bool,
    config: &Config,
) -> Result<(u32, u32, u32, Vec<String>), String> {
    let mut debug_msgs = Vec::new();

    let mut file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
    let file_size = file.metadata().map_err(|e| format!("Failed to get metadata: {}", e))?.len();

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

// Helper to get an integer field from a Java object using field name
fn get_int_field(env: &mut JNIEnv, obj: &JObject, field_name: &str) -> i32 {
    env.get_field(obj, field_name, "I")
        .expect("Failed to get int field")
        .i()
        .expect("Field is not an int")
}

// Helper to get a long field from a Java object using field name
fn get_long_field(env: &mut JNIEnv, obj: &JObject, field_name: &str) -> i64 {
    env.get_field(obj, field_name, "J")
        .expect("Failed to get long field")
        .j()
        .expect("Field is not a long")
}

// JNI function for extractWithConfig
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_dere3046_arbinspector_ArbInspector_extractWithConfig(
    mut env: JNIEnv,
    _class: JClass,
    path: JString,
    debug: jboolean,
    block_mode: jboolean,
    config: JObject,  // may be null
) -> jobject {
    // Convert parameters
    let path_str: String = env
        .get_string(&path)
        .expect("Couldn't get Java string")
        .into();
    let debug = debug != 0;
    let block_mode = block_mode != 0;

    // Build config from Java object or use defaults
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

    // Run core extraction with the config
    let result = extract_metadata(&path_str, debug, block_mode, &rust_config);

    // Find ArbResult class
    let arb_result_class = env
        .find_class("com/dere3046/arbinspector/ArbResult")
        .expect("Failed to find ArbResult class");

    // Create a new ArbResult object
    let arb_result = env
        .new_object(arb_result_class, "()V", &[])
        .expect("Failed to create ArbResult object");

    // Helper macros to set fields
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
            set_int_field!(&arb_result, "major", major);
            set_int_field!(&arb_result, "minor", minor);
            set_int_field!(&arb_result, "arb", arb);

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

            set_object_field!(&arb_result, "debugMessages", "Ljava/util/List;", &array_list);
            set_object_field!(&arb_result, "error", "Ljava/lang/String;", &JObject::null());
        }
        Err(err_msg) => {
            let jerr = env
                .new_string(err_msg)
                .expect("Failed to create error string");
            set_object_field!(&arb_result, "error", "Ljava/lang/String;", &*jerr);

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

// Keep the original extract function for compatibility
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_dere3046_arbinspector_ArbInspector_extract(
    env: JNIEnv,
    class: JClass,
    path: JString,
    debug: jboolean,
    block_mode: jboolean,
) -> jobject {
    // Delegate to extractWithConfig with null config
    Java_com_dere3046_arbinspector_ArbInspector_extractWithConfig(
        env, class, path, debug, block_mode, JObject::null()
    )
}