use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use jni::objects::{JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jint, jobject};
use jni::JNIEnv;

// ELF constants
const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;

// Program header constants (not used directly, kept for completeness)
#[allow(dead_code)]
const PT_LOAD: u32 = 1;
#[allow(dead_code)]
const PT_NOTE: u32 = 4;

// Hash segment constants (Qualcomm extension)
const HASH_TABLE_HEADER_SIZE: usize = 40;
const OS_TYPE_HASH: u32 = 2;

// MBN constants
const MBN_HDR_SIZE: usize = 40;
const MBN_V7_HDR_SIZE: usize = 64;
const MBN_V8_HDR_SIZE: usize = 80;

// Default config values
const DEFAULT_MAX_SEGMENT_BYTES: u64 = 20 * 1024 * 1024;
const DEFAULT_VERSION_MIN: u32 = 1;
const DEFAULT_VERSION_MAX: u32 = 1000;
const DEFAULT_COMMON_SIZE_MAX: usize = 0x1000;
const DEFAULT_QTI_SIZE_MAX: usize = 0x1000;
const DEFAULT_OEM_SIZE_MAX: usize = 0x4000;
const DEFAULT_HASH_TABLE_SIZE_MAX: usize = 0x10000;
const DEFAULT_ARB_VALUE_MAX: u32 = 127;

// Configuration structure (must match Java class)
#[derive(Clone, Copy)]
struct Config {
    #[allow(dead_code)]
    hash_scan_max: usize,          // unused in current impl, kept for compatibility
    max_segment_size: u64,
    min_version: u32,
    max_version: u32,
    max_common_sz: usize,
    max_qti_sz: usize,
    max_oem_sz: usize,
    max_hash_tbl_sz: usize,
    max_arb: u32,
    full_mode: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            hash_scan_max: 0x1000,
            max_segment_size: DEFAULT_MAX_SEGMENT_BYTES,
            min_version: DEFAULT_VERSION_MIN,
            max_version: DEFAULT_VERSION_MAX,
            max_common_sz: DEFAULT_COMMON_SIZE_MAX,
            max_qti_sz: DEFAULT_QTI_SIZE_MAX,
            max_oem_sz: DEFAULT_OEM_SIZE_MAX,
            max_hash_tbl_sz: DEFAULT_HASH_TABLE_SIZE_MAX,
            max_arb: DEFAULT_ARB_VALUE_MAX,
            full_mode: false,
        }
    }
}

// -----------------------------------------------------------------------------
// Little‑endian helpers
// -----------------------------------------------------------------------------
#[inline]
fn read_le_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(buf[off..off + 2].try_into().unwrap())
}
#[inline]
fn read_le_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}
#[inline]
fn read_le_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
}

// -----------------------------------------------------------------------------
// MBN structures
// -----------------------------------------------------------------------------
#[allow(dead_code)]
struct MbnHeader {
    image_id: u32,
    version: u32,
    image_src: u32,
    image_dest_ptr: u32,
    image_size: u32,
    code_size: u32,
    sig_ptr: u32,
    sig_size: u32,
    cert_chain_ptr: u32,
    cert_chain_size: u32,
}

impl MbnHeader {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < MBN_HDR_SIZE {
            return Err("Insufficient data for MBN header");
        }
        Ok(Self {
            image_id: read_le_u32(data, 0),
            version: read_le_u32(data, 4),
            image_src: read_le_u32(data, 8),
            image_dest_ptr: read_le_u32(data, 12),
            image_size: read_le_u32(data, 16),
            code_size: read_le_u32(data, 20),
            sig_ptr: read_le_u32(data, 24),
            sig_size: read_le_u32(data, 28),
            cert_chain_ptr: read_le_u32(data, 32),
            cert_chain_size: read_le_u32(data, 36),
        })
    }

    fn header_size(&self) -> usize {
        match self.version {
            7 => MBN_V7_HDR_SIZE,
            8 => MBN_V8_HDR_SIZE,
            _ => MBN_HDR_SIZE,
        }
    }
}

struct Mbn {
    header: MbnHeader,
    _code: Vec<u8>,
}

impl Mbn {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 8 {
            return Err("Insufficient data for MBN");
        }
        let header = MbnHeader::from_bytes(data)?;
        let header_size = header.header_size();
        if data.len() < header_size {
            return Err("Insufficient data for MBN with padding");
        }
        let code = data[header_size..].to_vec();
        Ok(Self { header, _code: code })
    }
}

// -----------------------------------------------------------------------------
// ELF program header reader
// -----------------------------------------------------------------------------
fn read_program_header(
    file: &mut File,
    offset: u64,
    class: u8,
) -> Result<(u32, u64, u64, u32), std::io::Error> {
    let size = if class == ELFCLASS32 { 32 } else { 56 };
    let mut buf = vec![0u8; size];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut buf)?;

    if class == ELFCLASS32 {
        let p_type = read_le_u32(&buf, 0);
        let p_offset = read_le_u32(&buf, 4) as u64;
        let p_filesz = read_le_u32(&buf, 16) as u64;
        let p_flags = read_le_u32(&buf, 24);
        Ok((p_type, p_offset, p_filesz, p_flags))
    } else {
        let p_type = read_le_u32(&buf, 0);
        let p_offset = read_le_u64(&buf, 8);
        let p_filesz = read_le_u64(&buf, 32);
        let p_flags = read_le_u32(&buf, 4);
        Ok((p_type, p_offset, p_filesz, p_flags))
    }
}

// -----------------------------------------------------------------------------
// Parse hash table header (Qualcomm)
// -----------------------------------------------------------------------------
fn parse_hash_header(data: &[u8], config: &Config) -> Option<(usize, usize, usize)> {
    if data.len() < HASH_TABLE_HEADER_SIZE {
        return None;
    }
    let version = read_le_u32(data, 4);
    let common_sz = read_le_u32(data, 8) as usize;
    let qti_sz = read_le_u32(data, 12) as usize;
    let oem_sz = read_le_u32(data, 16) as usize;
    let hash_tbl_sz = read_le_u32(data, 20) as usize;

    if !(config.min_version..=config.max_version).contains(&version) {
        return None;
    }
    if common_sz > config.max_common_sz
        || qti_sz > config.max_qti_sz
        || oem_sz > config.max_oem_sz
        || hash_tbl_sz == 0
        || hash_tbl_sz > config.max_hash_tbl_sz
    {
        return None;
    }
    Some((common_sz, qti_sz, oem_sz))
}

// -----------------------------------------------------------------------------
// Core extraction logic (supports ELF and MBN, quick/full modes)
// -----------------------------------------------------------------------------
fn extract_metadata(
    path: &str,
    debug: bool,
    block_mode: bool,
    config: &Config,
) -> Result<(u32, u32, u32, Vec<String>), String> {
    let mut msgs = Vec::new();

    let mut file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
    let file_size = file.metadata().map_err(|e| format!("Failed to get metadata: {}", e))?.len();

    let mut header = [0u8; 64];
    file.read_exact(&mut header).map_err(|e| format!("Failed to read header: {}", e))?;

    // Check ELF magic
    if &header[0..4] == ELF_MAGIC {
        // -------------------- ELF handling --------------------
        if header[EI_DATA] != ELFDATA2LSB {
            return Err("Not a little‑endian ELF file".into());
        }
        let elf_class = header[EI_CLASS];
        if elf_class != ELFCLASS32 && elf_class != ELFCLASS64 {
            return Err("Unsupported ELF class".into());
        }

        if config.full_mode {
            msgs.push(format!("File: {}", path));
            msgs.push(format!("Format: ELF ({})", if elf_class == ELFCLASS32 { "32-bit" } else { "64-bit" }));
        }
        if debug {
            msgs.push(format!("[DEBUG] ELF class: {}", if elf_class == ELFCLASS32 { "32-bit" } else { "64-bit" }));
        }

        // Read program header table info
        let (e_phoff, e_phentsize, e_phnum) = if elf_class == ELFCLASS32 {
            (read_le_u32(&header, 28) as u64, read_le_u16(&header, 42) as usize, read_le_u16(&header, 44) as usize)
        } else {
            (read_le_u64(&header, 32), read_le_u16(&header, 54) as usize, read_le_u16(&header, 56) as usize)
        };

        if e_phnum == 0 || e_phentsize < (if elf_class == ELFCLASS32 { 32 } else { 56 }) {
            return Err("Invalid program header table".into());
        }

        if debug {
            msgs.push(format!("[DEBUG] Program headers: {}, table offset: 0x{:x}", e_phnum, e_phoff));
        }

        // Scan for HASH segment (os_type == 2)
        let mut hash_seg_info = None;
        for i in 0..e_phnum {
            let ph_offset = e_phoff + (i as u64) * e_phentsize as u64;
            let (p_type, p_offset, p_filesz, p_flags) =
                read_program_header(&mut file, ph_offset, elf_class).map_err(|e| e.to_string())?;

            if p_filesz == 0 {
                continue;
            }

            if !block_mode && p_offset + p_filesz > file_size {
                if debug {
                    msgs.push(format!("[DEBUG] Segment {} (type {}) extends beyond file – skipping", i, p_type));
                }
                continue;
            }
            if p_filesz > config.max_segment_size {
                if debug {
                    msgs.push(format!("[DEBUG] Segment {} too large ({} bytes) – skipping", i, p_filesz));
                }
                continue;
            }

            let os_type = (p_flags >> 24) & 0x7;
            if os_type == OS_TYPE_HASH {
                if debug {
                    msgs.push(format!("[DEBUG] Found HASH segment at index {}: offset 0x{:x}, size 0x{:x}", i, p_offset, p_filesz));
                }
                hash_seg_info = Some((p_offset, p_filesz));
                break;
            } else if debug {
                msgs.push(format!("[DEBUG] Segment {}: type {}, os_type {} – not HASH", i, p_type, os_type));
            }
        }

        let (hash_off, hash_size) = hash_seg_info.ok_or_else(|| "No HASH segment found in ELF".to_string())?;

        // Read the whole HASH segment
        let mut hash_data = vec![0u8; hash_size as usize];
        file.seek(SeekFrom::Start(hash_off)).map_err(|e| e.to_string())?;
        file.read_exact(&mut hash_data).map_err(|e| e.to_string())?;

        // Parse hash header
        let (common_sz, qti_sz, oem_sz) = parse_hash_header(&hash_data, config)
            .ok_or_else(|| "Invalid HASH segment header".to_string())?;

        if debug {
            msgs.push(format!("[DEBUG] HASH header: common={}, qti={}, oem={}", common_sz, qti_sz, oem_sz));
        }

        // Locate OEM metadata (after header + common + qti)
        let oem_off = HASH_TABLE_HEADER_SIZE + common_sz + qti_sz;
        if oem_off + 12 > hash_data.len() {
            return Err("OEM metadata truncated".into());
        }
        let oem_slice = &hash_data[oem_off..oem_off + 12];
        let oem_major = read_le_u32(oem_slice, 0);
        let oem_minor = read_le_u32(oem_slice, 4);
        let oem_arb = read_le_u32(oem_slice, 8);

        if oem_major > config.max_version || oem_minor > config.max_version || oem_arb > config.max_arb {
            return Err("OEM metadata values out of expected range".into());
        }

        if config.full_mode {
            msgs.push(format!("Entry point: 0x{:x}", if elf_class == ELFCLASS32 { read_le_u32(&header, 24) as u64 } else { read_le_u64(&header, 24) }));
            msgs.push(format!("Program headers: {}", e_phnum));

            // Re‑scan program headers to list them
            for i in 0..e_phnum {
                let ph_offset = e_phoff + (i as u64) * e_phentsize as u64;
                let (p_type, p_offset, p_filesz, _) =
                    read_program_header(&mut file, ph_offset, elf_class).map_err(|e| e.to_string())?;
                let type_str = match p_type {
                    0 => "NULL",
                    1 => "LOAD",
                    4 => "NOTE",
                    _ => "OTHER",
                };
                msgs.push(format!("  [{}] Type: {} Offset: 0x{:x} VAddr: ??? FileSize: 0x{:x}", i, type_str, p_offset, p_filesz));
            }

            if hash_seg_info.is_some() {
                msgs.push("Hash Table Segment Header:".to_string());
                let version = read_le_u32(&hash_data, 4);
                msgs.push(format!("  Version: {}", version));
                msgs.push(format!("  Common Metadata Size: {}", common_sz));
                msgs.push(format!("  OEM Metadata Size: {}", oem_sz));
                msgs.push(format!("  Hash Table Size: {}", read_le_u32(&hash_data, 20)));
            }
        }

        if debug {
            msgs.push(format!("[DEBUG] OEM metadata: major={}, minor={}, arb={}", oem_major, oem_minor, oem_arb));
        }

        Ok((oem_major, oem_minor, oem_arb, msgs))

    } else {
        // -------------------- MBN detection --------------------
        let version = read_le_u32(&header, 4);
        if [3, 5, 6, 7, 8].contains(&version) {
            file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
            let mut full_data = Vec::new();
            file.read_to_end(&mut full_data).map_err(|e| e.to_string())?;
            let mbn = Mbn::from_bytes(&full_data).map_err(|e| e.to_string())?;

            if config.full_mode {
                msgs.push(format!("File: {}", path));
                msgs.push(format!("Format: MBN v{}", mbn.header.version));
                msgs.push(format!("Image ID: 0x{:x}", mbn.header.image_id));
                msgs.push(format!("Code size: {} bytes", mbn.header.code_size));
                msgs.push(format!("Image size: {} bytes", mbn.header.image_size));
                msgs.push(format!("Signature ptr: 0x{:x}, size: {}", mbn.header.sig_ptr, mbn.header.sig_size));
                msgs.push(format!("Certificate chain ptr: 0x{:x}, size: {}", mbn.header.cert_chain_ptr, mbn.header.cert_chain_size));
                msgs.push("ARB: not applicable".to_string());
            } else {
                msgs.push("MBN format does not contain ARB field".to_string());
            }

            if debug {
                msgs.push(format!("[DEBUG] MBN version: {}", mbn.header.version));
                msgs.push(format!("[DEBUG] Code size: {}", mbn.header.code_size));
            }

            Ok((0, 0, 0, msgs))
        } else {
            Err("Unknown file format (not ELF or MBN)".into())
        }
    }
}

// -----------------------------------------------------------------------------
// Helper: get int field from Java object
// -----------------------------------------------------------------------------
fn get_int_field(env: &mut JNIEnv, obj: &JObject, field_name: &str) -> i32 {
    env.get_field(obj, field_name, "I")
        .expect("Failed to get int field")
        .i()
        .expect("Field is not an int")
}

// Helper: get long field from Java object
fn get_long_field(env: &mut JNIEnv, obj: &JObject, field_name: &str) -> i64 {
    env.get_field(obj, field_name, "J")
        .expect("Failed to get long field")
        .j()
        .expect("Field is not a long")
}

// Helper: get boolean field from Java object
fn get_boolean_field(env: &mut JNIEnv, obj: &JObject, field_name: &str) -> bool {
    env.get_field(obj, field_name, "Z")
        .expect("Failed to get boolean field")
        .z()
        .expect("Field is not a boolean")
}

// -----------------------------------------------------------------------------
// JNI entry point with custom config (config may be null)
// -----------------------------------------------------------------------------
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_dere3046_arbinspector_ArbInspector_extractWithConfig(
    mut env: JNIEnv,
    _class: JClass,
    path: JString,
    debug: jboolean,
    block_mode: jboolean,
    config: JObject,
) -> jobject {
    // Convert Java parameters
    let path_str: String = env
        .get_string(&path)
        .expect("Couldn't get Java string")
        .into();
    let debug = debug != 0;
    let block_mode = block_mode != 0;

    // Build Rust Config from Java object or use defaults
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
            full_mode: get_boolean_field(&mut env, &config, "fullMode"),
        }
    };

    // Perform extraction
    let result = extract_metadata(&path_str, debug, block_mode, &rust_config);

    // Find ArbResult class
    let arb_result_class = env
        .find_class("com/dere3046/arbinspector/ArbResult")
        .expect("Failed to find ArbResult class");

    // Create new ArbResult object
    let arb_result = env
        .new_object(arb_result_class, "()V", &[])
        .expect("Failed to create ArbResult object");

    // Macros for setting fields
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
        Ok((major, minor, arb, msgs)) => {
            set_int_field!(&arb_result, "major", major);
            set_int_field!(&arb_result, "minor", minor);
            set_int_field!(&arb_result, "arb", arb);

            // Create ArrayList<String> for messages
            let array_list_class = env
                .find_class("java/util/ArrayList")
                .expect("Failed to find ArrayList class");
            let array_list = env
                .new_object(array_list_class, "()V", &[])
                .expect("Failed to create ArrayList");

            for msg in msgs {
                let jmsg = env.new_string(msg).expect("Failed to create Java string");
                env.call_method(
                    &array_list,
                    "add",
                    "(Ljava/lang/Object;)Z",
                    &[JValue::Object(&*jmsg)],
                )
                .expect("Failed to add message");
            }

            set_object_field!(&arb_result, "debugMessages", "Ljava/util/List;", &array_list);
            set_object_field!(&arb_result, "error", "Ljava/lang/String;", &JObject::null());
        }
        Err(err_msg) => {
            let jerr = env
                .new_string(err_msg)
                .expect("Failed to create error string");
            set_object_field!(&arb_result, "error", "Ljava/lang/String;", &*jerr);

            // Empty list for debugMessages
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

// -----------------------------------------------------------------------------
// Legacy entry point (backward compatibility) – defaults to quick mode (fullMode = false)
// -----------------------------------------------------------------------------
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
