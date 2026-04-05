use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use jni::objects::{JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jint, jobject};
use jni::JNIEnv;

// ============================================================================
// elf.rs constants (inlined from arb_inspector_next)
// ============================================================================

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;

const PT_NULL: u32 = 0;
const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;
const PT_PHDR: u32 = 6;

const PF_PERM_MASK: u32 = 0x7;
const PF_OS_SEGMENT_TYPE_MASK: u32 = 0x0700_0000;
const PF_OS_ACCESS_TYPE_MASK: u32 = 0x00E0_0000;
const PF_OS_PAGE_MODE_MASK: u32 = 0x0010_0000;

const PF_OS_SEGMENT_HASH: u32 = 0x2;
const PF_OS_SEGMENT_PHDR: u32 = 0x7;

const PF_OS_ACCESS_RW: u32 = 0x0;
const PF_OS_ACCESS_RO: u32 = 0x1;
const PF_OS_ACCESS_ZI: u32 = 0x2;
const PF_OS_ACCESS_NOTUSED: u32 = 0x3;
const PF_OS_ACCESS_SHARED: u32 = 0x4;

const PF_OS_NON_PAGED_SEGMENT: u32 = 0x0;
const PF_OS_PAGED_SEGMENT: u32 = 0x1;

const ELF_BLOCK_ALIGN: u64 = 0x1000;

const ELF32_HDR_SIZE: usize = 52;
const ELF64_HDR_SIZE: usize = 64;
const ELF32_PHDR_SIZE: usize = 32;
const ELF64_PHDR_SIZE: usize = 56;

const OS_TYPE_HASH: u32 = 0x2;

// ============================================================================
// hash_segment.rs constants (inlined from arb_inspector_next)
// ============================================================================

const HASH_TABLE_HEADER_SIZE: usize = 40;
const HASH_TABLE_HEADER_SIZE_V7: usize = 56;

const VERSION_MIN: u32 = 1;
const VERSION_MAX: u32 = 1000;
const COMMON_SIZE_MAX: usize = 0x1000;
const QTI_SIZE_MAX: usize = 0x1000;
const OEM_SIZE_MAX: usize = 0x4000;
const HASH_TABLE_SIZE_MAX: usize = 0x10000;
const ARB_VALUE_MAX: u32 = 127;

const SHA256_SIZE: usize = 32;

const MBN_HDR_SIZE: usize = 40;
const MBN_V7_HDR_SIZE: usize = 64;
const MBN_V8_HDR_SIZE: usize = 80;

// ============================================================================
// Helper read functions
// ============================================================================

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

// ============================================================================
// metadata.rs (inlined from arb_inspector_next)
// ============================================================================

#[derive(Debug, Clone)]
struct MetadataV00 {
    major_version: u32,
    minor_version: u32,
    software_id: u32,
    soc_hw_vers: [u32; 32],
    jtag_id: u64,
    serial_numbers: [u32; 8],
    oem_id: u32,
    oem_product_id: u32,
    anti_rollback_version: u32,
    mrc_index: u32,
    debug: u32,
    secondary_software_id: u32,
    flags: u32,
}

impl MetadataV00 {
    const SIZE: usize = 208;

    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < Self::SIZE {
            return Err("Insufficient data for MetadataV00");
        }
        let mut soc_hw_vers = [0u32; 32];
        let mut serial_numbers = [0u32; 8];
        for i in 0..32 {
            soc_hw_vers[i] = read_le_u32(data, 8 + i * 4);
        }
        for i in 0..8 {
            serial_numbers[i] = read_le_u32(data, 144 + i * 4);
        }
        Ok(Self {
            major_version: read_le_u32(data, 0),
            minor_version: read_le_u32(data, 4),
            software_id: read_le_u32(data, 136),
            soc_hw_vers,
            jtag_id: read_le_u64(data, 264),
            serial_numbers,
            oem_id: read_le_u32(data, 304),
            oem_product_id: read_le_u32(data, 308),
            anti_rollback_version: read_le_u32(data, 312),
            mrc_index: read_le_u32(data, 316),
            debug: read_le_u32(data, 320),
            secondary_software_id: read_le_u32(data, 324),
            flags: read_le_u32(data, 328),
        })
    }

    fn get_arb_version(&self) -> u32 {
        self.anti_rollback_version
    }
}

#[derive(Debug, Clone)]
struct MetadataV10 {
    base: MetadataV00,
    in_use_jtag_id: u32,
    oem_product_id_independent: u32,
}

impl MetadataV10 {
    const SIZE: usize = 336;

    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        let base = MetadataV00::from_bytes(data)?;
        if data.len() < Self::SIZE {
            return Err("Insufficient data for MetadataV10");
        }
        Ok(Self {
            base,
            in_use_jtag_id: read_le_u32(data, 332),
            oem_product_id_independent: read_le_u32(data, 336),
        })
    }

    fn get_arb_version(&self) -> u32 {
        self.base.get_arb_version()
    }
}

#[derive(Debug, Clone)]
struct MetadataV20 {
    major_version: u32,
    minor_version: u32,
    anti_rollback_version: u32,
    mrc_index: u32,
    soc_hw_vers: [u32; 32],
    soc_feature_id: u32,
    jtag_id: u64,
    serial_numbers: [u32; 8],
    oem_id: u32,
    oem_product_id: u32,
    soc_lifecycle_state: u32,
    oem_lifecycle_state: u32,
    oem_root_certificate_hash_algorithm: u32,
    oem_root_certificate_hash: [u8; 64],
    flags: u32,
}

impl MetadataV20 {
    const SIZE: usize = 456;

    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 16 {
            return Err("Insufficient data for MetadataV20");
        }
        let mut soc_hw_vers = [0u32; 32];
        let mut serial_numbers = [0u32; 8];
        let mut oem_root_certificate_hash = [0u8; 64];
        for i in 0..32 {
            if 16 + i * 4 + 4 <= data.len() {
                soc_hw_vers[i] = read_le_u32(data, 16 + i * 4);
            }
        }
        for i in 0..8 {
            if 152 + i * 4 + 4 <= data.len() {
                serial_numbers[i] = read_le_u32(data, 152 + i * 4);
            }
        }
        if data.len() >= 240 {
            let copy_len = 64.min(data.len() - 240);
            oem_root_certificate_hash[..copy_len].copy_from_slice(&data[240..240 + copy_len]);
        }
        Ok(Self {
            major_version: read_le_u32(data, 0),
            minor_version: read_le_u32(data, 4),
            anti_rollback_version: read_le_u32(data, 8),
            mrc_index: read_le_u32(data, 12),
            soc_hw_vers,
            soc_feature_id: if data.len() > 236 { read_le_u32(data, 232) } else { 0 },
            jtag_id: if data.len() > 244 { read_le_u64(data, 236) } else { 0 },
            serial_numbers,
            oem_id: if data.len() > 228 { read_le_u32(data, 224) } else { 0 },
            oem_product_id: if data.len() > 232 { read_le_u32(data, 228) } else { 0 },
            soc_lifecycle_state: if data.len() > 320 { read_le_u32(data, 316) } else { 0 },
            oem_lifecycle_state: if data.len() > 324 { read_le_u32(data, 320) } else { 0 },
            oem_root_certificate_hash_algorithm: if data.len() > 328 { read_le_u32(data, 324) } else { 0 },
            oem_root_certificate_hash,
            flags: if data.len() > 332 { read_le_u32(data, 328) } else { 0 },
        })
    }

    fn get_arb_version(&self) -> u32 {
        self.anti_rollback_version
    }
}

#[derive(Debug, Clone)]
struct MetadataV30 {
    base: MetadataV20,
    qti_lifecycle_state: u32,
}

impl MetadataV30 {
    const SIZE: usize = 460;

    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        let base = MetadataV20::from_bytes(data)?;
        if data.len() < Self::SIZE {
            return Err("Insufficient data for MetadataV30");
        }
        Ok(Self {
            base,
            qti_lifecycle_state: read_le_u32(data, 456),
        })
    }

    fn get_arb_version(&self) -> u32 {
        self.base.get_arb_version()
    }
}

#[derive(Debug, Clone)]
struct MetadataV31 {
    base: MetadataV30,
    measurement_register_target: u32,
}

impl MetadataV31 {
    const SIZE: usize = 464;

    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        let base = MetadataV30::from_bytes(data)?;
        if data.len() < Self::SIZE {
            return Err("Insufficient data for MetadataV31");
        }
        Ok(Self {
            base,
            measurement_register_target: read_le_u32(data, 460),
        })
    }

    fn get_arb_version(&self) -> u32 {
        self.base.base.get_arb_version()
    }
}

#[derive(Debug)]
enum Metadata {
    V00(MetadataV00),
    V10(MetadataV10),
    V20(MetadataV20),
    V30(MetadataV30),
    V31(MetadataV31),
}

impl Metadata {
    fn from_bytes(data: &[u8], major: u32, minor: u32) -> Result<Self, &'static str> {
        match (major, minor) {
            (0, 0) => Ok(Metadata::V00(MetadataV00::from_bytes(data)?)),
            (1, 0) => Ok(Metadata::V10(MetadataV10::from_bytes(data)?)),
            (2, 0) => Ok(Metadata::V20(MetadataV20::from_bytes(data)?)),
            (3, 0) => Ok(Metadata::V30(MetadataV30::from_bytes(data)?)),
            (3, 1) => Ok(Metadata::V31(MetadataV31::from_bytes(data)?)),
            _ => {
                if data.len() >= 12 {
                    let arb = read_le_u32(data, 8);
                    if arb <= ARB_VALUE_MAX {
                        return Ok(Metadata::V20(MetadataV20 {
                            major_version: major,
                            minor_version: minor,
                            anti_rollback_version: arb,
                            mrc_index: if data.len() > 16 { read_le_u32(data, 12) } else { 0 },
                            soc_hw_vers: [0; 32],
                            soc_feature_id: 0,
                            jtag_id: 0,
                            serial_numbers: [0; 8],
                            oem_id: 0,
                            oem_product_id: 0,
                            soc_lifecycle_state: 0,
                            oem_lifecycle_state: 0,
                            oem_root_certificate_hash_algorithm: 0,
                            oem_root_certificate_hash: [0; 64],
                            flags: 0,
                        }));
                    }
                }
                Err("Unknown metadata version")
            }
        }
    }

    fn get_arb_version(&self) -> u32 {
        match self {
            Metadata::V00(m) => m.get_arb_version(),
            Metadata::V10(m) => m.get_arb_version(),
            Metadata::V20(m) => m.get_arb_version(),
            Metadata::V30(m) => m.get_arb_version(),
            Metadata::V31(m) => m.get_arb_version(),
        }
    }

    fn get_version_string(&self) -> String {
        match self {
            Metadata::V00(m) => format!("{}.{}", m.major_version, m.minor_version),
            Metadata::V10(m) => format!("{}.{}", m.base.major_version, m.base.minor_version),
            Metadata::V20(m) => format!("{}.{}", m.major_version, m.minor_version),
            Metadata::V30(m) => format!("{}.{}", m.base.major_version, m.base.minor_version),
            Metadata::V31(m) => format!("{}.{}", m.base.base.major_version, m.base.base.minor_version),
        }
    }
}

#[derive(Debug)]
enum CommonMetadata {
    V00(CommonMetadataV00),
    V01(CommonMetadataV01),
}

#[derive(Debug, Clone)]
struct CommonMetadataV00 {
    major_version: u32,
    minor_version: u32,
    one_shot_hash_algorithm: u32,
    segment_hash_algorithm: u32,
}

impl CommonMetadataV00 {
    const SIZE: usize = 16;

    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < Self::SIZE {
            return Err("Insufficient data for CommonMetadataV00");
        }
        Ok(Self {
            major_version: read_le_u32(data, 0),
            minor_version: read_le_u32(data, 4),
            one_shot_hash_algorithm: read_le_u32(data, 8),
            segment_hash_algorithm: read_le_u32(data, 12),
        })
    }
}

#[derive(Debug, Clone)]
struct CommonMetadataV01 {
    base: CommonMetadataV00,
    zi_segment_hash_algorithm: u32,
}

impl CommonMetadataV01 {
    const SIZE: usize = 20;

    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        let base = CommonMetadataV00::from_bytes(data)?;
        if data.len() < Self::SIZE {
            return Err("Insufficient data for CommonMetadataV01");
        }
        Ok(Self {
            base,
            zi_segment_hash_algorithm: read_le_u32(data, 16),
        })
    }
}

impl CommonMetadata {
    fn from_bytes(data: &[u8], major: u32, minor: u32) -> Result<Self, &'static str> {
        match (major, minor) {
            (0, 0) => Ok(CommonMetadata::V00(CommonMetadataV00::from_bytes(data)?)),
            (0, 1) => Ok(CommonMetadata::V01(CommonMetadataV01::from_bytes(data)?)),
            _ => Err("Unknown common metadata version"),
        }
    }

    fn get_version_string(&self) -> String {
        match self {
            CommonMetadata::V00(m) => format!("{}.{}", m.major_version, m.minor_version),
            CommonMetadata::V01(m) => format!("{}.{}", m.base.major_version, m.base.minor_version),
        }
    }
}

// ============================================================================
// mbn.rs (inlined from arb_inspector_next)
// ============================================================================

#[derive(Debug, Clone)]
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

#[derive(Debug)]
struct Mbn {
    header: MbnHeader,
    code: Vec<u8>,
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
        Ok(Self { header, code })
    }
}

// ============================================================================
// HashTableSegmentHeader & ElfWithHashTable (core logic from arb_inspector_next)
// ============================================================================

#[derive(Debug, Clone)]
struct HashTableSegmentHeader {
    reserved: u32,
    version: u32,
    common_metadata_size: u32,
    qti_metadata_size: u32,
    oem_metadata_size: u32,
    hash_table_size: u32,
    qti_sig_size: u32,
    qti_cert_chain_size: u32,
    oem_sig_size: u32,
    oem_cert_chain_size: u32,
}

impl HashTableSegmentHeader {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < HASH_TABLE_HEADER_SIZE {
            return Err("Insufficient data for hash table header");
        }
        Ok(Self {
            reserved: read_le_u32(data, 0),
            version: read_le_u32(data, 4),
            common_metadata_size: read_le_u32(data, 8),
            qti_metadata_size: read_le_u32(data, 12),
            oem_metadata_size: read_le_u32(data, 16),
            hash_table_size: read_le_u32(data, 20),
            qti_sig_size: read_le_u32(data, 24),
            qti_cert_chain_size: read_le_u32(data, 28),
            oem_sig_size: read_le_u32(data, 32),
            oem_cert_chain_size: read_le_u32(data, 36),
        })
    }

    fn is_plausible(&self) -> bool {
        let common_sz = self.common_metadata_size as usize;
        let qti_sz = self.qti_metadata_size as usize;
        let oem_sz = self.oem_metadata_size as usize;
        let hash_sz = self.hash_table_size as usize;

        (VERSION_MIN..=VERSION_MAX).contains(&self.version)
            && common_sz <= COMMON_SIZE_MAX
            && qti_sz <= QTI_SIZE_MAX
            && oem_sz <= OEM_SIZE_MAX
            && hash_sz > 0
            && hash_sz <= HASH_TABLE_SIZE_MAX
    }

    fn header_size(&self) -> usize {
        HASH_TABLE_HEADER_SIZE
    }
}

#[derive(Debug)]
struct ElfInfo {
    elf_class: u8,
    e_entry: u64,
    e_phoff: u64,
    e_phnum: u16,
    e_phentsize: u16,
    e_flags: u32,
    e_machine: u16,
    e_type: u16,
}

#[derive(Debug)]
struct ProgramHeaderInfo {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
}

#[derive(Debug)]
struct HashTableInfo {
    header: HashTableSegmentHeader,
    common_metadata: Option<CommonMetadata>,
    oem_metadata: Option<Metadata>,
    serial_num: Option<u32>,
    hashes: Vec<Vec<u8>>,
}

struct ElfWithHashTable {
    elf_info: ElfInfo,
    program_headers: Vec<ProgramHeaderInfo>,
    hash_table_info: Option<HashTableInfo>,
}

#[inline]
fn get_os_segment_type(flags: u32) -> u32 {
    (flags & PF_OS_SEGMENT_TYPE_MASK) >> 24
}

#[inline]
fn get_os_access_type(flags: u32) -> u32 {
    (flags & PF_OS_ACCESS_TYPE_MASK) >> 21
}

#[inline]
fn get_os_page_mode(flags: u32) -> u32 {
    (flags & PF_OS_PAGE_MODE_MASK) >> 20
}

#[inline]
fn get_perm_value(flags: u32) -> u32 {
    flags & PF_PERM_MASK
}

fn perm_to_string(perm: u32) -> &'static str {
    match perm {
        0x1 => "E",
        0x2 => "W",
        0x3 => "WE",
        0x4 => "R",
        0x5 => "RE",
        0x6 => "RW",
        0x7 => "RWE",
        _ => "None",
    }
}

fn os_segment_type_to_string(seg_type: u32) -> &'static str {
    match seg_type {
        PF_OS_SEGMENT_HASH => "HASH",
        PF_OS_SEGMENT_PHDR => "PHDR",
        0x0 => "L4",
        0x1 => "AMSS",
        0x3 => "BOOT",
        0x4 => "L4BSP",
        0x5 => "SWAPPED",
        0x6 => "SWAP_POOL",
        _ => "Unknown",
    }
}

fn os_access_type_to_string(access_type: u32) -> &'static str {
    match access_type {
        PF_OS_ACCESS_RW => "RW",
        PF_OS_ACCESS_RO => "RO",
        PF_OS_ACCESS_ZI => "ZI",
        PF_OS_ACCESS_NOTUSED => "NOTUSED",
        PF_OS_ACCESS_SHARED => "SHARED",
        _ => "Unknown",
    }
}

fn os_page_mode_to_string(page_mode: u32) -> &'static str {
    match page_mode {
        PF_OS_NON_PAGED_SEGMENT => "NON_PAGED",
        PF_OS_PAGED_SEGMENT => "PAGED",
        _ => "Unknown",
    }
}

fn p_type_to_string(p_type: u32) -> &'static str {
    match p_type {
        PT_NULL => "NULL",
        PT_LOAD => "LOAD",
        PT_NOTE => "NOTE",
        PT_PHDR => "PHDR",
        _ => "OTHER",
    }
}

impl ElfWithHashTable {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 16 || &data[0..4] != &ELF_MAGIC {
            return Err("Invalid ELF magic");
        }

        let elf_class = data[EI_CLASS];
        let elf_info = match elf_class {
            ELFCLASS32 => {
                if data.len() < ELF32_HDR_SIZE {
                    return Err("Insufficient data for ELF32 header");
                }
                ElfInfo {
                    elf_class,
                    e_type: read_le_u16(data, 16),
                    e_machine: read_le_u16(data, 18),
                    e_entry: read_le_u32(data, 24) as u64,
                    e_phoff: read_le_u32(data, 28) as u64,
                    e_flags: read_le_u32(data, 36),
                    e_phnum: read_le_u16(data, 44),
                    e_phentsize: read_le_u16(data, 42),
                }
            }
            ELFCLASS64 => {
                if data.len() < ELF64_HDR_SIZE {
                    return Err("Insufficient data for ELF64 header");
                }
                ElfInfo {
                    elf_class,
                    e_type: read_le_u16(data, 16),
                    e_machine: read_le_u16(data, 18),
                    e_entry: read_le_u64(data, 24),
                    e_phoff: read_le_u64(data, 32),
                    e_flags: read_le_u32(data, 48),
                    e_phnum: read_le_u16(data, 56),
                    e_phentsize: read_le_u16(data, 54),
                }
            }
            _ => return Err("Unsupported ELF class"),
        };

        let mut program_headers = Vec::with_capacity(elf_info.e_phnum as usize);
        for i in 0..elf_info.e_phnum {
            let offset = (elf_info.e_phoff + (i as u64) * (elf_info.e_phentsize as u64)) as usize;
            if offset + (elf_info.e_phentsize as usize) > data.len() {
                continue;
            }

            let phdr_info = match elf_class {
                ELFCLASS32 => {
                    if data.len() < offset + ELF32_PHDR_SIZE {
                        continue;
                    }
                    let p_type = read_le_u32(data, offset);
                    let p_offset = read_le_u32(data, offset + 4);
                    let p_vaddr = read_le_u32(data, offset + 8);
                    let p_paddr = read_le_u32(data, offset + 12);
                    let p_filesz = read_le_u32(data, offset + 16);
                    let p_memsz = read_le_u32(data, offset + 20);
                    let p_flags = read_le_u32(data, offset + 24);
                    let p_align = read_le_u32(data, offset + 28);
                    ProgramHeaderInfo {
                        p_type,
                        p_flags,
                        p_offset: p_offset as u64,
                        p_vaddr: p_vaddr as u64,
                        p_paddr: p_paddr as u64,
                        p_filesz: p_filesz as u64,
                        p_memsz: p_memsz as u64,
                    }
                }
                ELFCLASS64 => {
                    if data.len() < offset + ELF64_PHDR_SIZE {
                        continue;
                    }
                    let p_type = read_le_u32(data, offset);
                    let p_flags = read_le_u32(data, offset + 4);
                    let p_offset = read_le_u64(data, offset + 8);
                    let p_vaddr = read_le_u64(data, offset + 16);
                    let p_paddr = read_le_u64(data, offset + 24);
                    let p_filesz = read_le_u64(data, offset + 32);
                    let p_memsz = read_le_u64(data, offset + 40);
                    let p_align = read_le_u64(data, offset + 48);
                    ProgramHeaderInfo {
                        p_type,
                        p_flags,
                        p_offset,
                        p_vaddr,
                        p_paddr,
                        p_filesz,
                        p_memsz,
                    }
                }
                _ => unreachable!(),
            };
            program_headers.push(phdr_info);
        }

        let mut hash_table_info = None;

        for phdr in &program_headers {
            let os_type = get_os_segment_type(phdr.p_flags);
            if os_type == OS_TYPE_HASH {
                let p_offset = phdr.p_offset as usize;
                let p_filesz = phdr.p_filesz as usize;

                if p_offset + p_filesz <= data.len() && p_filesz >= HASH_TABLE_HEADER_SIZE {
                    let header_size_to_read = HASH_TABLE_HEADER_SIZE_V7.min(p_filesz);
                    if let Ok(ht_header) = HashTableSegmentHeader::from_bytes(
                        &data[p_offset..p_offset + header_size_to_read],
                    ) {
                        if ht_header.is_plausible() {
                            let header_size = ht_header.header_size();
                            let mut offset = p_offset + header_size;

                            let mut common_metadata = None;
                            let mut oem_metadata = None;
                            let mut serial_num = None;
                            let mut hashes = Vec::new();

                            // Parse common metadata
                            if ht_header.common_metadata_size > 0
                                && offset + ht_header.common_metadata_size as usize <= data.len()
                            {
                                let cm_data =
                                    &data[offset..offset + ht_header.common_metadata_size as usize];
                                if cm_data.len() >= 8 {
                                    let cm_major = read_le_u32(cm_data, 0);
                                    let cm_minor = read_le_u32(cm_data, 4);
                                    if let Ok(cm) =
                                        CommonMetadata::from_bytes(cm_data, cm_major, cm_minor)
                                    {
                                        common_metadata = Some(cm);
                                    }
                                }
                                offset += ht_header.common_metadata_size as usize;
                            }

                            // Parse OEM metadata
                            if ht_header.oem_metadata_size > 0
                                && offset + ht_header.oem_metadata_size as usize <= data.len()
                            {
                                let oem_data =
                                    &data[offset..offset + ht_header.oem_metadata_size as usize];
                                if oem_data.len() >= 12 {
                                    let oem_major = read_le_u32(oem_data, 0);
                                    let oem_minor = read_le_u32(oem_data, 4);
                                    let arb_candidate = read_le_u32(oem_data, 8);

                                    if ht_header.version == 7
                                        && oem_data.len() >= 12
                                        && arb_candidate <= ARB_VALUE_MAX
                                    {
                                        oem_metadata = Some(Metadata::V20(MetadataV20 {
                                            major_version: oem_major,
                                            minor_version: oem_minor,
                                            anti_rollback_version: arb_candidate,
                                            mrc_index: if oem_data.len() > 12 {
                                                read_le_u32(oem_data, 12)
                                            } else {
                                                0
                                            },
                                            soc_hw_vers: [0; 32],
                                            soc_feature_id: 0,
                                            jtag_id: 0,
                                            serial_numbers: [0; 8],
                                            oem_id: 0,
                                            oem_product_id: 0,
                                            soc_lifecycle_state: 0,
                                            oem_lifecycle_state: 0,
                                            oem_root_certificate_hash_algorithm: 0,
                                            oem_root_certificate_hash: [0; 64],
                                            flags: 0,
                                        }));
                                    } else if let Ok(om) =
                                        Metadata::from_bytes(oem_data, oem_major, oem_minor)
                                    {
                                        oem_metadata = Some(om);
                                    }
                                }
                            }

                            // Parse hash table
                            let hash_table_offset = offset;
                            let hash_table_size = ht_header.hash_table_size as usize;
                            if hash_table_offset + hash_table_size <= data.len()
                                && hash_table_size > 0
                            {
                                let hash_table =
                                    &data[hash_table_offset..hash_table_offset + hash_table_size];

                                let hash_size = SHA256_SIZE;
                                let mut ht_offset = 0;

                                // Try to detect serial number
                                if hash_table.len() >= hash_size * 2 {
                                    let potential_serial = read_le_u32(&hash_table, hash_size);
                                    let mut is_valid_serial = true;
                                    for i in 0..hash_size {
                                        if hash_table[i] != 0 {
                                            is_valid_serial = false;
                                            break;
                                        }
                                    }
                                    if is_valid_serial && potential_serial != 0 {
                                        serial_num = Some(potential_serial);
                                        ht_offset = hash_size * 2;
                                    }
                                }

                                while ht_offset + hash_size <= hash_table.len() {
                                    let hash = hash_table[ht_offset..ht_offset + hash_size].to_vec();
                                    hashes.push(hash);
                                    ht_offset += hash_size;
                                }
                            }

                            hash_table_info = Some(HashTableInfo {
                                header: ht_header,
                                common_metadata,
                                oem_metadata,
                                serial_num,
                                hashes,
                            });
                            break;
                        }
                    }
                }
            }
        }

        Ok(Self {
            elf_info,
            program_headers,
            hash_table_info,
        })
    }

    fn get_arb_version(&self) -> Option<u32> {
        self.hash_table_info
            .as_ref()
            .and_then(|ht| ht.oem_metadata.as_ref().map(|m| m.get_arb_version()))
    }
}

// ============================================================================
// File type detection
// ============================================================================

enum FileType {
    Elf,
    Mbn,
    Unknown,
}

fn detect_file_type(data: &[u8]) -> FileType {
    if data.starts_with(&ELF_MAGIC) {
        FileType::Elf
    } else if data.len() >= 8 {
        let version = read_le_u32(data, 4);
        if [3, 5, 6, 7, 8].contains(&version) {
            FileType::Mbn
        } else {
            FileType::Unknown
        }
    } else {
        FileType::Unknown
    }
}

// ============================================================================
// Extraction logic
// ============================================================================

struct ExtractionResult {
    major: u32,
    minor: u32,
    arb: u32,
    messages: Vec<String>,
}

fn extract_arb_from_path(
    path: &str,
    full_mode: bool,
    debug: bool,
) -> Result<ExtractionResult, String> {
    let mut file =
        File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
    let file_size = file
        .metadata()
        .map_err(|e| format!("Failed to get file size: {}", e))?
        .len();
    if file_size < 64 {
        return Err("File too small to be a valid image".into());
    }

    let mut header_buf = [0u8; 64];
    file.read_exact(&mut header_buf)
        .map_err(|e| format!("Failed to read header: {}", e))?;

    match detect_file_type(&header_buf) {
        FileType::Elf => {
            if debug {
                eprintln!("[DEBUG] Detected ELF file");
            }

            if header_buf[EI_DATA] != ELFDATA2LSB {
                return Err("Not a little-endian ELF file".into());
            }

            let elf_class = header_buf[EI_CLASS];
            if elf_class != ELFCLASS32 && elf_class != ELFCLASS64 {
                return Err("Unsupported ELF class".into());
            }

            if debug {
                eprintln!(
                    "[DEBUG] ELF class: {}",
                    if elf_class == ELFCLASS32 {
                        "32-bit"
                    } else {
                        "64-bit"
                    }
                );
            }

            let mut full_data = Vec::new();
            file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
            file.read_to_end(&mut full_data)
                .map_err(|e| format!("Failed to read file: {}", e))?;

            if debug {
                eprintln!("[DEBUG] Full ELF size: {} bytes", full_data.len());
            }

            let elf_with_hash = ElfWithHashTable::from_bytes(&full_data)?;

            if debug {
                eprintln!(
                    "[DEBUG] ELF entry: 0x{:x}",
                    elf_with_hash.elf_info.e_entry
                );
                eprintln!(
                    "[DEBUG] Program header offset: 0x{:x}",
                    elf_with_hash.elf_info.e_phoff
                );
                eprintln!(
                    "[DEBUG] Program header count: {}",
                    elf_with_hash.elf_info.e_phnum
                );
                eprintln!(
                    "[DEBUG] Program header size: {} bytes",
                    elf_with_hash.elf_info.e_phentsize
                );

                for (i, ph) in elf_with_hash.program_headers.iter().enumerate() {
                    let flags = ph.p_flags;
                    let perm = get_perm_value(flags);
                    let os_seg = get_os_segment_type(flags);
                    let os_access = get_os_access_type(flags);
                    let os_page = get_os_page_mode(flags);
                    eprintln!(
                        "[DEBUG] PH[{}]: type={:#x} offset=0x{:x} filesz=0x{:x} flags={:#x}",
                        i, ph.p_type, ph.p_offset, ph.p_filesz, flags
                    );
                    eprintln!(
                        "[DEBUG]        Perm: {} OS_Seg: {} OS_Access: {} Page: {}",
                        perm_to_string(perm),
                        os_segment_type_to_string(os_seg),
                        os_access_type_to_string(os_access),
                        os_page_mode_to_string(os_page)
                    );
                }
            }

            let arb = elf_with_hash.get_arb_version();

            if debug {
                if let Some(ref ht) = elf_with_hash.hash_table_info {
                    eprintln!("[DEBUG] Found HASH segment header:");
                    eprintln!("[DEBUG]   version: {}", ht.header.version);
                    eprintln!(
                        "[DEBUG]   common_metadata_size: {}",
                        ht.header.common_metadata_size
                    );
                    eprintln!(
                        "[DEBUG]   oem_metadata_size: {}",
                        ht.header.oem_metadata_size
                    );
                    eprintln!(
                        "[DEBUG]   hash_table_size: {}",
                        ht.header.hash_table_size
                    );
                } else {
                    eprintln!("[DEBUG] No HASH segment header found");
                }

                if let Some(arb_val) = arb {
                    eprintln!("[DEBUG] Extracted ARB: {}", arb_val);
                }
            }

            let mut messages = Vec::new();

            if full_mode {
                messages.push(format!("File: {}", path));
                messages.push(format!(
                    "Format: ELF ({})",
                    if elf_class == ELFCLASS32 {
                        "32-bit"
                    } else {
                        "64-bit"
                    }
                ));
                messages.push(format!(
                    "Entry point: 0x{:x}",
                    elf_with_hash.elf_info.e_entry
                ));
                messages.push(format!(
                    "Program headers: {}",
                    elf_with_hash.elf_info.e_phnum
                ));

                for (i, phdr) in elf_with_hash.program_headers.iter().enumerate() {
                    messages.push(format!(
                        "  [{}] Type: {} Offset: 0x{:x} VAddr: 0x{:x} FileSize: 0x{:x} MemSize: 0x{:x}",
                        i,
                        p_type_to_string(phdr.p_type),
                        phdr.p_offset,
                        phdr.p_vaddr,
                        phdr.p_filesz,
                        phdr.p_memsz
                    ));
                    let flags = phdr.p_flags;
                    let perm = get_perm_value(flags);
                    let os_seg_type = get_os_segment_type(flags);
                    let os_access = get_os_access_type(flags);
                    let os_page_mode = get_os_page_mode(flags);
                    messages.push(format!(
                        "      Flags: {:#x} Perm: {} OS_Type: {} OS_Access: {} Page_Mode: {}",
                        flags,
                        perm_to_string(perm),
                        os_segment_type_to_string(os_seg_type),
                        os_access_type_to_string(os_access),
                        os_page_mode_to_string(os_page_mode)
                    ));
                }

                if let Some(ref ht) = elf_with_hash.hash_table_info {
                    messages.push("Hash Table Segment Header:".to_string());
                    messages.push(format!("  Version: {}", ht.header.version));
                    messages.push(format!(
                        "  Common Metadata Size: {}",
                        ht.header.common_metadata_size
                    ));
                    messages.push(format!(
                        "  OEM Metadata Size: {}",
                        ht.header.oem_metadata_size
                    ));
                    messages.push(format!(
                        "  Hash Table Size: {}",
                        ht.header.hash_table_size
                    ));

                    if let Some(ref cm) = ht.common_metadata {
                        messages.push(format!(
                            "  Common Metadata Version: {}",
                            cm.get_version_string()
                        ));
                    }
                    if let Some(ref om) = ht.oem_metadata {
                        messages.push(format!(
                            "  OEM Metadata Version: {}",
                            om.get_version_string()
                        ));
                    }
                }

                if let Some(arb_val) = arb {
                    if arb_val <= ARB_VALUE_MAX {
                        messages.push(format!("Anti-Rollback Version: {}", arb_val));
                    } else {
                        messages.push(format!(
                            "Warning: ARB value {} exceeds expected maximum.",
                            arb_val
                        ));
                        messages.push(format!("Anti-Rollback Version: {}", arb_val));
                    }
                } else {
                    messages.push("Anti-Rollback Version: not present".to_string());
                }
            }

            let (major, minor, arb_val) = if let Some(arb_val) = arb {
                if full_mode && arb_val > ARB_VALUE_MAX {
                    eprintln!(
                        "Warning: ARB value {} exceeds expected maximum.",
                        arb_val
                    );
                }
                (0, 0, arb_val)
            } else {
                if !full_mode {
                    eprintln!("No ARB version found in the image");
                }
                (0, 0, 0)
            };

            Ok(ExtractionResult {
                major,
                minor,
                arb: arb_val,
                messages,
            })
        }
        FileType::Mbn => {
            if debug {
                eprintln!("[DEBUG] Detected MBN file");
            }
            file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
            let mut full_data = Vec::new();
            file.read_to_end(&mut full_data)
                .map_err(|e| e.to_string())?;

            if debug {
                eprintln!("[DEBUG] Full MBN size: {} bytes", full_data.len());
            }

            let mbn = Mbn::from_bytes(&full_data)?;

            if debug {
                eprintln!("[DEBUG] MBN version: {}", mbn.header.version);
                eprintln!("[DEBUG] Image ID: 0x{:x}", mbn.header.image_id);
                eprintln!("[DEBUG] Code size: {}", mbn.header.code_size);
                eprintln!("[DEBUG] Image size: {}", mbn.header.image_size);
                eprintln!(
                    "[DEBUG] Signature ptr: 0x{:x}",
                    mbn.header.sig_ptr
                );
                eprintln!("[DEBUG] Signature size: {}", mbn.header.sig_size);
                eprintln!(
                    "[DEBUG] Certificate chain ptr: 0x{:x}",
                    mbn.header.cert_chain_ptr
                );
                eprintln!(
                    "[DEBUG] Certificate chain size: {}",
                    mbn.header.cert_chain_size
                );
            }

            let mut messages = Vec::new();

            if full_mode {
                messages.push(format!("File: {}", path));
                messages.push(format!("Format: MBN v{}", mbn.header.version));
                messages.push(format!("Image ID: 0x{:x}", mbn.header.image_id));
                messages.push(format!("Code size: {} bytes", mbn.header.code_size));
                messages.push(format!(
                    "Image size: {} bytes",
                    mbn.header.image_size
                ));
                messages.push(format!(
                    "Signature ptr: 0x{:x}, size: {}",
                    mbn.header.sig_ptr, mbn.header.sig_size
                ));
                messages.push(format!(
                    "Certificate chain ptr: 0x{:x}, size: {}",
                    mbn.header.cert_chain_ptr, mbn.header.cert_chain_size
                ));
                messages.push("ARB: not applicable".to_string());
            } else {
                messages.push("MBN format does not contain ARB field".to_string());
            }

            Ok(ExtractionResult {
                major: 0,
                minor: 0,
                arb: 0,
                messages,
            })
        }
        FileType::Unknown => Err("Unknown file format (not ELF or MBN)".into()),
    }
}

// ============================================================================
// JNI helpers
// ============================================================================

fn create_error_result<'local>(
    env: &mut JNIEnv<'local>,
    error_msg: &str,
) -> Result<JObject<'local>, String> {
    let arb_result_class = env
        .find_class("com/dere3046/arbinspector/ArbResult")
        .map_err(|e| format!("Failed to find ArbResult class: {}", e))?;
    let arb_result = env
        .new_object(arb_result_class, "()V", &[])
        .map_err(|e| format!("Failed to create ArbResult object: {}", e))?;

    let jerr = env
        .new_string(error_msg)
        .map_err(|e| format!("Failed to create error string: {}", e))?;
    env.set_field(
        &arb_result,
        "error",
        "Ljava/lang/String;",
        JValue::Object(&jerr),
    )
    .map_err(|e| format!("Failed to set error field: {}", e))?;

    let array_list_class = env
        .find_class("java/util/ArrayList")
        .map_err(|e| format!("Failed to find ArrayList class: {}", e))?;
    let array_list = env
        .new_object(array_list_class, "()V", &[])
        .map_err(|e| format!("Failed to create ArrayList: {}", e))?;
    env.set_field(
        &arb_result,
        "debugMessages",
        "Ljava/util/List;",
        JValue::Object(&array_list),
    )
    .map_err(|e| format!("Failed to set debugMessages field: {}", e))?;

    Ok(arb_result)
}

// ============================================================================
// JNI entry points (signatures unchanged)
// ============================================================================

#[no_mangle]
pub extern "system" fn Java_com_dere3046_arbinspector_ArbInspector_getVersion<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> JString<'local> {
    let version = env!("CARGO_PKG_VERSION");
    env.new_string(version).unwrap()
}

#[no_mangle]
pub extern "system" fn Java_com_dere3046_arbinspector_ArbInspector_extract<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    path: JString<'local>,
    debug: jboolean,
    block_mode: jboolean,
) -> jobject {
    let _ = block_mode; // kept for API compatibility

    let result = (|| -> Result<JObject<'local>, String> {
        let path_str: String = env
            .get_string(&path)
            .map_err(|e| format!("Failed to get path string: {}", e))?
            .into();
        let debug = debug != 0;

        let extraction = extract_arb_from_path(&path_str, false, debug)?;

        let arb_result_class = env
            .find_class("com/dere3046/arbinspector/ArbResult")
            .map_err(|e| format!("Failed to find ArbResult class: {}", e))?;
        let arb_result = env
            .new_object(arb_result_class, "()V", &[])
            .map_err(|e| format!("Failed to create ArbResult object: {}", e))?;

        env.set_field(
            &arb_result,
            "major",
            "I",
            JValue::Int(extraction.major as jint),
        )
        .map_err(|e| format!("Failed to set major field: {}", e))?;
        env.set_field(
            &arb_result,
            "minor",
            "I",
            JValue::Int(extraction.minor as jint),
        )
        .map_err(|e| format!("Failed to set minor field: {}", e))?;
        env.set_field(
            &arb_result,
            "arb",
            "I",
            JValue::Int(extraction.arb as jint),
        )
        .map_err(|e| format!("Failed to set arb field: {}", e))?;

        let array_list_class = env
            .find_class("java/util/ArrayList")
            .map_err(|e| format!("Failed to find ArrayList class: {}", e))?;
        let array_list = env
            .new_object(array_list_class, "()V", &[])
            .map_err(|e| format!("Failed to create ArrayList: {}", e))?;

        for msg in extraction.messages {
            let jmsg = env
                .new_string(&msg)
                .map_err(|e| format!("Failed to create Java string: {}", e))?;
            env.call_method(
                &array_list,
                "add",
                "(Ljava/lang/Object;)Z",
                &[JValue::Object(&jmsg)],
            )
            .map_err(|e| format!("Failed to add message to list: {}", e))?;
        }

        env.set_field(
            &arb_result,
            "debugMessages",
            "Ljava/util/List;",
            JValue::Object(&array_list),
        )
        .map_err(|e| format!("Failed to set debugMessages field: {}", e))?;
        env.set_field(
            &arb_result,
            "error",
            "Ljava/lang/String;",
            JValue::Object(&JObject::null()),
        )
        .map_err(|e| format!("Failed to set error field: {}", e))?;

        Ok(arb_result)
    })();

    match result {
        Ok(obj) => obj.as_raw(),
        Err(err_msg) => match create_error_result(&mut env, &err_msg) {
            Ok(err_obj) => err_obj.as_raw(),
            Err(fatal) => panic!("Fatal JNI error: {}", fatal),
        },
    }
}

#[no_mangle]
pub extern "system" fn Java_com_dere3046_arbinspector_ArbInspector_extractWithMode<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    path: JString<'local>,
    full_mode: jboolean,
    debug: jboolean,
) -> jobject {
    let result = (|| -> Result<JObject<'local>, String> {
        let path_str: String = env
            .get_string(&path)
            .map_err(|e| format!("Failed to get path string: {}", e))?
            .into();
        let full_mode = full_mode != 0;
        let debug = debug != 0;

        let extraction = extract_arb_from_path(&path_str, full_mode, debug)?;

        let arb_result_class = env
            .find_class("com/dere3046/arbinspector/ArbResult")
            .map_err(|e| format!("Failed to find ArbResult class: {}", e))?;
        let arb_result = env
            .new_object(arb_result_class, "()V", &[])
            .map_err(|e| format!("Failed to create ArbResult object: {}", e))?;

        env.set_field(
            &arb_result,
            "major",
            "I",
            JValue::Int(extraction.major as jint),
        )
        .map_err(|e| format!("Failed to set major field: {}", e))?;
        env.set_field(
            &arb_result,
            "minor",
            "I",
            JValue::Int(extraction.minor as jint),
        )
        .map_err(|e| format!("Failed to set minor field: {}", e))?;
        env.set_field(
            &arb_result,
            "arb",
            "I",
            JValue::Int(extraction.arb as jint),
        )
        .map_err(|e| format!("Failed to set arb field: {}", e))?;

        let array_list_class = env
            .find_class("java/util/ArrayList")
            .map_err(|e| format!("Failed to find ArrayList class: {}", e))?;
        let array_list = env
            .new_object(array_list_class, "()V", &[])
            .map_err(|e| format!("Failed to create ArrayList: {}", e))?;

        for msg in extraction.messages {
            let jmsg = env
                .new_string(&msg)
                .map_err(|e| format!("Failed to create Java string: {}", e))?;
            env.call_method(
                &array_list,
                "add",
                "(Ljava/lang/Object;)Z",
                &[JValue::Object(&jmsg)],
            )
            .map_err(|e| format!("Failed to add message to list: {}", e))?;
        }

        env.set_field(
            &arb_result,
            "debugMessages",
            "Ljava/util/List;",
            JValue::Object(&array_list),
        )
        .map_err(|e| format!("Failed to set debugMessages field: {}", e))?;
        env.set_field(
            &arb_result,
            "error",
            "Ljava/lang/String;",
            JValue::Object(&JObject::null()),
        )
        .map_err(|e| format!("Failed to set error field: {}", e))?;

        Ok(arb_result)
    })();

    match result {
        Ok(obj) => obj.as_raw(),
        Err(err_msg) => match create_error_result(&mut env, &err_msg) {
            Ok(err_obj) => err_obj.as_raw(),
            Err(fatal) => panic!("Fatal JNI error: {}", fatal),
        },
    }
}
