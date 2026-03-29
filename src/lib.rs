use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use jni::objects::{JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jint, jobject};
use jni::JNIEnv;

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;

const PT_NULL: u32 = 0;
const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;

const ELF32_HDR_SIZE: usize = 52;
const ELF64_HDR_SIZE: usize = 64;
const ELF32_PHDR_SIZE: usize = 32;
const ELF64_PHDR_SIZE: usize = 56;

const HASH_TABLE_HEADER_SIZE: usize = 40;
const OS_TYPE_HASH: u32 = 2;

const VERSION_MIN: u32 = 1;
const VERSION_MAX: u32 = 1000;
const COMMON_SIZE_MAX: usize = 0x1000;
const QTI_SIZE_MAX: usize = 0x1000;
const OEM_SIZE_MAX: usize = 0x4000;
const HASH_TABLE_SIZE_MAX: usize = 0x10000;
const ARB_VALUE_MAX: u32 = 127;

const MBN_HDR_SIZE: usize = 40;
const MBN_V7_HDR_SIZE: usize = 64;
const MBN_V8_HDR_SIZE: usize = 80;

#[inline]
fn read_le_u16(buf: &[u8], off: usize) -> Result<u16, &'static str> {
    if off + 2 > buf.len() {
        return Err("Buffer too short for u16");
    }
    Ok(u16::from_le_bytes([buf[off], buf[off + 1]]))
}

#[inline]
fn read_le_u32(buf: &[u8], off: usize) -> Result<u32, &'static str> {
    if off + 4 > buf.len() {
        return Err("Buffer too short for u32");
    }
    Ok(u32::from_le_bytes([
        buf[off], buf[off + 1], buf[off + 2], buf[off + 3],
    ]))
}

#[inline]
fn read_le_u64(buf: &[u8], off: usize) -> Result<u64, &'static str> {
    if off + 8 > buf.len() {
        return Err("Buffer too short for u64");
    }
    Ok(u64::from_le_bytes([
        buf[off], buf[off + 1], buf[off + 2], buf[off + 3],
        buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7],
    ]))
}

trait ElfHeaderTrait {
    fn e_entry(&self) -> u64;
    fn e_phoff(&self) -> u64;
    fn e_phentsize(&self) -> u16;
    fn e_phnum(&self) -> u16;
}

struct Elf32Header {
    e_entry: u32,
    e_phoff: u32,
    e_phentsize: u16,
    e_phnum: u16,
}

impl Elf32Header {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < ELF32_HDR_SIZE {
            return Err("Insufficient data for ELF32 header");
        }
        Ok(Self {
            e_entry: read_le_u32(data, 24)?,
            e_phoff: read_le_u32(data, 28)?,
            e_phentsize: read_le_u16(data, 42)?,
            e_phnum: read_le_u16(data, 44)?,
        })
    }
}

impl ElfHeaderTrait for Elf32Header {
    fn e_entry(&self) -> u64 { self.e_entry as u64 }
    fn e_phoff(&self) -> u64 { self.e_phoff as u64 }
    fn e_phentsize(&self) -> u16 { self.e_phentsize }
    fn e_phnum(&self) -> u16 { self.e_phnum }
}

struct Elf64Header {
    e_entry: u64,
    e_phoff: u64,
    e_phentsize: u16,
    e_phnum: u16,
}

impl Elf64Header {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < ELF64_HDR_SIZE {
            return Err("Insufficient data for ELF64 header");
        }
        Ok(Self {
            e_entry: read_le_u64(data, 24)?,
            e_phoff: read_le_u64(data, 32)?,
            e_phentsize: read_le_u16(data, 54)?,
            e_phnum: read_le_u16(data, 56)?,
        })
    }
}

impl ElfHeaderTrait for Elf64Header {
    fn e_entry(&self) -> u64 { self.e_entry }
    fn e_phoff(&self) -> u64 { self.e_phoff }
    fn e_phentsize(&self) -> u16 { self.e_phentsize }
    fn e_phnum(&self) -> u16 { self.e_phnum }
}

trait ProgramHeaderTrait {
    fn p_type(&self) -> u32;
    fn p_flags(&self) -> u32;
    fn p_offset(&self) -> u64;
    fn p_vaddr(&self) -> u64;
    fn p_filesz(&self) -> u64;
}

struct Elf32ProgramHeader {
    p_type: u32,
    p_offset: u32,
    p_vaddr: u32,
    p_filesz: u32,
    p_flags: u32,
}

impl Elf32ProgramHeader {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < ELF32_PHDR_SIZE {
            return Err("Insufficient data for ELF32 program header");
        }
        Ok(Self {
            p_type: read_le_u32(data, 0)?,
            p_offset: read_le_u32(data, 4)?,
            p_vaddr: read_le_u32(data, 8)?,
            p_filesz: read_le_u32(data, 16)?,
            p_flags: read_le_u32(data, 24)?,
        })
    }
}

impl ProgramHeaderTrait for Elf32ProgramHeader {
    fn p_type(&self) -> u32 { self.p_type }
    fn p_flags(&self) -> u32 { self.p_flags }
    fn p_offset(&self) -> u64 { self.p_offset as u64 }
    fn p_vaddr(&self) -> u64 { self.p_vaddr as u64 }
    fn p_filesz(&self) -> u64 { self.p_filesz as u64 }
}

struct Elf64ProgramHeader {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_filesz: u64,
}

impl Elf64ProgramHeader {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < ELF64_PHDR_SIZE {
            return Err("Insufficient data for ELF64 program header");
        }
        Ok(Self {
            p_type: read_le_u32(data, 0)?,
            p_flags: read_le_u32(data, 4)?,
            p_offset: read_le_u64(data, 8)?,
            p_vaddr: read_le_u64(data, 16)?,
            p_filesz: read_le_u64(data, 32)?,
        })
    }
}

impl ProgramHeaderTrait for Elf64ProgramHeader {
    fn p_type(&self) -> u32 { self.p_type }
    fn p_flags(&self) -> u32 { self.p_flags }
    fn p_offset(&self) -> u64 { self.p_offset }
    fn p_vaddr(&self) -> u64 { self.p_vaddr }
    fn p_filesz(&self) -> u64 { self.p_filesz }
}

enum ElfFormat {
    Elf32(Elf32Header, Vec<Elf32ProgramHeader>),
    Elf64(Elf64Header, Vec<Elf64ProgramHeader>),
}

struct Elf {
    format: ElfFormat,
}

impl Elf {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 16 || &data[0..4] != ELF_MAGIC {
            return Err("Invalid ELF magic");
        }
        match data[EI_CLASS] {
            ELFCLASS32 => {
                let header = Elf32Header::from_bytes(data)?;
                let phoff = header.e_phoff as usize;
                let phnum = header.e_phnum as usize;
                let phentsize = header.e_phentsize as usize;

                let mut phdrs = Vec::with_capacity(phnum);
                for i in 0..phnum {
                    let offset = phoff + i * phentsize;
                    if offset + phentsize <= data.len() {
                        if let Ok(ph) = Elf32ProgramHeader::from_bytes(&data[offset..offset + phentsize]) {
                            phdrs.push(ph);
                        }
                    }
                }

                Ok(Self {
                    format: ElfFormat::Elf32(header, phdrs),
                })
            }
            ELFCLASS64 => {
                let header = Elf64Header::from_bytes(data)?;
                let phoff = header.e_phoff as usize;
                let phnum = header.e_phnum as usize;
                let phentsize = header.e_phentsize as usize;

                let mut phdrs = Vec::with_capacity(phnum);
                for i in 0..phnum {
                    let offset = phoff + i * phentsize;
                    if offset + phentsize <= data.len() {
                        if let Ok(ph) = Elf64ProgramHeader::from_bytes(&data[offset..offset + phentsize]) {
                            phdrs.push(ph);
                        }
                    }
                }

                Ok(Self {
                    format: ElfFormat::Elf64(header, phdrs),
                })
            }
            _ => Err("Unsupported ELF class"),
        }
    }

    fn phdrs(&self) -> Vec<&dyn ProgramHeaderTrait> {
        match &self.format {
            ElfFormat::Elf32(_, phdrs) => phdrs.iter().map(|p| p as &dyn ProgramHeaderTrait).collect(),
            ElfFormat::Elf64(_, phdrs) => phdrs.iter().map(|p| p as &dyn ProgramHeaderTrait).collect(),
        }
    }

    fn elf_header(&self) -> Option<&dyn ElfHeaderTrait> {
        match &self.format {
            ElfFormat::Elf32(h, _) => Some(h),
            ElfFormat::Elf64(h, _) => Some(h),
        }
    }

    fn elf_class(&self) -> u8 {
        match &self.format {
            ElfFormat::Elf32(_, _) => ELFCLASS32,
            ElfFormat::Elf64(_, _) => ELFCLASS64,
        }
    }
}

#[derive(Clone)]
struct HashTableSegmentHeader {
    version: u32,
    common_metadata_size: u32,
    qti_metadata_size: u32,
    oem_metadata_size: u32,
    hash_table_size: u32,
}

impl HashTableSegmentHeader {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < HASH_TABLE_HEADER_SIZE {
            return Err("Insufficient data for hash table header");
        }
        Ok(Self {
            version: read_le_u32(data, 4)?,
            common_metadata_size: read_le_u32(data, 8)?,
            qti_metadata_size: read_le_u32(data, 12)?,
            oem_metadata_size: read_le_u32(data, 16)?,
            hash_table_size: read_le_u32(data, 20)?,
        })
    }

    fn get_arb_version(&self, oem_metadata: &[u8]) -> Option<u32> {
        if oem_metadata.len() >= 12 {
            read_le_u32(oem_metadata, 8).ok()
        } else {
            None
        }
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
}

struct ElfWithHashTableSegment {
    elf: Elf,
    hash_table_header: Option<HashTableSegmentHeader>,
    oem_metadata: Vec<u8>,
}

impl ElfWithHashTableSegment {
    fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        let elf = Elf::from_bytes(data)?;

        let mut hash_table_header = None;
        let mut oem_metadata = Vec::new();

        if let Some(header) = elf.elf_header() {
            let phoff = header.e_phoff();
            let phnum = header.e_phnum();
            let phentsize = header.e_phentsize();

            for i in 0..phnum {
                let phdr_offset = (phoff + (i as u64) * (phentsize as u64)) as usize;
                if phdr_offset + (phentsize as usize) > data.len() {
                    continue;
                }

                let (p_flags_off, p_offset_off, p_filesz_off) = match elf.elf_class() {
                    ELFCLASS32 => (24, 4, 16),
                    ELFCLASS64 => (4, 8, 32),
                    _ => unreachable!(),
                };

                if phdr_offset + p_flags_off + 4 > data.len() {
                    continue;
                }
                let p_flags = match read_le_u32(data, phdr_offset + p_flags_off) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let os_type = (p_flags >> 24) & 0x7;

                if os_type == OS_TYPE_HASH {
                    if phdr_offset + p_offset_off + 8 > data.len() {
                        continue;
                    }
                    let p_offset = match elf.elf_class() {
                        ELFCLASS32 => read_le_u32(data, phdr_offset + p_offset_off).map(|v| v as usize),
                        ELFCLASS64 => read_le_u64(data, phdr_offset + p_offset_off).map(|v| v as usize),
                        _ => unreachable!(),
                    };
                    let p_filesz = match elf.elf_class() {
                        ELFCLASS32 => read_le_u32(data, phdr_offset + p_filesz_off).map(|v| v as usize),
                        ELFCLASS64 => read_le_u64(data, phdr_offset + p_filesz_off).map(|v| v as usize),
                        _ => unreachable!(),
                    };
                    if let (Ok(p_offset), Ok(p_filesz)) = (p_offset, p_filesz) {
                        if p_offset + p_filesz <= data.len() && p_filesz >= HASH_TABLE_HEADER_SIZE {
                            if let Ok(ht) = HashTableSegmentHeader::from_bytes(&data[p_offset..p_offset + HASH_TABLE_HEADER_SIZE]) {
                                if ht.is_plausible() {
                                    hash_table_header = Some(ht.clone());

                                    let common_start = p_offset + HASH_TABLE_HEADER_SIZE;
                                    let oem_start = common_start + ht.common_metadata_size as usize;

                                    if oem_start + ht.oem_metadata_size as usize <= data.len() {
                                        oem_metadata = data[oem_start..oem_start + ht.oem_metadata_size as usize].to_vec();
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(Self {
            elf,
            hash_table_header,
            oem_metadata,
        })
    }

    fn get_arb_version(&self) -> Option<u32> {
        if let Some(ref header) = self.hash_table_header {
            header.get_arb_version(&self.oem_metadata)
        } else {
            None
        }
    }
}

struct MbnHeader {
    image_id: u32,
    version: u32,
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
            image_id: read_le_u32(data, 0)?,
            version: read_le_u32(data, 4)?,
            image_size: read_le_u32(data, 16)?,
            code_size: read_le_u32(data, 20)?,
            sig_ptr: read_le_u32(data, 24)?,
            sig_size: read_le_u32(data, 28)?,
            cert_chain_ptr: read_le_u32(data, 32)?,
            cert_chain_size: read_le_u32(data, 36)?,
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
        Ok(Self { header })
    }
}

enum FileType {
    Elf,
    Mbn,
    Unknown,
}

fn detect_file_type(data: &[u8]) -> FileType {
    if data.starts_with(ELF_MAGIC) {
        FileType::Elf
    } else if data.len() >= 8 {
        if let Ok(version) = read_le_u32(data, 4) {
            if [3, 5, 6, 7, 8].contains(&version) {
                return FileType::Mbn;
            }
        }
        FileType::Unknown
    } else {
        FileType::Unknown
    }
}

struct ExtractionResult {
    major: u32,
    minor: u32,
    arb: u32,
    messages: Vec<String>,
}

fn extract_arb_from_path(path: &str, full_mode: bool, debug: bool) -> Result<ExtractionResult, String> {
    let mut file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
    let file_size = file.metadata().map_err(|e| format!("Failed to get file size: {}", e))?.len();
    if file_size < 64 {
        return Err("File too small to be a valid image".into());
    }

    let mut header_buf = [0u8; 64];
    file.read_exact(&mut header_buf).map_err(|e| format!("Failed to read header: {}", e))?;

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
                eprintln!("[DEBUG] ELF class: {}", if elf_class == ELFCLASS32 { "32-bit" } else { "64-bit" });
            }

            let mut full_data = Vec::new();
            file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
            file.read_to_end(&mut full_data).map_err(|e| format!("Failed to read file: {}", e))?;

            if debug {
                eprintln!("[DEBUG] Full ELF size: {} bytes", full_data.len());
            }

            let elf_with_hash = ElfWithHashTableSegment::from_bytes(&full_data)?;

            if debug {
                if let Some(hdr) = elf_with_hash.elf.elf_header() {
                    eprintln!("[DEBUG] ELF entry: 0x{:x}", hdr.e_entry());
                    eprintln!("[DEBUG] Program header offset: 0x{:x}", hdr.e_phoff());
                    eprintln!("[DEBUG] Program header count: {}", hdr.e_phnum());
                    eprintln!("[DEBUG] Program header size: {} bytes", hdr.e_phentsize());
                }

                let phdrs = elf_with_hash.elf.phdrs();
                for (i, ph) in phdrs.iter().enumerate() {
                    eprintln!(
                        "[DEBUG] PH[{}]: type={:#x} offset=0x{:x} filesz=0x{:x} flags={:#x}",
                        i, ph.p_type(), ph.p_offset(), ph.p_filesz(), ph.p_flags()
                    );
                }
            }

            let arb = elf_with_hash.get_arb_version();

            if debug {
                if let Some(ht) = &elf_with_hash.hash_table_header {
                    eprintln!("[DEBUG] Found HASH segment header:");
                    eprintln!("[DEBUG]   version: {}", ht.version);
                    eprintln!("[DEBUG]   common_metadata_size: {}", ht.common_metadata_size);
                    eprintln!("[DEBUG]   oem_metadata_size: {}", ht.oem_metadata_size);
                    eprintln!("[DEBUG]   hash_table_size: {}", ht.hash_table_size);
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
                messages.push(format!("Format: ELF ({})", if elf_class == ELFCLASS32 { "32-bit" } else { "64-bit" }));
                if let Some(hdr) = elf_with_hash.elf.elf_header() {
                    messages.push(format!("Entry point: 0x{:x}", hdr.e_entry()));
                    messages.push(format!("Program headers: {}", hdr.e_phnum()));
                }

                let phdrs = elf_with_hash.elf.phdrs();
                for (i, phdr) in phdrs.iter().enumerate() {
                    messages.push(format!(
                        "  [{}] Type: {} Offset: 0x{:x} VAddr: 0x{:x} FileSize: 0x{:x}",
                        i,
                        match phdr.p_type() {
                            PT_LOAD => "LOAD",
                            PT_NULL => "NULL",
                            PT_NOTE => "NOTE",
                            _ => "OTHER",
                        },
                        phdr.p_offset(),
                        phdr.p_vaddr(),
                        phdr.p_filesz()
                    ));
                }

                if let Some(ref ht) = elf_with_hash.hash_table_header {
                    messages.push("Hash Table Segment Header:".to_string());
                    messages.push(format!("  Version: {}", ht.version));
                    messages.push(format!("  Common Metadata Size: {}", ht.common_metadata_size));
                    messages.push(format!("  OEM Metadata Size: {}", ht.oem_metadata_size));
                    messages.push(format!("  Hash Table Size: {}", ht.hash_table_size));
                }

                if let Some(arb_val) = arb {
                    if arb_val <= ARB_VALUE_MAX {
                        messages.push(format!("Anti-Rollback Version: {}", arb_val));
                    } else {
                        messages.push(format!("Warning: ARB value {} exceeds expected maximum.", arb_val));
                        messages.push(format!("Anti-Rollback Version: {}", arb_val));
                    }
                } else {
                    messages.push("Anti-Rollback Version: not present".to_string());
                }
            }

            let (major, minor, arb_val) = if let Some(arb_val) = arb {
                if full_mode && arb_val > ARB_VALUE_MAX {
                    eprintln!("Warning: ARB value {} exceeds expected maximum.", arb_val);
                }
                (0, 0, arb_val)
            } else {
                if !full_mode {
                    eprintln!("No ARB version found in the image");
                }
                (0, 0, 0)
            };

            if !full_mode {
                if let Some(arb_val) = arb {
                    if arb_val <= ARB_VALUE_MAX {
                        println!("{}", arb_val);
                    } else {
                        eprintln!("Warning: ARB value {} exceeds expected maximum.", arb_val);
                        println!("{}", arb_val);
                    }
                } else {
                    eprintln!("No ARB version found in the image");
                }
            }

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
            file.read_to_end(&mut full_data).map_err(|e| e.to_string())?;

            if debug {
                eprintln!("[DEBUG] Full MBN size: {} bytes", full_data.len());
            }

            let mbn = Mbn::from_bytes(&full_data)?;

            if debug {
                eprintln!("[DEBUG] MBN version: {}", mbn.header.version);
                eprintln!("[DEBUG] Image ID: 0x{:x}", mbn.header.image_id);
                eprintln!("[DEBUG] Code size: {}", mbn.header.code_size);
                eprintln!("[DEBUG] Image size: {}", mbn.header.image_size);
                eprintln!("[DEBUG] Signature ptr: 0x{:x}", mbn.header.sig_ptr);
                eprintln!("[DEBUG] Signature size: {}", mbn.header.sig_size);
                eprintln!("[DEBUG] Certificate chain ptr: 0x{:x}", mbn.header.cert_chain_ptr);
                eprintln!("[DEBUG] Certificate chain size: {}", mbn.header.cert_chain_size);
            }

            let mut messages = Vec::new();

            if full_mode {
                messages.push(format!("File: {}", path));
                messages.push(format!("Format: MBN v{}", mbn.header.version));
                messages.push(format!("Image ID: 0x{:x}", mbn.header.image_id));
                messages.push(format!("Code size: {} bytes", mbn.header.code_size));
                messages.push(format!("Image size: {} bytes", mbn.header.image_size));
                messages.push(format!("Signature ptr: 0x{:x}, size: {}", mbn.header.sig_ptr, mbn.header.sig_size));
                messages.push(format!("Certificate chain ptr: 0x{:x}, size: {}", mbn.header.cert_chain_ptr, mbn.header.cert_chain_size));
                messages.push("ARB: not applicable".to_string());
            } else {
                println!("MBN format does not contain ARB field");
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

fn create_error_result<'local>(env: &mut JNIEnv<'local>, error_msg: &str) -> Result<JObject<'local>, String> {
    let arb_result_class = env
        .find_class("com/dere3046/arbinspector/ArbResult")
        .map_err(|e| format!("Failed to find ArbResult class: {}", e))?;
    let arb_result = env
        .new_object(arb_result_class, "()V", &[])
        .map_err(|e| format!("Failed to create ArbResult object: {}", e))?;

    let jerr = env
        .new_string(error_msg)
        .map_err(|e| format!("Failed to create error string: {}", e))?;
    env.set_field(&arb_result, "error", "Ljava/lang/String;", JValue::Object(&jerr))
        .map_err(|e| format!("Failed to set error field: {}", e))?;

    let array_list_class = env
        .find_class("java/util/ArrayList")
        .map_err(|e| format!("Failed to find ArrayList class: {}", e))?;
    let array_list = env
        .new_object(array_list_class, "()V", &[])
        .map_err(|e| format!("Failed to create ArrayList: {}", e))?;
    env.set_field(&arb_result, "debugMessages", "Ljava/util/List;", JValue::Object(&array_list))
        .map_err(|e| format!("Failed to set debugMessages field: {}", e))?;

    Ok(arb_result)
}

#[no_mangle]
pub extern "system" fn Java_com_dere3046_arbinspector_ArbInspector_getVersion<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> JString<'local> {
    let version = env!("CARGO_PKG_VERSION");
    env.new_string(version).unwrap()
}

#[no_mangle]
pub extern "system" fn Java_com_dere3046_arbinspector_ArbInspector_extract<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    path: JString<'local>,
    debug: jboolean,
    block_mode: jboolean,
) -> jobject {
    let result = (|| -> Result<JObject<'local>, String> {
        let path_str: String = env.get_string(&path)
            .map_err(|e| format!("Failed to get path string: {}", e))?
            .into();
        let debug = debug != 0;
        let _block_mode = block_mode != 0;

        let extraction = extract_arb_from_path(&path_str, false, debug)
            .map_err(|e| e.to_string())?;

        let arb_result_class = env
            .find_class("com/dere3046/arbinspector/ArbResult")
            .map_err(|e| format!("Failed to find ArbResult class: {}", e))?;
        let arb_result = env
            .new_object(arb_result_class, "()V", &[])
            .map_err(|e| format!("Failed to create ArbResult object: {}", e))?;

        env.set_field(&arb_result, "major", "I", JValue::Int(extraction.major as jint))
            .map_err(|e| format!("Failed to set major field: {}", e))?;
        env.set_field(&arb_result, "minor", "I", JValue::Int(extraction.minor as jint))
            .map_err(|e| format!("Failed to set minor field: {}", e))?;
        env.set_field(&arb_result, "arb", "I", JValue::Int(extraction.arb as jint))
            .map_err(|e| format!("Failed to set arb field: {}", e))?;

        let array_list_class = env
            .find_class("java/util/ArrayList")
            .map_err(|e| format!("Failed to find ArrayList class: {}", e))?;
        let array_list = env
            .new_object(array_list_class, "()V", &[])
            .map_err(|e| format!("Failed to create ArrayList: {}", e))?;

        for msg in extraction.messages {
            let jmsg = env
                .new_string(msg)
                .map_err(|e| format!("Failed to create Java string: {}", e))?;
            env.call_method(
                &array_list,
                "add",
                "(Ljava/lang/Object;)Z",
                &[JValue::Object(&jmsg)],
            )
            .map_err(|e| format!("Failed to add message to list: {}", e))?;
        }

        env.set_field(&arb_result, "debugMessages", "Ljava/util/List;", JValue::Object(&array_list))
            .map_err(|e| format!("Failed to set debugMessages field: {}", e))?;
        env.set_field(&arb_result, "error", "Ljava/lang/String;", JValue::Object(&JObject::null()))
            .map_err(|e| format!("Failed to set error field: {}", e))?;

        Ok(arb_result)
    })();

    match result {
        Ok(obj) => obj.as_raw(),
        Err(err_msg) => {
            match create_error_result(&mut env, &err_msg) {
                Ok(err_obj) => err_obj.as_raw(),
                Err(fatal) => panic!("Fatal JNI error: {}", fatal),
            }
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_dere3046_arbinspector_ArbInspector_extractWithMode<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    path: JString<'local>,
    full_mode: jboolean,
    debug: jboolean,
) -> jobject {
    let result = (|| -> Result<JObject<'local>, String> {
        let path_str: String = env.get_string(&path)
            .map_err(|e| format!("Failed to get path string: {}", e))?
            .into();
        let full_mode = full_mode != 0;
        let debug = debug != 0;

        let extraction = extract_arb_from_path(&path_str, full_mode, debug)
            .map_err(|e| e.to_string())?;

        let arb_result_class = env
            .find_class("com/dere3046/arbinspector/ArbResult")
            .map_err(|e| format!("Failed to find ArbResult class: {}", e))?;
        let arb_result = env
            .new_object(arb_result_class, "()V", &[])
            .map_err(|e| format!("Failed to create ArbResult object: {}", e))?;

        env.set_field(&arb_result, "major", "I", JValue::Int(extraction.major as jint))
            .map_err(|e| format!("Failed to set major field: {}", e))?;
        env.set_field(&arb_result, "minor", "I", JValue::Int(extraction.minor as jint))
            .map_err(|e| format!("Failed to set minor field: {}", e))?;
        env.set_field(&arb_result, "arb", "I", JValue::Int(extraction.arb as jint))
            .map_err(|e| format!("Failed to set arb field: {}", e))?;

        let array_list_class = env
            .find_class("java/util/ArrayList")
            .map_err(|e| format!("Failed to find ArrayList class: {}", e))?;
        let array_list = env
            .new_object(array_list_class, "()V", &[])
            .map_err(|e| format!("Failed to create ArrayList: {}", e))?;

        for msg in extraction.messages {
            let jmsg = env
                .new_string(msg)
                .map_err(|e| format!("Failed to create Java string: {}", e))?;
            env.call_method(
                &array_list,
                "add",
                "(Ljava/lang/Object;)Z",
                &[JValue::Object(&jmsg)],
            )
            .map_err(|e| format!("Failed to add message to list: {}", e))?;
        }

        env.set_field(&arb_result, "debugMessages", "Ljava/util/List;", JValue::Object(&array_list))
            .map_err(|e| format!("Failed to set debugMessages field: {}", e))?;
        env.set_field(&arb_result, "error", "Ljava/lang/String;", JValue::Object(&JObject::null()))
            .map_err(|e| format!("Failed to set error field: {}", e))?;

        Ok(arb_result)
    })();

    match result {
        Ok(obj) => obj.as_raw(),
        Err(err_msg) => {
            match create_error_result(&mut env, &err_msg) {
                Ok(err_obj) => err_obj.as_raw(),
                Err(fatal) => panic!("Fatal JNI error: {}", fatal),
            }
        }
    }
}