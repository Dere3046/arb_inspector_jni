use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use jni::objects::{JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jint, jobject};
use jni::JNIEnv;

use arb_inspector_lib::elf::defines as elf_defs;
use arb_inspector_lib::elf::parser::ElfParser;
use arb_inspector_lib::hash_segment::defines as hs_defs;
use arb_inspector_lib::hash_segment::metadata::{CommonMetadata, Metadata};
use arb_inspector_lib::hash_segment::parser::{HashSegmentInfo, SignatureStatus};
use arb_inspector_lib::mbn::parser::MbnParser;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn detect_file_type(data: &[u8]) -> FileType {
    if data.starts_with(&elf_defs::ELFMAG) {
        FileType::Elf
    } else if data.len() >= 8 {
        let version = arb_inspector_lib::data::read_le_u32(data, 4);
        if hs_defs::is_valid_hash_segment_version(version) {
            FileType::Mbn
        } else {
            FileType::Unknown
        }
    } else {
        FileType::Unknown
    }
}

enum FileType {
    Elf,
    Mbn,
    Unknown,
}

fn extract_metadata(
    path: &str,
    full_mode: bool,
    debug: bool,
) -> Result<(u32, u32, u32, Vec<String>), String> {
    let mut file = File::open(path).map_err(|e| format!("Failed to open file: {}", e))?;
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
            if header_buf[elf_defs::EI_DATA] != elf_defs::ELFDATA2LSB {
                return Err("Not a little-endian ELF file".into());
            }

            let elf_class = header_buf[elf_defs::EI_CLASS];
            if elf_class != elf_defs::ELFCLASS32 && elf_class != elf_defs::ELFCLASS64 {
                return Err("Unsupported ELF class".into());
            }

            if debug {
                eprintln!(
                    "[DEBUG] ELF class: {}",
                    if elf_class == elf_defs::ELFCLASS32 { "32-bit" } else { "64-bit" }
                );
            }

            let mut full_data = Vec::new();
            file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
            file.read_to_end(&mut full_data)
                .map_err(|e| format!("Failed to read file: {}", e))?;

            if debug {
                eprintln!("[DEBUG] Full ELF size: {} bytes", full_data.len());
            }

            let parser = ElfParser::from_bytes(&full_data)
                .map_err(|e| format!("ELF parse error: {}", e))?;

            if debug {
                eprintln!("[DEBUG] ELF entry: 0x{:x}", parser.header.e_entry);
                eprintln!("[DEBUG] Program header offset: 0x{:x}", parser.header.e_phoff);
                eprintln!("[DEBUG] Program header count: {}", parser.header.e_phnum);
                eprintln!("[DEBUG] Program header size: {} bytes", parser.header.e_phentsize);

                for (i, ph) in parser.program_headers.iter().enumerate() {
                    let flags = ph.p_flags;
                    let perm = elf_defs::get_perm_value(flags);
                    let os_seg = elf_defs::os_segment_type_to_string(elf_defs::p_flags_os_segment_type(flags));
                    let os_access = elf_defs::os_access_type_to_string(elf_defs::p_flags_os_access_type(flags));
                    let os_page = elf_defs::os_page_mode_to_string(elf_defs::p_flags_os_page_mode(flags));
                    eprintln!(
                        "[DEBUG] PH[{}]: type={:#x} offset=0x{:x} filesz=0x{:x} flags={:#x}",
                        i, ph.p_type, ph.p_offset, ph.p_filesz, flags
                    );
                    eprintln!(
                        "[DEBUG]        Perm: {} OS_Seg: {} OS_Access: {} Page: {}",
                        perm, os_seg, os_access, os_page
                    );
                }
            }

            let hash_info = if let Some(hash_phdr) = parser.find_hash_segment() {
                let offset = hash_phdr.p_offset as usize;
                match HashSegmentInfo::parse(&full_data, offset) {
                    Ok(Some(info)) => Some(info),
                    Ok(None) => None,
                    Err(e) => {
                        if debug {
                            eprintln!("[DEBUG] Hash segment parse error: {}", e);
                        }
                        None
                    }
                }
            } else {
                if debug {
                    eprintln!("[DEBUG] No HASH segment found");
                }
                None
            };

            let arb = hash_info.as_ref().and_then(|ht| ht.get_arb_version());

            if debug {
                if let Some(ref ht) = hash_info {
                    eprintln!("[DEBUG] Found HASH segment header:");
                    eprintln!("[DEBUG]   version: {}", ht.header.version());
                    eprintln!("[DEBUG]   common_metadata_size: {}", ht.header.common_metadata_size());
                    eprintln!("[DEBUG]   oem_metadata_size: {}", ht.header.oem_metadata_size());
                    eprintln!("[DEBUG]   hash_table_size: {}", ht.header.hash_table_size());

                    match ht.signature_status() {
                        SignatureStatus::Both => eprintln!("[DEBUG]   Signed: Yes (QTI+OEM)"),
                        SignatureStatus::QtiOnly => eprintln!("[DEBUG]   Signed: Yes (QTI only)"),
                        SignatureStatus::OemOnly => eprintln!("[DEBUG]   Signed: Yes (OEM only)"),
                        SignatureStatus::Unsigned => eprintln!("[DEBUG]   Signed: No"),
                    }
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
                    if elf_class == elf_defs::ELFCLASS32 { "32-bit" } else { "64-bit" }
                ));
                messages.push(format!("Entry point: 0x{:x}", parser.header.e_entry));
                messages.push(format!("Program headers: {}", parser.header.e_phnum));

                for (i, phdr) in parser.program_headers.iter().enumerate() {
                    messages.push(format!(
                        "  [{}] Type: {} Offset: 0x{:x} VAddr: 0x{:x} FileSize: 0x{:x} MemSize: 0x{:x}",
                        i,
                        elf_defs::p_type_to_string(phdr.p_type),
                        phdr.p_offset,
                        phdr.p_vaddr,
                        phdr.p_filesz,
                        phdr.p_memsz
                    ));
                    let flags = phdr.p_flags;
                    messages.push(format!(
                        "      Flags: {:#x} Perm: {} OS_Type: {} OS_Access: {} Page_Mode: {}",
                        flags,
                        elf_defs::perm_to_string(elf_defs::get_perm_value(flags)),
                        elf_defs::os_segment_type_to_string(elf_defs::p_flags_os_segment_type(flags)),
                        elf_defs::os_access_type_to_string(elf_defs::p_flags_os_access_type(flags)),
                        elf_defs::os_page_mode_to_string(elf_defs::p_flags_os_page_mode(flags))
                    ));
                }

                if let Some(ref ht) = hash_info {
                    messages.push("Hash Table Segment Header:".to_string());
                    messages.push(format!("  Version: {}", ht.header.version()));
                    messages.push(format!("  Common Metadata Size: {}", ht.header.common_metadata_size()));
                    messages.push(format!("  QTI Metadata Size: {}", ht.header.qti_metadata_size()));
                    messages.push(format!("  OEM Metadata Size: {}", ht.header.oem_metadata_size()));
                    messages.push(format!("  Hash Table Size: {}", ht.header.hash_table_size()));
                    messages.push(format!("  QTI Signature Size: {}", ht.header.qti_signature_size()));
                    messages.push(format!("  QTI Cert Chain Size: {}", ht.header.qti_certificate_chain_size()));
                    messages.push(format!("  OEM Signature Size: {}", ht.header.oem_signature_size()));
                    messages.push(format!("  OEM Cert Chain Size: {}", ht.header.oem_certificate_chain_size()));

                    if let Some(ref cm) = ht.common_metadata {
                        messages.push(format!("  Common Metadata Version: {}", cm.get_version_string()));
                        match cm {
                            CommonMetadata::V00(m) => {
                                messages.push(format!("    Hash Table Algorithm: {}", m.hash_table_algorithm));
                                messages.push(format!("    Measurement Register Target: {}", m.measurement_register_target));
                            }
                            CommonMetadata::V01(m) => {
                                messages.push(format!("    Hash Table Algorithm: {}", m.base.hash_table_algorithm));
                                messages.push(format!("    Measurement Register Target: {}", m.base.measurement_register_target));
                                messages.push(format!("    ZI Segment Hash Algorithm: {}", m.zi_segment_hash_algorithm));
                            }
                        }
                    }
                    if let Some(ref om) = ht.oem_metadata {
                        messages.push(format!("  OEM Metadata Version: {}", om.get_version_string()));
                        messages.push(format!("  OEM Anti-Rollback Version: {}", om.get_arb_version()));
                        match om {
                            Metadata::V00(m) => {
                                messages.push(format!("    Software ID: 0x{:x}", m.software_id));
                                messages.push(format!("    OEM ID: 0x{:x}", m.oem_id));
                                messages.push(format!("    OEM Product ID: 0x{:x}", m.oem_product_id));
                                messages.push(format!("    MRC Index: {}", m.mrc_index));
                                messages.push(format!("    Flags: 0x{:x}", m.flags));
                            }
                            Metadata::V10(m) => {
                                messages.push(format!("    Software ID: 0x{:x}", m.base.software_id));
                                messages.push(format!("    OEM ID: 0x{:x}", m.base.oem_id));
                                messages.push(format!("    OEM Product ID: 0x{:x}", m.base.oem_product_id));
                                messages.push(format!("    MRC Index: {}", m.base.mrc_index));
                                messages.push(format!("    Flags: 0x{:x}", m.base.flags));
                            }
                            Metadata::V20(m) => {
                                messages.push(format!("    SoC Feature ID: 0x{:x}", m.soc_feature_id));
                                messages.push(format!("    OEM ID: 0x{:x}", m.oem_id));
                                messages.push(format!("    OEM Product ID: 0x{:x}", m.oem_product_id));
                                messages.push(format!("    MRC Index: {}", m.mrc_index));
                                messages.push(format!("    SoC Lifecycle State: {}", m.soc_lifecycle_state));
                                messages.push(format!("    OEM Lifecycle State: {}", m.oem_lifecycle_state));
                                messages.push(format!("    OEM Root Cert Hash Algo: {}", m.oem_root_certificate_hash_algorithm));
                                messages.push(format!("    Flags: 0x{:x}", m.flags));
                            }
                            Metadata::V30(m) => {
                                messages.push(format!("    SoC Feature ID: 0x{:x}", m.base.soc_feature_id));
                                messages.push(format!("    OEM ID: 0x{:x}", m.base.oem_id));
                                messages.push(format!("    OEM Product ID: 0x{:x}", m.base.oem_product_id));
                                messages.push(format!("    MRC Index: {}", m.base.mrc_index));
                                messages.push(format!("    SoC Lifecycle State: {}", m.base.soc_lifecycle_state));
                                messages.push(format!("    OEM Lifecycle State: {}", m.base.oem_lifecycle_state));
                                messages.push(format!("    Product Segment ID: 0x{:x}", m.product_segment_id));
                                messages.push(format!("    Flags: 0x{:x}", m.base.flags));
                            }
                            Metadata::V31(m) => {
                                messages.push(format!("    SoC Feature ID: 0x{:x}", m.base.base.soc_feature_id));
                                messages.push(format!("    OEM ID: 0x{:x}", m.base.base.oem_id));
                                messages.push(format!("    OEM Product ID: 0x{:x}", m.base.base.oem_product_id));
                                messages.push(format!("    MRC Index: {}", m.base.base.mrc_index));
                                messages.push(format!("    SoC Lifecycle State: {}", m.base.base.soc_lifecycle_state));
                                messages.push(format!("    OEM Lifecycle State: {}", m.base.base.oem_lifecycle_state));
                                messages.push(format!("    Product Segment ID: 0x{:x}", m.base.product_segment_id));
                                messages.push(format!("    Flags: 0x{:x}", m.base.base.flags));
                            }
                        }
                    }

                    if ht.serial_num.is_some() || !ht.hashes.is_empty() {
                        if let Some(serial) = ht.serial_num {
                            messages.push(format!("  Serial Number: {}", serial));
                        }
                        for (idx, hash) in ht.hashes.iter().enumerate() {
                            let hash_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
                            messages.push(format!("  Hash[{}]: {}", idx, hash_hex));
                        }
                    }
                }

                if let Some(arb_val) = arb {
                    if arb_val <= hs_defs::ARB_VALUE_MAX {
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
                (0, 0, arb_val)
            } else {
                (0, 0, 0)
            };

            Ok((major, minor, arb_val, messages))
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

            let mbn_parser = MbnParser::from_bytes(&full_data)
                .map_err(|e| format!("MBN parse error: {}", e))?;
            let header = &mbn_parser.header;

            if debug {
                eprintln!("[DEBUG] MBN version: {}", header.version());
                eprintln!("[DEBUG] Image ID: 0x{:x}", header.image_id());
                eprintln!("[DEBUG] Code size: {}", header.code_size());
                eprintln!("[DEBUG] Image size: {}", header.image_size());
            }

            let mut messages = Vec::new();

            if full_mode {
                messages.push(format!("File: {}", path));
                messages.push(format!("Format: MBN v{}", header.version()));
                messages.push(format!("Image ID: 0x{:x}", header.image_id()));
                messages.push(format!("Code size: {} bytes", header.code_size()));
                messages.push(format!("Image size: {} bytes", header.image_size()));
                messages.push("ARB: not applicable".to_string());
            } else {
                messages.push("MBN format does not contain ARB field".to_string());
            }

            Ok((0, 0, 0, messages))
        }
        FileType::Unknown => Err("Unknown file format (not ELF or MBN)".into()),
    }
}

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

#[no_mangle]
pub extern "system" fn Java_com_dere3046_arbinspector_ArbInspector_getVersion<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> JString<'local> {
    env.new_string(VERSION).unwrap()
}

#[no_mangle]
pub extern "system" fn Java_com_dere3046_arbinspector_ArbInspector_extract<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    path: JString<'local>,
    debug: jboolean,
    block_mode: jboolean,
) -> jobject {
    let _ = block_mode;

    let result = (|| -> Result<JObject<'local>, String> {
        let path_str: String = env
            .get_string(&path)
            .map_err(|e| format!("Failed to get path string: {}", e))?
            .into();
        let debug = debug != 0;

        let (major, minor, arb, messages) = extract_metadata(&path_str, false, debug)?;

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
            JValue::Int(major as jint),
        )
        .map_err(|e| format!("Failed to set major field: {}", e))?;
        env.set_field(
            &arb_result,
            "minor",
            "I",
            JValue::Int(minor as jint),
        )
        .map_err(|e| format!("Failed to set minor field: {}", e))?;
        env.set_field(
            &arb_result,
            "arb",
            "I",
            JValue::Int(arb as jint),
        )
        .map_err(|e| format!("Failed to set arb field: {}", e))?;

        let array_list_class = env
            .find_class("java/util/ArrayList")
            .map_err(|e| format!("Failed to find ArrayList class: {}", e))?;
        let array_list = env
            .new_object(array_list_class, "()V", &[])
            .map_err(|e| format!("Failed to create ArrayList: {}", e))?;

        for msg in messages {
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
pub extern "system" fn Java_com_dere3046_arbinspector_ArbInspector_extractWithMode<'local>(
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

        let (major, minor, arb, messages) = extract_metadata(&path_str, full_mode, debug)?;

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
            JValue::Int(major as jint),
        )
        .map_err(|e| format!("Failed to set major field: {}", e))?;
        env.set_field(
            &arb_result,
            "minor",
            "I",
            JValue::Int(minor as jint),
        )
        .map_err(|e| format!("Failed to set minor field: {}", e))?;
        env.set_field(
            &arb_result,
            "arb",
            "I",
            JValue::Int(arb as jint),
        )
        .map_err(|e| format!("Failed to set arb field: {}", e))?;

        let array_list_class = env
            .find_class("java/util/ArrayList")
            .map_err(|e| format!("Failed to find ArrayList class: {}", e))?;
        let array_list = env
            .new_object(array_list_class, "()V", &[])
            .map_err(|e| format!("Failed to create ArrayList: {}", e))?;

        for msg in messages {
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
