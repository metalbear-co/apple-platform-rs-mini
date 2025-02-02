// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Functionality for reading signature data from files.

use {
    crate::{
        certificate::AppleCertificate,
        code_directory::CodeDirectoryBlob,
        cryptography::DigestType,
        embedded_signature::{BlobEntry, EmbeddedSignature},
        embedded_signature_builder::{CD_DIGESTS_OID, CD_DIGESTS_PLIST_OID},
        error::{AppleCodesignError, Result},
        macho::{MachFile, MachOBinary},
    },
    cryptographic_message_syntax::{SignedData, SignerInfo},
    goblin::mach::{fat::FAT_MAGIC, parse_magic_and_ctx},
    serde::Serialize,
    std::{
        fmt::Debug,
        fs::File,
        io::{BufWriter, Cursor, Read},
        ops::Deref,
        path::{Path, PathBuf},
    },
    x509_certificate::{CapturedX509Certificate, DigestAlgorithm},
};

enum MachOType {
    Mach,
    MachO,
}

impl MachOType {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Option<Self>, AppleCodesignError> {
        let mut fh = File::open(path.as_ref())?;

        let mut header = vec![0u8; 4];
        let count = fh.read(&mut header)?;

        if count < 4 {
            return Ok(None);
        }

        let magic = goblin::mach::peek(&header, 0)?;

        if magic == FAT_MAGIC {
            Ok(Some(Self::Mach))
        } else if let Ok((_, Some(_))) = parse_magic_and_ctx(&header, 0) {
            Ok(Some(Self::MachO))
        } else {
            Ok(None)
        }
    }
}

/// Test whether a given path is likely a XAR file.
pub fn path_is_xar(path: impl AsRef<Path>) -> Result<bool, AppleCodesignError> {
    let mut fh = File::open(path.as_ref())?;

    let mut header = [0u8; 4];

    let count = fh.read(&mut header)?;
    if count < 4 {
        Ok(false)
    } else {
        Ok(header.as_ref() == b"xar!")
    }
}

/// Test whether a given path is likely a ZIP file.
pub fn path_is_zip(path: impl AsRef<Path>) -> Result<bool, AppleCodesignError> {
    let mut fh = File::open(path.as_ref())?;

    let mut header = [0u8; 4];

    let count = fh.read(&mut header)?;
    if count < 4 {
        Ok(false)
    } else {
        Ok(header.as_ref() == [0x50, 0x4b, 0x03, 0x04])
    }
}

/// Whether the specified filesystem path is a Mach-O binary.
pub fn path_is_macho(path: impl AsRef<Path>) -> Result<bool, AppleCodesignError> {
    Ok(MachOType::from_path(path)?.is_some())
}

/// Describes the type of entity at a path.
///
/// This represents a best guess.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathType {
    MachO,
    Zip,
    Other,
}

impl PathType {
    /// Attempt to classify the type of signable entity based on a filesystem path.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, AppleCodesignError> {
        let path = path.as_ref();

        if path.is_file() {
            if path_is_macho(path)? {
                Ok(Self::MachO)
            } else {
                Ok(Self::Other)
            }
        } else {
            Ok(Self::Other)
        }
    }
}

fn format_integer<T: std::fmt::Display + std::fmt::LowerHex>(v: T) -> String {
    format!("{} / 0x{:x}", v, v)
}

fn pretty_print_xml(xml: &[u8]) -> Result<Vec<u8>, AppleCodesignError> {
    let mut reader = xml::reader::EventReader::new(Cursor::new(xml));
    let mut emitter = xml::EmitterConfig::new()
        .perform_indent(true)
        .create_writer(BufWriter::new(Vec::with_capacity(xml.len() * 2)));

    while let Ok(event) = reader.next() {
        match event {
            xml::reader::XmlEvent::EndDocument => {
                break;
            }
            xml::reader::XmlEvent::Whitespace(_) => {}
            event => {
                if let Some(event) = event.as_writer_event() {
                    emitter.write(event).map_err(AppleCodesignError::XmlWrite)?;
                }
            }
        }
    }

    let xml = emitter.into_inner().into_inner().map_err(|e| {
        AppleCodesignError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))
    })?;

    Ok(xml)
}

/// Pretty print XML and turn into a Vec of lines.
fn pretty_print_xml_lines(xml: &[u8]) -> Result<Vec<String>> {
    Ok(String::from_utf8_lossy(pretty_print_xml(xml)?.as_ref())
        .lines()
        .map(|x| x.to_string())
        .collect::<Vec<_>>())
}

#[derive(Clone, Debug, Serialize)]
pub struct BlobDescription {
    pub slot: String,
    pub magic: String,
    pub length: u32,
    pub sha1: String,
    pub sha256: String,
}

impl<'a> From<&BlobEntry<'a>> for BlobDescription {
    fn from(entry: &BlobEntry<'a>) -> Self {
        Self {
            slot: format!("{:?}", entry.slot),
            magic: format!("{:x}", u32::from(entry.magic)),
            length: entry.length as _,
            sha1: hex::encode(
                entry
                    .digest_with(DigestType::Sha1)
                    .expect("sha-1 digest should always work"),
            ),
            sha256: hex::encode(
                entry
                    .digest_with(DigestType::Sha256)
                    .expect("sha-256 digest should always work"),
            ),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_with_algorithm: Option<String>,
    pub is_apple_root_ca: bool,
    pub is_apple_intermediate_ca: bool,
    pub chains_to_apple_root_ca: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub apple_ca_extensions: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub apple_extended_key_usages: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub apple_code_signing_extensions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apple_certificate_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apple_team_id: Option<String>,
}

impl TryFrom<&CapturedX509Certificate> for CertificateInfo {
    type Error = AppleCodesignError;

    fn try_from(cert: &CapturedX509Certificate) -> Result<Self, Self::Error> {
        Ok(Self {
            subject: cert
                .subject_name()
                .user_friendly_str()
                .map_err(AppleCodesignError::CertificateDecode)?,
            issuer: cert
                .issuer_name()
                .user_friendly_str()
                .map_err(AppleCodesignError::CertificateDecode)?,
            key_algorithm: cert.key_algorithm().map(|x| x.to_string()),
            signature_algorithm: cert.signature_algorithm().map(|x| x.to_string()),
            signed_with_algorithm: cert.signature_signature_algorithm().map(|x| x.to_string()),
            is_apple_root_ca: cert.is_apple_root_ca(),
            is_apple_intermediate_ca: cert.is_apple_intermediate_ca(),
            chains_to_apple_root_ca: cert.chains_to_apple_root_ca(),
            apple_ca_extensions: cert
                .apple_ca_extensions()
                .into_iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>(),
            apple_extended_key_usages: cert
                .apple_extended_key_usage_purposes()
                .into_iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>(),
            apple_code_signing_extensions: cert
                .apple_code_signing_extensions()
                .into_iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>(),
            apple_certificate_profile: cert.apple_guess_profile().map(|x| x.to_string()),
            apple_team_id: cert.apple_team_id(),
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CmsSigner {
    pub issuer: String,
    pub digest_algorithm: String,
    pub signature_algorithm: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attributes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_time: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cdhash_plist: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cdhash_digests: Vec<(String, String)>,
    pub signature_verifies: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_stamp_token: Option<CmsSignature>,
}

impl CmsSigner {
    pub fn from_signer_info_and_signed_data(
        signer_info: &SignerInfo,
        signed_data: &SignedData,
    ) -> Result<Self, AppleCodesignError> {
        let mut attributes = vec![];
        let mut content_type = None;
        let mut message_digest = None;
        let mut signing_time = None;
        let mut time_stamp_token = None;
        let mut cdhash_plist = vec![];
        let mut cdhash_digests = vec![];

        if let Some(sa) = signer_info.signed_attributes() {
            content_type = Some(sa.content_type().to_string());
            message_digest = Some(hex::encode(sa.message_digest()));
            if let Some(t) = sa.signing_time() {
                signing_time = Some(*t);
            }

            for attr in sa.attributes().iter() {
                attributes.push(format!("{}", attr.typ));

                if attr.typ == CD_DIGESTS_PLIST_OID {
                    if let Some(data) = attr.values.get(0) {
                        let data = data.deref().clone();

                        let plist = data
                            .decode(|cons| {
                                let v = bcder::OctetString::take_from(cons)?;

                                Ok(v.into_bytes())
                            })
                            .map_err(|e| AppleCodesignError::Cms(e.into()))?;

                        cdhash_plist = pretty_print_xml_lines(&plist)?;
                    }
                } else if attr.typ == CD_DIGESTS_OID {
                    for value in &attr.values {
                        // Each value is a SEQUENECE of (OID, OctetString).
                        let data = value.deref().clone();

                        data.decode(|cons| {
                            loop {
                                let res = cons.take_opt_sequence(|cons| {
                                    let oid = bcder::Oid::take_from(cons)?;
                                    let value = bcder::OctetString::take_from(cons)?;

                                    cdhash_digests
                                        .push((format!("{oid}"), hex::encode(value.into_bytes())));

                                    Ok(())
                                })?;

                                if res.is_none() {
                                    break;
                                }
                            }

                            Ok(())
                        })
                        .map_err(|e| AppleCodesignError::Cms(e.into()))?;
                    }
                }
            }
        }

        // The order should matter per RFC 5652 but Apple's CMS implementation doesn't
        // conform to spec.
        attributes.sort();

        if let Some(tsk) = signer_info.time_stamp_token_signed_data()? {
            time_stamp_token = Some(tsk.try_into()?);
        }

        Ok(Self {
            issuer: signer_info
                .certificate_issuer_and_serial()
                .expect("issuer should always be set")
                .0
                .user_friendly_str()
                .map_err(AppleCodesignError::CertificateDecode)?,
            digest_algorithm: signer_info.digest_algorithm().to_string(),
            signature_algorithm: signer_info.signature_algorithm().to_string(),
            attributes,
            content_type,
            message_digest,
            signing_time,
            cdhash_plist,
            cdhash_digests,
            signature_verifies: signer_info
                .verify_signature_with_signed_data(signed_data)
                .is_ok(),

            time_stamp_token,
        })
    }
}

/// High-level representation of a CMS signature.
#[derive(Clone, Debug, Serialize)]
pub struct CmsSignature {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub certificates: Vec<CertificateInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub signers: Vec<CmsSigner>,
}

impl TryFrom<SignedData> for CmsSignature {
    type Error = AppleCodesignError;

    fn try_from(signed_data: SignedData) -> Result<Self, Self::Error> {
        let certificates = signed_data
            .certificates()
            .map(|x| x.try_into())
            .collect::<Result<Vec<_>, _>>()?;

        let signers = signed_data
            .signers()
            .map(|x| CmsSigner::from_signer_info_and_signed_data(x, &signed_data))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            certificates,
            signers,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CodeDirectory {
    pub version: String,
    pub flags: String,
    pub identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_name: Option<String>,
    pub digest_type: String,
    pub platform: u8,
    pub signed_entity_size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable_segment_flags: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_version: Option<String>,
    pub code_digests_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    slot_digests: Vec<String>,
}

impl<'a> TryFrom<CodeDirectoryBlob<'a>> for CodeDirectory {
    type Error = AppleCodesignError;

    fn try_from(cd: CodeDirectoryBlob<'a>) -> Result<Self, Self::Error> {
        let mut temp = cd
            .slot_digests()
            .iter()
            .map(|(slot, digest)| (slot, digest.as_hex()))
            .collect::<Vec<_>>();
        temp.sort_by(|(a, _), (b, _)| a.cmp(b));

        let slot_digests = temp
            .into_iter()
            .map(|(slot, digest)| format!("{slot:?}: {digest}"))
            .collect::<Vec<_>>();

        Ok(Self {
            version: format!("0x{:X}", cd.version),
            flags: format!("{:?}", cd.flags),
            identifier: cd.ident.to_string(),
            team_name: cd.team_name.map(|x| x.to_string()),
            signed_entity_size: cd.code_limit as _,
            digest_type: format!("{}", cd.digest_type),
            platform: cd.platform,
            executable_segment_flags: cd.exec_seg_flags.map(|x| format!("{x:?}")),
            runtime_version: cd
                .runtime
                .map(|x| format!("{}", crate::macho::parse_version_nibbles(x))),
            code_digests_count: cd.code_digests.len(),
            slot_digests,
        })
    }
}

/// High level representation of a code signature.
#[derive(Clone, Debug, Serialize)]
pub struct CodeSignature {
    /// Length of the code signature data.
    pub superblob_length: String,
    pub blob_count: u32,
    pub blobs: Vec<BlobDescription>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_directory: Option<CodeDirectory>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub alternative_code_directories: Vec<(String, CodeDirectory)>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub entitlements_plist: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub entitlements_der_plist: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub launch_constraints_self: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub launch_constraints_parent: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub launch_constraints_responsible: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub library_constraints: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub code_requirements: Vec<String>,
    pub cms: Option<CmsSignature>,
}

impl<'a> TryFrom<EmbeddedSignature<'a>> for CodeSignature {
    type Error = AppleCodesignError;

    fn try_from(sig: EmbeddedSignature<'a>) -> Result<Self, Self::Error> {
        let mut entitlements_plist = vec![];
        let mut entitlements_der_plist = vec![];
        let mut launch_constraints_self = vec![];
        let mut launch_constraints_parent = vec![];
        let mut launch_constraints_responsible = vec![];
        let mut library_constraints = vec![];
        let mut code_requirements = vec![];
        let mut cms = None;

        let code_directory = if let Some(cd) = sig.code_directory()? {
            Some(CodeDirectory::try_from(*cd)?)
        } else {
            None
        };

        let alternative_code_directories = sig
            .alternate_code_directories()?
            .into_iter()
            .map(|(slot, cd)| Ok((format!("{slot:?}"), CodeDirectory::try_from(*cd)?)))
            .collect::<Result<Vec<_>, AppleCodesignError>>()?;

        if let Some(blob) = sig.entitlements()? {
            entitlements_plist = blob
                .as_str()
                .lines()
                .map(|x| x.replace('\t', "  "))
                .collect::<Vec<_>>();
        }

        if let Some(blob) = sig.entitlements_der()? {
            let xml = blob.plist_xml()?;

            entitlements_der_plist = pretty_print_xml_lines(&xml)?;
        }

        if let Some(blob) = sig.launch_constraints_self()? {
            launch_constraints_self = pretty_print_xml_lines(&blob.plist_xml()?)?;
        }

        if let Some(blob) = sig.launch_constraints_parent()? {
            launch_constraints_parent = pretty_print_xml_lines(&blob.plist_xml()?)?;
        }

        if let Some(blob) = sig.launch_constraints_responsible()? {
            launch_constraints_responsible = pretty_print_xml_lines(&blob.plist_xml()?)?;
        }

        if let Some(blob) = sig.library_constraints()? {
            library_constraints = pretty_print_xml_lines(&blob.plist_xml()?)?;
        }

        if let Some(req) = sig.code_requirements()? {
            let mut temp = vec![];

            for (req, blob) in req.requirements {
                let reqs = blob.parse_expressions()?;
                temp.push((req, format!("{reqs}")));
            }

            temp.sort_by(|(a, _), (b, _)| a.cmp(b));

            code_requirements = temp
                .into_iter()
                .map(|(req, value)| format!("{req}: {value}"))
                .collect::<Vec<_>>();
        }

        if let Some(signed_data) = sig.signed_data()? {
            cms = Some(signed_data.try_into()?);
        }

        Ok(Self {
            superblob_length: format_integer(sig.length),
            blob_count: sig.count,
            blobs: sig
                .blobs
                .iter()
                .map(BlobDescription::from)
                .collect::<Vec<_>>(),
            code_directory,
            alternative_code_directories,
            entitlements_plist,
            entitlements_der_plist,
            launch_constraints_self,
            launch_constraints_parent,
            launch_constraints_responsible,
            library_constraints,
            code_requirements,
            cms,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct MachOEntity {
    pub macho_linkedit_start_offset: Option<String>,
    pub macho_signature_start_offset: Option<String>,
    pub macho_signature_end_offset: Option<String>,
    pub macho_linkedit_end_offset: Option<String>,
    pub macho_end_offset: Option<String>,
    pub linkedit_signature_start_offset: Option<String>,
    pub linkedit_signature_end_offset: Option<String>,
    pub linkedit_bytes_after_signature: Option<String>,
    pub signature: Option<CodeSignature>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DmgEntity {
    pub code_signature_offset: u64,
    pub code_signature_size: u64,
    pub signature: Option<CodeSignature>,
}

#[derive(Clone, Debug, Serialize)]
pub enum CodeSignatureFile {
    ResourcesXml(Vec<String>),
    NotarizationTicket,
    Other,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureEntity {
    MachO(MachOEntity),
    Dmg(DmgEntity),
    BundleCodeSignatureFile(CodeSignatureFile),
    Other,
}

#[derive(Clone, Debug, Serialize)]
pub struct FileEntity {
    pub path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symlink_target: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_path: Option<String>,
    #[serde(with = "serde_yaml::with::singleton_map")]
    pub entity: SignatureEntity,
}

impl FileEntity {
    /// Construct an instance from a [Path].
    pub fn from_path(path: &Path, report_path: Option<&Path>) -> Result<Self, AppleCodesignError> {
        let metadata = std::fs::symlink_metadata(path)?;

        let report_path = if let Some(p) = report_path {
            p.to_path_buf()
        } else {
            path.to_path_buf()
        };

        let (file_size, file_sha256, symlink_target) = if metadata.is_symlink() {
            (None, None, Some(std::fs::read_link(path)?))
        } else {
            (
                Some(metadata.len()),
                Some(hex::encode(DigestAlgorithm::Sha256.digest_path(path)?)),
                None,
            )
        };

        Ok(Self {
            path: report_path,
            file_size,
            file_sha256,
            symlink_target,
            sub_path: None,
            entity: SignatureEntity::Other,
        })
    }
}

/// Entity for reading Apple code signature data.
pub enum SignatureReader {
    MachO(PathBuf, Vec<u8>),
}

impl SignatureReader {
    /// Construct a signature reader from a path.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, AppleCodesignError> {
        let path = path.as_ref();
        match PathType::from_path(path)? {
            PathType::MachO => {
                let data = std::fs::read(path)?;
                MachFile::parse(&data)?;

                Ok(Self::MachO(path.to_path_buf(), data))
            }
            PathType::Zip | PathType::Other => Err(AppleCodesignError::UnrecognizedPathType),
        }
    }

    /// Obtain entities that are possibly relevant to code signing.
    pub fn entities(&self) -> Result<Vec<FileEntity>, AppleCodesignError> {
        match self {
            Self::MachO(path, data) => Self::resolve_macho_entities_from_data(path, data, None),
        }
    }

    fn resolve_macho_entities_from_data(
        path: &Path,
        data: &[u8],
        report_path: Option<&Path>,
    ) -> Result<Vec<FileEntity>, AppleCodesignError> {
        let mut entities = vec![];

        let entity = FileEntity::from_path(path, report_path)?;

        for macho in MachFile::parse(data)?.into_iter() {
            let mut entity = entity.clone();

            if let Some(index) = macho.index {
                entity.sub_path = Some(format!("macho-index:{index}"));
            }

            entity.entity = SignatureEntity::MachO(Self::resolve_macho_entity(macho)?);

            entities.push(entity);
        }

        Ok(entities)
    }

    fn resolve_macho_entity(macho: MachOBinary) -> Result<MachOEntity, AppleCodesignError> {
        let mut entity = MachOEntity::default();

        entity.macho_end_offset = Some(format_integer(macho.data.len()));

        if let Some(sig) = macho.find_signature_data()? {
            entity.macho_linkedit_start_offset =
                Some(format_integer(sig.linkedit_segment_start_offset));
            entity.macho_linkedit_end_offset =
                Some(format_integer(sig.linkedit_segment_end_offset));
            entity.macho_signature_start_offset =
                Some(format_integer(sig.signature_file_start_offset));
            entity.linkedit_signature_start_offset =
                Some(format_integer(sig.signature_segment_start_offset));
        }

        if let Some(sig) = macho.code_signature()? {
            if let Some(sig_info) = macho.find_signature_data()? {
                entity.macho_signature_end_offset = Some(format_integer(
                    sig_info.signature_file_start_offset + sig.length as usize,
                ));
                entity.linkedit_signature_end_offset = Some(format_integer(
                    sig_info.signature_segment_start_offset + sig.length as usize,
                ));

                let mut linkedit_remaining =
                    sig_info.linkedit_segment_end_offset - sig_info.linkedit_segment_start_offset;
                linkedit_remaining -= sig_info.signature_segment_start_offset;
                linkedit_remaining -= sig.length as usize;
                entity.linkedit_bytes_after_signature = Some(format_integer(linkedit_remaining));
            }

            entity.signature = Some(sig.try_into()?);
        }

        Ok(entity)
    }
}
