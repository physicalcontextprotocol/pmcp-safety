//! TEE Attestation - Rust Implementation
//! Additional components for Intel SGX and AWS Nitro Enclaves support

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationDocument {
    pub version: u32,
    pub timestamp: u64,
    pub pcrs: Vec<PCR>,
    pub public_key: Vec<u8>,
    pub user_data: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
    pub certificate: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PCR {
    pub index: u32,
    pub hash: String,
    pub hash_algorithm: String,
}

impl AttestationDocument {
    pub fn new() -> Self {
        Self {
            version: 1,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            pcrs: Vec::new(),
            public_key: Vec::new(),
            user_data: None,
            nonce: None,
            certificate: Vec::new(),
        }
    }

    pub fn with_pcrs(mut self, pcrs: Vec<PCR>) -> Self {
        self.pcrs = pcrs;
        self
    }

    pub fn with_public_key(mut self, key: Vec<u8>) -> Self {
        self.public_key = key;
        self
    }

    pub fn verify(&self, expected_pcrs: &HashMap<u32, String>) -> Result<bool, String> {
        for expected in expected_pcrs {
            let found = self.pcrs.iter().find(|p| p.index == *expected.0);
            match found {
                Some(pcr) if pcr.hash == *expected.1 => continue,
                _ => return Err(format!("PCR{} mismatch", expected.0)),
            }
        }
        Ok(true)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveIdentity {
    pub enclave_id: String,
    pub mr_enclave: String,
    pub mr_signer: String,
    pub product_id: u32,
    pub security_version: u32,
    pub is_debug: bool,
    pub attributes: EnclaveAttributes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveAttributes {
    pub initialized: bool,
    pub debuggable: bool,
    pub mode64bit: bool,
    pub provisioning: bool,
    pub enclave_held: bool,
    pub nonce: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quote {
    pub version: u16,
    pub_guest_type: u8,
    pub security_version: u32,
    pub is_debuggable: bool,
    pub svn: u16,
    pub cpu_svn: CPUSVN,
    pub misc_select: u32,
    pub misc_mask: u32,
    pub key_values: Vec<u8>,
    pub report_data: [u8; 64],
    pub mr_enclave: [u8; 32],
    pub mr_signer: [u8; 32],
    pub config_id: [u8; 64],
    pub config_svn: [u8; 16],
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    pub reserved: [u8; 32],
    pub measurement: [u8; 48],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CPUSVN {
    pub bytes: [u8; 16],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyName {
    pub key_id: [u8; 32],
    pub cpu_svn: CPUSVN,
    pub isv_svn: u16,
}

pub struct AttestationService {
    enclave_identities: HashMap<String, EnclaveIdentity>,
    trusted_measurements: HashMap<String, Vec<String>>,
    revocation_lists: Vec<RevocationEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    pub mr_enclave: String,
    pub reason: String,
    pub timestamp: u64,
}

impl AttestationService {
    pub fn new() -> Self {
        Self {
            enclave_identities: HashMap::new(),
            trusted_measurements: HashMap::new(),
            revocation_lists: Vec::new(),
        }
    }

    pub fn register_enclave(&mut self, identity: EnclaveIdentity) {
        self.enclave_identities.insert(identity.enclave_id.clone(), identity);
    }

    pub fn verify_measurement(&self, enclave_id: &str, measurement: &str) -> Result<bool, String> {
        if let Some(identity) = self.enclave_identities.get(enclave_id) {
            return Ok(identity.mr_enclave == measurement);
        }
        Err("Enclave not found".to_string())
    }

    pub fn add_trusted_measurement(&mut self, name: &str, mr_enclave: String) {
        self.trusted_measurements
            .entry(name.to_string())
            .or_insert_with(Vec::new)
            .push(mr_enclave);
    }

    pub fn verify_against_trusted(&self, name: &str, measurement: &str) -> Result<bool, String> {
        if let Some(trusted) = self.trusted_measurements.get(name) {
            return Ok(trusted.contains(&measurement.to_string()));
        }
        Err("Trusted measurement list not found".to_string())
    }

    pub fn add_revocation(&mut self, entry: RevocationEntry) {
        self.revocation_lists.push(entry);
    }

    pub fn is_revoked(&self, mr_enclave: &str) -> bool {
        self.revocation_lists
            .iter()
            .any(|e| e.mr_enclave == mr_enclave)
    }
}

pub struct SGXAttestor {
    service: AttestationService,
}

impl SGXAttestor {
    pub fn new() -> Self {
        Self {
            service: AttestationService::new(),
        }
    }

    pub fn create_attestation(&self, enclave_id: &str, nonce: Vec<u8>) -> Result<AttestationDocument, String> {
        let identity = self.service.enclave_identities.get(enclave_id)
            .ok_or("Enclave not registered")?;

        let mut doc = AttestationDocument::new();
        doc.nonce = Some(nonce);

        let pcrs = vec![
            PCR {
                index: 0,
                hash: identity.mr_enclave.clone(),
                hash_algorithm: "SHA256".to_string(),
            },
            PCR {
                index: 1,
                hash: identity.mr_signer.clone(),
                hash_algorithm: "SHA256".to_string(),
            },
            PCR {
                index: 2,
                hash: format!("{:016x}", identity.security_version),
                hash_algorithm: "SHA256".to_string(),
            },
            PCR {
                index: 3,
                hash: format!("{:016x}", identity.product_id),
                hash_algorithm: "SHA256".to_string(),
            },
        ];

        Ok(doc.with_pcrs(pcrs))
    }

    pub fn verify_attestation(&self, doc: &AttestationDocument, enclave_id: &str) -> Result<bool, String> {
        if let Some(identity) = self.service.enclave_identities.get(enclave_id) {
            let mut expected = HashMap::new();
            expected.insert(0, identity.mr_enclave.clone());
            expected.insert(1, identity.mr_signer.clone());
            return doc.verify(&expected);
        }
        Err("Enclave not found".to_string())
    }
}

pub struct NitroAttestor {
    service: AttestationService,
}

impl NitroAttestor {
    pub fn new() -> Self {
        Self {
            service: AttestationService::new(),
        }
    }

    pub fn get_attestation_document(&self) -> AttestationDocument {
        let pcrs = vec![
            PCR { index: 0, hash: "PCR0_MEASUREMENT".to_string(), hash_algorithm: "SHA384".to_string() },
            PCR { index: 1, hash: "PCR1_BOOT_MEASUREMENT".to_string(), hash_algorithm: "SHA384".to_string() },
            PCR { index: 2, hash: "PCR2_KERNEL_MEASUREMENT".to_string(), hash_algorithm: "SHA384".to_string() },
            PCR { index: 3, hash: "PCR3_AWS_CONFIG".to_string(), hash_algorithm: "SHA384".to_string() },
            PCR { index: 4, hash: "PCR4_IMAGE_ID".to_string(), hash_algorithm: "SHA384".to_string() },
            PCR { index: 5, hash: "PCR5_OWNER_MEASUREMENT".to_string(), hash_algorithm: "SHA384".to_string() },
            PCR { index: 8, hash: "PCR8_ENCLAVE_IMAGE".to_string(), hash_algorithm: "SHA384".to_string() },
        ];

        AttestationDocument::new().with_pcrs(pcrs)
    }

    pub fn verify_nitro_attestation(&self, doc: &AttestationDocument, expected_pcrs: &HashMap<u32, String>) -> Result<bool, String> {
        doc.verify(expected_pcrs)
    }
}

pub struct AttestationConfig {
    pub attestation_type: String,
    pub pcr_selection: Vec<u32>,
    pub user_data: Option<Vec<u8>>,
    pub nonce_size: usize,
    pub validity_seconds: u64,
}

impl Default for AttestationConfig {
    fn default() -> Self {
        Self {
            attestation_type: "sgx_ecdsa".to_string(),
            pcr_selection: vec![0, 1, 2, 3],
            user_data: None,
            nonce_size: 32,
            validity_seconds: 3600,
        }
    }
}

pub struct AttestationSession {
    session_id: String,
    enclave_id: String,
    nonce: Vec<u8>,
    created_at: u64,
    expires_at: u64,
    state: SessionState,
}

enum SessionState {
    Pending,
    ChallengeSent,
    AttestationReceived,
    Verified,
    Failed,
}

impl AttestationSession {
    pub fn new(session_id: String, enclave_id: String, nonce: Vec<u8>, validity: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            session_id,
            enclave_id,
            nonce,
            created_at: now,
            expires_at: now + validity,
            state: SessionState::Pending,
        }
    }

    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.expires_at
    }

    pub fn update_state(&mut self, state: SessionState) {
        self.state = state;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attestation_document() {
        let doc = AttestationDocument::new();
        assert_eq!(doc.version, 1);
    }

    #[test]
    fn test_sgx_attestor() {
        let mut attestor = SGXAttestor::new();
        let identity = EnclaveIdentity {
            enclave_id: "test-enclave".to_string(),
            mr_enclave: "abc123".to_string(),
            mr_signer: "def456".to_string(),
            product_id: 1,
            security_version: 1,
            is_debug: false,
            attributes: EnclaveAttributes {
                initialized: true,
                debuggable: false,
                mode64bit: true,
                provisioning: false,
                enclave_held: false,
                nonce: true,
            },
        };
        attestor.service.register_enclave(identity);

        let doc = attestor.create_attestation("test-enclave", vec![1, 2, 3, 4]).unwrap();
        assert_eq!(doc.pcrs.len(), 4);
    }
}