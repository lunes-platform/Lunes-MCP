//! Lunes MCP Server - key management service.
//!
//! In-memory key management for the local agent key. Private key material is
//! kept inside this module and is only used after policy checks pass.
//!
//! ## Security Properties
//!
//! - Uses a single `parking_lot::Mutex` to keep KMS state consistent.
//! - Enables `zeroize` support in `ed25519-dalek` for private key cleanup.
//! - Blocks accidental key replacement; call `revoke_key()` before reprovisioning.

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use parking_lot::Mutex;
use rand::rngs::OsRng;
use serde::Serialize;
use std::collections::HashMap;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Error, ErrorKind, Write};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use crate::config::{AgentMode, PermissionsConfig};

const MAX_AUDIT_LOG_ENTRIES: usize = 1024;
pub const AUDIT_LOG_PATH_ENV: &str = "LUNES_MCP_AUDIT_LOG_PATH";

#[cfg(unix)]
unsafe extern "C" {
    fn geteuid() -> u32;
}

fn audit_log_path_from_env() -> Option<PathBuf> {
    std::env::var(AUDIT_LOG_PATH_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn audit_payload_hash(payload_bytes: &[u8]) -> String {
    let mut hasher = Blake2bVar::new(32).expect("32-byte Blake2b output size is valid");
    hasher.update(payload_bytes);
    let mut output = [0u8; 32];
    hasher
        .finalize_variable(&mut output)
        .expect("fixed-size output buffer has the requested length");
    format!("0x{}", hex::encode(output))
}

fn append_persistent_audit_entry(path: &Path, entry: &AuditEntry) -> std::io::Result<()> {
    validate_audit_log_path_before_open(path)?;

    let mut options = OpenOptions::new();
    options.create(true).append(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options.open(path)?;
    validate_open_audit_log_file(&file)?;
    serde_json::to_writer(&mut file, entry).map_err(std::io::Error::other)?;
    file.write_all(b"\n")?;
    file.flush()
}

fn validate_audit_log_path_before_open(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => validate_existing_audit_log_metadata(path, &metadata),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn validate_existing_audit_log_metadata(path: &Path, metadata: &Metadata) -> std::io::Result<()> {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!("audit log path must not be a symlink: {}", path.display()),
        ));
    }
    if !file_type.is_file() {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!("audit log path must be a regular file: {}", path.display()),
        ));
    }

    validate_audit_log_metadata_permissions(path, metadata)
}

fn validate_open_audit_log_file(file: &File) -> std::io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "audit log path must be a regular file",
        ));
    }
    validate_audit_log_metadata_permissions(Path::new("<opened-audit-log>"), &metadata)
}

#[cfg(unix)]
fn validate_audit_log_metadata_permissions(
    path: &Path,
    metadata: &Metadata,
) -> std::io::Result<()> {
    let mode = metadata.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "audit log path must not be readable or writable by group/other: {}",
                path.display()
            ),
        ));
    }

    if metadata.uid() != current_effective_uid() {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "audit log path must be owned by the server user: {}",
                path.display()
            ),
        ));
    }

    Ok(())
}

#[cfg(not(unix))]
fn validate_audit_log_metadata_permissions(
    _path: &Path,
    _metadata: &Metadata,
) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn current_effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    unsafe { geteuid() }
}

#[derive(Debug, thiserror::Error)]
pub enum KmsError {
    #[error("Agent key not provisioned. Call lunes_provision_agent_wallet first.")]
    NotInitialized,

    #[error("Agent is configured as prepare_only. Autonomous signing is disabled.")]
    NotAutonomous,

    #[error("Agent key already provisioned. Call revoke first to re-provision.")]
    AlreadyProvisioned,

    #[error("Agent key TTL expired. Re-provision required.")]
    TtlExpired,

    #[error("Daily spending limit exceeded ({spent}/{limit} LUNES).")]
    DailyLimitExceeded { spent: u64, limit: u64 },

    #[error("Extrinsic '{0}' is not in the allowed list.")]
    UnauthorizedExtrinsic(String),

    #[error("Destination '{0}' is not in the whitelist.")]
    UnauthorizedDestination(String),

    #[error("Contract method '{method}' is not allowlisted for contract '{contract}'.")]
    UnauthorizedContractMessage { contract: String, method: String },

    #[error("Persistent audit log write failed: {0}")]
    AuditLogPersistenceFailed(String),
}

impl KmsError {
    /// Returns the JSON-RPC application error code used by tool responses.
    pub fn error_code(&self) -> i32 {
        match self {
            KmsError::NotInitialized => -32001,
            KmsError::NotAutonomous => -32011,
            KmsError::AlreadyProvisioned => -32011,
            KmsError::TtlExpired => -32012,
            KmsError::DailyLimitExceeded { .. } => -32010,
            KmsError::UnauthorizedExtrinsic(_) => -32011,
            KmsError::UnauthorizedDestination(_) => -32011,
            KmsError::UnauthorizedContractMessage { .. } => -32011,
            KmsError::AuditLogPersistenceFailed(_) => -32012,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub action: AuditAction,
    pub extrinsic: String,
    pub destination: Option<String>,
    pub amount_lunes: u64,
    pub payload_hash: Option<String>,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum AuditAction {
    #[serde(rename = "SIGN")]
    Sign,
    #[serde(rename = "DENIED")]
    Denied,
}

impl AuditEntry {
    fn new(
        extrinsic: &str,
        destination: Option<&str>,
        amount_lunes: u64,
        payload_hash: Option<&str>,
        success: bool,
        error: Option<&str>,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            action: if success {
                AuditAction::Sign
            } else {
                AuditAction::Denied
            },
            extrinsic: extrinsic.to_string(),
            destination: destination.map(str::to_string),
            amount_lunes,
            payload_hash: payload_hash.map(str::to_string),
            success,
            error: error.map(str::to_string),
        }
    }
}

struct SpendingTracker {
    /// Map of UTC day -> amount spent that day.
    daily_totals: HashMap<NaiveDate, u64>,
    limit: u64,
}

impl SpendingTracker {
    fn new(limit: u64) -> Self {
        Self {
            daily_totals: HashMap::new(),
            limit,
        }
    }

    fn current_day_key() -> NaiveDate {
        Utc::now().date_naive()
    }

    fn check(&self, amount: u64) -> Result<(), KmsError> {
        let today = Self::current_day_key();
        let spent = *self.daily_totals.get(&today).unwrap_or(&0);
        Self::checked_next_spent(self.limit, spent, amount).map(|_| ())
    }

    fn check_and_record(&mut self, amount: u64) -> Result<u64, KmsError> {
        let today = Self::current_day_key();
        let spent = self.daily_totals.entry(today).or_insert(0);
        let next_spent = Self::checked_next_spent(self.limit, *spent, amount)?;
        *spent = next_spent;
        Ok(*spent)
    }

    fn checked_next_spent(limit: u64, spent: u64, amount: u64) -> Result<u64, KmsError> {
        let next_spent = spent
            .checked_add(amount)
            .ok_or(KmsError::DailyLimitExceeded { spent, limit })?;

        if next_spent > limit {
            return Err(KmsError::DailyLimitExceeded { spent, limit });
        }

        Ok(next_spent)
    }

    fn spent_today(&self) -> u64 {
        let today = Self::current_day_key();
        *self.daily_totals.get(&today).unwrap_or(&0)
    }

    /// Keeps only the current day to avoid unbounded growth.
    fn cleanup_old_entries(&mut self) {
        let today = Self::current_day_key();
        self.daily_totals.retain(|day, _| day == &today);
    }
}

struct KmsState {
    /// Private signing key. Never exposed through the API.
    signing_key: Option<SigningKey>,
    public_key: Option<VerifyingKey>,
    provisioned_at: Option<DateTime<Utc>>,
    spending: SpendingTracker,
    audit_log: Vec<AuditEntry>,
}

pub struct AgentKms {
    mode: AgentMode,
    permissions: PermissionsConfig,
    audit_log_path: Option<PathBuf>,
    state: Mutex<KmsState>,
}

impl AgentKms {
    pub fn new(mode: AgentMode, permissions: PermissionsConfig) -> Self {
        Self::new_with_optional_audit_log_path(mode, permissions, audit_log_path_from_env())
    }

    fn new_with_optional_audit_log_path(
        mode: AgentMode,
        permissions: PermissionsConfig,
        audit_log_path: Option<PathBuf>,
    ) -> Self {
        let limit = permissions.daily_limit_lunes;
        Self {
            mode,
            permissions,
            audit_log_path,
            state: Mutex::new(KmsState {
                signing_key: None,
                public_key: None,
                provisioned_at: None,
                spending: SpendingTracker::new(limit),
                audit_log: Vec::new(),
            }),
        }
    }

    /// Generates a new Ed25519 keypair and returns the public key as hex.
    ///
    /// If a key already exists, this returns an error. Call `revoke_key()` before
    /// provisioning a replacement.
    pub fn provision_key(&self) -> Result<String, KmsError> {
        let mut state = self.state.lock();

        // Avoid accidental or adversarial key replacement.
        if state.signing_key.is_some() {
            warn!("Attempted re-provision of agent key - blocked.");
            return Err(KmsError::AlreadyProvisioned);
        }

        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let pub_hex = hex::encode(verifying_key.as_bytes());

        state.signing_key = Some(signing_key);
        state.public_key = Some(verifying_key);
        state.provisioned_at = Some(Utc::now());

        info!(
            agent_public_key = %pub_hex,
            mode = ?self.mode,
            ttl_hours = self.permissions.ttl_hours,
            "Agent key provisioned successfully"
        );

        Ok(pub_hex)
    }

    /// Revokes the current key and clears KMS state.
    pub fn revoke_key(&self) {
        let mut state = self.state.lock();
        state.signing_key = None;
        state.public_key = None;
        state.provisioned_at = None;
        // Clean up old spending entries during lifecycle transitions.
        state.spending.cleanup_old_entries();

        info!("Agent key revoked. KMS state cleared.");
    }

    /// Returns the public key as hex when provisioned.
    pub fn public_key_hex(&self) -> Option<String> {
        let state = self.state.lock();
        state.public_key.as_ref().map(|k| hex::encode(k.as_bytes()))
    }

    /// Returns the public key bytes when provisioned.
    pub fn public_key_bytes(&self) -> Option<[u8; 32]> {
        let state = self.state.lock();
        state.public_key.as_ref().map(|k| *k.as_bytes())
    }

    /// Returns whether autonomous signing is enabled.
    pub fn is_autonomous(&self) -> bool {
        self.mode == AgentMode::Autonomous
    }

    pub fn mode(&self) -> &AgentMode {
        &self.mode
    }

    /// Validates whether the agent may call a specific message on a Lunes contract.
    pub fn validate_contract_call(
        &self,
        contract_address: &str,
        method_name: &str,
    ) -> Result<(), KmsError> {
        if let Some(allowed_methods) = self.permissions.allowlist_contracts.get(contract_address) {
            if allowed_methods.iter().any(|m| m == method_name) {
                return Ok(());
            }
        }

        Err(KmsError::UnauthorizedContractMessage {
            contract: contract_address.to_string(),
            method: method_name.to_string(),
        })
    }

    pub fn permissions(&self) -> &PermissionsConfig {
        &self.permissions
    }

    /// Returns whether successful signing attempts are mirrored to an external audit log.
    pub fn persistent_audit_log_enabled(&self) -> bool {
        self.audit_log_path.is_some()
    }

    /// Returns whether a non-expired key is provisioned.
    pub fn is_active(&self) -> bool {
        let state = self.state.lock();
        state.signing_key.is_some() && self.check_ttl_inner(&state).is_ok()
    }

    fn check_ttl_inner(&self, state: &KmsState) -> Result<(), KmsError> {
        if self.permissions.ttl_hours == 0 {
            return Ok(()); // No expiration.
        }

        let provisioned = state.provisioned_at.ok_or(KmsError::NotInitialized)?;

        let deadline = provisioned + Duration::hours(self.permissions.ttl_hours as i64);
        if Utc::now() > deadline {
            warn!("Agent key TTL expired");
            return Err(KmsError::TtlExpired);
        }

        Ok(())
    }

    fn check_extrinsic(&self, extrinsic: &str) -> Result<(), KmsError> {
        if self.permissions.allowed_extrinsics.is_empty() {
            return Err(KmsError::UnauthorizedExtrinsic(extrinsic.to_string()));
        }

        if !self
            .permissions
            .allowed_extrinsics
            .iter()
            .any(|e| e == extrinsic)
        {
            return Err(KmsError::UnauthorizedExtrinsic(extrinsic.to_string()));
        }

        Ok(())
    }

    fn check_destination(&self, destination: &str) -> Result<(), KmsError> {
        if self.permissions.whitelisted_addresses.is_empty() {
            return Err(KmsError::UnauthorizedDestination(destination.to_string()));
        }

        if !self
            .permissions
            .whitelisted_addresses
            .iter()
            .any(|a| a == destination)
        {
            return Err(KmsError::UnauthorizedDestination(destination.to_string()));
        }

        Ok(())
    }

    /// Validates write policies without signing or consuming daily budget.
    pub fn preflight_write(
        &self,
        extrinsic: &str,
        destination: &str,
        amount_lunes: u64,
    ) -> Result<(), KmsError> {
        self.check_extrinsic(extrinsic)?;
        self.check_destination(destination)?;
        let state = self.state.lock();
        state.spending.check(amount_lunes)
    }

    /// Validates mode, key lifecycle, allowlists, and daily budget before signing.
    pub fn sign_payload(
        &self,
        extrinsic: &str,
        destination: &str,
        amount_lunes: u64,
        payload_bytes: &[u8],
    ) -> Result<SignedResult, KmsError> {
        let payload_hash = audit_payload_hash(payload_bytes);

        if self.mode != AgentMode::Autonomous {
            self.log_audit(
                extrinsic,
                Some(destination),
                amount_lunes,
                Some(&payload_hash),
                false,
                Some("NotAutonomous"),
            );
            return Err(KmsError::NotAutonomous);
        }

        // One lock covers the full operation to keep state consistent.
        let mut state = self.state.lock();

        if state.signing_key.is_none() {
            self.log_denied_audit(
                &mut state,
                extrinsic,
                destination,
                amount_lunes,
                &payload_hash,
                "NotInitialized",
            );
            return Err(KmsError::NotInitialized);
        }

        if let Err(e) = self.check_ttl_inner(&state) {
            self.log_denied_audit(
                &mut state,
                extrinsic,
                destination,
                amount_lunes,
                &payload_hash,
                "TtlExpired",
            );
            return Err(e);
        }

        if let Err(e) = self.check_extrinsic(extrinsic) {
            self.log_denied_audit(
                &mut state,
                extrinsic,
                destination,
                amount_lunes,
                &payload_hash,
                "UnauthorizedExtrinsic",
            );
            return Err(e);
        }

        if let Err(e) = self.check_destination(destination) {
            self.log_denied_audit(
                &mut state,
                extrinsic,
                destination,
                amount_lunes,
                &payload_hash,
                "UnauthorizedDestination",
            );
            return Err(e);
        }

        if let Err(e) = state.spending.check(amount_lunes) {
            self.log_denied_audit(
                &mut state,
                extrinsic,
                destination,
                amount_lunes,
                &payload_hash,
                "DailyLimitExceeded",
            );
            return Err(e);
        }

        Self::log_audit_inner(
            &mut state.audit_log,
            self.audit_log_path.as_deref(),
            AuditEntry::new(
                extrinsic,
                Some(destination),
                amount_lunes,
                Some(&payload_hash),
                true,
                None,
            ),
        )
        .map_err(|error| KmsError::AuditLogPersistenceFailed(error.to_string()))?;

        state
            .spending
            .check_and_record(amount_lunes)
            .expect("spending was checked while holding the same KMS lock");

        let (sig_hex, pub_hex) = {
            let signing_key = state
                .signing_key
                .as_ref()
                .expect("signing key was checked before policy validation");
            let signature = signing_key.sign(payload_bytes);
            (
                hex::encode(signature.to_bytes()),
                hex::encode(signing_key.verifying_key().as_bytes()),
            )
        };

        info!(
            extrinsic = extrinsic,
            amount = amount_lunes,
            "Transaction signed successfully by KMS"
        );

        Ok(SignedResult {
            signature: sig_hex,
            public_key: pub_hex,
        })
    }

    fn log_audit(
        &self,
        extrinsic: &str,
        destination: Option<&str>,
        amount: u64,
        payload_hash: Option<&str>,
        success: bool,
        error: Option<&str>,
    ) {
        let mut state = self.state.lock();
        Self::log_audit_inner(
            &mut state.audit_log,
            self.audit_log_path.as_deref(),
            AuditEntry::new(extrinsic, destination, amount, payload_hash, success, error),
        )
        .unwrap_or_else(|error| self.warn_audit_persistence_failure(error));
    }

    fn log_denied_audit(
        &self,
        state: &mut KmsState,
        extrinsic: &str,
        destination: &str,
        amount_lunes: u64,
        payload_hash: &str,
        reason: &'static str,
    ) {
        Self::log_audit_inner(
            &mut state.audit_log,
            self.audit_log_path.as_deref(),
            AuditEntry::new(
                extrinsic,
                Some(destination),
                amount_lunes,
                Some(payload_hash),
                false,
                Some(reason),
            ),
        )
        .unwrap_or_else(|error| self.warn_audit_persistence_failure(error));
    }

    /// Internal version that operates on the audit vector while the caller holds the lock.
    fn log_audit_inner(
        audit_log: &mut Vec<AuditEntry>,
        audit_log_path: Option<&Path>,
        entry: AuditEntry,
    ) -> std::io::Result<()> {
        if let Some(path) = audit_log_path {
            append_persistent_audit_entry(path, &entry)?;
        }

        if audit_log.len() >= MAX_AUDIT_LOG_ENTRIES {
            audit_log.remove(0);
        }
        audit_log.push(entry);

        Ok(())
    }

    fn warn_audit_persistence_failure(&self, error: std::io::Error) {
        if let Some(path) = &self.audit_log_path {
            warn!(
                audit_log_path = %path.display(),
                error = %error,
                "Failed to append persistent KMS audit entry"
            );
        }
    }

    /// Returns a copy of the audit log.
    pub fn get_audit_log(&self) -> Vec<AuditEntry> {
        self.state.lock().audit_log.clone()
    }

    /// Returns the amount spent today.
    pub fn spent_today(&self) -> u64 {
        self.state.lock().spending.spent_today()
    }
}

#[derive(Debug)]
pub struct SignedResult {
    pub signature: String,
    pub public_key: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PermissionsConfig;

    fn test_permissions() -> PermissionsConfig {
        PermissionsConfig {
            allowed_extrinsics: vec!["balances.transfer".into(), "contracts.call".into()],
            whitelisted_addresses: vec!["5Gxyz".into(), "5G".into()],
            daily_limit_lunes: 100,
            allowlist_contracts: Default::default(),
            governance: Default::default(),
            ttl_hours: 168,
            human_approval_required: true,
            approval_message_template: None,
        }
    }

    #[test]
    fn test_provision_generates_key() {
        let kms = AgentKms::new(AgentMode::Autonomous, test_permissions());
        let pub_key = kms.provision_key().expect("provision should succeed");
        assert_eq!(pub_key.len(), 64); // 32 bytes hex
        assert!(kms.is_active());
    }

    #[test]
    fn test_double_provision_is_blocked() {
        let kms = AgentKms::new(AgentMode::Autonomous, test_permissions());
        let first = kms.provision_key();
        assert!(first.is_ok());

        let second = kms.provision_key();
        assert!(second.is_err());
        match second.unwrap_err() {
            KmsError::AlreadyProvisioned => {}
            e => panic!("Expected AlreadyProvisioned, got {:?}", e),
        }
    }

    #[test]
    fn test_revoke_then_reprovision_works() {
        let kms = AgentKms::new(AgentMode::Autonomous, test_permissions());
        kms.provision_key().unwrap();
        kms.revoke_key();
        assert!(!kms.is_active());

        let second = kms.provision_key();
        assert!(second.is_ok());
        assert!(kms.is_active());
    }

    #[test]
    fn test_prepare_only_rejects_signing() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, test_permissions());
        kms.provision_key().unwrap();
        let result = kms.sign_payload("balances.transfer", "5Gxyz", 10, b"payload");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().error_code(), -32011);
    }

    #[test]
    fn test_unauthorized_extrinsic_blocked() {
        let kms = AgentKms::new(AgentMode::Autonomous, test_permissions());
        kms.provision_key().unwrap();
        let result = kms.sign_payload("staking.bond", "5Gxyz", 10, b"payload");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().error_code(), -32011);
    }

    #[test]
    fn test_empty_allowed_extrinsics_blocks_all_writes() {
        let perms = PermissionsConfig {
            allowed_extrinsics: vec![],
            whitelisted_addresses: vec![],
            daily_limit_lunes: 100,
            allowlist_contracts: Default::default(),
            governance: Default::default(),
            ttl_hours: 168,
            human_approval_required: true,
            approval_message_template: None,
        };
        let kms = AgentKms::new(AgentMode::Autonomous, perms);
        kms.provision_key().unwrap();

        let result = kms.sign_payload("balances.transfer", "5Gxyz", 10, b"payload");

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().error_code(), -32011);
    }

    #[test]
    fn test_empty_whitelist_blocks_destinations() {
        let perms = PermissionsConfig {
            allowed_extrinsics: vec!["balances.transfer".into()],
            whitelisted_addresses: vec![],
            daily_limit_lunes: 100,
            allowlist_contracts: Default::default(),
            governance: Default::default(),
            ttl_hours: 168,
            human_approval_required: true,
            approval_message_template: None,
        };
        let kms = AgentKms::new(AgentMode::Autonomous, perms);
        kms.provision_key().unwrap();

        let result = kms.sign_payload("balances.transfer", "5Gxyz", 10, b"payload");

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().error_code(), -32011);
    }

    #[test]
    fn test_daily_limit_enforced() {
        let kms = AgentKms::new(AgentMode::Autonomous, test_permissions());
        kms.provision_key().unwrap();

        let r1 = kms.sign_payload("balances.transfer", "5Gxyz", 90, b"tx1");
        assert!(r1.is_ok());

        let r2 = kms.sign_payload("balances.transfer", "5Gxyz", 20, b"tx2");
        assert!(r2.is_err());
        assert_eq!(r2.unwrap_err().error_code(), -32010);
    }

    #[test]
    fn test_zero_daily_limit_blocks_positive_spend() {
        let perms = PermissionsConfig {
            allowed_extrinsics: vec!["balances.transfer".into()],
            whitelisted_addresses: vec!["5Gxyz".into()],
            daily_limit_lunes: 0,
            allowlist_contracts: Default::default(),
            governance: Default::default(),
            ttl_hours: 168,
            human_approval_required: true,
            approval_message_template: None,
        };
        let kms = AgentKms::new(AgentMode::Autonomous, perms);
        kms.provision_key().unwrap();

        let result = kms.sign_payload("balances.transfer", "5Gxyz", 1, b"payload");

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().error_code(), -32010);
    }

    #[test]
    fn test_daily_limit_overflow_is_rejected() {
        let perms = PermissionsConfig {
            allowed_extrinsics: vec!["balances.transfer".into()],
            whitelisted_addresses: vec!["5Gxyz".into()],
            daily_limit_lunes: u64::MAX,
            allowlist_contracts: Default::default(),
            governance: Default::default(),
            ttl_hours: 168,
            human_approval_required: true,
            approval_message_template: None,
        };
        let kms = AgentKms::new(AgentMode::Autonomous, perms);
        kms.provision_key().unwrap();

        let first = kms.sign_payload("balances.transfer", "5Gxyz", u64::MAX, b"tx1");
        let second = kms.sign_payload("balances.transfer", "5Gxyz", 1, b"tx2");

        assert!(first.is_ok());
        assert!(second.is_err());
        assert_eq!(second.unwrap_err().error_code(), -32010);
    }

    #[test]
    fn test_whitelist_enforced() {
        let perms = PermissionsConfig {
            allowed_extrinsics: vec!["balances.transfer".into()],
            whitelisted_addresses: vec!["5GoodAddress".into()],
            daily_limit_lunes: 1000,
            allowlist_contracts: Default::default(),
            governance: Default::default(),
            ttl_hours: 168,
            human_approval_required: true,
            approval_message_template: None,
        };
        let kms = AgentKms::new(AgentMode::Autonomous, perms);
        kms.provision_key().unwrap();

        let ok = kms.sign_payload("balances.transfer", "5GoodAddress", 10, b"tx");
        assert!(ok.is_ok());

        let bad = kms.sign_payload("balances.transfer", "5EvilHacker", 10, b"tx2");
        assert!(bad.is_err());
    }

    #[test]
    fn test_audit_log_records_all() {
        let kms = AgentKms::new(AgentMode::Autonomous, test_permissions());
        kms.provision_key().unwrap();

        let _ = kms.sign_payload("balances.transfer", "5G", 10, b"ok");
        let _ = kms.sign_payload("staking.bond", "5G", 10, b"fail");

        let log = kms.get_audit_log();
        assert_eq!(log.len(), 2);
        assert!(log[0].success);
        assert!(!log[1].success);
    }

    #[test]
    fn test_audit_log_is_bounded() {
        let kms = AgentKms::new(AgentMode::Autonomous, test_permissions());
        kms.provision_key().unwrap();

        for _ in 0..(MAX_AUDIT_LOG_ENTRIES + 10) {
            let _ = kms.sign_payload("staking.bond", "5G", 1, b"fail");
        }

        let log = kms.get_audit_log();
        assert_eq!(log.len(), MAX_AUDIT_LOG_ENTRIES);
    }

    #[test]
    fn test_persistent_audit_log_writes_jsonl_without_payload() {
        let path = std::env::temp_dir().join(format!(
            "lunes-mcp-audit-{}-{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let kms = AgentKms::new_with_optional_audit_log_path(
            AgentMode::Autonomous,
            test_permissions(),
            Some(path.clone()),
        );
        kms.provision_key().unwrap();

        kms.sign_payload("balances.transfer", "5G", 10, b"secret payload")
            .unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        assert!(contents.contains("\"action\":\"SIGN\""));
        assert!(contents.contains("\"destination\":\"5G\""));
        assert!(contents.contains("\"payload_hash\":\"0x"));
        assert!(!contents.contains("secret payload"));
    }

    #[test]
    fn test_persistent_audit_log_failure_blocks_successful_signing() {
        let path = std::env::temp_dir()
            .join(format!(
                "lunes-mcp-missing-audit-dir-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ))
            .join("audit.jsonl");
        let kms = AgentKms::new_with_optional_audit_log_path(
            AgentMode::Autonomous,
            test_permissions(),
            Some(path),
        );
        kms.provision_key().unwrap();

        let result = kms.sign_payload("balances.transfer", "5G", 10, b"payload");

        assert!(matches!(
            result,
            Err(KmsError::AuditLogPersistenceFailed(_))
        ));
        assert_eq!(kms.spent_today(), 0);
        assert!(kms.get_audit_log().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn test_persistent_audit_log_rejects_weak_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "lunes-mcp-audit-weak-{}-{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let kms = AgentKms::new_with_optional_audit_log_path(
            AgentMode::Autonomous,
            test_permissions(),
            Some(path.clone()),
        );
        kms.provision_key().unwrap();

        let result = kms.sign_payload("balances.transfer", "5G", 10, b"payload");
        let _ = std::fs::remove_file(&path);

        assert!(matches!(
            result,
            Err(KmsError::AuditLogPersistenceFailed(_))
        ));
        assert!(kms.get_audit_log().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn test_persistent_audit_log_rejects_symlink() {
        let base = std::env::temp_dir().join(format!(
            "lunes-mcp-audit-link-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let target = base.with_extension("target");
        let link = base.with_extension("link");
        std::fs::write(&target, "").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let kms = AgentKms::new_with_optional_audit_log_path(
            AgentMode::Autonomous,
            test_permissions(),
            Some(link.clone()),
        );
        kms.provision_key().unwrap();

        let result = kms.sign_payload("balances.transfer", "5G", 10, b"payload");
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&target);

        assert!(matches!(
            result,
            Err(KmsError::AuditLogPersistenceFailed(_))
        ));
        assert!(kms.get_audit_log().is_empty());
    }

    #[test]
    fn test_contract_call_requires_explicit_method_allowlist() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, test_permissions());

        let result = kms.validate_contract_call("5G", "PSP22::balance_of");

        assert!(matches!(
            result,
            Err(KmsError::UnauthorizedContractMessage { .. })
        ));
    }

    #[test]
    fn test_spending_tracker_cleanup() {
        let mut tracker = SpendingTracker::new(100);
        tracker
            .daily_totals
            .insert(NaiveDate::from_ymd_opt(2020, 1, 1).unwrap(), 50);
        tracker
            .daily_totals
            .insert(SpendingTracker::current_day_key(), 30);

        tracker.cleanup_old_entries();

        assert_eq!(tracker.daily_totals.len(), 1);
        assert_eq!(tracker.spent_today(), 30);
    }
}
