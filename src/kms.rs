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

use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use parking_lot::Mutex;
use rand::rngs::OsRng;
use std::collections::HashMap;
use tracing::{info, warn};

use crate::config::{AgentMode, PermissionsConfig};

// --- KMS errors ----------------------------------------------------------

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
        }
    }
}

// --- Audit log -----------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub action: String,
    pub extrinsic: String,
    pub amount_lunes: u64,
    pub success: bool,
    pub error: Option<String>,
}

// --- Spending tracker ----------------------------------------------------

struct SpendingTracker {
    /// Map of UTC day -> amount spent that day.
    daily_totals: HashMap<String, u64>,
    limit: u64,
}

impl SpendingTracker {
    fn new(limit: u64) -> Self {
        Self {
            daily_totals: HashMap::new(),
            limit,
        }
    }

    fn current_day_key() -> String {
        Utc::now().format("%Y-%m-%d").to_string()
    }

    /// Checks whether an amount fits within the daily limit.
    fn check(&self, amount: u64) -> Result<(), KmsError> {
        let today = Self::current_day_key();
        let spent = *self.daily_totals.get(&today).unwrap_or(&0);
        let next_spent = spent
            .checked_add(amount)
            .ok_or(KmsError::DailyLimitExceeded {
                spent,
                limit: self.limit,
            })?;

        if next_spent > self.limit {
            return Err(KmsError::DailyLimitExceeded {
                spent,
                limit: self.limit,
            });
        }

        Ok(())
    }

    /// Checks and records an amount against the daily limit.
    fn check_and_record(&mut self, amount: u64) -> Result<u64, KmsError> {
        let today = Self::current_day_key();
        let spent = self.daily_totals.entry(today).or_insert(0);

        let next_spent = spent
            .checked_add(amount)
            .ok_or(KmsError::DailyLimitExceeded {
                spent: *spent,
                limit: self.limit,
            })?;

        if next_spent > self.limit {
            return Err(KmsError::DailyLimitExceeded {
                spent: *spent,
                limit: self.limit,
            });
        }

        *spent = next_spent;
        Ok(*spent)
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

// --- Internal state ------------------------------------------------------

struct KmsState {
    /// Private signing key. Never exposed through the API.
    signing_key: Option<SigningKey>,

    /// Derived public key.
    public_key: Option<VerifyingKey>,

    /// Provisioning timestamp.
    provisioned_at: Option<DateTime<Utc>>,

    /// Daily spending tracker.
    spending: SpendingTracker,

    /// In-memory audit log.
    audit_log: Vec<AuditEntry>,
}

// --- Agent KMS -----------------------------------------------------------

pub struct AgentKms {
    mode: AgentMode,
    permissions: PermissionsConfig,
    state: Mutex<KmsState>,
}

impl AgentKms {
    pub fn new(mode: AgentMode, permissions: PermissionsConfig) -> Self {
        let limit = permissions.daily_limit_lunes;
        Self {
            mode,
            permissions,
            state: Mutex::new(KmsState {
                signing_key: None,
                public_key: None,
                provisioned_at: None,
                spending: SpendingTracker::new(limit),
                audit_log: Vec::new(),
            }),
        }
    }

    // Provisioning

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

    /// Returns whether autonomous signing is enabled.
    pub fn is_autonomous(&self) -> bool {
        self.mode == AgentMode::Autonomous
    }

    /// Returns whether a non-expired key is provisioned.
    pub fn is_active(&self) -> bool {
        let state = self.state.lock();
        state.signing_key.is_some() && self.check_ttl_inner(&state).is_ok()
    }

    // Policy validation

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

    // Signing

    /// Validates all policies and signs the payload.
    ///
    /// Before using the private key, the KMS checks mode, key lifecycle,
    /// extrinsic allowlist, destination whitelist, and daily spending limit.
    ///
    /// ## Validation Pipeline
    /// 1. Autonomous mode enabled?
    /// 2. Agent key provisioned?
    /// 3. TTL valid?
    /// 4. Extrinsic allowed?
    /// 5. Destination whitelisted?
    /// 6. Daily limit available?
    pub fn sign_payload(
        &self,
        extrinsic: &str,
        destination: &str,
        amount_lunes: u64,
        payload_bytes: &[u8],
    ) -> Result<SignedResult, KmsError> {
        // 1. Autonomous mode?
        if self.mode != AgentMode::Autonomous {
            self.log_audit(extrinsic, amount_lunes, false, Some("NotAutonomous"));
            return Err(KmsError::NotAutonomous);
        }

        // One lock covers the full operation to keep state consistent.
        let mut state = self.state.lock();

        // 2. Key provisioned?
        if state.signing_key.is_none() {
            Self::log_audit_inner(
                &mut state.audit_log,
                extrinsic,
                amount_lunes,
                false,
                Some("NotInitialized"),
            );
            return Err(KmsError::NotInitialized);
        }

        // 3. TTL valid?
        if let Err(e) = self.check_ttl_inner(&state) {
            Self::log_audit_inner(
                &mut state.audit_log,
                extrinsic,
                amount_lunes,
                false,
                Some("TtlExpired"),
            );
            return Err(e);
        }

        // 4. Extrinsic allowed?
        if let Err(e) = self.check_extrinsic(extrinsic) {
            Self::log_audit_inner(
                &mut state.audit_log,
                extrinsic,
                amount_lunes,
                false,
                Some("UnauthorizedExtrinsic"),
            );
            return Err(e);
        }

        // 5. Destination whitelisted?
        if let Err(e) = self.check_destination(destination) {
            Self::log_audit_inner(
                &mut state.audit_log,
                extrinsic,
                amount_lunes,
                false,
                Some("UnauthorizedDestination"),
            );
            return Err(e);
        }

        // 6. Daily limit available?
        if let Err(e) = state.spending.check_and_record(amount_lunes) {
            Self::log_audit_inner(
                &mut state.audit_log,
                extrinsic,
                amount_lunes,
                false,
                Some("DailyLimitExceeded"),
            );
            return Err(e);
        }

        // All checks passed; sign with the local key.
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

        Self::log_audit_inner(&mut state.audit_log, extrinsic, amount_lunes, true, None);

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

    // Audit

    fn log_audit(&self, extrinsic: &str, amount: u64, success: bool, error: Option<&str>) {
        let mut state = self.state.lock();
        Self::log_audit_inner(&mut state.audit_log, extrinsic, amount, success, error);
    }

    /// Internal version that operates on the audit vector while the caller holds the lock.
    fn log_audit_inner(
        audit_log: &mut Vec<AuditEntry>,
        extrinsic: &str,
        amount: u64,
        success: bool,
        error: Option<&str>,
    ) {
        let entry = AuditEntry {
            timestamp: Utc::now(),
            action: if success {
                "SIGN".into()
            } else {
                "DENIED".into()
            },
            extrinsic: extrinsic.to_string(),
            amount_lunes: amount,
            success,
            error: error.map(|s| s.to_string()),
        };
        audit_log.push(entry);
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

// --- Signed result -------------------------------------------------------

#[derive(Debug)]
pub struct SignedResult {
    pub signature: String,
    pub public_key: String,
}

// --- Tests ---------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PermissionsConfig;

    fn test_permissions() -> PermissionsConfig {
        PermissionsConfig {
            allowed_extrinsics: vec!["balances.transfer".into(), "contracts.call".into()],
            whitelisted_addresses: vec!["5Gxyz".into(), "5G".into()],
            daily_limit_lunes: 100,
            ttl_hours: 168,
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
            KmsError::AlreadyProvisioned => {} // expected
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
            ttl_hours: 168,
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
            ttl_hours: 168,
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

        // Spend 90: allowed.
        let r1 = kms.sign_payload("balances.transfer", "5Gxyz", 90, b"tx1");
        assert!(r1.is_ok());

        // Spend 20 more: blocked because total would be 110 > 100.
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
            ttl_hours: 168,
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
            ttl_hours: 168,
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
            ttl_hours: 168,
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
    fn test_spending_tracker_cleanup() {
        let mut tracker = SpendingTracker::new(100);
        // Simulate spending from a previous day.
        tracker.daily_totals.insert("2020-01-01".to_string(), 50);
        tracker
            .daily_totals
            .insert(SpendingTracker::current_day_key(), 30);

        tracker.cleanup_old_entries();

        // The old day should be removed.
        assert_eq!(tracker.daily_totals.len(), 1);
        assert_eq!(tracker.spent_today(), 30);
    }
}
