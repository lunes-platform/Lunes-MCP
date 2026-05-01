//! Agent configuration loading and runtime validation.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// Agent operating mode.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AgentMode {
    /// The server signs with the local agent key after policy checks.
    Autonomous,
    /// The server only prepares unsigned payloads for external review.
    #[default]
    PrepareOnly,
}

pub const AUTONOMOUS_MODE_ENV_VAR: &str = "LUNES_MCP_ALLOW_AUTONOMOUS";
pub const AUTONOMOUS_STUB_ENV_VAR: &str = "LUNES_MCP_ALLOW_AUTONOMOUS_STUB";

/// Root TOML structure.
#[derive(Debug, Deserialize)]
pub struct ConfigFile {
    pub network: NetworkConfig,
    pub agent: AgentConfig,
    /// Optional server configuration for binding and rate limiting.
    #[serde(default)]
    pub server: Option<ServerConfig>,
}

/// Lunes network endpoints.
#[derive(Debug, Deserialize)]
pub struct NetworkConfig {
    /// Primary RPC endpoint, for example `wss://ws.lunes.io`.
    pub rpc_url: String,

    /// Fallback endpoints.
    #[serde(default)]
    pub rpc_failovers: Vec<String>,

    /// Archive endpoint for historical queries.
    #[serde(default)]
    pub archive_url: Option<String>,
}

/// Complete agent configuration.
#[derive(Debug, Deserialize)]
pub struct AgentConfig {
    pub wallet: WalletConfig,
    pub permissions: PermissionsConfig,
}

/// Agent wallet settings.
#[derive(Debug, Deserialize)]
pub struct WalletConfig {
    pub mode: AgentMode,
}

/// Permission and spending limits.
#[derive(Debug, Deserialize)]
pub struct PermissionsConfig {
    /// Extrinsics the agent may invoke, for example `balances.transfer`.
    pub allowed_extrinsics: Vec<String>,

    /// Destination addresses or contracts the agent may interact with.
    /// An empty list blocks all write destinations.
    #[serde(default)]
    pub whitelisted_addresses: Vec<String>,

    /// Maximum LUNES amount the agent may spend in a 24-hour window.
    pub daily_limit_lunes: u64,

    /// Allowed messages per contract, keyed by Lunes contract address.
    #[serde(default)]
    pub allowlist_contracts: HashMap<String, Vec<String>>,

    /// Local metadata and transfer limits for PSP22 assets, keyed by contract address.
    #[serde(default)]
    pub asset_policies: HashMap<String, AssetPolicyConfig>,

    /// Explicit prepare-only governance policy. Defaults deny every vote.
    #[serde(default)]
    pub governance: GovernancePolicyConfig,

    /// Agent key lifetime in hours. Zero disables expiration.
    #[serde(default = "default_ttl_hours")]
    pub ttl_hours: u64,

    /// Whether pending write responses include an explicit human approval notice.
    #[serde(default = "default_human_approval")]
    pub human_approval_required: bool,

    /// Custom template for human approval pending message.
    pub approval_message_template: Option<String>,
}

/// Local PSP22 asset policy. Metadata is advisory; limits are enforcement inputs.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct AssetPolicyConfig {
    /// Human-readable asset name shown by MCP tools.
    #[serde(default)]
    pub name: Option<String>,

    /// Asset ticker shown by MCP tools.
    #[serde(default)]
    pub symbol: Option<String>,

    /// Decimal places used by the PSP22 asset.
    #[serde(default)]
    pub decimals: Option<u8>,

    /// Maximum amount per transfer, expressed in PSP22 base units.
    #[serde(default)]
    pub max_transfer_base_units: Option<String>,

    /// Recipients allowed for this asset. Empty blocks PSP22 transfers.
    #[serde(default)]
    pub allowed_recipients: Vec<String>,
}

/// Prepare-only governance policy. This never authorizes final voting broadcast.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct GovernancePolicyConfig {
    /// Allows MCP tools to prepare human-review governance payloads.
    #[serde(default)]
    pub allow_prepare_votes: bool,

    /// Referendum indexes the agent may prepare payloads for.
    #[serde(default)]
    pub allowed_referenda: Vec<u32>,

    /// Allowed vote directions, for example `aye` and/or `nay`.
    #[serde(default)]
    pub allowed_vote_directions: Vec<String>,

    /// Allowed conviction values, for example `none`, `locked1x`, `locked2x`.
    #[serde(default)]
    pub allowed_convictions: Vec<String>,

    /// Maximum LUNES lock amount for a prepared vote. Zero denies vote payloads.
    #[serde(default)]
    pub max_vote_lunes: u64,
}

fn default_ttl_hours() -> u64 {
    168 // 7 days
}

fn default_human_approval() -> bool {
    true
}

/// HTTP/RPC server configuration.
#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    /// Bind address. Defaults to 127.0.0.1.
    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    /// Server port. Defaults to 9950.
    #[serde(default = "default_port")]
    pub port: u16,

    /// Requests per second.
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_second: u64,

    /// Maximum rate-limit burst.
    #[serde(default = "default_rate_burst")]
    pub rate_limit_burst: u32,
}

fn default_bind_address() -> String {
    "127.0.0.1".into()
}
fn default_port() -> u16 {
    9950
}
fn default_rate_limit() -> u64 {
    10
}
fn default_rate_burst() -> u32 {
    20
}

/// Loads and parses the full configuration file.
pub fn load_config(path: &str) -> Result<ConfigFile, ConfigError> {
    let path = Path::new(path);
    if !path.exists() {
        return Err(ConfigError::FileNotFound(path.display().to_string()));
    }

    let contents =
        std::fs::read_to_string(path).map_err(|e| ConfigError::ReadError(e.to_string()))?;

    let file: ConfigFile =
        toml::from_str(&contents).map_err(|e| ConfigError::ParseError(e.to_string()))?;

    Ok(file)
}

/// Returns a safe default configuration.
pub fn default_safe_config() -> ConfigFile {
    ConfigFile {
        network: NetworkConfig {
            rpc_url: "wss://ws.lunes.io".to_string(),
            rpc_failovers: vec![
                "wss://ws-lunes-main-01.lunes.io".to_string(),
                "wss://ws-lunes-main-02.lunes.io".to_string(),
            ],
            archive_url: Some("wss://ws-archive.lunes.io".to_string()),
        },
        agent: AgentConfig {
            wallet: WalletConfig {
                mode: AgentMode::PrepareOnly,
            },
            permissions: PermissionsConfig {
                allowed_extrinsics: vec![],
                whitelisted_addresses: vec![],
                daily_limit_lunes: 0,
                allowlist_contracts: HashMap::new(),
                asset_policies: HashMap::new(),
                governance: GovernancePolicyConfig::default(),
                ttl_hours: 168,
                human_approval_required: true,
                approval_message_template: None,
            },
        },
        server: None,
    }
}

/// Validates policies that must be safe before the server accepts traffic.
pub fn validate_runtime_config(
    config: &ConfigFile,
    autonomous_stub_allowed: bool,
) -> Result<(), ConfigValidationError> {
    validate_network_config(&config.network)?;

    if config.agent.wallet.mode != AgentMode::Autonomous {
        return Ok(());
    }

    if !autonomous_stub_allowed {
        return Err(ConfigValidationError::StubNotAllowed);
    }

    let permissions = &config.agent.permissions;

    if permissions.allowed_extrinsics.is_empty() {
        return Err(ConfigValidationError::ExtrinsicsRequired);
    }

    if permissions.whitelisted_addresses.is_empty() {
        return Err(ConfigValidationError::WhitelistRequired);
    }

    if permissions.ttl_hours == 0 {
        return Err(ConfigValidationError::TtlRequired);
    }

    if permissions.daily_limit_lunes == 0 {
        return Err(ConfigValidationError::DailyLimitRequired);
    }

    if permissions
        .allowed_extrinsics
        .iter()
        .any(|extrinsic| extrinsic == "contracts.call")
    {
        validate_autonomous_contract_call_policy(permissions)?;
    }

    if let Some(extrinsic) = permissions
        .allowed_extrinsics
        .iter()
        .find(|extrinsic| is_autonomous_high_risk_extrinsic(extrinsic))
    {
        return Err(ConfigValidationError::HighRiskAutonomousExtrinsicDisabled(
            extrinsic.clone(),
        ));
    }

    Ok(())
}

fn validate_autonomous_contract_call_policy(
    permissions: &PermissionsConfig,
) -> Result<(), ConfigValidationError> {
    if permissions.allowlist_contracts.is_empty() {
        return Err(ConfigValidationError::ContractsCallDisabled);
    }

    for (contract, methods) in &permissions.allowlist_contracts {
        if methods.is_empty()
            || methods
                .iter()
                .any(|method| !is_psp22_asset_method(method.as_str()))
        {
            return Err(ConfigValidationError::ContractsCallDisabled);
        }

        if !methods
            .iter()
            .any(|method| is_psp22_transfer_method(method.as_str()))
        {
            continue;
        }

        let Some(policy) = permissions.asset_policies.get(contract) else {
            return Err(ConfigValidationError::ContractsCallDisabled);
        };
        let Some(max_transfer) = policy
            .max_transfer_base_units
            .as_deref()
            .and_then(|value| value.parse::<u128>().ok())
        else {
            return Err(ConfigValidationError::ContractsCallDisabled);
        };
        if max_transfer == 0 || policy.allowed_recipients.is_empty() {
            return Err(ConfigValidationError::ContractsCallDisabled);
        }
    }

    Ok(())
}

fn is_psp22_transfer_method(method: &str) -> bool {
    method == "PSP22::transfer" || method == "transfer"
}

fn is_psp22_balance_method(method: &str) -> bool {
    method == "PSP22::balance_of" || method == "balance_of"
}

fn is_psp22_asset_method(method: &str) -> bool {
    is_psp22_balance_method(method) || is_psp22_transfer_method(method)
}

fn is_autonomous_high_risk_extrinsic(extrinsic: &str) -> bool {
    let normalized = extrinsic.to_ascii_lowercase().replace('_', "");
    normalized.starts_with("referenda.")
        || normalized.starts_with("democracy.")
        || normalized.starts_with("convictionvoting.")
        || normalized.starts_with("utility.")
        || normalized.starts_with("proxy.")
        || normalized.starts_with("multisig.")
        || normalized.starts_with("scheduler.")
        || normalized.starts_with("preimage.")
}

fn validate_network_config(network: &NetworkConfig) -> Result<(), ConfigValidationError> {
    validate_rpc_endpoint("network.rpc_url", &network.rpc_url)?;
    for endpoint in &network.rpc_failovers {
        validate_rpc_endpoint("network.rpc_failovers", endpoint)?;
    }
    if let Some(endpoint) = &network.archive_url {
        validate_rpc_endpoint("network.archive_url", endpoint)?;
    }

    Ok(())
}

fn validate_rpc_endpoint(field: &'static str, endpoint: &str) -> Result<(), ConfigValidationError> {
    let Some((scheme, rest)) = endpoint.split_once("://") else {
        return Err(ConfigValidationError::UnsafeRpcEndpoint {
            field,
            endpoint: redact_config_endpoint(endpoint),
            reason: "missing URL scheme".into(),
        });
    };

    let (authority, _) = rest
        .find(['/', '?', '#'])
        .map(|idx| rest.split_at(idx))
        .unwrap_or((rest, ""));
    if authority.is_empty() {
        return Err(ConfigValidationError::UnsafeRpcEndpoint {
            field,
            endpoint: redact_config_endpoint(endpoint),
            reason: "missing URL host".into(),
        });
    }
    let host = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority);
    let is_local_ws = scheme == "ws"
        && matches!(
            host.split(':').next().unwrap_or(""),
            "127.0.0.1" | "::1" | "localhost"
        );

    if scheme != "wss" && !is_local_ws {
        return Err(ConfigValidationError::UnsafeRpcEndpoint {
            field,
            endpoint: redact_config_endpoint(endpoint),
            reason: "RPC endpoints must use wss://, except local ws:// development endpoints"
                .into(),
        });
    }

    if authority.contains('@') || endpoint.contains('?') || endpoint.contains('#') {
        return Err(ConfigValidationError::UnsafeRpcEndpoint {
            field,
            endpoint: redact_config_endpoint(endpoint),
            reason: "RPC endpoints must not contain credentials, query strings, or fragments"
                .into(),
        });
    }

    Ok(())
}

fn redact_config_endpoint(endpoint: &str) -> String {
    let Some((scheme, rest)) = endpoint.split_once("://") else {
        return endpoint.to_string();
    };
    let (authority, suffix) = rest
        .find(['/', '?', '#'])
        .map(|idx| rest.split_at(idx))
        .unwrap_or((rest, ""));
    let authority = authority
        .rsplit_once('@')
        .map(|(_, host)| format!("<redacted>@{host}"))
        .unwrap_or_else(|| authority.to_string());
    let suffix = suffix
        .find(['?', '#'])
        .map(|idx| {
            let marker = suffix.as_bytes()[idx] as char;
            format!("{}{}<redacted>", &suffix[..idx], marker)
        })
        .unwrap_or_else(|| suffix.to_string());

    format!("{scheme}://{authority}{suffix}")
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Config file not found: {0}")]
    FileNotFound(String),

    #[error("Failed to read config: {0}")]
    ReadError(String),

    #[error("Invalid TOML format: {0}")]
    ParseError(String),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigValidationError {
    #[error("autonomous mode is disabled unless {AUTONOMOUS_MODE_ENV_VAR}=1 is set explicitly")]
    StubNotAllowed,

    #[error("autonomous mode requires at least one allowed extrinsic")]
    ExtrinsicsRequired,

    #[error("autonomous mode requires an explicit destination whitelist")]
    WhitelistRequired,

    #[error("autonomous mode requires ttl_hours > 0")]
    TtlRequired,

    #[error("autonomous mode requires daily_limit_lunes > 0")]
    DailyLimitRequired,

    #[error("autonomous contracts.call requires PSP22-only allowlists with asset-specific transfer limits and recipients")]
    ContractsCallDisabled,

    #[error("autonomous extrinsic '{0}' is disabled until a dedicated safe policy exists")]
    HighRiskAutonomousExtrinsicDisabled(String),

    #[error("{field} contains unsafe RPC endpoint '{endpoint}': {reason}")]
    UnsafeRpcEndpoint {
        field: &'static str,
        endpoint: String,
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_autonomous_config() {
        let toml_str = r#"
[network]
rpc_url = "wss://ws.lunes.io"
rpc_failovers = ["wss://ws-lunes-main-01.lunes.io"]
archive_url = "wss://ws-archive.lunes.io"

[agent.wallet]
mode = "autonomous"

[agent.permissions]
allowed_extrinsics = ["balances.transfer", "contracts.call"]
whitelisted_addresses = ["5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"]
daily_limit_lunes = 100
ttl_hours = 48
"#;
        let file: ConfigFile = toml::from_str(toml_str).unwrap();
        assert_eq!(file.network.rpc_url, "wss://ws.lunes.io");
        assert_eq!(file.agent.wallet.mode, AgentMode::Autonomous);
        assert_eq!(file.agent.permissions.daily_limit_lunes, 100);
        assert_eq!(file.agent.permissions.ttl_hours, 48);
        assert_eq!(file.agent.permissions.whitelisted_addresses.len(), 1);
        assert!(file.agent.permissions.allowlist_contracts.is_empty());
        assert!(file.agent.permissions.asset_policies.is_empty());
        assert!(!file.agent.permissions.governance.allow_prepare_votes);
    }

    #[test]
    fn test_parse_prepare_only_config() {
        let toml_str = r#"
[network]
rpc_url = "wss://ws.lunes.io"

[agent.wallet]
mode = "prepare_only"

[agent.permissions]
allowed_extrinsics = []
daily_limit_lunes = 0
"#;
        let file: ConfigFile = toml::from_str(toml_str).unwrap();
        assert_eq!(file.agent.wallet.mode, AgentMode::PrepareOnly);
        assert_eq!(file.agent.permissions.ttl_hours, 168);
    }

    #[test]
    fn test_parse_asset_policy_config() {
        let toml_str = r#"
[network]
rpc_url = "wss://ws.lunes.io"

[agent.wallet]
mode = "prepare_only"

[agent.permissions]
allowed_extrinsics = ["contracts.call"]
whitelisted_addresses = ["5ContractAddress"]
daily_limit_lunes = 1

[agent.permissions.allowlist_contracts]
"5ContractAddress" = ["PSP22::transfer"]

[agent.permissions.asset_policies."5ContractAddress"]
name = "Policy Token"
symbol = "POL"
decimals = 12
max_transfer_base_units = "1000"
allowed_recipients = ["5RecipientAddress"]
"#;
        let file: ConfigFile = toml::from_str(toml_str).unwrap();
        let policy = file
            .agent
            .permissions
            .asset_policies
            .get("5ContractAddress")
            .unwrap();

        assert_eq!(policy.name.as_deref(), Some("Policy Token"));
        assert_eq!(policy.symbol.as_deref(), Some("POL"));
        assert_eq!(policy.decimals, Some(12));
        assert_eq!(policy.max_transfer_base_units.as_deref(), Some("1000"));
        assert_eq!(policy.allowed_recipients, vec!["5RecipientAddress"]);
    }

    #[test]
    fn test_default_safe_config() {
        let cfg = default_safe_config();
        assert_eq!(cfg.network.rpc_url, "wss://ws.lunes.io");
        assert_eq!(cfg.agent.wallet.mode, AgentMode::PrepareOnly);
        assert_eq!(cfg.agent.permissions.daily_limit_lunes, 0);
    }

    #[test]
    fn test_agent_config_example_is_safe_by_default() {
        let cfg = load_config("agent_config.toml").unwrap();

        assert_eq!(cfg.agent.wallet.mode, AgentMode::PrepareOnly);
        assert!(cfg.agent.permissions.allowed_extrinsics.is_empty());
        assert_eq!(cfg.agent.permissions.daily_limit_lunes, 0);
    }

    #[test]
    fn autonomous_mode_requires_explicit_stub_opt_in() {
        let cfg = autonomous_config(vec!["balances.transfer"], vec!["5GoodAddress"], 100, 168);

        let err = validate_runtime_config(&cfg, false).unwrap_err();

        assert!(matches!(err, ConfigValidationError::StubNotAllowed));
    }

    #[test]
    fn autonomous_mode_requires_destination_whitelist() {
        let cfg = autonomous_config(vec!["balances.transfer"], vec![], 100, 168);

        let err = validate_runtime_config(&cfg, true).unwrap_err();

        assert!(matches!(err, ConfigValidationError::WhitelistRequired));
    }

    #[test]
    fn autonomous_mode_rejects_unbounded_ttl() {
        let cfg = autonomous_config(vec!["balances.transfer"], vec!["5GoodAddress"], 100, 0);

        let err = validate_runtime_config(&cfg, true).unwrap_err();

        assert!(matches!(err, ConfigValidationError::TtlRequired));
    }

    #[test]
    fn autonomous_mode_requires_daily_limit() {
        let cfg = autonomous_config(vec!["balances.transfer"], vec!["5GoodAddress"], 0, 168);

        let err = validate_runtime_config(&cfg, true).unwrap_err();

        assert!(matches!(err, ConfigValidationError::DailyLimitRequired));
    }

    #[test]
    fn autonomous_mode_disables_contracts_call_until_limits_exist() {
        let cfg = autonomous_config(vec!["contracts.call"], vec!["5GoodAddress"], 100, 168);

        let err = validate_runtime_config(&cfg, true).unwrap_err();

        assert!(matches!(err, ConfigValidationError::ContractsCallDisabled));
    }

    #[test]
    fn autonomous_mode_accepts_psp22_contracts_call_with_asset_policy() {
        let contract = "5ContractAddress";
        let recipient = "5RecipientAddress";
        let mut cfg = autonomous_config(vec!["contracts.call"], vec![contract], 100, 168);
        cfg.agent.permissions.allowlist_contracts.insert(
            contract.into(),
            vec!["PSP22::balance_of".into(), "PSP22::transfer".into()],
        );
        cfg.agent.permissions.asset_policies.insert(
            contract.into(),
            AssetPolicyConfig {
                name: Some("Policy Token".into()),
                symbol: Some("POL".into()),
                decimals: Some(12),
                max_transfer_base_units: Some("1000".into()),
                allowed_recipients: vec![recipient.into()],
            },
        );

        validate_runtime_config(&cfg, true).unwrap();
    }

    #[test]
    fn autonomous_mode_rejects_contracts_call_with_generic_message() {
        let contract = "5ContractAddress";
        let mut cfg = autonomous_config(vec!["contracts.call"], vec![contract], 100, 168);
        cfg.agent
            .permissions
            .allowlist_contracts
            .insert(contract.into(), vec!["PSP22::approve".into()]);
        cfg.agent.permissions.asset_policies.insert(
            contract.into(),
            AssetPolicyConfig {
                name: None,
                symbol: None,
                decimals: None,
                max_transfer_base_units: Some("1000".into()),
                allowed_recipients: vec!["5RecipientAddress".into()],
            },
        );

        let err = validate_runtime_config(&cfg, true).unwrap_err();

        assert!(matches!(err, ConfigValidationError::ContractsCallDisabled));
    }

    #[test]
    fn autonomous_mode_rejects_high_risk_governance_and_indirection_extrinsics() {
        for extrinsic in [
            "conviction_voting.vote",
            "referenda.submit",
            "democracy.vote",
            "utility.batch",
            "proxy.proxy",
            "multisig.as_multi",
            "scheduler.schedule",
            "preimage.note_preimage",
        ] {
            let cfg = autonomous_config(vec![extrinsic], vec!["5GoodAddress"], 100, 168);

            let err = validate_runtime_config(&cfg, true).unwrap_err();

            assert!(matches!(
                err,
                ConfigValidationError::HighRiskAutonomousExtrinsicDisabled(_)
            ));
        }
    }

    #[test]
    fn autonomous_mode_accepts_safe_stub_config_when_explicitly_enabled() {
        let cfg = autonomous_config(vec!["balances.transfer"], vec!["5GoodAddress"], 100, 168);

        assert_eq!(validate_runtime_config(&cfg, true), Ok(()));
    }

    #[test]
    fn runtime_config_rejects_public_ws_rpc_endpoint() {
        let mut cfg = autonomous_config(vec!["balances.transfer"], vec!["5GoodAddress"], 100, 168);
        cfg.network.rpc_url = "ws://rpc.example".into();

        let err = validate_runtime_config(&cfg, true).unwrap_err();

        assert!(matches!(
            err,
            ConfigValidationError::UnsafeRpcEndpoint {
                field: "network.rpc_url",
                ..
            }
        ));
    }

    #[test]
    fn runtime_config_allows_local_ws_rpc_endpoint() {
        let mut cfg = autonomous_config(vec!["balances.transfer"], vec!["5GoodAddress"], 100, 168);
        cfg.network.rpc_url = "ws://127.0.0.1:9944".into();

        assert_eq!(validate_runtime_config(&cfg, true), Ok(()));
    }

    #[test]
    fn runtime_config_rejects_rpc_credentials_and_query_strings() {
        let mut cfg = autonomous_config(vec!["balances.transfer"], vec!["5GoodAddress"], 100, 168);
        cfg.network.rpc_url = "wss://user:secret@rpc.example/ws?token=abc".into();

        let err = validate_runtime_config(&cfg, true).unwrap_err();

        assert!(matches!(
            err,
            ConfigValidationError::UnsafeRpcEndpoint {
                field: "network.rpc_url",
                ..
            }
        ));
        assert!(!err.to_string().contains("secret"));
        assert!(!err.to_string().contains("token=abc"));
    }

    #[test]
    fn runtime_config_rejects_rpc_endpoint_without_host() {
        let mut cfg = autonomous_config(vec!["balances.transfer"], vec!["5GoodAddress"], 100, 168);
        cfg.network.rpc_url = "wss://".into();

        let err = validate_runtime_config(&cfg, true).unwrap_err();

        assert!(matches!(
            err,
            ConfigValidationError::UnsafeRpcEndpoint {
                field: "network.rpc_url",
                ..
            }
        ));
    }

    fn autonomous_config(
        allowed_extrinsics: Vec<&str>,
        whitelisted_addresses: Vec<&str>,
        daily_limit_lunes: u64,
        ttl_hours: u64,
    ) -> ConfigFile {
        ConfigFile {
            network: NetworkConfig {
                rpc_url: "wss://ws.lunes.io".to_string(),
                rpc_failovers: vec![],
                archive_url: None,
            },
            agent: AgentConfig {
                wallet: WalletConfig {
                    mode: AgentMode::Autonomous,
                },
                permissions: PermissionsConfig {
                    allowed_extrinsics: allowed_extrinsics
                        .into_iter()
                        .map(str::to_string)
                        .collect(),
                    whitelisted_addresses: whitelisted_addresses
                        .into_iter()
                        .map(str::to_string)
                        .collect(),
                    daily_limit_lunes,
                    allowlist_contracts: HashMap::new(),
                    asset_policies: HashMap::new(),
                    governance: GovernancePolicyConfig::default(),
                    ttl_hours,
                    human_approval_required: true,
                    approval_message_template: None,
                },
            },
            server: None,
        }
    }
}
