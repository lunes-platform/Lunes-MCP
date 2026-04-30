/// Lunes MCP Server - agent configuration.
///
/// Loads the `agent_config.toml` file that controls agent mode,
/// permission boundaries, and server transport settings.
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

// --- Typed enums ---------------------------------------------------------

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

pub const AUTONOMOUS_STUB_ENV_VAR: &str = "LUNES_MCP_ALLOW_AUTONOMOUS_STUB";

// --- Configuration structs ----------------------------------------------

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

    /// Agent key lifetime in hours. Zero disables expiration.
    #[serde(default = "default_ttl_hours")]
    pub ttl_hours: u64,

    /// Whether pending write responses include an explicit human approval notice.
    #[serde(default = "default_human_approval")]
    pub human_approval_required: bool,

    /// Custom template for human approval pending message.
    pub approval_message_template: Option<String>,
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

// --- Loader --------------------------------------------------------------

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
        return Err(ConfigValidationError::ContractsCallDisabled);
    }

    Ok(())
}

// --- Errors --------------------------------------------------------------

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
    #[error("autonomous mode is disabled until real Lunes Network transaction signing is implemented; set {AUTONOMOUS_STUB_ENV_VAR}=1 only for local testing")]
    StubNotAllowed,

    #[error("autonomous mode requires at least one allowed extrinsic")]
    ExtrinsicsRequired,

    #[error("autonomous mode requires an explicit destination whitelist")]
    WhitelistRequired,

    #[error("autonomous mode requires ttl_hours > 0")]
    TtlRequired,

    #[error("autonomous mode requires daily_limit_lunes > 0")]
    DailyLimitRequired,

    #[error("autonomous contracts.call is disabled until contract message allowlists and asset-specific limits exist")]
    ContractsCallDisabled,
}

// --- Tests ---------------------------------------------------------------

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
        assert_eq!(file.agent.permissions.ttl_hours, 168); // default
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
    fn autonomous_mode_accepts_safe_stub_config_when_explicitly_enabled() {
        let cfg = autonomous_config(vec!["balances.transfer"], vec!["5GoodAddress"], 100, 168);

        assert_eq!(validate_runtime_config(&cfg, true), Ok(()));
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
                    ttl_hours,
                    human_approval_required: true,
                    approval_message_template: None,
                },
            },
            server: None,
        }
    }
}
