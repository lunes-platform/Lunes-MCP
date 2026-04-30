//! Lunes MCP Server - entry point.
//!
//! JSON-RPC server exposing MCP tools for Lunes Network workflows.
//! It loads the agent configuration, initializes the KMS, registers RPC
//! methods, and applies policy and transport guardrails before handling calls.

mod abi_registry;
mod address;
mod config;
mod kms;
mod lunes_client;
mod security;
mod tools;

use anyhow::Context;
use jsonrpsee::server::{RpcModule, ServerBuilder};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::config::{
    default_safe_config, load_config, validate_runtime_config, AgentMode, AUTONOMOUS_STUB_ENV_VAR,
};
use crate::kms::AgentKms;
use crate::lunes_client::LunesClient;
use crate::security::{
    validate_public_exposure, RateLimitSettings, TransportSecurityLayer, TransportSecurityState,
    API_KEY_ENV_VAR,
};
use crate::tools::{dispatch_tool_call_with_chain, tool_definitions, ToolCallRequest};

const MAX_REQUEST_BODY_BYTES: u32 = 64 * 1024;
const MAX_RESPONSE_BODY_BYTES: u32 = 256 * 1024;
const MAX_CONNECTIONS: u32 = 64;

// --- Shared context ------------------------------------------------------

struct McpContext {
    kms: AgentKms,
    lunes_client: LunesClient,
    config_mode: AgentMode,
    rpc_url: String,
    rpc_failover_count: usize,
    archive_url: Option<String>,
    rate_limit_per_second: u64,
    rate_limit_burst: u32,
    auth_required: bool,
}

// --- Main ----------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing with optional RUST_LOG filters.
    // Use JSON formatting if in production.
    let is_prod = std::env::var("ENVIRONMENT").unwrap_or_default() == "production";
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    if is_prod {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
    }

    info!("Lunes MCP Server");
    info!("Secure agent gateway for Lunes Network tooling");
    info!(version = env!("CARGO_PKG_VERSION"), "Starting server");

    // 1. Load configuration.
    let config_file = match load_config("agent_config.toml") {
        Ok(cfg) => {
            info!(
                rpc_url = %cfg.network.rpc_url,
                mode = ?cfg.agent.wallet.mode,
                daily_limit = cfg.agent.permissions.daily_limit_lunes,
                ttl_hours = cfg.agent.permissions.ttl_hours,
                allowed_extrinsics = ?cfg.agent.permissions.allowed_extrinsics,
                "Config loaded successfully"
            );
            cfg
        }
        Err(e) => {
            warn!(
                "Failed to load agent_config.toml: {}. Using safe defaults (prepare_only, mainnet).",
                e
            );
            default_safe_config()
        }
    };

    let mode = config_file.agent.wallet.mode.clone();
    let rpc_url = config_file.network.rpc_url.clone();
    let rpc_failover_count = config_file.network.rpc_failovers.len();
    let archive_url = config_file.network.archive_url.clone();
    let autonomous_stub_allowed = std::env::var(AUTONOMOUS_STUB_ENV_VAR)
        .map(|value| value == "1")
        .unwrap_or(false);
    validate_runtime_config(&config_file, autonomous_stub_allowed)?;

    let (configured_bind_addr, rate_limit_per_second, rate_limit_burst) =
        if let Some(server) = config_file.server.as_ref() {
            (
                format!("{}:{}", server.bind_address, server.port),
                server.rate_limit_per_second,
                server.rate_limit_burst,
            )
        } else {
            ("127.0.0.1:9950".to_string(), 10, 20)
        };

    // Bind address: env var -> config -> default
    let bind_addr = std::env::var("LUNES_MCP_BIND").unwrap_or(configured_bind_addr);

    let addr: SocketAddr = bind_addr
        .parse()
        .with_context(|| format!("Invalid bind address: {bind_addr}"))?;

    let api_key = std::env::var(API_KEY_ENV_VAR)
        .ok()
        .and_then(|key| (!key.trim().is_empty()).then_some(key));
    let rate_limit = RateLimitSettings {
        per_second: rate_limit_per_second,
        burst: rate_limit_burst,
    };
    let security_state = Arc::new(TransportSecurityState::new(api_key, rate_limit));
    let auth_required = security_state.api_key_configured();

    validate_public_exposure(&addr, auth_required, rate_limit)
        .with_context(|| format!("Refusing unsafe public bind on {addr}"))?;

    // 2. Initialize the KMS.
    let lunes_client = LunesClient::new(
        rpc_url.clone(),
        config_file.network.rpc_failovers.clone(),
        archive_url.clone(),
    );
    let kms = AgentKms::new(config_file.agent.wallet.mode, config_file.agent.permissions);
    let ctx = Arc::new(McpContext {
        kms,
        lunes_client,
        config_mode: mode.clone(),
        rpc_url: rpc_url.clone(),
        rpc_failover_count,
        archive_url,
        rate_limit_per_second,
        rate_limit_burst,
        auth_required,
    });

    // 3. Configure the JSON-RPC server.
    let http_middleware =
        tower::ServiceBuilder::new().layer(TransportSecurityLayer::new(security_state));
    let server = ServerBuilder::default()
        .http_only()
        .max_request_body_size(MAX_REQUEST_BODY_BYTES)
        .max_response_body_size(MAX_RESPONSE_BODY_BYTES)
        .max_connections(MAX_CONNECTIONS)
        .set_http_middleware(http_middleware)
        .build(addr)
        .await?;
    let mut module = RpcModule::new(ctx);

    // Endpoint: initialize (MCP lifecycle)
    module.register_method("initialize", |_, _, _| {
        serde_json::json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {
                "tools": {
                    "listChanged": false
                }
            },
            "serverInfo": {
                "name": "lunes-mcp-server",
                "version": env!("CARGO_PKG_VERSION")
            }
        })
    })?;

    // Endpoint: notifications/initialized (MCP lifecycle)
    // MCP clients send this notification after `initialize`; no state is needed here.
    module.register_method("notifications/initialized", |_, _, _| serde_json::json!({}))?;

    // Endpoint: tools/list
    module.register_method("tools/list", |_, _, _| {
        serde_json::json!({
            "tools": tool_definitions(),
            "nextCursor": serde_json::Value::Null
        })
    })?;

    // Endpoint: tools/call
    module.register_async_method("tools/call", |params, ctx, _| async move {
        let request: ToolCallRequest = match params.parse() {
            Ok(r) => r,
            Err(e) => {
                error!("Invalid tool call request: {}", e);
                return serde_json::json!({
                    "content": [{ "type": "text", "text": format!("Invalid request: {}", e) }],
                    "isError": true
                });
            }
        };

        info!(tool = %request.name, "Processing tool call");
        let response = dispatch_tool_call_with_chain(&request, &ctx.kms, &ctx.lunes_client).await;
        serde_json::to_value(&response).unwrap_or_default()
    })?;

    // Endpoint: mcp_execute_agent_tx
    module.register_async_method("mcp_execute_agent_tx", |params, ctx, _| async move {
        let request: ToolCallRequest = match params.parse() {
            Ok(r) => r,
            Err(e) => {
                error!("Invalid execute request: {}", e);
                return serde_json::json!({
                    "content": [{ "type": "text", "text": format!("Invalid request: {}", e) }],
                    "isError": true
                });
            }
        };

        info!(tool = %request.name, "Executing autonomous agent transaction");
        let response = dispatch_tool_call_with_chain(&request, &ctx.kms, &ctx.lunes_client).await;
        serde_json::to_value(&response).unwrap_or_default()
    })?;

    // Endpoint: mcp_health
    module.register_method("mcp_health", |_, ctx, _| {
        serde_json::json!({
            "status": "ok",
            "server": "lunes-mcp-server",
            "version": env!("CARGO_PKG_VERSION"),
            "agent_mode": format!("{:?}", ctx.config_mode),
            "auth_required": ctx.auth_required,
        })
    })?;

    // Endpoint: mcp_status
    module.register_method("mcp_status", |_, ctx, _| {
        serde_json::json!({
            "server": "lunes-mcp-server",
            "version": env!("CARGO_PKG_VERSION"),
            "agent_mode": format!("{:?}", ctx.config_mode),
            "kms_active": ctx.kms.is_active(),
            "agent_public_key": ctx.kms.public_key_hex(),
            "spent_today_lunes": ctx.kms.spent_today(),
            "network": {
                "rpc_url": ctx.rpc_url,
                "rpc_failover_count": ctx.rpc_failover_count,
                "archive_url": ctx.archive_url,
            },
            "rate_limit": {
                "requests_per_second": ctx.rate_limit_per_second,
                "burst": ctx.rate_limit_burst,
            },
            "transport": {
                "auth_required": ctx.auth_required,
                "http_only": true,
                "max_request_body_bytes": MAX_REQUEST_BODY_BYTES,
                "max_response_body_bytes": MAX_RESPONSE_BODY_BYTES,
                "max_connections": MAX_CONNECTIONS,
            }
        })
    })?;

    // Endpoint: mcp_audit_log
    module.register_method("mcp_audit_log", |_, ctx, _| {
        let log = ctx.kms.get_audit_log();
        let entries: Vec<serde_json::Value> = log
            .iter()
            .map(|entry| {
                serde_json::json!({
                    "timestamp": entry.timestamp.to_rfc3339(),
                    "action": entry.action,
                    "extrinsic": entry.extrinsic,
                    "amount_lunes": entry.amount_lunes,
                    "success": entry.success,
                    "error": entry.error,
                })
            })
            .collect();
        serde_json::json!({ "audit_log": entries })
    })?;

    // 4. Start the server.
    info!("Lunes MCP Server listening on http://{}", addr);
    info!("Connected to Lunes network: {}", rpc_url);
    info!(
        requests_per_second = rate_limit_per_second,
        burst = rate_limit_burst,
        "Rate limit middleware enabled"
    );
    info!(
        auth_required,
        http_only = true,
        max_request_body_bytes = MAX_REQUEST_BODY_BYTES,
        max_connections = MAX_CONNECTIONS,
        "Transport security configured"
    );

    match &mode {
        AgentMode::Autonomous => {
            info!("Mode: AUTONOMOUS - agent can sign transactions within limits.");
        }
        AgentMode::PrepareOnly => {
            info!("Mode: PREPARE_ONLY - agent can only prepare unsigned payloads.");
        }
    }

    let handle = server.start(module);
    let stopped_handle = handle.clone();

    // 5. Graceful shutdown.
    tokio::select! {
        _ = stopped_handle.stopped() => {
            info!("Server stopped.");
        }
        _ = shutdown_signal() => {
            info!("Received shutdown signal. Shutting down gracefully...");
            if let Err(e) = handle.stop() {
                warn!("Server was already stopped: {}", e);
            }
        }
    }

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to install SIGTERM handler");

        tokio::select! {
            _ = ctrl_c => {}
            _ = terminate.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
}
