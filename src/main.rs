//! JSON-RPC server exposing MCP tools for Lunes Network workflows.

mod abi_registry;
mod address;
mod config;
mod kms;
mod lunes_client;
mod security;
mod tools;

use anyhow::Context;
use jsonrpsee::server::{RpcModule, ServerBuilder};
use jsonrpsee::types::Params;
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::config::{
    default_safe_config, load_config, validate_runtime_config, AgentMode, AUTONOMOUS_MODE_ENV_VAR,
    AUTONOMOUS_STUB_ENV_VAR,
};
use crate::kms::{AgentKms, AuditAction};
use crate::lunes_client::{redact_rpc_endpoint, LunesClient};
use crate::security::{
    validate_public_exposure, RateLimitSettings, TransportSecurityLayer, TransportSecurityState,
    API_KEY_ENV_VAR,
};
use crate::tools::{dispatch_tool_call_with_chain, tool_definitions, ToolCallRequest};

const MAX_REQUEST_BODY_BYTES: u32 = 64 * 1024;
const MAX_RESPONSE_BODY_BYTES: u32 = 256 * 1024;
const MAX_CONNECTIONS: u32 = 64;

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
    transport_security: Arc<TransportSecurityState>,
}

#[derive(serde::Serialize)]
struct AuditLogEntry {
    timestamp: String,
    action: AuditAction,
    extrinsic: String,
    destination: Option<String>,
    amount_lunes: u64,
    payload_hash: Option<String>,
    success: bool,
    error: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

    let config_file = match load_config("agent_config.toml") {
        Ok(cfg) => cfg,
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
    let display_rpc_url = redact_rpc_endpoint(&rpc_url);
    let display_archive_url = archive_url
        .as_ref()
        .map(|endpoint| redact_rpc_endpoint(endpoint));
    let autonomous_mode_allowed = std::env::var(AUTONOMOUS_MODE_ENV_VAR)
        .map(|value| value == "1")
        .unwrap_or(false)
        || std::env::var(AUTONOMOUS_STUB_ENV_VAR)
            .map(|value| value == "1")
            .unwrap_or(false);
    validate_runtime_config(&config_file, autonomous_mode_allowed)?;
    info!(
        rpc_url = %display_rpc_url,
        mode = ?config_file.agent.wallet.mode,
        daily_limit = config_file.agent.permissions.daily_limit_lunes,
        ttl_hours = config_file.agent.permissions.ttl_hours,
        allowed_extrinsics = ?config_file.agent.permissions.allowed_extrinsics,
        "Config loaded successfully"
    );

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

    let lunes_client = LunesClient::new(
        rpc_url.clone(),
        config_file.network.rpc_failovers.clone(),
        archive_url.clone(),
    );
    let kms = AgentKms::new(config_file.agent.wallet.mode, config_file.agent.permissions);
    let ctx = McpContext {
        kms,
        lunes_client,
        config_mode: mode.clone(),
        rpc_url: display_rpc_url.clone(),
        rpc_failover_count,
        archive_url: display_archive_url,
        rate_limit_per_second,
        rate_limit_burst,
        auth_required,
        transport_security: security_state.clone(),
    };

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

    // MCP clients send this notification after `initialize`; no state is needed here.
    module.register_method("notifications/initialized", |_, _, _| serde_json::json!({}))?;

    module.register_method("tools/list", |_, _, _| {
        serde_json::json!({
            "tools": tool_definitions(),
            "nextCursor": serde_json::Value::Null
        })
    })?;

    module.register_async_method("tools/call", |params, ctx, _| async move {
        handle_tool_rpc(
            params,
            ctx,
            "Processing tool call",
            "Invalid tool call request",
        )
        .await
    })?;

    module.register_async_method("mcp_execute_agent_tx", |params, ctx, _| async move {
        handle_tool_rpc(
            params,
            ctx,
            "Executing autonomous agent transaction",
            "Invalid execute request",
        )
        .await
    })?;

    module.register_method("mcp_health", |_, ctx, _| {
        serde_json::json!({
            "status": "ok",
            "server": "lunes-mcp-server",
            "version": env!("CARGO_PKG_VERSION"),
            "agent_mode": format!("{:?}", ctx.config_mode),
            "auth_required": ctx.auth_required,
        })
    })?;

    module.register_method("mcp_status", |_, ctx, _| {
        let transport = ctx.transport_security.metrics();
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
            },
            "transport_metrics": transport,
        })
    })?;

    module.register_method("mcp_metrics", |_, ctx, _| {
        let transport = ctx.transport_security.metrics();
        let audit_log_entries = ctx.kms.get_audit_log().len();

        serde_json::json!({
            "server": "lunes-mcp-server",
            "version": env!("CARGO_PKG_VERSION"),
            "transport": {
                "accepted_requests": transport.accepted_requests,
                "auth_rejections": transport.auth_rejections,
                "rate_limit_rejections": transport.rate_limit_rejections,
                "auth_required": ctx.auth_required,
                "rate_limit": {
                    "requests_per_second": ctx.rate_limit_per_second,
                    "burst": ctx.rate_limit_burst,
                },
            },
            "kms": {
                "active": ctx.kms.is_active(),
                "spent_today_lunes": ctx.kms.spent_today(),
                "audit_log_entries": audit_log_entries,
                "persistent_audit_log_enabled": ctx.kms.persistent_audit_log_enabled(),
            },
            "network": {
                "rpc_failover_count": ctx.rpc_failover_count,
                "archive_configured": ctx.archive_url.is_some(),
            }
        })
    })?;

    module.register_method("mcp_audit_log", |_, ctx, _| {
        let log = ctx.kms.get_audit_log();
        let entries: Vec<AuditLogEntry> = log
            .iter()
            .map(|entry| AuditLogEntry {
                timestamp: entry.timestamp.to_rfc3339(),
                action: entry.action,
                extrinsic: entry.extrinsic.clone(),
                destination: entry.destination.clone(),
                amount_lunes: entry.amount_lunes,
                payload_hash: entry.payload_hash.clone(),
                success: entry.success,
                error: entry.error.clone(),
            })
            .collect();
        serde_json::json!({ "audit_log": entries })
    })?;

    info!("Lunes MCP Server listening on http://{}", addr);
    info!("Connected to Lunes network: {}", display_rpc_url);
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

async fn handle_tool_rpc(
    params: Params<'static>,
    ctx: Arc<McpContext>,
    log_message: &'static str,
    invalid_request_log_message: &'static str,
) -> Value {
    let request: ToolCallRequest = match params.parse() {
        Ok(request) => request,
        Err(error) => {
            error!("{invalid_request_log_message}: {}", error);
            return invalid_tool_request_response(error);
        }
    };

    info!(tool = %request.name, "{log_message}");
    let response = dispatch_tool_call_with_chain(&request, &ctx.kms, &ctx.lunes_client).await;
    serde_json::to_value(&response).expect("MCP tool result serializes to JSON value")
}

fn invalid_tool_request_response(error: impl std::fmt::Display) -> Value {
    serde_json::json!({
        "content": [{ "type": "text", "text": format!("Invalid request: {}", error) }],
        "isError": true
    })
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
