//! Lunes MCP Server - tool dispatcher
//!
//! Maps MCP tool names to typed handlers. Each handler validates arguments,
//! calls the KMS when needed, and returns an MCP-compatible tool result.
//!
//! ## Tool Result Format
//!
//! Every `tools/call` response uses this shape:
//! ```json
//! { "content": [{ "type": "text", "text": "..." }], "isError": false }
//! ```

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::address::{validate_lunes_address, LUNES_SS58_PREFIX};
use crate::kms::AgentKms;
use crate::lunes_client::{
    LunesClient, LunesClientError, NativeBalance, DEFAULT_ARCHIVE_TX_LOOKBACK_BLOCKS,
    MAX_ARCHIVE_TX_LOOKBACK_BLOCKS,
};

const LUNES_DECIMALS: u32 = 8;
const LUNES_BASE_UNITS: u128 = 100_000_000;
const STAKING_POLICY_DESTINATION: &str = "staking";
const MAX_NOMINATIONS: usize = 16;
const DEFAULT_VALIDATOR_LIMIT: usize = 16;
const MAX_VALIDATOR_LIMIT: usize = 64;

// --- MCP-compatible response schemas ------------------------------------

#[derive(Debug, Deserialize)]
pub struct ToolCallRequest {
    pub name: String,
    pub arguments: Value,
}

/// Content block returned inside an MCP tool result.
#[derive(Debug, Serialize)]
pub struct ContentBlock {
    #[serde(rename = "type")]
    pub content_type: String,
    pub text: String,
}

/// MCP tool result shape: `{ "content": [...], "isError": bool }`.
#[derive(Debug, Serialize)]
pub struct McpToolResult {
    pub content: Vec<ContentBlock>,
    #[serde(rename = "isError")]
    pub is_error: bool,
}

impl McpToolResult {
    /// Successful response with JSON data serialized as text content.
    pub fn success(data: Value) -> Self {
        Self {
            content: vec![ContentBlock {
                content_type: "text".into(),
                text: serde_json::to_string_pretty(&data).unwrap_or_default(),
            }],
            is_error: false,
        }
    }

    /// Error response with an application error code and message.
    pub fn error(code: i32, message: String) -> Self {
        let error_data = serde_json::json!({
            "error_code": code,
            "message": message,
        });
        Self {
            content: vec![ContentBlock {
                content_type: "text".into(),
                text: serde_json::to_string_pretty(&error_data).unwrap_or_default(),
            }],
            is_error: true,
        }
    }

    /// Pending response for operations that need human approval.
    pub fn pending(data: Value) -> Self {
        let pending_data = serde_json::json!({
            "status": "pending_human_approval",
            "data": data,
        });
        Self {
            content: vec![ContentBlock {
                content_type: "text".into(),
                text: serde_json::to_string_pretty(&pending_data).unwrap_or_default(),
            }],
            is_error: false,
        }
    }
}

// --- SS58 address validation --------------------------------------------

/// Basic SS58 address validation for Lunes-compatible addresses.
fn is_valid_ss58(address: &str) -> bool {
    validate_lunes_address(address).is_ok()
}

/// Validates an SS58 address and maps failures to a tool error.
fn validate_address(address: &str, field_name: &str) -> Result<(), McpToolResult> {
    if address.is_empty() {
        return Err(McpToolResult::error(
            -32001,
            format!("Missing required field: {}", field_name),
        ));
    }
    if !is_valid_ss58(address) {
        return Err(McpToolResult::error(
            -32001,
            format!(
                "Invalid Lunes address for '{}': '{}'. Expected SS58 prefix {} with a valid checksum.",
                field_name, address, LUNES_SS58_PREFIX
            ),
        ));
    }
    Ok(())
}

// --- Dispatcher ----------------------------------------------------------

/// Routes a tool call name to the matching handler.
pub fn dispatch_tool_call(request: &ToolCallRequest, kms: &AgentKms) -> McpToolResult {
    match request.name.as_str() {
        // Read-only queries that do not need live RPC
        "lunes_search_contract" => handle_search_contract(&request.arguments),
        "lunes_validate_address" => handle_validate_address(&request.arguments),
        "lunes_get_permissions" => handle_get_permissions(kms),
        "lunes_get_balance"
        | "lunes_get_transaction_status"
        | "lunes_get_network_health"
        | "lunes_get_account_overview"
        | "lunes_get_investment_position"
        | "lunes_get_validator_set"
        | "lunes_get_staking_overview" => {
            McpToolResult::error(-32020, "Tool requires a live Lunes RPC client".into())
        }

        // Write operations that go through the KMS policy checks
        "lunes_transfer_native" => handle_transfer_native(&request.arguments, kms),
        "lunes_transfer_psp22" => handle_transfer_psp22(&request.arguments, kms),
        "lunes_call_contract" => handle_call_contract(&request.arguments, kms),
        "lunes_stake_bond" => handle_stake_bond(&request.arguments, kms),
        "lunes_stake_unbond" => handle_stake_unbond(&request.arguments, kms),
        "lunes_stake_withdraw_unbonded" => handle_stake_withdraw_unbonded(&request.arguments, kms),
        "lunes_stake_nominate" => handle_stake_nominate(&request.arguments, kms),
        "lunes_stake_chill" => handle_stake_chill(kms),
        "lunes_stake_set_payee" => handle_stake_set_payee(&request.arguments, kms),

        // Agent wallet lifecycle
        "lunes_provision_agent_wallet" => handle_provision_wallet(kms),
        "lunes_revoke_agent_wallet" => handle_revoke_wallet(kms),

        _ => McpToolResult::error(-32601, format!("Unknown tool: '{}'", request.name)),
    }
}

pub async fn dispatch_tool_call_with_chain(
    request: &ToolCallRequest,
    kms: &AgentKms,
    lunes_client: &LunesClient,
) -> McpToolResult {
    match request.name.as_str() {
        "lunes_get_chain_info" => handle_get_chain_info(lunes_client).await,
        "lunes_get_network_health" => handle_get_network_health(lunes_client).await,
        "lunes_get_balance" => handle_get_balance(&request.arguments, lunes_client).await,
        "lunes_get_account_overview" => {
            handle_get_account_overview(&request.arguments, kms, lunes_client).await
        }
        "lunes_get_investment_position" => {
            handle_get_investment_position(&request.arguments, kms, lunes_client).await
        }
        "lunes_get_validator_set" => {
            handle_get_validator_set(&request.arguments, lunes_client).await
        }
        "lunes_get_staking_overview" => {
            handle_get_staking_overview(&request.arguments, kms, lunes_client).await
        }
        "lunes_get_transaction_status" => {
            handle_get_tx_status(&request.arguments, lunes_client).await
        }
        _ => dispatch_tool_call(request, kms),
    }
}

/// MCP tool descriptors exposed by the server.
pub fn tool_definitions() -> Vec<Value> {
    vec![
        serde_json::json!({
            "name": "lunes_get_balance",
            "description": "Read the native LUNES or PSP22 balance for an address.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "address": { "type": "string", "description": "SS58 address on Lunes Network." },
                    "asset_id": { "type": "string", "description": "PSP22 contract address. Omit for native LUNES." }
                },
                "required": ["address"]
            }
        }),
        serde_json::json!({
            "name": "lunes_get_network_health",
            "description": "Read live Lunes Network health, peer count, head/finality lag, and pending pool size.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "lunes_get_account_overview",
            "description": "Read an account overview with native LUNES balances, nonce, spendable amount, and active agent policy.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "address": { "type": "string", "description": "SS58 address on Lunes Network." }
                },
                "required": ["address"]
            }
        }),
        serde_json::json!({
            "name": "lunes_get_investment_position",
            "description": "Summarize liquid, reserved, and locked LUNES for agent-assisted staking and investment planning.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "address": { "type": "string", "description": "SS58 address on Lunes Network." }
                },
                "required": ["address"]
            }
        }),
        serde_json::json!({
            "name": "lunes_get_validator_set",
            "description": "Read the current Lunes validator set from live network state.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_VALIDATOR_LIMIT,
                        "description": "Maximum validator addresses to return. Defaults to 16."
                    }
                }
            }
        }),
        serde_json::json!({
            "name": "lunes_get_staking_overview",
            "description": "Summarize live staking visibility and the staking actions this agent is allowed to prepare.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "validator_limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_VALIDATOR_LIMIT,
                        "description": "Maximum validator addresses to include in the sample. Defaults to 16."
                    }
                }
            }
        }),
        serde_json::json!({
            "name": "lunes_get_transaction_status",
            "description": "Read transaction status and events by hash.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tx_hash": { "type": "string", "description": "Hexadecimal transaction hash." },
                    "archive_lookback_blocks": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": MAX_ARCHIVE_TX_LOOKBACK_BLOCKS,
                        "description": "Optional archive search depth. Defaults to a small recent-block window; 0 disables archive fallback."
                    }
                },
                "required": ["tx_hash"]
            }
        }),
        serde_json::json!({
            "name": "lunes_search_contract",
            "description": "Look up metadata and ABI details for an ink! contract.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "contract_address": { "type": "string", "description": "Contract SS58 address." }
                },
                "required": ["contract_address"]
            }
        }),
        serde_json::json!({
            "name": "lunes_get_chain_info",
            "description": "Read live Lunes Network metadata, token settings, address prefix, and runtime information.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "lunes_validate_address",
            "description": "Validate that an address belongs to the Lunes Network SS58 format.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "address": { "type": "string", "description": "Address to validate." }
                },
                "required": ["address"]
            }
        }),
        serde_json::json!({
            "name": "lunes_get_permissions",
            "description": "Summarize what this agent can read, prepare, sign, and never do.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "lunes_transfer_native",
            "description": "Prepare or sign a native LUNES transfer.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "to": { "type": "string", "description": "Recipient SS58 address." },
                    "amount": { "type": "integer", "minimum": 1, "description": "LUNES amount." }
                },
                "required": ["to", "amount"]
            }
        }),
        serde_json::json!({
            "name": "lunes_transfer_psp22",
            "description": "Prepare or sign a PSP22 token transfer.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "contract_address": { "type": "string", "description": "PSP22 contract SS58 address." },
                    "to": { "type": "string", "description": "Recipient SS58 address." },
                    "amount": { "type": "integer", "minimum": 1, "description": "Token amount." }
                },
                "required": ["contract_address", "to", "amount"]
            }
        }),
        serde_json::json!({
            "name": "lunes_call_contract",
            "description": "Prepare or sign a generic ink! contract call.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "contract_address": { "type": "string", "description": "Contract SS58 address." },
                    "message": { "type": "string", "description": "ABI message name." },
                    "args": { "type": "object", "description": "ABI message arguments." },
                    "value": { "type": "integer", "minimum": 0, "description": "Native LUNES value to send with the call. Defaults to 0." }
                },
                "required": ["contract_address", "message"]
            }
        }),
        serde_json::json!({
            "name": "lunes_stake_bond",
            "description": "Prepare or sign a Lunes staking bond operation.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "amount": { "type": "integer", "minimum": 1, "description": "LUNES amount to bond." },
                    "reward_destination": { "type": "string", "description": "Reward destination: staked, stash, controller, or account. Defaults to staked." },
                    "reward_account": { "type": "string", "description": "Required when reward_destination is account." }
                },
                "required": ["amount"]
            }
        }),
        serde_json::json!({
            "name": "lunes_stake_unbond",
            "description": "Prepare or sign a Lunes staking unbond operation.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "amount": { "type": "integer", "minimum": 1, "description": "LUNES amount to unbond." }
                },
                "required": ["amount"]
            }
        }),
        serde_json::json!({
            "name": "lunes_stake_withdraw_unbonded",
            "description": "Prepare or sign withdrawal of unlocked staking funds.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "slashing_spans": { "type": "integer", "minimum": 0, "description": "Slashing spans count. Defaults to 0." }
                }
            }
        }),
        serde_json::json!({
            "name": "lunes_stake_nominate",
            "description": "Prepare or sign validator nomination for Lunes staking.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "validators": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": MAX_NOMINATIONS,
                        "items": { "type": "string" },
                        "description": "Validator addresses to nominate. Every address must be whitelisted."
                    }
                },
                "required": ["validators"]
            }
        }),
        serde_json::json!({
            "name": "lunes_stake_chill",
            "description": "Prepare or sign a pause of active nominations.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "lunes_stake_set_payee",
            "description": "Prepare or sign staking reward destination update.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "reward_destination": { "type": "string", "description": "Reward destination: staked, stash, controller, or account." },
                    "reward_account": { "type": "string", "description": "Required when reward_destination is account." }
                },
                "required": ["reward_destination"]
            }
        }),
        serde_json::json!({
            "name": "lunes_provision_agent_wallet",
            "description": "Create a local agent key and return a human approval request.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "lunes_revoke_agent_wallet",
            "description": "Revoke the current local agent key.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
    ]
}

// --- Generic write operation helper -------------------------------------

/// Runs a write operation through the common policy and signing pipeline.
fn execute_write_operation(
    kms: &AgentKms,
    extrinsic: &str,
    destination: &str,
    amount_lunes: u64,
    payload: &str,
    success_data: impl FnOnce(&str, &str) -> Value, // (signature, public_key) -> response data
    pending_data: Value,
) -> McpToolResult {
    // Validate extrinsic, destination, and daily limit without consuming budget.
    if let Err(e) = kms.preflight_write(extrinsic, destination, amount_lunes) {
        return McpToolResult::error(e.error_code(), e.to_string());
    }

    // Prepare-only mode returns a payload for external human review.
    if !kms.is_autonomous() {
        return McpToolResult::pending(pending_data);
    }

    // Autonomous mode signs through the KMS after all checks pass.
    match kms.sign_payload(extrinsic, destination, amount_lunes, payload.as_bytes()) {
        Ok(signed) => McpToolResult::success(success_data(&signed.signature, &signed.public_key)),
        Err(e) => McpToolResult::error(e.error_code(), e.to_string()),
    }
}

// --- Read-only handlers --------------------------------------------------

/// `lunes_get_balance` - reads native or PSP22 balance information.
async fn handle_get_balance(args: &Value, lunes_client: &LunesClient) -> McpToolResult {
    let address = args.get("address").and_then(|v| v.as_str()).unwrap_or("");
    let asset_id = args.get("asset_id").and_then(|v| v.as_str());

    let parsed = match parse_lunes_address(address, "address") {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };

    if let Some(asset_id) = asset_id {
        if let Err(error) = validate_address(asset_id, "asset_id") {
            return error;
        }

        return McpToolResult::success(serde_json::json!({
            "address": address,
            "asset": {
                "type": "psp22",
                "contract_address": asset_id,
            },
            "status": "pending_implementation",
            "note": "PSP22 balance lookup needs contract read support in a future sprint."
        }));
    }

    match lunes_client.native_balance(parsed.account_id).await {
        Ok(balance) => native_balance_response(address, balance),
        Err(error) => McpToolResult::error(-32020, error.to_string()),
    }
}

async fn handle_get_network_health(lunes_client: &LunesClient) -> McpToolResult {
    match lunes_client.network_health().await {
        Ok(health) => McpToolResult::success(serde_json::json!({
            "status": health.status(),
            "endpoint": health.endpoint,
            "network": health.chain,
            "node": {
                "name": health.node_name,
                "version": health.node_version,
            },
            "peers": health.peers,
            "is_syncing": health.is_syncing,
            "should_have_peers": health.should_have_peers,
            "best_block": {
                "hash": health.best_block_hash,
                "number": health.best_block_number,
            },
            "finalized_block": {
                "hash": health.finalized_block_hash,
                "number": health.finalized_block_number,
            },
            "finality_lag_blocks": health.finality_lag_blocks(),
            "pending_extrinsics": health.pending_extrinsics,
            "rpc_methods": health.rpc_methods,
            "lookup": "live_lunes_rpc",
        })),
        Err(error) => McpToolResult::error(-32020, error.to_string()),
    }
}

async fn handle_get_account_overview(
    args: &Value,
    kms: &AgentKms,
    lunes_client: &LunesClient,
) -> McpToolResult {
    let address = args.get("address").and_then(|v| v.as_str()).unwrap_or("");
    let parsed = match parse_lunes_address(address, "address") {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };

    let balance = match lunes_client.native_balance(parsed.account_id).await {
        Ok(balance) => balance,
        Err(error) => return McpToolResult::error(-32020, error.to_string()),
    };
    let nonce = match lunes_client.account_next_index(address).await {
        Ok(nonce) => nonce,
        Err(error) => return McpToolResult::error(-32020, error.to_string()),
    };

    McpToolResult::success(serde_json::json!({
        "address": address,
        "account_id_hex": hex::encode(parsed.account_id),
        "nonce": nonce,
        "asset": native_asset_json(),
        "balances": native_balance_json(balance),
        "policy": agent_policy_json(kms),
        "lookup": "live_lunes_rpc",
    }))
}

async fn handle_get_investment_position(
    args: &Value,
    kms: &AgentKms,
    lunes_client: &LunesClient,
) -> McpToolResult {
    let address = args.get("address").and_then(|v| v.as_str()).unwrap_or("");
    let parsed = match parse_lunes_address(address, "address") {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };

    let balance = match lunes_client.native_balance(parsed.account_id).await {
        Ok(balance) => balance,
        Err(error) => return McpToolResult::error(-32020, error.to_string()),
    };
    let nonce = match lunes_client.account_next_index(address).await {
        Ok(nonce) => nonce,
        Err(error) => return McpToolResult::error(-32020, error.to_string()),
    };

    let liquid = balance.free.saturating_sub(balance.frozen);
    let reserved_or_locked = balance.reserved.saturating_add(balance.frozen);
    let can_manage_staking = can_manage_staking(kms);
    let can_prepare_writes = can_prepare_writes(kms);

    McpToolResult::success(serde_json::json!({
        "address": address,
        "nonce": nonce,
        "asset": native_asset_json(),
        "position": {
            "liquid_base_units": liquid.to_string(),
            "liquid_lunes": format_lunes_amount(liquid),
            "reserved_or_locked_base_units": reserved_or_locked.to_string(),
            "reserved_or_locked_lunes": format_lunes_amount(reserved_or_locked),
            "free_lunes": format_lunes_amount(balance.free),
            "reserved_lunes": format_lunes_amount(balance.reserved),
            "frozen_lunes": format_lunes_amount(balance.frozen),
        },
        "agent_actions": {
            "can_prepare_staking_actions": can_prepare_writes && can_manage_staking,
            "can_sign_local_intents": kms.is_autonomous() && kms.is_active(),
            "can_broadcast_to_lunes_network": false,
            "available_staking_tools": staking_tools_allowed(kms),
        },
        "risk_notes": [
            "This is a read-only position summary, not financial advice.",
            "Staking operations remain prepare-only or local-intent signed until final Lunes Network transaction submission is implemented.",
            "Validator choices should be reviewed by a human and constrained through the whitelist."
        ],
        "lookup": "live_lunes_rpc",
    }))
}

async fn handle_get_validator_set(args: &Value, lunes_client: &LunesClient) -> McpToolResult {
    let limit = match validator_limit_arg(args, "limit") {
        Ok(limit) => limit,
        Err(error) => return error,
    };

    match lunes_client.validator_set().await {
        Ok(validator_set) => {
            let validator_count = validator_set.validators.len();
            let validators = validator_set
                .validators
                .iter()
                .take(limit)
                .cloned()
                .collect::<Vec<_>>();
            McpToolResult::success(serde_json::json!({
                "lookup": validator_set.lookup,
                "validator_count": validator_count,
                "returned": validators.len(),
                "limit": limit,
                "truncated": validator_count > validators.len(),
                "validators": validators,
            }))
        }
        Err(error) => McpToolResult::error(-32020, error.to_string()),
    }
}

async fn handle_get_staking_overview(
    args: &Value,
    kms: &AgentKms,
    lunes_client: &LunesClient,
) -> McpToolResult {
    let validator_limit = match validator_limit_arg(args, "validator_limit") {
        Ok(limit) => limit,
        Err(error) => return error,
    };

    match lunes_client.validator_set().await {
        Ok(validator_set) => {
            let active_validator_count = validator_set.validators.len();
            let validator_sample = validator_set
                .validators
                .iter()
                .take(validator_limit)
                .cloned()
                .collect::<Vec<_>>();
            McpToolResult::success(serde_json::json!({
                "lookup": validator_set.lookup,
                "active_validator_count": active_validator_count,
                "validator_sample": validator_sample,
                "validator_sample_limit": validator_limit,
                "agent_policy": agent_policy_json(kms),
                "allowed_staking_tools": staking_tools_allowed(kms),
                "write_status": "prepare_or_local_intent_only",
                "broadcast_enabled": false,
                "next_live_reads": [
                    "staking ledger",
                    "active nominations",
                    "reward destination",
                    "unbonding schedule",
                    "validator commission and exposure"
                ],
            }))
        }
        Err(error) => McpToolResult::error(-32020, error.to_string()),
    }
}

/// `lunes_get_transaction_status` - reads transaction status by hash.
async fn handle_get_tx_status(args: &Value, lunes_client: &LunesClient) -> McpToolResult {
    let tx_hash = args.get("tx_hash").and_then(|v| v.as_str()).unwrap_or("");
    let requested_archive_lookback_blocks =
        args.get("archive_lookback_blocks").and_then(|v| v.as_u64());
    let archive_lookback_blocks =
        requested_archive_lookback_blocks.unwrap_or(DEFAULT_ARCHIVE_TX_LOOKBACK_BLOCKS);

    if tx_hash.is_empty() {
        return McpToolResult::error(-32001, "Missing required field: tx_hash".into());
    }

    if archive_lookback_blocks > MAX_ARCHIVE_TX_LOOKBACK_BLOCKS {
        return McpToolResult::error(
            -32001,
            format!(
                "archive_lookback_blocks must be <= {}",
                MAX_ARCHIVE_TX_LOOKBACK_BLOCKS
            ),
        );
    }

    let status_result = if requested_archive_lookback_blocks.is_some() {
        lunes_client
            .transaction_status_with_archive_lookback(tx_hash, archive_lookback_blocks)
            .await
    } else {
        lunes_client.transaction_status(tx_hash).await
    };

    let lookup_note = if archive_lookback_blocks == 0 {
        "Lookup checks pending pool and current heads; archive fallback was disabled for this request."
    } else {
        "Lookup checks pending pool, current heads, and the configured archive endpoint with a bounded recent-block search."
    };

    match status_result {
        Ok(status) => McpToolResult::success(serde_json::json!({
            "tx_hash": status.tx_hash,
            "status": status.status,
            "block_hash": status.block_hash,
            "block_number": status.block_number,
            "extrinsic_index": status.extrinsic_index,
            "lookup_scope": status.lookup_scope,
            "archive_lookback_blocks": archive_lookback_blocks,
            "note": lookup_note
        })),
        Err(LunesClientError::InvalidTransactionHash(message)) => {
            McpToolResult::error(-32001, message)
        }
        Err(error) => McpToolResult::error(-32020, error.to_string()),
    }
}

/// `lunes_search_contract` - looks up ink! contract metadata.
fn handle_search_contract(args: &Value) -> McpToolResult {
    let contract_address = args
        .get("contract_address")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if let Err(e) = validate_address(contract_address, "contract_address") {
        return e;
    }

    // TODO: connect to Lunes Network RPC and the metadata registry.
    McpToolResult::success(serde_json::json!({
        "contract_address": contract_address,
        "status": "pending_implementation",
        "note": "Will return ABI messages from on-chain metadata"
    }))
}

async fn handle_get_chain_info(lunes_client: &LunesClient) -> McpToolResult {
    match lunes_client.chain_info().await {
        Ok(info) => McpToolResult::success(serde_json::json!({
            "summary": format!(
                "{} uses {} with {} decimals and SS58 prefix {}.",
                info.chain,
                info.properties.token_symbol,
                info.properties.token_decimals,
                info.properties.ss58_format
            ),
            "network": info.chain,
            "node": {
                "name": info.node_name,
                "version": info.node_version,
                "rpc_endpoint": info.rpc_endpoint,
            },
            "token": {
                "symbol": info.properties.token_symbol,
                "decimals": info.properties.token_decimals,
            },
            "address_format": {
                "ss58_prefix": info.properties.ss58_format,
                "expected_lunes_prefix": LUNES_SS58_PREFIX,
                "matches_lunes": info.properties.ss58_format == LUNES_SS58_PREFIX,
            },
            "runtime": {
                "spec_name": info.runtime.spec_name,
                "impl_name": info.runtime.impl_name,
                "spec_version": info.runtime.spec_version,
                "transaction_version": info.runtime.transaction_version,
                "state_version": info.runtime.state_version,
            }
        })),
        Err(error) => McpToolResult::error(-32020, error.to_string()),
    }
}

fn handle_validate_address(args: &Value) -> McpToolResult {
    let address = args.get("address").and_then(|v| v.as_str()).unwrap_or("");
    if address.is_empty() {
        return McpToolResult::error(-32001, "Missing required field: address".into());
    }

    match validate_lunes_address(address) {
        Ok(parsed) => McpToolResult::success(serde_json::json!({
            "address": address,
            "is_valid": true,
            "network": "Lunes",
            "ss58_prefix": parsed.ss58_prefix,
            "account_id_hex": hex::encode(parsed.account_id),
        })),
        Err(error) => McpToolResult::success(serde_json::json!({
            "address": address,
            "is_valid": false,
            "network": "Lunes",
            "expected_ss58_prefix": LUNES_SS58_PREFIX,
            "reason": error.to_string(),
        })),
    }
}

fn parse_lunes_address(
    address: &str,
    field_name: &str,
) -> Result<crate::address::LunesAddress, McpToolResult> {
    if address.is_empty() {
        return Err(McpToolResult::error(
            -32001,
            format!("Missing required field: {}", field_name),
        ));
    }

    validate_lunes_address(address).map_err(|_| {
        McpToolResult::error(
            -32001,
            format!(
                "Invalid Lunes address for '{}': '{}'. Expected SS58 prefix {} with a valid checksum.",
                field_name, address, LUNES_SS58_PREFIX
            ),
        )
    })
}

fn native_asset_json() -> Value {
    serde_json::json!({
        "type": "native",
        "symbol": "LUNES",
        "decimals": LUNES_DECIMALS,
    })
}

fn native_balance_json(balance: NativeBalance) -> Value {
    let spendable = balance.free.saturating_sub(balance.frozen);
    serde_json::json!({
        "free_base_units": balance.free.to_string(),
        "reserved_base_units": balance.reserved.to_string(),
        "frozen_base_units": balance.frozen.to_string(),
        "spendable_base_units": spendable.to_string(),
        "free_lunes": format_lunes_amount(balance.free),
        "reserved_lunes": format_lunes_amount(balance.reserved),
        "frozen_lunes": format_lunes_amount(balance.frozen),
        "spendable_lunes": format_lunes_amount(spendable),
    })
}

fn native_balance_response(address: &str, balance: NativeBalance) -> McpToolResult {
    let spendable = balance.free.saturating_sub(balance.frozen);
    McpToolResult::success(serde_json::json!({
        "address": address,
        "asset": native_asset_json(),
        "free_balance": balance.free.to_string(),
        "reserved_balance": balance.reserved.to_string(),
        "frozen_balance": balance.frozen.to_string(),
        "spendable_balance": spendable.to_string(),
        "balances": native_balance_json(balance),
        "lookup": "live_lunes_rpc",
    }))
}

fn format_lunes_amount(value: u128) -> String {
    let whole = value / LUNES_BASE_UNITS;
    let fractional = value % LUNES_BASE_UNITS;

    if fractional == 0 {
        return whole.to_string();
    }

    let fractional = format!("{:08}", fractional)
        .trim_end_matches('0')
        .to_string();
    format!("{whole}.{fractional}")
}

fn can_prepare_writes(kms: &AgentKms) -> bool {
    let permissions = kms.permissions();
    !permissions.allowed_extrinsics.is_empty() && !permissions.whitelisted_addresses.is_empty()
}

fn can_manage_staking(kms: &AgentKms) -> bool {
    kms.permissions()
        .allowed_extrinsics
        .iter()
        .any(|extrinsic| extrinsic.starts_with("staking."))
}

fn staking_tools_allowed(kms: &AgentKms) -> Vec<String> {
    kms.permissions()
        .allowed_extrinsics
        .iter()
        .filter(|extrinsic| extrinsic.starts_with("staking."))
        .cloned()
        .collect()
}

fn agent_policy_json(kms: &AgentKms) -> Value {
    let permissions = kms.permissions();
    let can_prepare_writes =
        !permissions.allowed_extrinsics.is_empty() && !permissions.whitelisted_addresses.is_empty();
    let can_manage_staking = permissions
        .allowed_extrinsics
        .iter()
        .any(|extrinsic| extrinsic.starts_with("staking."));

    serde_json::json!({
        "mode": format!("{:?}", kms.mode()),
        "kms_active": kms.is_active(),
        "can_prepare_writes": can_prepare_writes,
        "can_manage_staking": can_manage_staking,
        "can_sign_local_intents": kms.is_autonomous() && kms.is_active(),
        "can_broadcast_to_lunes_network": false,
        "allowed_extrinsics": permissions.allowed_extrinsics,
        "whitelisted_addresses": permissions.whitelisted_addresses,
        "daily_limit_lunes": permissions.daily_limit_lunes,
        "spent_today_lunes": kms.spent_today(),
        "remaining_today_lunes": permissions.daily_limit_lunes.saturating_sub(kms.spent_today()),
        "ttl_hours": permissions.ttl_hours,
    })
}

fn validator_limit_arg(args: &Value, field_name: &str) -> Result<usize, McpToolResult> {
    let limit = args
        .get(field_name)
        .and_then(|value| value.as_u64())
        .unwrap_or(DEFAULT_VALIDATOR_LIMIT as u64);

    if limit == 0 || limit > MAX_VALIDATOR_LIMIT as u64 {
        return Err(McpToolResult::error(
            -32001,
            format!("{field_name} must be between 1 and {MAX_VALIDATOR_LIMIT}"),
        ));
    }

    Ok(limit as usize)
}

fn handle_get_permissions(kms: &AgentKms) -> McpToolResult {
    let permissions = kms.permissions();
    let is_autonomous = kms.is_autonomous();
    let can_prepare_writes = can_prepare_writes(kms);
    let can_manage_staking = can_manage_staking(kms);

    let signing_status = if is_autonomous {
        "local intent signing is enabled after policy checks"
    } else {
        "local signing is disabled; write tools return human approval payloads"
    };

    McpToolResult::success(serde_json::json!({
        "summary": if is_autonomous {
            "Agent is in autonomous mode, but every write still requires allowlists, TTL, and spend limits."
        } else {
            "Agent is in prepare-only mode. It can help prepare actions, but cannot sign or broadcast."
        },
        "mode": format!("{:?}", kms.mode()),
        "kms_active": kms.is_active(),
        "capabilities": {
            "can_read": true,
            "can_validate_lunes_addresses": true,
            "can_prepare_writes": can_prepare_writes,
            "can_manage_staking": can_manage_staking,
            "can_sign_local_intents": is_autonomous && kms.is_active(),
            "can_broadcast_to_lunes_network": false,
        },
        "policy": {
            "allowed_extrinsics": permissions.allowed_extrinsics,
            "whitelisted_addresses": permissions.whitelisted_addresses,
            "daily_limit_lunes": permissions.daily_limit_lunes,
            "spent_today_lunes": kms.spent_today(),
            "remaining_today_lunes": permissions.daily_limit_lunes.saturating_sub(kms.spent_today()),
            "ttl_hours": permissions.ttl_hours,
        },
        "guardrails": [
            "public HTTP bind requires API key and rate limit",
            "empty extrinsic allowlist blocks all write tools",
            "empty destination whitelist blocks all write destinations",
            "staking tools require the staking policy target plus validator or reward accounts in the whitelist",
            "generic contract calls are blocked in autonomous mode until message allowlists exist",
            "broadcast to Lunes Network is not enabled in this release"
        ],
        "signing_status": signing_status,
    }))
}

// --- Write handlers ------------------------------------------------------

/// `lunes_transfer_native` - prepares or signs a native LUNES transfer.
fn handle_transfer_native(args: &Value, kms: &AgentKms) -> McpToolResult {
    let to = args.get("to").and_then(|v| v.as_str()).unwrap_or("");
    let amount = args.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);

    if let Err(e) = validate_address(to, "to") {
        return e;
    }
    if amount == 0 {
        return McpToolResult::error(-32001, "Missing or zero required field: amount".into());
    }

    let payload = format!("balances.transfer({to},{amount})");

    execute_write_operation(
        kms,
        "balances.transfer",
        to,
        amount,
        &payload,
        |sig, pk| {
            serde_json::json!({
                "action": "balances.transfer",
                "to": to,
                "amount_lunes": amount,
                "signature": sig,
                "signer": pk,
                "broadcasted": false,
                "submission_status": "not_broadcasted",
                "note": "Signed locally. Lunes Network broadcast pending."
            })
        },
        serde_json::json!({
            "action": "balances.transfer",
            "to": to,
            "amount_lunes": amount,
            "unsigned_payload": payload,
            "broadcasted": false,
            "next_step": "Human must review and sign this transfer with an external wallet."
        }),
    )
}

/// `lunes_transfer_psp22` - prepares or signs a PSP22 token transfer.
fn handle_transfer_psp22(args: &Value, kms: &AgentKms) -> McpToolResult {
    let contract = args
        .get("contract_address")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let to = args.get("to").and_then(|v| v.as_str()).unwrap_or("");
    let amount = args.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);

    if let Err(e) = validate_address(contract, "contract_address") {
        return e;
    }
    if let Err(e) = validate_address(to, "to") {
        return e;
    }
    if amount == 0 {
        return McpToolResult::error(-32001, "Missing or zero required field: amount".into());
    }

    let payload = format!("contracts.call({contract},PSP22::transfer,{to},{amount})");

    execute_write_operation(
        kms,
        "contracts.call",
        contract,
        amount,
        &payload,
        |sig, pk| {
            serde_json::json!({
                "action": "contracts.call (PSP22::transfer)",
                "contract": contract,
                "to": to,
                "amount_tokens": amount,
                "signature": sig,
                "signer": pk,
                "broadcasted": false,
                "submission_status": "not_broadcasted",
                "note": "Signed locally. Lunes Network broadcast pending."
            })
        },
        serde_json::json!({
            "action": "contracts.call (PSP22::transfer)",
            "contract": contract,
            "to": to,
            "amount_tokens": amount,
            "unsigned_payload": payload,
            "broadcasted": false,
            "next_step": "Human must review and sign this PSP22 transfer with an external wallet."
        }),
    )
}

/// `lunes_call_contract` - prepares or signs a generic ink! contract call.
fn handle_call_contract(args: &Value, kms: &AgentKms) -> McpToolResult {
    let contract = args
        .get("contract_address")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let message = args.get("message").and_then(|v| v.as_str()).unwrap_or("");
    let value = args.get("value").and_then(|v| v.as_u64()).unwrap_or(0);

    if let Err(e) = validate_address(contract, "contract_address") {
        return e;
    }
    if message.is_empty() {
        return McpToolResult::error(-32001, "Missing required field: message".into());
    }

    let call_args = args.get("args").cloned().unwrap_or(Value::Null);
    let payload = format!("contracts.call({contract},{message},{call_args},{value})");
    let action = format!("contracts.call ({})", message);

    execute_write_operation(
        kms,
        "contracts.call",
        contract,
        value,
        &payload,
        |sig, pk| {
            serde_json::json!({
                "action": action,
                "contract": contract,
                "message": message,
                "args": call_args,
                "value_lunes": value,
                "signature": sig,
                "signer": pk,
                "broadcasted": false,
                "submission_status": "not_broadcasted",
                "note": "Signed locally. Lunes Network broadcast pending."
            })
        },
        serde_json::json!({
            "action": action,
            "contract": contract,
            "message": message,
            "args": call_args,
            "value_lunes": value,
            "unsigned_payload": payload,
            "broadcasted": false,
            "next_step": "Human must review and sign this contract call with an external wallet."
        }),
    )
}

/// `lunes_stake_bond` - prepares or signs a staking bond operation.
fn handle_stake_bond(args: &Value, kms: &AgentKms) -> McpToolResult {
    let amount = args.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);
    if amount == 0 {
        return McpToolResult::error(-32001, "Missing or zero required field: amount".into());
    }

    let reward = match reward_destination_from_args(args, true) {
        Ok(reward) => reward,
        Err(error) => return error,
    };
    if let Some(error) = validate_reward_account_whitelist(kms, &reward) {
        return error;
    }

    let payload = format!("staking.bond({amount},{})", reward.payload_value());
    execute_staking_operation(
        kms,
        "staking.bond",
        amount,
        &payload,
        serde_json::json!({
            "action": "staking.bond",
            "amount_lunes": amount,
            "reward_destination": reward.destination,
            "reward_account": reward.account,
        }),
    )
}

/// `lunes_stake_unbond` - prepares or signs staking unbond.
fn handle_stake_unbond(args: &Value, kms: &AgentKms) -> McpToolResult {
    let amount = args.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);
    if amount == 0 {
        return McpToolResult::error(-32001, "Missing or zero required field: amount".into());
    }

    let payload = format!("staking.unbond({amount})");
    execute_staking_operation(
        kms,
        "staking.unbond",
        amount,
        &payload,
        serde_json::json!({
            "action": "staking.unbond",
            "amount_lunes": amount,
        }),
    )
}

/// `lunes_stake_withdraw_unbonded` - prepares or signs unlocked fund withdrawal.
fn handle_stake_withdraw_unbonded(args: &Value, kms: &AgentKms) -> McpToolResult {
    let slashing_spans = args
        .get("slashing_spans")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let payload = format!("staking.withdraw_unbonded({slashing_spans})");
    execute_staking_operation(
        kms,
        "staking.withdraw_unbonded",
        0,
        &payload,
        serde_json::json!({
            "action": "staking.withdraw_unbonded",
            "slashing_spans": slashing_spans,
        }),
    )
}

/// `lunes_stake_nominate` - prepares or signs validator nominations.
fn handle_stake_nominate(args: &Value, kms: &AgentKms) -> McpToolResult {
    let validators = match string_array(args, "validators") {
        Ok(validators) => validators,
        Err(error) => return error,
    };

    if validators.is_empty() {
        return McpToolResult::error(-32001, "validators must not be empty".into());
    }
    if validators.len() > MAX_NOMINATIONS {
        return McpToolResult::error(
            -32001,
            format!("validators exceeds maximum of {MAX_NOMINATIONS}"),
        );
    }

    for validator in &validators {
        if let Err(error) = validate_address(validator, "validators") {
            return error;
        }
    }
    if let Some(error) = validate_extra_whitelisted_destinations(kms, &validators) {
        return error;
    }

    let payload = format!("staking.nominate({})", validators.join(","));
    execute_staking_operation(
        kms,
        "staking.nominate",
        0,
        &payload,
        serde_json::json!({
            "action": "staking.nominate",
            "validators": validators,
        }),
    )
}

/// `lunes_stake_chill` - prepares or signs nomination pause.
fn handle_stake_chill(kms: &AgentKms) -> McpToolResult {
    execute_staking_operation(
        kms,
        "staking.chill",
        0,
        "staking.chill()",
        serde_json::json!({
            "action": "staking.chill",
        }),
    )
}

/// `lunes_stake_set_payee` - prepares or signs reward destination update.
fn handle_stake_set_payee(args: &Value, kms: &AgentKms) -> McpToolResult {
    let reward = match reward_destination_from_args(args, false) {
        Ok(reward) => reward,
        Err(error) => return error,
    };
    if let Some(error) = validate_reward_account_whitelist(kms, &reward) {
        return error;
    }

    let payload = format!("staking.set_payee({})", reward.payload_value());
    execute_staking_operation(
        kms,
        "staking.set_payee",
        0,
        &payload,
        serde_json::json!({
            "action": "staking.set_payee",
            "reward_destination": reward.destination,
            "reward_account": reward.account,
        }),
    )
}

fn execute_staking_operation(
    kms: &AgentKms,
    extrinsic: &str,
    amount_lunes: u64,
    payload: &str,
    data: Value,
) -> McpToolResult {
    execute_write_operation(
        kms,
        extrinsic,
        STAKING_POLICY_DESTINATION,
        amount_lunes,
        payload,
        |sig, pk| {
            let mut data = data.clone();
            if let Some(object) = data.as_object_mut() {
                object.insert("signature".into(), Value::String(sig.to_string()));
                object.insert("signer".into(), Value::String(pk.to_string()));
                object.insert("broadcasted".into(), Value::Bool(false));
                object.insert(
                    "submission_status".into(),
                    Value::String("not_broadcasted".into()),
                );
                object.insert(
                    "note".into(),
                    Value::String("Signed locally. Lunes Network broadcast pending.".into()),
                );
            }
            data
        },
        {
            let mut pending = data.clone();
            if let Some(object) = pending.as_object_mut() {
                object.insert(
                    "unsigned_payload".into(),
                    Value::String(payload.to_string()),
                );
                object.insert("broadcasted".into(), Value::Bool(false));
                object.insert(
                    "next_step".into(),
                    Value::String(
                        "Human must review and sign this staking operation with an external wallet."
                            .into(),
                    ),
                );
            }
            pending
        },
    )
}

#[derive(Debug)]
struct RewardDestination {
    destination: String,
    account: Option<String>,
}

impl RewardDestination {
    fn payload_value(&self) -> String {
        match &self.account {
            Some(account) => format!("{}:{account}", self.destination),
            None => self.destination.clone(),
        }
    }
}

fn reward_destination_from_args(
    args: &Value,
    default_to_staked: bool,
) -> Result<RewardDestination, McpToolResult> {
    let destination = args
        .get("reward_destination")
        .and_then(|v| v.as_str())
        .unwrap_or(if default_to_staked { "staked" } else { "" });

    if destination.is_empty() {
        return Err(McpToolResult::error(
            -32001,
            "Missing required field: reward_destination".into(),
        ));
    }

    if !matches!(destination, "staked" | "stash" | "controller" | "account") {
        return Err(McpToolResult::error(
            -32001,
            "reward_destination must be staked, stash, controller, or account".into(),
        ));
    }

    let account = args
        .get("reward_account")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    if destination == "account" {
        let account = account.ok_or_else(|| {
            McpToolResult::error(
                -32001,
                "reward_account is required when reward_destination is account".into(),
            )
        })?;
        validate_address(&account, "reward_account")?;
        return Ok(RewardDestination {
            destination: destination.into(),
            account: Some(account),
        });
    }

    Ok(RewardDestination {
        destination: destination.into(),
        account: None,
    })
}

fn string_array(args: &Value, field_name: &str) -> Result<Vec<String>, McpToolResult> {
    let values = args
        .get(field_name)
        .and_then(|value| value.as_array())
        .ok_or_else(|| {
            McpToolResult::error(-32001, format!("Missing required field: {field_name}"))
        })?;

    values
        .iter()
        .map(|value| {
            value.as_str().map(str::to_string).ok_or_else(|| {
                McpToolResult::error(-32001, format!("{field_name} must contain only strings"))
            })
        })
        .collect()
}

fn validate_reward_account_whitelist(
    kms: &AgentKms,
    reward: &RewardDestination,
) -> Option<McpToolResult> {
    reward.account.as_ref().and_then(|account| {
        validate_extra_whitelisted_destinations(kms, std::slice::from_ref(account))
    })
}

fn validate_extra_whitelisted_destinations(
    kms: &AgentKms,
    destinations: &[String],
) -> Option<McpToolResult> {
    let permissions = kms.permissions();
    for destination in destinations {
        if !permissions
            .whitelisted_addresses
            .iter()
            .any(|allowed| allowed == destination)
        {
            return Some(McpToolResult::error(
                -32011,
                format!("Destination '{destination}' is not in the whitelist."),
            ));
        }
    }

    None
}

/// `lunes_provision_agent_wallet` - creates a local agent key for approval.
fn handle_provision_wallet(kms: &AgentKms) -> McpToolResult {
    match kms.provision_key() {
        Ok(pub_key) => McpToolResult::pending(serde_json::json!({
            "agent_public_key": pub_key,
            "message": "Approval request sent to Lunes Web Gateway. Waiting for human signature.",
            "next_step": "Human must sign a proxy delegation tx using their Master Key."
        })),
        Err(e) => McpToolResult::error(e.error_code(), e.to_string()),
    }
}

/// `lunes_revoke_agent_wallet` - removes the current local agent key.
fn handle_revoke_wallet(kms: &AgentKms) -> McpToolResult {
    kms.revoke_key();

    McpToolResult::success(serde_json::json!({
        "revoked": true,
        "kms_active": false
    }))
}

// --- Tests ---------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::encode_lunes_address_for_tests;
    use crate::config::{AgentMode, PermissionsConfig};
    use crate::lunes_client::{
        ChainInfo, ChainProperties, NativeBalance, NetworkHealth, RuntimeInfo, TransactionState,
        TransactionStatus, ValidatorSet,
    };

    fn lunes_address(seed: u8) -> String {
        encode_lunes_address_for_tests([seed; 32])
    }

    fn permissions() -> PermissionsConfig {
        PermissionsConfig {
            allowed_extrinsics: vec!["balances.transfer".into(), "contracts.call".into()],
            whitelisted_addresses: vec![lunes_address(1)],
            daily_limit_lunes: 100,
            ttl_hours: 168,
        }
    }

    fn staking_permissions() -> PermissionsConfig {
        PermissionsConfig {
            allowed_extrinsics: vec![
                "staking.bond".into(),
                "staking.unbond".into(),
                "staking.withdraw_unbonded".into(),
                "staking.nominate".into(),
                "staking.chill".into(),
                "staking.set_payee".into(),
            ],
            whitelisted_addresses: vec!["staking".into(), lunes_address(8), lunes_address(9)],
            daily_limit_lunes: 1_000,
            ttl_hours: 168,
        }
    }

    fn response_json(response: &McpToolResult) -> serde_json::Value {
        serde_json::from_str(&response.content[0].text).expect("tool response text is JSON")
    }

    #[test]
    fn unknown_tool_returns_tool_not_found() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_missing".into(),
                arguments: serde_json::json!({}),
            },
            &kms,
        );

        assert!(response.is_error);
    }

    #[tokio::test]
    async fn get_balance_requires_valid_address() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        let client = LunesClient::static_native_balance(NativeBalance::zero());

        // Empty address
        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_get_balance".into(),
                arguments: serde_json::json!({}),
            },
            &kms,
            &client,
        )
        .await;
        assert!(response.is_error);

        // Invalid SS58 (too short)
        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_get_balance".into(),
                arguments: serde_json::json!({"address": "abc"}),
            },
            &kms,
            &client,
        )
        .await;
        assert!(response.is_error);
    }

    #[tokio::test]
    async fn get_balance_with_valid_address_succeeds() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        let client = LunesClient::static_native_balance(NativeBalance {
            free: 1_250_000_000,
            reserved: 200_000_000,
            frozen: 50_000_000,
            flags: 0,
        });
        let address = lunes_address(1);
        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_get_balance".into(),
                arguments: serde_json::json!({"address": address}),
            },
            &kms,
            &client,
        )
        .await;

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["asset"]["symbol"], "LUNES");
        assert_eq!(data["free_balance"], "1250000000");
        assert_eq!(data["balances"]["free_lunes"], "12.5");
        assert_eq!(data["balances"]["spendable_lunes"], "12");
    }

    #[tokio::test]
    async fn get_balance_leaves_psp22_lookup_for_future_sprint() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        let client = LunesClient::static_native_balance(NativeBalance::zero());
        let address = lunes_address(1);
        let asset_id = lunes_address(2);
        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_get_balance".into(),
                arguments: serde_json::json!({
                    "address": address,
                    "asset_id": asset_id,
                }),
            },
            &kms,
            &client,
        )
        .await;

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["asset"]["type"], "psp22");
        assert_eq!(data["status"], "pending_implementation");
    }

    #[tokio::test]
    async fn get_network_health_returns_live_status_shape() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        let client = LunesClient::static_network_health(NetworkHealth {
            endpoint: "wss://ws.lunes.io".into(),
            chain: "Lunes Nigthly".into(),
            node_name: "Lunes Nightly".into(),
            node_version: "4.0.0-dev".into(),
            peers: 12,
            is_syncing: false,
            should_have_peers: true,
            best_block_hash: format!("0x{}", "aa".repeat(32)),
            best_block_number: 100,
            finalized_block_hash: format!("0x{}", "bb".repeat(32)),
            finalized_block_number: 98,
            pending_extrinsics: 2,
            rpc_methods: 90,
        });

        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_get_network_health".into(),
                arguments: serde_json::json!({}),
            },
            &kms,
            &client,
        )
        .await;

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["status"], "healthy");
        assert_eq!(data["finality_lag_blocks"], 2);
        assert_eq!(data["peers"], 12);
    }

    #[tokio::test]
    async fn get_account_overview_combines_balance_nonce_and_policy() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, staking_permissions());
        let client = LunesClient::static_account_state(
            NativeBalance {
                free: 2_500_000_000,
                reserved: 500_000_000,
                frozen: 200_000_000,
                flags: 0,
            },
            7,
        );
        let address = lunes_address(4);

        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_get_account_overview".into(),
                arguments: serde_json::json!({ "address": address }),
            },
            &kms,
            &client,
        )
        .await;

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["nonce"], 7);
        assert_eq!(data["balances"]["free_lunes"], "25");
        assert_eq!(data["balances"]["spendable_lunes"], "23");
        assert_eq!(data["policy"]["can_manage_staking"], true);
    }

    #[tokio::test]
    async fn get_investment_position_reports_liquidity_and_actions() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, staking_permissions());
        let client = LunesClient::static_account_state(
            NativeBalance {
                free: 1_000_000_000,
                reserved: 300_000_000,
                frozen: 100_000_000,
                flags: 0,
            },
            3,
        );
        let address = lunes_address(5);

        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_get_investment_position".into(),
                arguments: serde_json::json!({ "address": address }),
            },
            &kms,
            &client,
        )
        .await;

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["position"]["liquid_lunes"], "9");
        assert_eq!(data["position"]["reserved_or_locked_lunes"], "4");
        assert!(data["agent_actions"]["can_prepare_staking_actions"]
            .as_bool()
            .unwrap());
    }

    #[tokio::test]
    async fn get_validator_set_respects_limit() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        let client = LunesClient::static_validator_set(ValidatorSet {
            lookup: "session.validators".into(),
            validators: vec![lunes_address(1), lunes_address(2), lunes_address(3)],
        });

        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_get_validator_set".into(),
                arguments: serde_json::json!({ "limit": 2 }),
            },
            &kms,
            &client,
        )
        .await;

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["validator_count"], 3);
        assert_eq!(data["validators"].as_array().unwrap().len(), 2);
        assert_eq!(data["truncated"], true);
    }

    #[tokio::test]
    async fn get_staking_overview_summarizes_available_read_state() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, staking_permissions());
        let client = LunesClient::static_validator_set(ValidatorSet {
            lookup: "session.validators".into(),
            validators: vec![lunes_address(8), lunes_address(9)],
        });

        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_get_staking_overview".into(),
                arguments: serde_json::json!({}),
            },
            &kms,
            &client,
        )
        .await;

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["active_validator_count"], 2);
        assert_eq!(data["agent_policy"]["can_manage_staking"], true);
        assert_eq!(data["write_status"], "prepare_or_local_intent_only");
    }

    #[tokio::test]
    async fn get_transaction_status_returns_network_status() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        let client = LunesClient::static_transaction_status(TransactionStatus {
            tx_hash: format!("0x{}", "11".repeat(32)),
            status: TransactionState::Finalized,
            block_hash: Some(format!("0x{}", "22".repeat(32))),
            block_number: Some(42),
            extrinsic_index: Some(3),
            lookup_scope: "test scope".into(),
        });

        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_get_transaction_status".into(),
                arguments: serde_json::json!({ "tx_hash": format!("0x{}", "11".repeat(32)) }),
            },
            &kms,
            &client,
        )
        .await;

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["status"], "finalized");
        assert_eq!(data["block_number"], 42);
        assert_eq!(data["extrinsic_index"], 3);
        assert_eq!(
            data["archive_lookback_blocks"],
            DEFAULT_ARCHIVE_TX_LOOKBACK_BLOCKS
        );
    }

    #[tokio::test]
    async fn get_transaction_status_rejects_invalid_hash() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        let client = LunesClient::static_transaction_status(TransactionStatus {
            tx_hash: format!("0x{}", "11".repeat(32)),
            status: TransactionState::NotFound,
            block_hash: None,
            block_number: None,
            extrinsic_index: None,
            lookup_scope: "test scope".into(),
        });

        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_get_transaction_status".into(),
                arguments: serde_json::json!({ "tx_hash": "0x1234" }),
            },
            &kms,
            &client,
        )
        .await;

        assert!(response.is_error);
        assert!(response.content[0].text.contains("expected 32 bytes"));
    }

    #[tokio::test]
    async fn get_transaction_status_rejects_archive_lookback_above_limit() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        let client = LunesClient::static_transaction_status(TransactionStatus {
            tx_hash: format!("0x{}", "11".repeat(32)),
            status: TransactionState::NotFound,
            block_hash: None,
            block_number: None,
            extrinsic_index: None,
            lookup_scope: "test scope".into(),
        });

        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_get_transaction_status".into(),
                arguments: serde_json::json!({
                    "tx_hash": format!("0x{}", "11".repeat(32)),
                    "archive_lookback_blocks": MAX_ARCHIVE_TX_LOOKBACK_BLOCKS + 1,
                }),
            },
            &kms,
            &client,
        )
        .await;

        assert!(response.is_error);
        assert!(response.content[0].text.contains("archive_lookback_blocks"));
    }

    #[test]
    fn validate_address_reports_lunes_prefix_and_account_id() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        let address = lunes_address(7);
        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_validate_address".into(),
                arguments: serde_json::json!({ "address": address }),
            },
            &kms,
        );

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["is_valid"], true);
        assert_eq!(data["ss58_prefix"], 57);
        assert_eq!(data["account_id_hex"], hex::encode([7u8; 32]));
    }

    #[test]
    fn validate_address_returns_false_for_wrong_network_prefix() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_validate_address".into(),
                arguments: serde_json::json!({
                    "address": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
                }),
            },
            &kms,
        );

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["is_valid"], false);
        assert_eq!(data["expected_ss58_prefix"], 57);
    }

    #[test]
    fn get_permissions_summarizes_prepare_only_capabilities() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_get_permissions".into(),
                arguments: serde_json::json!({}),
            },
            &kms,
        );

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["capabilities"]["can_read"], true);
        assert_eq!(data["capabilities"]["can_sign_local_intents"], false);
        assert_eq!(
            data["capabilities"]["can_broadcast_to_lunes_network"],
            false
        );
        assert_eq!(data["policy"]["daily_limit_lunes"], 100);
    }

    #[tokio::test]
    async fn get_chain_info_returns_static_lunes_rpc_metadata() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        let client = LunesClient::static_info(ChainInfo {
            rpc_endpoint: "wss://ws.lunes.io".into(),
            chain: "Lunes Nigthly".into(),
            node_name: "Lunes Nightly".into(),
            node_version: "4.0.0-dev".into(),
            properties: ChainProperties {
                ss58_format: 57,
                token_decimals: 8,
                token_symbol: "LUNES".into(),
            },
            runtime: RuntimeInfo {
                spec_name: "lunes-nightly".into(),
                impl_name: "lunes-nightly".into(),
                spec_version: 107,
                transaction_version: 2,
                state_version: 2,
            },
        });

        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_get_chain_info".into(),
                arguments: serde_json::json!({}),
            },
            &kms,
            &client,
        )
        .await;

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["token"]["symbol"], "LUNES");
        assert_eq!(data["address_format"]["ss58_prefix"], 57);
        assert_eq!(data["runtime"]["spec_version"], 107);
    }

    #[test]
    fn prepare_only_native_transfer_waits_for_human_approval() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        let to = lunes_address(1);
        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_transfer_native".into(),
                arguments: serde_json::json!({
                    "to": to,
                    "amount": 10
                }),
            },
            &kms,
        );

        assert!(!response.is_error);
        let text = &response.content[0].text;
        assert!(text.contains("pending_human_approval"));
    }

    #[test]
    fn autonomous_native_transfer_signs_locally() {
        let kms = AgentKms::new(AgentMode::Autonomous, permissions());
        kms.provision_key().unwrap();
        let to = lunes_address(1);

        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_transfer_native".into(),
                arguments: serde_json::json!({
                    "to": to,
                    "amount": 10
                }),
            },
            &kms,
        );

        assert!(!response.is_error);
        let text = &response.content[0].text;
        assert!(text.contains("signature"));
        assert!(text.contains("not_broadcasted"));
    }

    #[test]
    fn psp22_transfer_consumes_daily_budget() {
        let contract = lunes_address(2);
        let to = lunes_address(3);
        let kms = AgentKms::new(
            AgentMode::Autonomous,
            PermissionsConfig {
                allowed_extrinsics: vec!["contracts.call".into()],
                whitelisted_addresses: vec![contract.clone()],
                daily_limit_lunes: 5,
                ttl_hours: 168,
            },
        );
        kms.provision_key().unwrap();

        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_transfer_psp22".into(),
                arguments: serde_json::json!({
                    "contract_address": contract,
                    "to": to,
                    "amount": 10
                }),
            },
            &kms,
        );

        assert!(response.is_error);
        assert!(response.content[0].text.contains("-32010"));
    }

    #[test]
    fn provision_wallet_returns_pending() {
        let kms = AgentKms::new(AgentMode::Autonomous, permissions());
        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_provision_agent_wallet".into(),
                arguments: serde_json::json!({}),
            },
            &kms,
        );

        assert!(!response.is_error);
        let text = &response.content[0].text;
        assert!(text.contains("agent_public_key"));
    }

    #[test]
    fn double_provision_returns_error() {
        let kms = AgentKms::new(AgentMode::Autonomous, permissions());
        let first = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_provision_agent_wallet".into(),
                arguments: serde_json::json!({}),
            },
            &kms,
        );
        assert!(!first.is_error);

        let second = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_provision_agent_wallet".into(),
                arguments: serde_json::json!({}),
            },
            &kms,
        );
        assert!(second.is_error);
    }

    #[test]
    fn tools_list_includes_all_schemas() {
        let tools = tool_definitions();
        assert_eq!(tools.len(), 22);
        assert!(tools.iter().any(|tool| tool["name"] == "lunes_get_balance"));
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_get_network_health"));
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_get_account_overview"));
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_get_investment_position"));
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_get_validator_set"));
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_get_staking_overview"));
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_get_chain_info"));
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_get_permissions"));
        let tx_tool = tools
            .iter()
            .find(|tool| tool["name"] == "lunes_get_transaction_status")
            .expect("transaction status tool");
        assert!(tx_tool["inputSchema"]["properties"]
            .get("archive_lookback_blocks")
            .is_some());
        assert!(tools.iter().any(|tool| tool["name"] == "lunes_stake_bond"));
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_stake_nominate"));
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_transfer_native"));
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_revoke_agent_wallet"));
        assert!(tools.iter().all(|tool| tool.get("inputSchema").is_some()));
    }

    #[test]
    fn staking_bond_prepares_human_review_payload() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, staking_permissions());
        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_stake_bond".into(),
                arguments: serde_json::json!({
                    "amount": 100,
                    "reward_destination": "staked"
                }),
            },
            &kms,
        );

        assert!(!response.is_error);
        let text = &response.content[0].text;
        assert!(text.contains("pending_human_approval"));
        assert!(text.contains("staking.bond"));
        assert!(text.contains("reward_destination"));
    }

    #[test]
    fn staking_nominate_requires_validator_whitelist() {
        let kms = AgentKms::new(
            AgentMode::PrepareOnly,
            PermissionsConfig {
                allowed_extrinsics: vec!["staking.nominate".into()],
                whitelisted_addresses: vec!["staking".into(), lunes_address(8)],
                daily_limit_lunes: 1_000,
                ttl_hours: 168,
            },
        );
        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_stake_nominate".into(),
                arguments: serde_json::json!({
                    "validators": [lunes_address(8), lunes_address(9)]
                }),
            },
            &kms,
        );

        assert!(response.is_error);
        assert!(response.content[0].text.contains("not in the whitelist"));
    }

    #[test]
    fn staking_unbond_signs_when_autonomous_policy_allows_it() {
        let kms = AgentKms::new(AgentMode::Autonomous, staking_permissions());
        kms.provision_key().unwrap();
        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_stake_unbond".into(),
                arguments: serde_json::json!({
                    "amount": 50
                }),
            },
            &kms,
        );

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["action"], "staking.unbond");
        assert_eq!(data["broadcasted"], false);
        assert!(data["signature"].is_string());
    }

    #[test]
    fn staking_chill_prepares_when_policy_allows_it() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, staking_permissions());
        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_stake_chill".into(),
                arguments: serde_json::json!({}),
            },
            &kms,
        );

        assert!(!response.is_error);
        assert!(response.content[0].text.contains("staking.chill"));
    }

    #[test]
    fn staking_set_payee_account_requires_reward_account() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, staking_permissions());
        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_stake_set_payee".into(),
                arguments: serde_json::json!({
                    "reward_destination": "account"
                }),
            },
            &kms,
        );

        assert!(response.is_error);
        assert!(response.content[0]
            .text
            .contains("reward_account is required"));
    }

    #[test]
    fn revoke_agent_wallet_deactivates_kms() {
        let kms = AgentKms::new(AgentMode::Autonomous, permissions());
        kms.provision_key().unwrap();
        assert!(kms.is_active());

        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_revoke_agent_wallet".into(),
                arguments: serde_json::json!({}),
            },
            &kms,
        );

        assert!(!response.is_error);
        assert!(!kms.is_active());
    }

    #[test]
    fn ss58_validation_works() {
        assert!(is_valid_ss58(&lunes_address(4)));
        // Too short
        assert!(!is_valid_ss58("5Gxyz"));
        assert!(!is_valid_ss58(
            "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
        ));
    }
}
