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

use crate::abi_registry::AbiRegistry;
use crate::address::{validate_lunes_address, LunesAddress, LUNES_SS58_PREFIX};
use crate::config::AssetPolicyConfig;
use crate::kms::{AgentKms, KmsError, AUDIT_LOG_PATH_ENV};
use crate::lunes_client::{
    signed_extrinsic_payload_hash, LunesClient, LunesClientError, NativeBalance,
    StakingRewardDestination, StakingRewardDestinationKind, ValidatorProfile,
    DEFAULT_ARCHIVE_TX_LOOKBACK_BLOCKS, MAX_ARCHIVE_TX_LOOKBACK_BLOCKS,
};

const LUNES_DECIMALS: u32 = 8;
const LUNES_BASE_UNITS: u128 = 100_000_000;
const STAKING_POLICY_DESTINATION: &str = "staking";
const BROADCAST_POLICY_EXTRINSIC: &str = "author.submit_extrinsic";
const BROADCAST_POLICY_DESTINATION: &str = "broadcast";
const MAX_NOMINATIONS: usize = 16;
const DEFAULT_VALIDATOR_LIMIT: usize = 16;
const MAX_VALIDATOR_LIMIT: usize = 64;
const DEFAULT_GOVERNANCE_REFERENDA_LIMIT: usize = 16;
const MAX_GOVERNANCE_REFERENDA_LIMIT: usize = 64;
const BROADCAST_OPT_IN_ENV: &str = "LUNES_MCP_ENABLE_BROADCAST";
const INTERNAL_SIGNING_OPT_IN_ENV: &str = "LUNES_MCP_ENABLE_INTERNAL_SIGNING";
const BROADCAST_HASH_ALLOWLIST_ENV: &str = "LUNES_MCP_ALLOWED_BROADCAST_HASHES";
const DEFAULT_SUBMISSION_WAIT_BLOCKS: u64 = 4;
const MAX_SUBMISSION_WAIT_BLOCKS: u64 = 16;

#[derive(Debug, Deserialize)]
pub struct ToolCallRequest {
    pub name: String,
    /// Intentional JSON boundary: MCP tool arguments are validated by each handler
    /// against that tool's schema.
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
    /// Successful response with tool-specific JSON data serialized as text content.
    ///
    /// `Value` is intentional at this MCP boundary because each tool returns a
    /// different JSON object while the outer MCP result shape stays fixed.
    pub fn success(data: Value) -> Self {
        Self {
            content: vec![ContentBlock {
                content_type: "text".into(),
                text: serde_json::to_string_pretty(&data)
                    .expect("serde_json::Value serializes to JSON text"),
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
                text: serde_json::to_string_pretty(&error_data)
                    .expect("serde_json::Value serializes to JSON text"),
            }],
            is_error: true,
        }
    }

    /// Pending response for operations that need human approval.
    ///
    /// `data` remains open JSON because pending payloads intentionally mirror the
    /// write action being prepared for external review.
    pub fn pending(data: Value) -> Self {
        let pending_data = serde_json::json!({
            "status": "pending_human_approval",
            "data": data,
        });
        Self {
            content: vec![ContentBlock {
                content_type: "text".into(),
                text: serde_json::to_string_pretty(&pending_data)
                    .expect("serde_json::Value serializes to JSON text"),
            }],
            is_error: false,
        }
    }
}

/// Validates an SS58 address and maps failures to a tool error.
fn validate_address(address: &str, field_name: &str) -> Result<(), McpToolResult> {
    parse_lunes_address(address, field_name).map(|_| ())
}

/// Routes a tool call name to the matching handler.
pub fn dispatch_tool_call(request: &ToolCallRequest, kms: &AgentKms) -> McpToolResult {
    match request.name.as_str() {
        // Read-only queries that do not need live RPC
        "lunes_search_contract" => handle_search_contract(&request.arguments, kms),
        "lunes_validate_address" => handle_validate_address(&request.arguments),
        "lunes_get_permissions" => handle_get_permissions(kms),
        "lunes_get_assets" => handle_get_assets(kms),
        "lunes_get_balance"
        | "lunes_get_asset_balance"
        | "lunes_search_account_activity"
        | "lunes_get_transaction_status"
        | "lunes_get_recent_blocks"
        | "lunes_get_block_events"
        | "lunes_get_network_health"
        | "lunes_get_account_overview"
        | "lunes_get_investment_position"
        | "lunes_get_validator_set"
        | "lunes_get_validator_profiles"
        | "lunes_get_validator_scores"
        | "lunes_get_staking_overview"
        | "lunes_get_staking_account"
        | "lunes_get_governance_overview"
        | "lunes_get_referenda"
        | "lunes_submit_signed_extrinsic"
        | "lunes_read_contract" => {
            McpToolResult::error(-32020, "Tool requires a live Lunes RPC client".into())
        }

        // Write operations that go through the KMS policy checks
        "lunes_transfer_native" => handle_transfer_native(&request.arguments, kms),
        "lunes_transfer_psp22" => handle_transfer_psp22(&request.arguments, kms),
        "lunes_call_contract" => handle_call_contract(&request.arguments, kms),
        "lunes_stake_bond" => handle_stake_bond(&request.arguments, kms),
        "lunes_stake_unbond" => handle_stake_unbond(&request.arguments, kms),
        "lunes_stake_rebond" => handle_stake_rebond(&request.arguments, kms),
        "lunes_stake_withdraw_unbonded" => handle_stake_withdraw_unbonded(&request.arguments, kms),
        "lunes_stake_nominate" => handle_stake_nominate(&request.arguments, kms),
        "lunes_stake_payout" => handle_stake_payout(&request.arguments, kms),
        "lunes_stake_chill" => handle_stake_chill(kms),
        "lunes_stake_set_payee" => handle_stake_set_payee(&request.arguments, kms),
        "lunes_prepare_governance_vote" => handle_prepare_governance_vote(&request.arguments, kms),
        "lunes_prepare_governance_remove_vote" => {
            handle_prepare_governance_remove_vote(&request.arguments, kms)
        }
        "lunes_prepare_governance_delegate" => {
            handle_prepare_governance_delegate(&request.arguments, kms)
        }
        "lunes_prepare_governance_undelegate" => {
            handle_prepare_governance_undelegate(&request.arguments, kms)
        }

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
        "lunes_get_assets" => handle_get_assets(kms),
        "lunes_get_balance" => handle_get_balance(&request.arguments, kms, lunes_client).await,
        "lunes_get_asset_balance" => {
            handle_get_asset_balance(&request.arguments, kms, lunes_client).await
        }
        "lunes_get_account_overview" => {
            handle_get_account_overview(&request.arguments, kms, lunes_client).await
        }
        "lunes_get_investment_position" => {
            handle_get_investment_position(&request.arguments, kms, lunes_client).await
        }
        "lunes_get_validator_set" => {
            handle_get_validator_set(&request.arguments, lunes_client).await
        }
        "lunes_get_validator_profiles" => {
            handle_get_validator_profiles(&request.arguments, lunes_client).await
        }
        "lunes_get_validator_scores" => {
            handle_get_validator_scores(&request.arguments, lunes_client).await
        }
        "lunes_get_staking_overview" => {
            handle_get_staking_overview(&request.arguments, kms, lunes_client).await
        }
        "lunes_get_staking_account" => {
            handle_get_staking_account(&request.arguments, kms, lunes_client).await
        }
        "lunes_get_governance_overview" => {
            handle_get_governance_overview(&request.arguments, kms, lunes_client).await
        }
        "lunes_get_referenda" => handle_get_referenda(&request.arguments, lunes_client).await,
        "lunes_get_transaction_status" => {
            handle_get_tx_status(&request.arguments, lunes_client).await
        }
        "lunes_get_recent_blocks" => {
            handle_get_recent_blocks(&request.arguments, lunes_client).await
        }
        "lunes_get_block_events" => handle_get_block_events(&request.arguments, lunes_client).await,
        "lunes_submit_signed_extrinsic" => {
            handle_submit_signed_extrinsic(&request.arguments, kms, lunes_client).await
        }
        "lunes_search_account_activity" => {
            handle_search_account_activity(&request.arguments, lunes_client).await
        }
        "lunes_read_contract" => handle_read_contract(&request.arguments, kms, lunes_client).await,
        "lunes_transfer_native" => {
            handle_transfer_native_with_chain(&request.arguments, kms, lunes_client).await
        }
        _ => dispatch_tool_call(request, kms),
    }
}

/// MCP tool descriptors exposed by the server.
///
/// The descriptors are JSON Schema boundary documents, so `Value` is used here
/// deliberately instead of modeling the full schema vocabulary in Rust.
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
            "name": "lunes_get_assets",
            "description": "List native LUNES plus PSP22 contracts currently allowed by this agent policy.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "lunes_get_asset_balance",
            "description": "Read native LUNES balance or dry-run PSP22::balance_of for an allowlisted token contract.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "address": { "type": "string", "description": "Owner SS58 address on Lunes Network." },
                    "asset_id": { "type": "string", "description": "Use native, LUNES, or an allowlisted PSP22 contract address." }
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
            "name": "lunes_get_validator_profiles",
            "description": "Read live validator profile data, including active-set status, commission, blocked state, and nomination eligibility.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "validators": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": MAX_VALIDATOR_LIMIT,
                        "items": { "type": "string" },
                        "description": "Optional validator addresses. If omitted, the tool samples the active validator set."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_VALIDATOR_LIMIT,
                        "description": "Maximum validators to profile when validators is omitted. Defaults to 16."
                    }
                }
            }
        }),
        serde_json::json!({
            "name": "lunes_get_validator_scores",
            "description": "Score validators from observable live profile data. Exposure and reward history are reported as not decoded unless available in future versions.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "validators": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": MAX_VALIDATOR_LIMIT,
                        "items": { "type": "string" },
                        "description": "Optional validator addresses. If omitted, the tool samples the active validator set."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_VALIDATOR_LIMIT,
                        "description": "Maximum validators to score when validators is omitted. Defaults to 16."
                    }
                }
            }
        }),
        serde_json::json!({
            "name": "lunes_get_staking_account",
            "description": "Read live staking state for one Lunes account, including bond, ledger, reward destination, nominations, and validator preferences when present.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "address": { "type": "string", "description": "SS58 address on Lunes Network." }
                },
                "required": ["address"]
            }
        }),
        serde_json::json!({
            "name": "lunes_get_governance_overview",
            "description": "Summarize live Lunes governance visibility and the prepare-only vote policy configured for this agent.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_GOVERNANCE_REFERENDA_LIMIT,
                        "description": "Maximum referendum storage entries to sample. Defaults to 16."
                    }
                }
            }
        }),
        serde_json::json!({
            "name": "lunes_get_referenda",
            "description": "Read bounded raw referendum storage entries from live Lunes governance state.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_GOVERNANCE_REFERENDA_LIMIT,
                        "description": "Maximum referendum storage entries to return. Defaults to 16."
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
            "name": "lunes_get_recent_blocks",
            "description": "List recent finalized Lunes blocks with hash, number, and extrinsic count only.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "lookback_blocks": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": MAX_ARCHIVE_TX_LOOKBACK_BLOCKS,
                        "description": "Number of finalized blocks before the finalized head to include. Defaults to the bounded archive lookup window."
                    }
                }
            }
        }),
        serde_json::json!({
            "name": "lunes_get_block_events",
            "description": "Read raw event storage for a finalized Lunes block by hash, number, or the current finalized head.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "block_hash": { "type": "string", "description": "Optional 32-byte block hash. Omit with block_number to use finalized head." },
                    "block_number": { "type": "integer", "minimum": 0, "description": "Optional block number. Do not provide with block_hash." }
                }
            }
        }),
        serde_json::json!({
            "name": "lunes_submit_signed_extrinsic",
            "description": "Broadcast a human-signed Lunes extrinsic and poll for inclusion/finality. Requires broadcast env opt-in, hash preapproval, confirm_broadcast=true, and agent policy author.submit_extrinsic -> broadcast.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "signed_extrinsic": { "type": "string", "description": "0x-prefixed signed extrinsic bytes produced by an external Lunes wallet." },
                    "expected_tx_hash": { "type": "string", "description": "Optional expected hash for the signed extrinsic. When provided it must match the computed payload hash." },
                    "confirm_broadcast": { "type": "boolean", "description": "Must be true to broadcast." },
                    "wait_blocks": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": MAX_SUBMISSION_WAIT_BLOCKS,
                        "description": "Number of polling intervals to wait for inclusion/finality. Defaults to 4."
                    }
                },
                "required": ["signed_extrinsic", "confirm_broadcast"]
            }
        }),
        serde_json::json!({
            "name": "lunes_search_account_activity",
            "description": "Search the mempool and recent archive blocks for activity involving a specific account. Useful for debugging frozen state.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "address": { "type": "string", "description": "Lunes format address to scan for." },
                    "lookback_blocks": { "type": "integer", "minimum": 0, "maximum": MAX_ARCHIVE_TX_LOOKBACK_BLOCKS, "description": "Number of recent blocks to scan. Defaults to the bounded archive lookup window." }
                },
                "required": ["address"]
            }
        }),
        serde_json::json!({
            "name": "lunes_read_contract",
            "description": "Simulate a read-only Lunes contract call through live RPC.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "contract_address": { "type": "string", "description": "Lunes format address of the contract." },
                    "origin": { "type": "string", "description": "Optional Lunes origin address for the dry run. Defaults to contract_address." },
                    "method": { "type": "string", "description": "Method name to call (e.g., 'PSP22::balance_of' or 'transfer')." },
                    "args_hex": { "type": "string", "description": "Hex-encoded Lunes contract arguments without the 4-byte selector (optional)." }
                },
                "required": ["contract_address", "method"]
            }
        }),
        serde_json::json!({
            "name": "lunes_search_contract",
            "description": "Look up metadata and interface details for a Lunes contract.",
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
            "description": "Prepare, locally sign, or guarded-broadcast a native LUNES transfer.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "to": { "type": "string", "description": "Recipient SS58 address." },
                    "amount": { "type": "integer", "minimum": 1, "description": "Whole LUNES amount." },
                    "amount_base_units": { "type": "string", "description": "Exact base-unit amount. Must match amount when both are provided." },
                    "keep_alive": { "type": "boolean", "description": "Use Balances.transfer_keep_alive instead of transfer_allow_death." },
                    "confirm_broadcast": { "type": "boolean", "description": "Must be true to broadcast a final transaction." },
                    "wait_blocks": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": MAX_SUBMISSION_WAIT_BLOCKS,
                        "description": "Finalization wait budget. Defaults to 4."
                    }
                },
                "required": ["to"]
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
                    "amount": { "type": "integer", "minimum": 1, "description": "Token base-unit amount." },
                    "amount_base_units": { "type": "string", "description": "Exact token base-unit amount. Must match amount when both are provided." }
                },
                "required": ["contract_address", "to"]
            }
        }),
        serde_json::json!({
            "name": "lunes_call_contract",
            "description": "Prepare or sign a generic Lunes contract call.",
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
            "name": "lunes_stake_rebond",
            "description": "Prepare or sign a Lunes staking rebond operation.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "amount": { "type": "integer", "minimum": 1, "description": "LUNES amount to rebond." }
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
            "name": "lunes_stake_payout",
            "description": "Prepare or sign payout_stakers for a specific validator stash and era.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "validator_stash": { "type": "string", "description": "Validator stash SS58 address. Must be whitelisted." },
                    "era": { "type": "integer", "minimum": 0, "description": "Staking era to pay out." }
                },
                "required": ["validator_stash", "era"]
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
            "name": "lunes_prepare_governance_vote",
            "description": "Prepare a human-review governance vote payload without signing or broadcasting.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "referendum_index": { "type": "integer", "minimum": 0, "description": "Referendum index allowed by governance policy." },
                    "vote": { "type": "string", "enum": ["aye", "nay"], "description": "Vote direction." },
                    "conviction": { "type": "string", "description": "Conviction lock, for example none, locked1x, locked2x, locked3x, locked4x, locked5x, locked6x." },
                    "amount": { "type": "integer", "minimum": 1, "description": "Whole LUNES lock amount." },
                    "amount_base_units": { "type": "string", "description": "Exact base-unit lock amount. Must match amount when both are provided." },
                    "confirm_broadcast": { "type": "boolean", "description": "Rejected when true; governance tools never broadcast." }
                },
                "required": ["referendum_index", "vote", "conviction"]
            }
        }),
        serde_json::json!({
            "name": "lunes_prepare_governance_remove_vote",
            "description": "Prepare a human-review governance remove-vote payload without signing or broadcasting.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "referendum_index": { "type": "integer", "minimum": 0, "description": "Referendum index allowed by governance policy." },
                    "confirm_broadcast": { "type": "boolean", "description": "Rejected when true; governance tools never broadcast." }
                },
                "required": ["referendum_index"]
            }
        }),
        serde_json::json!({
            "name": "lunes_prepare_governance_delegate",
            "description": "Prepare a human-review governance delegation payload without signing or broadcasting.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "track": { "type": "integer", "minimum": 0, "description": "Governance track/class allowed by delegation policy." },
                    "delegate": { "type": "string", "description": "Delegate SS58 address allowed by governance policy." },
                    "conviction": { "type": "string", "description": "Conviction lock, for example none, locked1x, locked2x, locked3x, locked4x, locked5x, locked6x." },
                    "amount": { "type": "integer", "minimum": 1, "description": "Whole LUNES lock amount." },
                    "amount_base_units": { "type": "string", "description": "Exact base-unit lock amount. Must match amount when both are provided." },
                    "confirm_broadcast": { "type": "boolean", "description": "Rejected when true; governance tools never broadcast." }
                },
                "required": ["track", "delegate", "conviction"]
            }
        }),
        serde_json::json!({
            "name": "lunes_prepare_governance_undelegate",
            "description": "Prepare a human-review governance undelegation payload without signing or broadcasting.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "track": { "type": "integer", "minimum": 0, "description": "Governance track/class allowed by delegation policy." },
                    "confirm_broadcast": { "type": "boolean", "description": "Rejected when true; governance tools never broadcast." }
                },
                "required": ["track"]
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
    if let Err(e) = kms.preflight_write(extrinsic, destination, amount_lunes) {
        return McpToolResult::error(e.error_code(), e.to_string());
    }

    if !kms.is_autonomous() {
        let mut final_pending = pending_data;
        if kms.permissions().human_approval_required {
            if let Some(template) = &kms.permissions().approval_message_template {
                if let Some(obj) = final_pending.as_object_mut() {
                    obj.insert(
                        "human_approval_notice".to_string(),
                        Value::String(template.clone()),
                    );
                }
            }
        }
        return McpToolResult::pending(final_pending);
    }

    match kms.sign_payload(extrinsic, destination, amount_lunes, payload.as_bytes()) {
        Ok(signed) => McpToolResult::success(success_data(&signed.signature, &signed.public_key)),
        Err(e) => McpToolResult::error(e.error_code(), e.to_string()),
    }
}

async fn handle_get_balance(
    args: &Value,
    kms: &AgentKms,
    lunes_client: &LunesClient,
) -> McpToolResult {
    handle_get_asset_balance(args, kms, lunes_client).await
}

fn handle_get_assets(kms: &AgentKms) -> McpToolResult {
    let permissions = kms.permissions();
    let mut contract_addresses: Vec<String> = permissions
        .allowlist_contracts
        .iter()
        .filter(|(_, methods)| {
            methods
                .iter()
                .any(|method| is_psp22_asset_method(method.as_str()))
        })
        .map(|(contract_address, _)| contract_address.clone())
        .collect();
    for contract_address in permissions.asset_policies.keys() {
        if !contract_addresses
            .iter()
            .any(|existing| existing == contract_address)
        {
            contract_addresses.push(contract_address.clone());
        }
    }

    let mut contract_assets: Vec<_> = contract_addresses
        .into_iter()
        .map(|contract_address| {
            let methods = permissions
                .allowlist_contracts
                .get(&contract_address)
                .cloned()
                .unwrap_or_default();
            let read_methods_allowed: Vec<_> = methods
                .iter()
                .filter(|method| is_psp22_balance_method(method.as_str()))
                .cloned()
                .collect();
            let transfer_methods_allowed: Vec<_> = methods
                .iter()
                .filter(|method| is_psp22_transfer_method(method.as_str()))
                .cloned()
                .collect();
            let policy = permissions.asset_policies.get(&contract_address);
            serde_json::json!({
                "type": "psp22",
                "contract_address": contract_address,
                "interface": "PSP22",
                "metadata": psp22_asset_metadata_json(policy),
                "methods_allowed": methods,
                "read_methods_allowed": read_methods_allowed,
                "transfer_methods_allowed": transfer_methods_allowed,
                "transfer_policy": psp22_transfer_policy_json(policy),
                "balance_lookup": "contracts_call_dry_run",
                "decoded": false,
            })
        })
        .collect();
    contract_assets.sort_by(|left, right| {
        left["contract_address"]
            .as_str()
            .cmp(&right["contract_address"].as_str())
    });

    McpToolResult::success(serde_json::json!({
        "assets": {
            "native": native_asset_json(),
            "contracts": contract_assets,
        },
        "policy": {
            "psp22_balance_requires_contract_allowlist": true,
            "native_daily_limit_lunes": kms.permissions().daily_limit_lunes,
            "asset_specific_transfer_limits": true,
            "psp22_transfer_requires_asset_policy": true,
        },
        "lookup": "local_agent_policy",
    }))
}

async fn handle_get_asset_balance(
    args: &Value,
    kms: &AgentKms,
    lunes_client: &LunesClient,
) -> McpToolResult {
    let address = args.get("address").and_then(|v| v.as_str()).unwrap_or("");
    let asset_id = args.get("asset_id").and_then(|v| v.as_str());

    let parsed = match parse_lunes_address(address, "address") {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };

    if let Some(asset_id) = asset_id.filter(|asset_id| !is_native_asset_id(asset_id)) {
        if let Err(error) = validate_address(asset_id, "asset_id") {
            return error;
        }

        if let Err(error) = validate_psp22_balance_read(kms, asset_id) {
            return McpToolResult::error(error.error_code(), error.to_string());
        }

        let selector = AbiRegistry::new()
            .resolve_selector("PSP22::balance_of")
            .expect("PSP22 balance selector is registered");
        let mut input_data = selector.to_vec();
        input_data.extend_from_slice(&parsed.account_id);

        return match lunes_client
            .fetch_contract_read(asset_id, address, &input_data)
            .await
        {
            Ok(raw_result) => McpToolResult::success(serde_json::json!({
                "address": address,
                "account_id_hex": hex::encode(parsed.account_id),
                "asset": {
                    "type": "psp22",
                    "contract_address": asset_id,
                    "interface": "PSP22",
                },
                "balance": {
                    "decoded": false,
                    "raw_result": raw_result,
                    "note": "Returned exactly as provided by Lunes RPC; token-specific decoding remains explicit future work."
                },
                "lookup": "live_lunes_contract_read",
            })),
            Err(error) => {
                McpToolResult::error(-32021, format!("Asset balance read failed: {error}"))
            }
        };
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
            "can_broadcast_to_lunes_network": can_broadcast_to_lunes_network(kms),
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

async fn handle_get_validator_profiles(args: &Value, lunes_client: &LunesClient) -> McpToolResult {
    let validators = match validator_addresses_from_args(args, lunes_client).await {
        Ok(validators) => validators,
        Err(error) => return error,
    };
    let parsed_validators = match parse_validator_addresses(&validators) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };

    match lunes_client.validator_profiles(&parsed_validators).await {
        Ok(profiles) => {
            let eligible_count = profiles
                .iter()
                .filter(|profile| profile.eligible_for_nomination)
                .count();
            let blocked_count = profiles.iter().filter(|profile| profile.blocked).count();
            let inactive_count = profiles
                .iter()
                .filter(|profile| !profile.active_session_validator)
                .count();

            McpToolResult::success(serde_json::json!({
                "lookup": "live_lunes_rpc_validator_profile_storage",
                "requested": validators.len(),
                "returned": profiles.len(),
                "summary": {
                    "eligible_for_nomination": eligible_count,
                    "blocked": blocked_count,
                    "inactive_or_unknown": inactive_count,
                },
                "profiles": profiles,
                "risk_notes": [
                    "Eligibility is a safety hint, not financial advice.",
                    "Agents should only nominate validators allowed by the configured whitelist.",
                    "Performance scoring and reward history remain future live reads."
                ],
            }))
        }
        Err(error) => McpToolResult::error(-32020, error.to_string()),
    }
}

async fn handle_get_validator_scores(args: &Value, lunes_client: &LunesClient) -> McpToolResult {
    let validators = match validator_addresses_from_args(args, lunes_client).await {
        Ok(validators) => validators,
        Err(error) => return error,
    };
    let parsed_validators = match parse_validator_addresses(&validators) {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };

    match lunes_client.validator_profiles(&parsed_validators).await {
        Ok(profiles) => {
            let scores = profiles
                .iter()
                .map(validator_score_json)
                .collect::<Vec<_>>();
            McpToolResult::success(serde_json::json!({
                "lookup": "live_lunes_rpc_validator_profile_storage",
                "requested": validators.len(),
                "returned": scores.len(),
                "score_model": {
                    "name": "observable_validator_safety_score_v1",
                    "max_score": 100,
                    "confidence": "partial",
                    "inputs": [
                        "active_session_validator",
                        "commission_perbill",
                        "blocked",
                        "eligible_for_nomination",
                        "nomination_warnings"
                    ],
                    "not_decoded": [
                        "validator_exposure",
                        "reward_payout_history",
                        "era_points",
                        "slashing_history"
                    ]
                },
                "scores": scores,
                "risk_notes": [
                    "Score is a bounded safety heuristic, not financial advice.",
                    "Exposure and performance history are not decoded by this MCP yet.",
                    "Agents must still use configured validator whitelists for nomination writes."
                ],
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
                    "reward payout history",
                    "validator exposure",
                    "validator performance scoring"
                ],
            }))
        }
        Err(error) => McpToolResult::error(-32020, error.to_string()),
    }
}

async fn handle_get_staking_account(
    args: &Value,
    kms: &AgentKms,
    lunes_client: &LunesClient,
) -> McpToolResult {
    let address = args.get("address").and_then(|v| v.as_str()).unwrap_or("");
    let parsed = match parse_lunes_address(address, "address") {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };

    match lunes_client
        .staking_account(address, parsed.account_id)
        .await
    {
        Ok(staking_account) => {
            let ledger = staking_account.ledger.as_ref().map(|ledger| {
                let unlocking = ledger
                    .unlocking
                    .iter()
                    .map(|chunk| {
                        serde_json::json!({
                            "value_base_units": chunk.value_base_units.to_string(),
                            "value_lunes": format_lunes_amount(chunk.value_base_units),
                            "era": chunk.era,
                        })
                    })
                    .collect::<Vec<_>>();

                serde_json::json!({
                    "stash_address": ledger.stash_address.clone(),
                    "total_base_units": ledger.total_base_units.to_string(),
                    "active_base_units": ledger.active_base_units.to_string(),
                    "unlocking_or_inactive_base_units": ledger.unlocking_or_inactive_base_units.to_string(),
                    "total_lunes": format_lunes_amount(ledger.total_base_units),
                    "active_lunes": format_lunes_amount(ledger.active_base_units),
                    "unlocking_or_inactive_lunes": format_lunes_amount(ledger.unlocking_or_inactive_base_units),
                    "unlocking": unlocking,
                    "claimed_rewards": ledger.claimed_rewards.clone(),
                    "raw_extra_bytes": ledger.raw_extra_bytes,
                })
            });
            let nominations = staking_account.nominations.as_ref().map(|nominations| {
                serde_json::json!({
                    "targets": nominations.targets.clone(),
                    "target_count": nominations.targets.len(),
                    "submitted_in": nominations.submitted_in,
                    "suppressed": nominations.suppressed,
                })
            });
            let validator_prefs = staking_account.validator_prefs.as_ref().map(|prefs| {
                serde_json::json!({
                    "commission_perbill": prefs.commission_perbill,
                    "commission_percent": prefs.commission_percent.clone(),
                    "blocked": prefs.blocked,
                })
            });

            McpToolResult::success(serde_json::json!({
                "address": staking_account.address,
                "stash_address": staking_account.stash_address,
                "controller_address": staking_account.controller_address,
                "bonded": staking_account.bonded,
                "roles": staking_account.roles,
                "ledger": ledger,
                "reward_destination": staking_account.reward_destination,
                "nominations": nominations,
                "validator_prefs": validator_prefs,
                "agent_policy": agent_policy_json(kms),
                "agent_actions": {
                    "can_prepare_staking_actions": can_prepare_writes(kms) && can_manage_staking(kms),
                    "can_sign_local_intents": kms.is_autonomous() && kms.is_active(),
                    "can_broadcast_to_lunes_network": can_broadcast_to_lunes_network(kms),
                    "available_staking_tools": staking_tools_allowed(kms),
                },
                "lookup": staking_account.lookup,
            }))
        }
        Err(error) => McpToolResult::error(-32020, error.to_string()),
    }
}

async fn handle_get_governance_overview(
    args: &Value,
    kms: &AgentKms,
    lunes_client: &LunesClient,
) -> McpToolResult {
    let limit = match governance_limit_arg(args, "limit") {
        Ok(limit) => limit,
        Err(error) => return error,
    };

    match lunes_client.governance_referenda(limit).await {
        Ok(referenda) => McpToolResult::success(serde_json::json!({
            "lookup": referenda.source,
            "network": "Lunes",
            "governance_storage": {
                "pallet": referenda.pallet,
                "storage_item": referenda.storage_item,
                "returned": referenda.returned,
                "limit": referenda.limit,
                "decoded": false,
            },
            "agent_policy": governance_policy_json(kms),
            "agent_actions": {
                "can_prepare_governance_actions": can_prepare_governance_actions(kms),
                "can_sign_governance_transactions": false,
                "can_broadcast_governance_transactions": false,
            },
            "write_status": "prepare_only",
            "risk_notes": [
                "Governance tools never sign or broadcast final votes.",
                "Raw referendum storage is exposed for transparency; full decoded governance metadata requires runtime-specific decoding.",
                "Any final vote must be reviewed and signed in an external human-controlled wallet."
            ],
        })),
        Err(error) => McpToolResult::error(-32020, error.to_string()),
    }
}

async fn handle_get_referenda(args: &Value, lunes_client: &LunesClient) -> McpToolResult {
    let limit = match governance_limit_arg(args, "limit") {
        Ok(limit) => limit,
        Err(error) => return error,
    };

    match lunes_client.governance_referenda(limit).await {
        Ok(referenda) => McpToolResult::success(serde_json::json!({
            "source": referenda.source,
            "pallet": referenda.pallet,
            "storage_item": referenda.storage_item,
            "returned": referenda.returned,
            "limit": referenda.limit,
            "decoded": false,
            "referenda": referenda.referenda,
            "note": "Referendum storage is returned raw. Decoding remains explicit future work."
        })),
        Err(error) => McpToolResult::error(-32020, error.to_string()),
    }
}

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
            "events": status.events,
            "events_lookup_error": status.events_lookup_error,
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

async fn handle_get_recent_blocks(args: &Value, lunes_client: &LunesClient) -> McpToolResult {
    let lookback_blocks = args
        .get("lookback_blocks")
        .and_then(|value| value.as_u64())
        .unwrap_or(DEFAULT_ARCHIVE_TX_LOOKBACK_BLOCKS);

    if lookback_blocks > MAX_ARCHIVE_TX_LOOKBACK_BLOCKS {
        return McpToolResult::error(
            -32001,
            format!(
                "lookback_blocks must be <= {}",
                MAX_ARCHIVE_TX_LOOKBACK_BLOCKS
            ),
        );
    }

    match lunes_client.recent_blocks(lookback_blocks).await {
        Ok(recent_blocks) => {
            let returned = recent_blocks.blocks.len();
            McpToolResult::success(serde_json::json!({
                "source": recent_blocks.source,
                "finalized_head": recent_blocks.finalized_head,
                "lookback_blocks": recent_blocks.lookback_blocks,
                "returned": returned,
                "blocks": recent_blocks.blocks,
                "note": "Summaries only; raw extrinsics are not returned."
            }))
        }
        Err(error) => McpToolResult::error(-32020, error.to_string()),
    }
}

async fn handle_get_block_events(args: &Value, lunes_client: &LunesClient) -> McpToolResult {
    let block_hash = args
        .get("block_hash")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty());
    let block_number = args.get("block_number").and_then(|value| value.as_u64());

    if block_hash.is_some() && block_number.is_some() {
        return McpToolResult::error(
            -32001,
            "Provide either block_hash or block_number, not both.".into(),
        );
    }

    match lunes_client.block_events(block_hash, block_number).await {
        Ok(block_events) => McpToolResult::success(serde_json::json!({
            "source": block_events.source,
            "block_hash": block_events.block_hash,
            "block_number": block_events.block_number,
            "events": block_events.events,
            "decoded": false,
            "note": "Event storage is returned raw. Decoding remains explicit future work."
        })),
        Err(LunesClientError::InvalidTransactionHash(message)) => {
            McpToolResult::error(-32001, message)
        }
        Err(error) => McpToolResult::error(-32020, error.to_string()),
    }
}

async fn handle_submit_signed_extrinsic(
    args: &Value,
    kms: &AgentKms,
    lunes_client: &LunesClient,
) -> McpToolResult {
    let signed_extrinsic = args
        .get("signed_extrinsic")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let confirm_broadcast = args
        .get("confirm_broadcast")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let wait_blocks = args
        .get("wait_blocks")
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_SUBMISSION_WAIT_BLOCKS);

    if signed_extrinsic.is_empty() {
        return McpToolResult::error(-32001, "Missing required field: signed_extrinsic".into());
    }
    if !confirm_broadcast {
        return McpToolResult::error(
            -32011,
            "confirm_broadcast must be true before broadcasting a signed Lunes extrinsic".into(),
        );
    }
    if !broadcast_enabled() {
        return McpToolResult::error(
            -32011,
            format!("{BROADCAST_OPT_IN_ENV}=1 is required before broadcasting to Lunes Network"),
        );
    }
    if wait_blocks > MAX_SUBMISSION_WAIT_BLOCKS {
        return McpToolResult::error(
            -32001,
            format!("wait_blocks must be <= {MAX_SUBMISSION_WAIT_BLOCKS}"),
        );
    }
    let signed_extrinsic_hash = match validate_broadcast_preapproval(args, signed_extrinsic) {
        Ok(hash) => hash,
        Err(error) => return error,
    };
    if let Err(error) =
        kms.preflight_write(BROADCAST_POLICY_EXTRINSIC, BROADCAST_POLICY_DESTINATION, 0)
    {
        return McpToolResult::error(
            error.error_code(),
            format!(
                "Broadcast policy denied: {}. Allow '{}' and whitelist '{}' to relay externally signed Lunes extrinsics.",
                error, BROADCAST_POLICY_EXTRINSIC, BROADCAST_POLICY_DESTINATION
            ),
        );
    }

    match lunes_client
        .submit_signed_extrinsic(signed_extrinsic, wait_blocks)
        .await
    {
        Ok(submission) => McpToolResult::success(serde_json::json!({
            "tx_hash": submission.tx_hash,
            "status": submission.status,
            "block_hash": submission.block_hash,
            "block_number": submission.block_number,
            "extrinsic_index": submission.extrinsic_index,
            "events": submission.events,
            "events_lookup_error": submission.events_lookup_error,
            "archive_lookup_error": submission.archive_lookup_error,
            "endpoint": submission.endpoint,
            "wait_blocks": submission.wait_blocks,
            "broadcasted": submission.broadcasted,
            "final_error": submission.final_error,
            "signed_extrinsic_hash": signed_extrinsic_hash,
            "note": "This tool only broadcasts an already-signed extrinsic. It does not construct or sign final Lunes Network transactions."
        })),
        Err(LunesClientError::InvalidSignedExtrinsic(message)) => {
            McpToolResult::error(-32001, message)
        }
        Err(LunesClientError::InvalidTransactionHash(message)) => {
            McpToolResult::error(-32020, message)
        }
        Err(error) => McpToolResult::error(-32020, error.to_string()),
    }
}

async fn handle_search_account_activity(args: &Value, lunes_client: &LunesClient) -> McpToolResult {
    let address = args.get("address").and_then(|v| v.as_str()).unwrap_or("");
    let lookback_blocks = args
        .get("lookback_blocks")
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_ARCHIVE_TX_LOOKBACK_BLOCKS);

    if lookback_blocks > MAX_ARCHIVE_TX_LOOKBACK_BLOCKS {
        return McpToolResult::error(
            -32001,
            format!(
                "lookback_blocks must be <= {}",
                MAX_ARCHIVE_TX_LOOKBACK_BLOCKS
            ),
        );
    }

    let parsed = match parse_lunes_address(address, "address") {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };

    match lunes_client
        .fetch_account_activity(parsed.account_id, lookback_blocks)
        .await
    {
        Ok(activity) => McpToolResult::success(activity),
        Err(e) => McpToolResult::error(-32020, format!("Failed to search account activity: {}", e)),
    }
}

fn broadcast_enabled() -> bool {
    std::env::var(BROADCAST_OPT_IN_ENV)
        .map(|value| value == "1")
        .unwrap_or(false)
}

fn internal_signing_enabled() -> bool {
    std::env::var(INTERNAL_SIGNING_OPT_IN_ENV)
        .map(|value| value == "1")
        .unwrap_or(false)
}

fn validate_broadcast_preapproval(
    args: &Value,
    signed_extrinsic: &str,
) -> Result<String, McpToolResult> {
    let signed_extrinsic_hash = signed_extrinsic_payload_hash(signed_extrinsic)
        .map_err(|error| McpToolResult::error(-32001, error.to_string()))?;

    if let Some(expected_tx_hash) = args
        .get("expected_tx_hash")
        .and_then(|value| value.as_str())
        .filter(|hash| !hash.is_empty())
    {
        if !expected_tx_hash.eq_ignore_ascii_case(&signed_extrinsic_hash) {
            return Err(McpToolResult::error(
                -32011,
                format!(
                    "expected_tx_hash does not match signed extrinsic hash {signed_extrinsic_hash}"
                ),
            ));
        }
    }

    if !allowed_broadcast_hashes()
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&signed_extrinsic_hash))
    {
        return Err(McpToolResult::error(
            -32011,
            format!(
                "signed extrinsic hash {signed_extrinsic_hash} must be pre-approved in {BROADCAST_HASH_ALLOWLIST_ENV}"
            ),
        ));
    }

    Ok(signed_extrinsic_hash)
}

fn allowed_broadcast_hashes() -> Vec<String> {
    std::env::var(BROADCAST_HASH_ALLOWLIST_ENV)
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|hash| !hash.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn can_broadcast_to_lunes_network(kms: &AgentKms) -> bool {
    broadcast_enabled()
        && !allowed_broadcast_hashes().is_empty()
        && kms
            .preflight_write(BROADCAST_POLICY_EXTRINSIC, BROADCAST_POLICY_DESTINATION, 0)
            .is_ok()
}

fn handle_search_contract(args: &Value, kms: &AgentKms) -> McpToolResult {
    let contract_address = args
        .get("contract_address")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if let Err(e) = validate_address(contract_address, "contract_address") {
        return e;
    }

    let registry = AbiRegistry::new();
    let allowed_messages = kms
        .permissions()
        .allowlist_contracts
        .get(contract_address)
        .cloned()
        .unwrap_or_default();
    let asset_policy = kms.permissions().asset_policies.get(contract_address);
    McpToolResult::success(serde_json::json!({
        "contract_address": contract_address,
        "metadata_source": "local_lunes_contract_interface_registry",
        "known_interfaces": ["PSP22"],
        "known_messages": registry.known_messages(),
        "policy": {
            "contract_allowlisted": !allowed_messages.is_empty(),
            "allowed_messages": allowed_messages,
            "autonomous_generic_call_signing": false,
        },
        "psp22_asset_metadata": psp22_asset_metadata_json(asset_policy),
        "psp22_transfer_policy": psp22_transfer_policy_json(asset_policy),
        "note": "Live contract metadata lookup is planned; this response exposes the local interface registry and configured policy used by agent guardrails."
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

fn parse_lunes_address(address: &str, field_name: &str) -> Result<LunesAddress, McpToolResult> {
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
        "asset_id": "native",
        "symbol": "LUNES",
        "decimals": LUNES_DECIMALS,
    })
}

fn psp22_asset_metadata_json(policy: Option<&AssetPolicyConfig>) -> Value {
    serde_json::json!({
        "name": policy.and_then(|policy| policy.name.as_deref()),
        "symbol": policy.and_then(|policy| policy.symbol.as_deref()),
        "decimals": policy.and_then(|policy| policy.decimals),
        "source": if policy.is_some() { "local_agent_policy" } else { "not_configured" },
        "live_decoded": false,
    })
}

fn psp22_transfer_policy_json(policy: Option<&AssetPolicyConfig>) -> Value {
    let allowed_recipients = policy
        .map(|policy| policy.allowed_recipients.clone())
        .unwrap_or_default();
    let allowed_recipients_count = allowed_recipients.len();
    serde_json::json!({
        "has_asset_specific_limit": policy
            .and_then(|policy| policy.max_transfer_base_units.as_deref())
            .is_some(),
        "max_transfer_base_units": policy.and_then(|policy| policy.max_transfer_base_units.as_deref()),
        "allowed_recipients": allowed_recipients,
        "allowed_recipients_count": allowed_recipients_count,
    })
}

fn configured_asset_policies_json(kms: &AgentKms) -> Vec<Value> {
    let mut policies: Vec<_> = kms
        .permissions()
        .asset_policies
        .iter()
        .map(|(contract_address, policy)| {
            serde_json::json!({
                "contract_address": contract_address,
                "metadata": psp22_asset_metadata_json(Some(policy)),
                "transfer_policy": psp22_transfer_policy_json(Some(policy)),
            })
        })
        .collect();
    policies.sort_by(|left, right| {
        left["contract_address"]
            .as_str()
            .cmp(&right["contract_address"].as_str())
    });
    policies
}

fn is_native_asset_id(asset_id: &str) -> bool {
    asset_id.eq_ignore_ascii_case("native") || asset_id.eq_ignore_ascii_case("lunes")
}

fn is_psp22_balance_method(method: &str) -> bool {
    method == "PSP22::balance_of" || method == "balance_of"
}

fn is_psp22_asset_method(method: &str) -> bool {
    is_psp22_balance_method(method) || is_psp22_transfer_method(method)
}

fn validate_psp22_balance_read(kms: &AgentKms, contract_address: &str) -> Result<(), KmsError> {
    kms.validate_contract_call(contract_address, "PSP22::balance_of")
        .or_else(|_| kms.validate_contract_call(contract_address, "balance_of"))
}

fn validate_psp22_transfer(kms: &AgentKms, contract_address: &str) -> Result<(), KmsError> {
    kms.validate_contract_call(contract_address, "PSP22::transfer")
        .or_else(|_| kms.validate_contract_call(contract_address, "transfer"))
}

fn is_psp22_transfer_method(method: &str) -> bool {
    method == "PSP22::transfer" || method == "transfer"
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

fn can_prepare_governance_actions(kms: &AgentKms) -> bool {
    can_prepare_governance_votes(kms) || can_prepare_governance_delegations(kms)
}

fn can_prepare_governance_votes(kms: &AgentKms) -> bool {
    let policy = &kms.permissions().governance;
    policy.allow_prepare_votes
        && !policy.allowed_referenda.is_empty()
        && !policy.allowed_vote_directions.is_empty()
        && !policy.allowed_convictions.is_empty()
        && policy.max_vote_lunes > 0
}

fn can_prepare_governance_delegations(kms: &AgentKms) -> bool {
    let policy = &kms.permissions().governance;
    policy.allow_prepare_delegations
        && !policy.allowed_delegation_tracks.is_empty()
        && !policy.allowed_delegates.is_empty()
        && !policy.allowed_convictions.is_empty()
        && policy.max_delegation_lunes > 0
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
        "can_broadcast_to_lunes_network": can_broadcast_to_lunes_network(kms),
        "allowed_extrinsics": permissions.allowed_extrinsics,
        "whitelisted_addresses": permissions.whitelisted_addresses,
        "daily_limit_lunes": permissions.daily_limit_lunes,
        "spent_today_lunes": kms.spent_today(),
        "remaining_today_lunes": permissions.daily_limit_lunes.saturating_sub(kms.spent_today()),
        "ttl_hours": permissions.ttl_hours,
        "asset_policies": configured_asset_policies_json(kms),
        "governance": governance_policy_json(kms),
    })
}

fn governance_policy_json(kms: &AgentKms) -> Value {
    let policy = &kms.permissions().governance;
    serde_json::json!({
        "allow_prepare_votes": policy.allow_prepare_votes,
        "allow_prepare_delegations": policy.allow_prepare_delegations,
        "allowed_referenda": policy.allowed_referenda,
        "allowed_delegation_tracks": policy.allowed_delegation_tracks,
        "allowed_delegates": policy.allowed_delegates,
        "allowed_vote_directions": policy.allowed_vote_directions,
        "allowed_convictions": policy.allowed_convictions,
        "max_vote_lunes": policy.max_vote_lunes,
        "max_delegation_lunes": policy.max_delegation_lunes,
        "can_prepare_governance_votes": can_prepare_governance_votes(kms),
        "can_prepare_governance_delegations": can_prepare_governance_delegations(kms),
        "can_prepare_governance_actions": can_prepare_governance_actions(kms),
        "final_vote_signing": "external_wallet_only",
        "mcp_broadcast": false,
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

fn governance_limit_arg(args: &Value, field_name: &str) -> Result<usize, McpToolResult> {
    let limit = args
        .get(field_name)
        .and_then(|value| value.as_u64())
        .unwrap_or(DEFAULT_GOVERNANCE_REFERENDA_LIMIT as u64);

    if limit == 0 || limit > MAX_GOVERNANCE_REFERENDA_LIMIT as u64 {
        return Err(McpToolResult::error(
            -32001,
            format!("{field_name} must be between 1 and {MAX_GOVERNANCE_REFERENDA_LIMIT}"),
        ));
    }

    Ok(limit as usize)
}

async fn validator_addresses_from_args(
    args: &Value,
    lunes_client: &LunesClient,
) -> Result<Vec<String>, McpToolResult> {
    let limit = validator_limit_arg(args, "limit")?;
    match optional_string_array(args, "validators") {
        Ok(Some(validators)) => {
            if validators.is_empty() {
                return Err(McpToolResult::error(
                    -32001,
                    "validators must not be empty".into(),
                ));
            }
            if validators.len() > MAX_VALIDATOR_LIMIT {
                return Err(McpToolResult::error(
                    -32001,
                    format!("validators exceeds maximum of {MAX_VALIDATOR_LIMIT}"),
                ));
            }
            Ok(validators)
        }
        Ok(None) => lunes_client
            .validator_set()
            .await
            .map(|validator_set| validator_set.validators.into_iter().take(limit).collect())
            .map_err(|error| McpToolResult::error(-32020, error.to_string())),
        Err(error) => Err(error),
    }
}

fn parse_validator_addresses(
    validators: &[String],
) -> Result<Vec<(String, [u8; 32])>, McpToolResult> {
    let mut parsed_validators = Vec::with_capacity(validators.len());
    for validator in validators {
        let parsed = parse_lunes_address(validator, "validators")?;
        parsed_validators.push((validator.clone(), parsed.account_id));
    }
    Ok(parsed_validators)
}

fn validator_score_json(profile: &ValidatorProfile) -> Value {
    let commission_score = validator_commission_score(profile.commission_perbill);
    let activity_score = if profile.active_session_validator {
        30
    } else {
        0
    };
    let eligibility_score = if profile.eligible_for_nomination {
        25
    } else {
        0
    };
    let not_blocked_score = if profile.blocked { 0 } else { 10 };
    let score = commission_score + activity_score + eligibility_score + not_blocked_score;

    serde_json::json!({
        "address": profile.address,
        "score": score,
        "score_confidence": "partial",
        "components": {
            "commission_score": commission_score,
            "activity_score": activity_score,
            "eligibility_score": eligibility_score,
            "not_blocked_score": not_blocked_score,
            "exposure_score": null,
        },
        "observed": {
            "active_session_validator": profile.active_session_validator,
            "commission_perbill": profile.commission_perbill,
            "commission_percent": profile.commission_percent,
            "blocked": profile.blocked,
            "eligible_for_nomination": profile.eligible_for_nomination,
        },
        "exposure": {
            "decoded": false,
            "score": null,
            "reason": "validator exposure is not decoded by this MCP yet"
        },
        "risk_flags": profile.nomination_warnings,
    })
}

fn validator_commission_score(commission_perbill: Option<u32>) -> u64 {
    const MAX_SCORE: u64 = 35;
    const ZERO_SCORE_AT_PERBILL: u64 = 200_000_000;

    let Some(commission_perbill) = commission_perbill else {
        return 0;
    };
    let commission = u64::from(commission_perbill).min(ZERO_SCORE_AT_PERBILL);
    MAX_SCORE.saturating_sub((commission * MAX_SCORE) / ZERO_SCORE_AT_PERBILL)
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
            "Agent is in prepare-only mode. It can help prepare actions and relay pre-approved externally signed extrinsics when broadcast guardrails are enabled."
        },
        "mode": format!("{:?}", kms.mode()),
        "kms_active": kms.is_active(),
        "capabilities": {
            "can_read": true,
            "can_validate_lunes_addresses": true,
            "can_prepare_writes": can_prepare_writes,
            "can_manage_staking": can_manage_staking,
            "can_prepare_governance_actions": can_prepare_governance_actions(kms),
            "can_sign_local_intents": is_autonomous && kms.is_active(),
            "can_broadcast_to_lunes_network": can_broadcast_to_lunes_network(kms),
        },
        "policy": {
            "allowed_extrinsics": permissions.allowed_extrinsics,
            "whitelisted_addresses": permissions.whitelisted_addresses,
            "daily_limit_lunes": permissions.daily_limit_lunes,
            "spent_today_lunes": kms.spent_today(),
            "remaining_today_lunes": permissions.daily_limit_lunes.saturating_sub(kms.spent_today()),
            "ttl_hours": permissions.ttl_hours,
            "asset_policies": configured_asset_policies_json(kms),
            "governance": governance_policy_json(kms),
        },
        "guardrails": [
            "public HTTP bind requires API key and rate limit",
            "empty extrinsic allowlist blocks all write tools",
            "empty destination whitelist blocks all write destinations",
            "staking tools require the staking policy target plus validator or reward accounts in the whitelist",
            "contract calls require explicit contract and message allowlists",
            "PSP22 transfers require an asset policy with max_transfer_base_units and allowed_recipients",
            "governance tools are read/prepare-only and never sign or broadcast final votes",
            "broadcast to Lunes Network requires local opt-in, caller confirmation, and a pre-approved signed extrinsic hash"
        ],
        "signing_status": signing_status,
    }))
}

fn handle_transfer_native(args: &Value, kms: &AgentKms) -> McpToolResult {
    let to = args.get("to").and_then(|v| v.as_str()).unwrap_or("");
    let amount = match native_transfer_amount_from_args(args) {
        Ok(amount) => amount,
        Err(error) => return error,
    };

    if let Err(e) = validate_address(to, "to") {
        return e;
    }

    let payload = format!("balances.transfer({to},{})", amount.amount_base_units);

    execute_write_operation(
        kms,
        "balances.transfer",
        to,
        amount.amount_lunes,
        &payload,
        |sig, pk| {
            serde_json::json!({
                "action": "balances.transfer",
                "to": to,
                "amount_lunes": amount.amount_lunes,
                "amount_exact_lunes": amount.exact_lunes,
                "amount_base_units": amount.amount_base_units.to_string(),
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
            "amount_lunes": amount.amount_lunes,
            "amount_exact_lunes": amount.exact_lunes,
            "amount_base_units": amount.amount_base_units.to_string(),
            "unsigned_payload": payload,
            "broadcasted": false,
            "next_step": "Human must review and sign this transfer with an external wallet."
        }),
    )
}

async fn handle_transfer_native_with_chain(
    args: &Value,
    kms: &AgentKms,
    lunes_client: &LunesClient,
) -> McpToolResult {
    let to = args.get("to").and_then(|v| v.as_str()).unwrap_or("");
    let confirm_broadcast = args
        .get("confirm_broadcast")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);

    if !confirm_broadcast {
        return handle_transfer_native(args, kms);
    }

    let parsed_to = match parse_lunes_address(to, "to") {
        Ok(parsed) => parsed,
        Err(error) => return error,
    };
    let amount = match native_transfer_amount_from_args(args) {
        Ok(amount) => amount,
        Err(error) => return error,
    };
    let wait_blocks = args
        .get("wait_blocks")
        .and_then(|value| value.as_u64())
        .unwrap_or(DEFAULT_SUBMISSION_WAIT_BLOCKS);
    if wait_blocks > MAX_SUBMISSION_WAIT_BLOCKS {
        return McpToolResult::error(
            -32001,
            format!("wait_blocks must be <= {MAX_SUBMISSION_WAIT_BLOCKS}"),
        );
    }

    if let Err(error) = kms.preflight_write("balances.transfer", to, amount.amount_lunes) {
        return McpToolResult::error(error.error_code(), error.to_string());
    }
    if !kms.is_autonomous() {
        return McpToolResult::error(
            KmsError::NotAutonomous.error_code(),
            KmsError::NotAutonomous.to_string(),
        );
    }
    if !broadcast_enabled() {
        return McpToolResult::error(
            -32011,
            format!("{BROADCAST_OPT_IN_ENV}=1 is required before broadcasting to Lunes Network"),
        );
    }
    if !internal_signing_enabled() {
        return McpToolResult::error(
            -32011,
            format!(
                "{INTERNAL_SIGNING_OPT_IN_ENV}=1 is required before the MCP server signs final Lunes transactions"
            ),
        );
    }
    if !kms.persistent_audit_log_enabled() {
        return McpToolResult::error(
            -32011,
            format!(
                "{AUDIT_LOG_PATH_ENV} must point to a writable JSONL file before internally signed Lunes transactions can be broadcast"
            ),
        );
    }
    if let Err(error) =
        kms.preflight_write(BROADCAST_POLICY_EXTRINSIC, BROADCAST_POLICY_DESTINATION, 0)
    {
        return McpToolResult::error(
            error.error_code(),
            format!(
                "Broadcast policy denied: {}. Allow '{}' and whitelist '{}' before submitting internally signed Lunes transactions.",
                error, BROADCAST_POLICY_EXTRINSIC, BROADCAST_POLICY_DESTINATION
            ),
        );
    }
    let signer_account_id = match kms.public_key_bytes() {
        Some(account_id) => account_id,
        None => {
            return McpToolResult::error(
                KmsError::NotInitialized.error_code(),
                KmsError::NotInitialized.to_string(),
            )
        }
    };

    let keep_alive = args
        .get("keep_alive")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let call_name = if keep_alive {
        "transfer_keep_alive"
    } else {
        "transfer_allow_death"
    };

    match lunes_client
        .submit_native_transfer_with_ed25519(
            signer_account_id,
            parsed_to.account_id,
            amount.amount_base_units,
            call_name,
            wait_blocks,
            |payload| {
                let signed = kms
                    .sign_payload("balances.transfer", to, amount.amount_lunes, payload)
                    .map_err(|error| LunesClientError::TransactionSubmission(error.to_string()))?;
                ed25519_signature_from_hex(&signed.signature)
            },
        )
        .await
    {
        Ok(submission) => McpToolResult::success(serde_json::json!({
            "action": "balances.transfer",
            "chain_call": format!("Balances.{call_name}"),
            "to": to,
            "amount_lunes": amount.amount_lunes,
            "amount_exact_lunes": amount.exact_lunes,
            "amount_base_units": amount.amount_base_units.to_string(),
            "tx_hash": submission.tx_hash,
            "status": submission.status,
            "block_hash": submission.block_hash,
            "block_number": submission.block_number,
            "extrinsic_index": submission.extrinsic_index,
            "events": submission.events,
            "events_lookup_error": submission.events_lookup_error,
            "archive_lookup_error": submission.archive_lookup_error,
            "endpoint": submission.endpoint,
            "wait_blocks": submission.wait_blocks,
            "broadcasted": submission.broadcasted,
            "final_error": submission.final_error,
        })),
        Err(error) => McpToolResult::error(-32020, error.to_string()),
    }
}

#[derive(Debug, Clone)]
struct NativeTransferAmount {
    amount_lunes: u64,
    amount_base_units: u128,
    exact_lunes: String,
}

fn native_transfer_amount_from_args(args: &Value) -> Result<NativeTransferAmount, McpToolResult> {
    let amount_lunes = args.get("amount").and_then(|value| value.as_u64());
    let amount_base_units = optional_u128_arg(args, "amount_base_units")?;

    match (amount_lunes, amount_base_units) {
        (Some(0), _) => Err(McpToolResult::error(
            -32001,
            "Missing or zero required field: amount".into(),
        )),
        (Some(amount_lunes), maybe_base_units) => {
            let amount_base_units = (amount_lunes as u128)
                .checked_mul(LUNES_BASE_UNITS)
                .ok_or_else(|| McpToolResult::error(-32001, "amount is too large".into()))?;
            if let Some(provided_base_units) = maybe_base_units {
                if provided_base_units != amount_base_units {
                    return Err(McpToolResult::error(
                        -32001,
                        "amount_base_units must match amount when both are provided".into(),
                    ));
                }
            }
            Ok(NativeTransferAmount {
                amount_lunes,
                amount_base_units,
                exact_lunes: format_lunes_amount(amount_base_units),
            })
        }
        (None, Some(amount_base_units)) if amount_base_units > 0 => {
            let amount_lunes = amount_lunes_for_policy(amount_base_units)?;
            Ok(NativeTransferAmount {
                amount_lunes,
                amount_base_units,
                exact_lunes: format_lunes_amount(amount_base_units),
            })
        }
        _ => Err(McpToolResult::error(
            -32001,
            "Missing required field: amount or amount_base_units".into(),
        )),
    }
}

fn optional_u128_arg(args: &Value, field_name: &str) -> Result<Option<u128>, McpToolResult> {
    let Some(value) = args.get(field_name) else {
        return Ok(None);
    };
    if let Some(value) = value.as_u64() {
        return Ok(Some(value as u128));
    }
    if let Some(value) = value.as_str() {
        return value.parse::<u128>().map(Some).map_err(|_| {
            McpToolResult::error(-32001, format!("{field_name} must be a positive integer"))
        });
    }
    Err(McpToolResult::error(
        -32001,
        format!("{field_name} must be a positive integer"),
    ))
}

fn amount_lunes_for_policy(amount_base_units: u128) -> Result<u64, McpToolResult> {
    let rounded_up = amount_base_units
        .checked_add(LUNES_BASE_UNITS - 1)
        .ok_or_else(|| McpToolResult::error(-32001, "amount_base_units is too large".into()))?
        / LUNES_BASE_UNITS;
    u64::try_from(rounded_up).map_err(|_| {
        McpToolResult::error(
            -32001,
            "amount_base_units exceeds the supported policy amount".into(),
        )
    })
}

#[derive(Debug, Clone, Copy)]
struct Psp22TransferAmount {
    base_units: u128,
}

fn psp22_transfer_amount_from_args(args: &Value) -> Result<Psp22TransferAmount, McpToolResult> {
    let amount = args.get("amount").and_then(|value| value.as_u64());
    let amount_base_units = optional_u128_arg(args, "amount_base_units")?;

    match (amount, amount_base_units) {
        (Some(0), _) => Err(McpToolResult::error(
            -32001,
            "Missing or zero required field: amount".into(),
        )),
        (Some(amount), maybe_base_units) => {
            let amount = amount as u128;
            if let Some(provided_base_units) = maybe_base_units {
                if provided_base_units != amount {
                    return Err(McpToolResult::error(
                        -32001,
                        "amount_base_units must match amount when both are provided".into(),
                    ));
                }
            }
            Ok(Psp22TransferAmount { base_units: amount })
        }
        (None, Some(amount_base_units)) if amount_base_units > 0 => Ok(Psp22TransferAmount {
            base_units: amount_base_units,
        }),
        _ => Err(McpToolResult::error(
            -32001,
            "Missing required field: amount or amount_base_units".into(),
        )),
    }
}

fn validate_psp22_asset_transfer_policy<'a>(
    kms: &'a AgentKms,
    contract: &str,
    to: &str,
    amount: Psp22TransferAmount,
) -> Result<&'a AssetPolicyConfig, McpToolResult> {
    let policy = kms
        .permissions()
        .asset_policies
        .get(contract)
        .ok_or_else(|| {
            McpToolResult::error(
                -32011,
                format!(
                    "PSP22 contract '{contract}' requires an asset-specific transfer limit in agent.permissions.asset_policies"
                ),
            )
        })?;

    let max_transfer = policy
        .max_transfer_base_units
        .as_deref()
        .ok_or_else(|| {
            McpToolResult::error(
                -32011,
                format!(
                    "PSP22 contract '{contract}' requires max_transfer_base_units in its asset-specific transfer limit"
                ),
            )
        })?
        .parse::<u128>()
        .map_err(|_| {
            McpToolResult::error(
                -32001,
                format!(
                    "PSP22 contract '{contract}' has invalid max_transfer_base_units in asset policy"
                ),
            )
        })?;

    if max_transfer == 0 {
        return Err(McpToolResult::error(
            -32011,
            format!("PSP22 contract '{contract}' has a zero asset-specific transfer limit"),
        ));
    }

    if amount.base_units > max_transfer {
        return Err(McpToolResult::error(
            -32010,
            format!(
                "PSP22 transfer amount {} exceeds asset-specific transfer limit {} for contract '{}'",
                amount.base_units, max_transfer, contract
            ),
        ));
    }

    if policy.allowed_recipients.is_empty() {
        return Err(McpToolResult::error(
            -32011,
            format!("PSP22 contract '{contract}' requires allowed_recipients in asset policy"),
        ));
    }

    if !policy
        .allowed_recipients
        .iter()
        .any(|allowed_recipient| allowed_recipient == to)
    {
        return Err(McpToolResult::error(
            -32011,
            format!("Recipient '{to}' is not allowlisted for PSP22 contract '{contract}'"),
        ));
    }

    Ok(policy)
}

fn ed25519_signature_from_hex(signature: &str) -> Result<[u8; 64], LunesClientError> {
    let bytes = hex::decode(signature).map_err(|error| {
        LunesClientError::TransactionSubmission(format!("invalid KMS signature hex: {error}"))
    })?;
    bytes.as_slice().try_into().map_err(|_| {
        LunesClientError::TransactionSubmission(format!(
            "invalid KMS signature length: expected 64 bytes, got {}",
            bytes.len()
        ))
    })
}

fn handle_transfer_psp22(args: &Value, kms: &AgentKms) -> McpToolResult {
    let contract = args
        .get("contract_address")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let to = args.get("to").and_then(|v| v.as_str()).unwrap_or("");
    let amount = match psp22_transfer_amount_from_args(args) {
        Ok(amount) => amount,
        Err(error) => return error,
    };

    if let Err(e) = validate_address(contract, "contract_address") {
        return e;
    }
    if let Err(e) = validate_address(to, "to") {
        return e;
    }

    if let Err(error) = validate_psp22_transfer(kms, contract) {
        return McpToolResult::error(error.error_code(), error.to_string());
    }
    let asset_policy = match validate_psp22_asset_transfer_policy(kms, contract, to, amount) {
        Ok(policy) => policy,
        Err(error) => return error,
    };

    let payload = format!(
        "contracts.call({contract},PSP22::transfer,{to},{})",
        amount.base_units
    );
    let asset_metadata = psp22_asset_metadata_json(Some(asset_policy));
    let transfer_policy = psp22_transfer_policy_json(Some(asset_policy));

    execute_write_operation(
        kms,
        "contracts.call",
        contract,
        0,
        &payload,
        |sig, pk| {
            serde_json::json!({
                "action": "contracts.call (PSP22::transfer)",
                "contract": contract,
                "to": to,
                "amount_base_units": amount.base_units.to_string(),
                "asset_metadata": asset_metadata,
                "transfer_policy": transfer_policy,
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
            "amount_base_units": amount.base_units.to_string(),
            "asset_metadata": psp22_asset_metadata_json(Some(asset_policy)),
            "transfer_policy": psp22_transfer_policy_json(Some(asset_policy)),
            "unsigned_payload": payload,
            "broadcasted": false,
            "next_step": "Human must review and sign this PSP22 transfer with an external wallet."
        }),
    )
}

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
    if kms.is_autonomous() {
        let guidance = if is_psp22_transfer_method(message) {
            "use lunes_transfer_psp22 so asset-specific limits apply"
        } else {
            "use a specialized MCP tool with explicit policy checks"
        };
        return McpToolResult::error(
            -32011,
            format!("Autonomous generic contract calls are disabled; {guidance}."),
        );
    }
    if let Err(error) = kms.validate_contract_call(contract, message) {
        return McpToolResult::error(error.error_code(), error.to_string());
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

fn handle_stake_rebond(args: &Value, kms: &AgentKms) -> McpToolResult {
    let amount = args.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);
    if amount == 0 {
        return McpToolResult::error(-32001, "Missing or zero required field: amount".into());
    }

    let payload = format!("staking.rebond({amount})");
    execute_staking_operation(
        kms,
        "staking.rebond",
        amount,
        &payload,
        serde_json::json!({
            "action": "staking.rebond",
            "amount_lunes": amount,
        }),
    )
}

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

fn handle_stake_payout(args: &Value, kms: &AgentKms) -> McpToolResult {
    let validator_stash = args
        .get("validator_stash")
        .or_else(|| args.get("validator"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if let Err(error) = validate_address(validator_stash, "validator_stash") {
        return error;
    }
    if let Some(error) =
        validate_extra_whitelisted_destinations(kms, &[validator_stash.to_string()])
    {
        return error;
    }

    let era = match staking_era_arg(args) {
        Ok(era) => era,
        Err(error) => return error,
    };

    let payload = format!("staking.payout_stakers({validator_stash},{era})");
    execute_staking_operation(
        kms,
        "staking.payout_stakers",
        0,
        &payload,
        serde_json::json!({
            "action": "staking.payout_stakers",
            "validator_stash": validator_stash,
            "era": era,
        }),
    )
}

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

fn handle_prepare_governance_vote(args: &Value, kms: &AgentKms) -> McpToolResult {
    if let Some(error) = reject_governance_broadcast(args) {
        return error;
    }

    let referendum_index = match governance_referendum_index_arg(args) {
        Ok(index) => index,
        Err(error) => return error,
    };
    let vote = match governance_vote_arg(args) {
        Ok(vote) => vote,
        Err(error) => return error,
    };
    let conviction = match governance_conviction_arg(args) {
        Ok(conviction) => conviction,
        Err(error) => return error,
    };
    let amount = match native_transfer_amount_from_args(args) {
        Ok(amount) => amount,
        Err(error) => return error,
    };

    if let Some(error) = validate_governance_vote_policy(
        kms,
        referendum_index,
        vote,
        conviction,
        amount.amount_lunes,
    ) {
        return error;
    }

    let unsigned_payload = format!(
        "conviction_voting.vote({referendum_index},{vote},{conviction},{})",
        amount.amount_base_units
    );

    governance_pending_result(
        kms,
        serde_json::json!({
            "action": "conviction_voting.vote",
            "referendum_index": referendum_index,
            "vote": {
                "direction": vote,
                "conviction": conviction,
                "amount_lunes": amount.amount_lunes,
                "amount_exact_lunes": amount.exact_lunes,
                "amount_base_units": amount.amount_base_units.to_string(),
            },
            "unsigned_payload": unsigned_payload,
            "broadcasted": false,
            "submission_status": "not_broadcasted",
            "signing_status": "not_signed_by_mcp",
            "next_step": "Human must review and sign this governance vote with an external wallet.",
        }),
    )
}

fn handle_prepare_governance_remove_vote(args: &Value, kms: &AgentKms) -> McpToolResult {
    if let Some(error) = reject_governance_broadcast(args) {
        return error;
    }

    let referendum_index = match governance_referendum_index_arg(args) {
        Ok(index) => index,
        Err(error) => return error,
    };
    if let Some(error) = validate_governance_referendum_policy(kms, referendum_index) {
        return error;
    }

    governance_pending_result(
        kms,
        serde_json::json!({
            "action": "conviction_voting.remove_vote",
            "referendum_index": referendum_index,
            "unsigned_payload": format!("conviction_voting.remove_vote({referendum_index})"),
            "broadcasted": false,
            "submission_status": "not_broadcasted",
            "signing_status": "not_signed_by_mcp",
            "next_step": "Human must review and sign this governance remove-vote operation with an external wallet.",
        }),
    )
}

fn handle_prepare_governance_delegate(args: &Value, kms: &AgentKms) -> McpToolResult {
    if let Some(error) = reject_governance_broadcast(args) {
        return error;
    }

    let track = match governance_track_arg(args) {
        Ok(track) => track,
        Err(error) => return error,
    };
    let delegate = args
        .get("delegate")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    if let Err(error) = parse_lunes_address(delegate, "delegate") {
        return error;
    }
    let conviction = match governance_conviction_arg(args) {
        Ok(conviction) => conviction,
        Err(error) => return error,
    };
    let amount = match native_transfer_amount_from_args(args) {
        Ok(amount) => amount,
        Err(error) => return error,
    };

    if let Some(error) =
        validate_governance_delegation_policy(kms, track, delegate, conviction, amount.amount_lunes)
    {
        return error;
    }

    governance_pending_result(
        kms,
        serde_json::json!({
            "action": "conviction_voting.delegate",
            "track": track,
            "delegate": delegate,
            "delegation": {
                "conviction": conviction,
                "amount_lunes": amount.amount_lunes,
                "amount_exact_lunes": amount.exact_lunes,
                "amount_base_units": amount.amount_base_units.to_string(),
            },
            "unsigned_payload": format!(
                "conviction_voting.delegate({track},{delegate},{conviction},{})",
                amount.amount_base_units
            ),
            "broadcasted": false,
            "submission_status": "not_broadcasted",
            "signing_status": "not_signed_by_mcp",
            "next_step": "Human must review and sign this governance delegation with an external wallet.",
        }),
    )
}

fn handle_prepare_governance_undelegate(args: &Value, kms: &AgentKms) -> McpToolResult {
    if let Some(error) = reject_governance_broadcast(args) {
        return error;
    }

    let track = match governance_track_arg(args) {
        Ok(track) => track,
        Err(error) => return error,
    };
    if let Some(error) = validate_governance_delegation_track_policy(kms, track) {
        return error;
    }

    governance_pending_result(
        kms,
        serde_json::json!({
            "action": "conviction_voting.undelegate",
            "track": track,
            "unsigned_payload": format!("conviction_voting.undelegate({track})"),
            "broadcasted": false,
            "submission_status": "not_broadcasted",
            "signing_status": "not_signed_by_mcp",
            "next_step": "Human must review and sign this governance undelegation with an external wallet.",
        }),
    )
}

fn governance_pending_result(kms: &AgentKms, mut data: Value) -> McpToolResult {
    if kms.permissions().human_approval_required {
        if let Some(template) = &kms.permissions().approval_message_template {
            if let Some(object) = data.as_object_mut() {
                object.insert(
                    "human_approval_notice".to_string(),
                    Value::String(template.clone()),
                );
            }
        }
    }

    McpToolResult::pending(data)
}

fn reject_governance_broadcast(args: &Value) -> Option<McpToolResult> {
    args.get("confirm_broadcast")
        .and_then(|value| value.as_bool())
        .filter(|confirm| *confirm)
        .map(|_| {
            McpToolResult::error(
                -32011,
                "governance tools are prepare-only and never broadcast final votes".into(),
            )
        })
}

fn governance_referendum_index_arg(args: &Value) -> Result<u32, McpToolResult> {
    let Some(index) = args
        .get("referendum_index")
        .and_then(|value| value.as_u64())
    else {
        return Err(McpToolResult::error(
            -32001,
            "Missing required field: referendum_index".into(),
        ));
    };

    u32::try_from(index).map_err(|_| {
        McpToolResult::error(
            -32001,
            "referendum_index exceeds the supported range".into(),
        )
    })
}

fn governance_track_arg(args: &Value) -> Result<u16, McpToolResult> {
    let Some(track) = args.get("track").and_then(|value| value.as_u64()) else {
        return Err(McpToolResult::error(
            -32001,
            "Missing required field: track".into(),
        ));
    };

    u16::try_from(track)
        .map_err(|_| McpToolResult::error(-32001, "track exceeds the supported range".into()))
}

fn governance_vote_arg(args: &Value) -> Result<&'static str, McpToolResult> {
    match args.get("vote").and_then(|value| value.as_str()) {
        Some("aye") => Ok("aye"),
        Some("nay") => Ok("nay"),
        Some(_) => Err(McpToolResult::error(
            -32001,
            "vote must be either aye or nay".into(),
        )),
        None => Err(McpToolResult::error(
            -32001,
            "Missing required field: vote".into(),
        )),
    }
}

fn governance_conviction_arg(args: &Value) -> Result<&'static str, McpToolResult> {
    match args.get("conviction").and_then(|value| value.as_str()) {
        Some("none") => Ok("none"),
        Some("locked1x") => Ok("locked1x"),
        Some("locked2x") => Ok("locked2x"),
        Some("locked3x") => Ok("locked3x"),
        Some("locked4x") => Ok("locked4x"),
        Some("locked5x") => Ok("locked5x"),
        Some("locked6x") => Ok("locked6x"),
        Some(_) => Err(McpToolResult::error(
            -32001,
            "conviction must be none or locked1x through locked6x".into(),
        )),
        None => Err(McpToolResult::error(
            -32001,
            "Missing required field: conviction".into(),
        )),
    }
}

fn validate_governance_vote_policy(
    kms: &AgentKms,
    referendum_index: u32,
    vote: &str,
    conviction: &str,
    amount_lunes: u64,
) -> Option<McpToolResult> {
    if let Some(error) = validate_governance_referendum_policy(kms, referendum_index) {
        return Some(error);
    }
    let policy = &kms.permissions().governance;

    if policy.max_vote_lunes == 0 || amount_lunes > policy.max_vote_lunes {
        return Some(McpToolResult::error(
            -32011,
            format!(
                "Governance vote amount {amount_lunes} LUNES exceeds configured max_vote_lunes {}",
                policy.max_vote_lunes
            ),
        ));
    }

    if !policy
        .allowed_vote_directions
        .iter()
        .any(|allowed| allowed == vote)
    {
        return Some(McpToolResult::error(
            -32011,
            format!("Governance vote direction '{vote}' is not allowed by policy"),
        ));
    }

    if !policy
        .allowed_convictions
        .iter()
        .any(|allowed| allowed == conviction)
    {
        return Some(McpToolResult::error(
            -32011,
            format!("Governance conviction '{conviction}' is not allowed by policy"),
        ));
    }

    None
}

fn validate_governance_delegation_policy(
    kms: &AgentKms,
    track: u16,
    delegate: &str,
    conviction: &str,
    amount_lunes: u64,
) -> Option<McpToolResult> {
    if let Some(error) = validate_governance_delegation_track_policy(kms, track) {
        return Some(error);
    }
    let policy = &kms.permissions().governance;

    if !policy
        .allowed_delegates
        .iter()
        .any(|allowed| allowed == delegate)
    {
        return Some(McpToolResult::error(
            -32011,
            format!("Governance delegate '{delegate}' is not allowed by policy"),
        ));
    }

    if !policy
        .allowed_convictions
        .iter()
        .any(|allowed| allowed == conviction)
    {
        return Some(McpToolResult::error(
            -32011,
            format!("Governance conviction '{conviction}' is not allowed by policy"),
        ));
    }

    if policy.max_delegation_lunes == 0 || amount_lunes > policy.max_delegation_lunes {
        return Some(McpToolResult::error(
            -32011,
            format!(
                "Governance delegation amount {amount_lunes} LUNES exceeds configured max_delegation_lunes {}",
                policy.max_delegation_lunes
            ),
        ));
    }

    None
}

fn validate_governance_delegation_track_policy(
    kms: &AgentKms,
    track: u16,
) -> Option<McpToolResult> {
    let policy = &kms.permissions().governance;
    if !policy.allow_prepare_delegations {
        return Some(McpToolResult::error(
            -32011,
            "Governance delegation preparation is disabled by policy".into(),
        ));
    }

    if !policy.allowed_delegation_tracks.contains(&track) {
        return Some(McpToolResult::error(
            -32011,
            format!("Governance track {track} is not allowed by delegation policy"),
        ));
    }

    None
}

fn validate_governance_referendum_policy(
    kms: &AgentKms,
    referendum_index: u32,
) -> Option<McpToolResult> {
    let policy = &kms.permissions().governance;
    if !policy.allow_prepare_votes {
        return Some(McpToolResult::error(
            -32011,
            "Governance vote preparation is disabled by policy".into(),
        ));
    }

    if !policy.allowed_referenda.contains(&referendum_index) {
        return Some(McpToolResult::error(
            -32011,
            format!("Referendum {referendum_index} is not allowed by governance policy"),
        ));
    }

    None
}

fn reward_destination_from_args(
    args: &Value,
    default_to_staked: bool,
) -> Result<StakingRewardDestination, McpToolResult> {
    let destination_arg = args
        .get("reward_destination")
        .and_then(|v| v.as_str())
        .unwrap_or(if default_to_staked { "staked" } else { "" });

    if destination_arg.is_empty() {
        return Err(McpToolResult::error(
            -32001,
            "Missing required field: reward_destination".into(),
        ));
    }

    let destination =
        StakingRewardDestinationKind::from_tool_arg(destination_arg).ok_or_else(|| {
            McpToolResult::error(
                -32001,
                "reward_destination must be staked, stash, controller, or account".into(),
            )
        })?;

    let account = args
        .get("reward_account")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    if destination == StakingRewardDestinationKind::Account {
        let account = account.ok_or_else(|| {
            McpToolResult::error(
                -32001,
                "reward_account is required when reward_destination is account".into(),
            )
        })?;
        validate_address(&account, "reward_account")?;
        return Ok(StakingRewardDestination {
            destination,
            account: Some(account),
        });
    }

    Ok(StakingRewardDestination {
        destination,
        account: None,
    })
}

fn staking_era_arg(args: &Value) -> Result<u32, McpToolResult> {
    let Some(era) = args.get("era").and_then(|value| value.as_u64()) else {
        return Err(McpToolResult::error(
            -32001,
            "Missing required field: era".into(),
        ));
    };
    u32::try_from(era)
        .map_err(|_| McpToolResult::error(-32001, "era exceeds the supported range".into()))
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

fn optional_string_array(
    args: &Value,
    field_name: &str,
) -> Result<Option<Vec<String>>, McpToolResult> {
    if args.get(field_name).is_none() {
        return Ok(None);
    }

    string_array(args, field_name).map(Some)
}

fn validate_reward_account_whitelist(
    kms: &AgentKms,
    reward: &StakingRewardDestination,
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

fn handle_revoke_wallet(kms: &AgentKms) -> McpToolResult {
    kms.revoke_key();

    McpToolResult::success(serde_json::json!({
        "revoked": true,
        "kms_active": false
    }))
}

async fn handle_read_contract(args: &Value, kms: &AgentKms, client: &LunesClient) -> McpToolResult {
    let contract = args
        .get("contract_address")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let method = args.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let args_hex = args.get("args_hex").and_then(|v| v.as_str()).unwrap_or("");
    let origin = args
        .get("origin")
        .and_then(|v| v.as_str())
        .unwrap_or(contract);

    if let Err(error) = validate_address(contract, "contract_address") {
        return error;
    }
    if let Err(error) = validate_address(origin, "origin") {
        return error;
    }
    if method.is_empty() {
        return McpToolResult::error(-32001, "Missing required field: method".into());
    }

    if let Err(e) = kms.validate_contract_call(contract, method) {
        return McpToolResult::error(e.error_code(), e.to_string());
    }

    let registry = AbiRegistry::new();
    let selector = match registry.resolve_selector(method) {
        Some(s) => s,
        None => {
            return McpToolResult::error(
                -32001,
                format!("Method '{method}' selector is not in the local Lunes contract registry."),
            )
        }
    };

    let mut data = selector.to_vec();
    if !args_hex.is_empty() {
        let clean_hex = args_hex.trim_start_matches("0x");
        match hex::decode(clean_hex) {
            Ok(decoded) => data.extend_from_slice(&decoded),
            Err(e) => return McpToolResult::error(-32001, format!("Invalid args_hex: {}", e)),
        }
    }

    match client.fetch_contract_read(contract, origin, &data).await {
        Ok(result) => McpToolResult::success(serde_json::json!({
            "contract_address": contract,
            "method": method,
            "raw_result": result,
            "note": "Raw result is returned as provided by Lunes RPC. Decoding depends on the contract return type.",
        })),
        Err(e) => McpToolResult::error(-32021, format!("Contract read failed: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::encode_lunes_address_for_tests;
    use crate::config::{AgentMode, AssetPolicyConfig, GovernancePolicyConfig, PermissionsConfig};
    use crate::lunes_client::{
        BlockEvents, BlockEventsLookup, BlockSummary, ChainInfo, ChainProperties,
        GovernanceReferenda, GovernanceReferendum, NativeBalance, NetworkHealth, Nominations,
        RecentBlocks, RuntimeInfo, SignedExtrinsicSubmission, StakingAccount, StakingLedger,
        StakingRewardDestination, StakingRewardDestinationKind, StakingRole, TransactionState,
        TransactionStatus, UnlockChunk, ValidatorPrefs, ValidatorProfile, ValidatorSet,
    };

    static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn lunes_address(seed: u8) -> String {
        encode_lunes_address_for_tests([seed; 32])
    }

    fn permissions() -> PermissionsConfig {
        PermissionsConfig {
            allowed_extrinsics: vec!["balances.transfer".into(), "contracts.call".into()],
            whitelisted_addresses: vec![lunes_address(1)],
            daily_limit_lunes: 100,
            allowlist_contracts: Default::default(),
            asset_policies: Default::default(),
            governance: Default::default(),
            ttl_hours: 168,
            human_approval_required: true,
            approval_message_template: None,
        }
    }

    fn staking_permissions() -> PermissionsConfig {
        PermissionsConfig {
            allowed_extrinsics: vec![
                "staking.bond".into(),
                "staking.unbond".into(),
                "staking.rebond".into(),
                "staking.withdraw_unbonded".into(),
                "staking.nominate".into(),
                "staking.payout_stakers".into(),
                "staking.chill".into(),
                "staking.set_payee".into(),
            ],
            whitelisted_addresses: vec!["staking".into(), lunes_address(8), lunes_address(9)],
            daily_limit_lunes: 1_000,
            allowlist_contracts: Default::default(),
            asset_policies: Default::default(),
            governance: Default::default(),
            ttl_hours: 168,
            human_approval_required: true,
            approval_message_template: None,
        }
    }

    fn broadcast_permissions() -> PermissionsConfig {
        PermissionsConfig {
            allowed_extrinsics: vec![BROADCAST_POLICY_EXTRINSIC.into()],
            whitelisted_addresses: vec![BROADCAST_POLICY_DESTINATION.into()],
            daily_limit_lunes: 1,
            allowlist_contracts: Default::default(),
            asset_policies: Default::default(),
            governance: Default::default(),
            ttl_hours: 168,
            human_approval_required: true,
            approval_message_template: None,
        }
    }

    fn transfer_broadcast_permissions(to: &str) -> PermissionsConfig {
        PermissionsConfig {
            allowed_extrinsics: vec![
                "balances.transfer".into(),
                BROADCAST_POLICY_EXTRINSIC.into(),
            ],
            whitelisted_addresses: vec![to.into(), BROADCAST_POLICY_DESTINATION.into()],
            daily_limit_lunes: 100,
            allowlist_contracts: Default::default(),
            asset_policies: Default::default(),
            governance: Default::default(),
            ttl_hours: 168,
            human_approval_required: true,
            approval_message_template: None,
        }
    }

    fn governance_permissions() -> PermissionsConfig {
        PermissionsConfig {
            governance: GovernancePolicyConfig {
                allow_prepare_votes: true,
                allow_prepare_delegations: true,
                allowed_referenda: vec![12],
                allowed_delegation_tracks: vec![0],
                allowed_delegates: vec![lunes_address(6)],
                allowed_vote_directions: vec!["aye".into()],
                allowed_convictions: vec!["locked1x".into()],
                max_vote_lunes: 50,
                max_delegation_lunes: 25,
            },
            ..permissions()
        }
    }

    fn psp22_asset_policy(
        max_transfer_base_units: u128,
        recipients: Vec<String>,
    ) -> AssetPolicyConfig {
        AssetPolicyConfig {
            name: Some("Policy Token".into()),
            symbol: Some("POL".into()),
            decimals: Some(12),
            max_transfer_base_units: Some(max_transfer_base_units.to_string()),
            allowed_recipients: recipients,
        }
    }

    fn signed_submission() -> SignedExtrinsicSubmission {
        SignedExtrinsicSubmission {
            tx_hash: "0x1111111111111111111111111111111111111111111111111111111111111111".into(),
            status: TransactionState::Finalized,
            block_hash: Some(
                "0x2222222222222222222222222222222222222222222222222222222222222222".into(),
            ),
            block_number: Some(42),
            extrinsic_index: Some(0),
            events: Some(BlockEvents {
                block_hash: "0x2222222222222222222222222222222222222222222222222222222222222222"
                    .into(),
                raw_storage: "0x00".into(),
                decoded: false,
            }),
            events_lookup_error: None,
            archive_lookup_error: None,
            endpoint: "memory://lunes".into(),
            wait_blocks: 0,
            broadcasted: true,
            final_error: None,
        }
    }

    fn governance_referenda_fixture() -> GovernanceReferenda {
        GovernanceReferenda {
            source: "static_test".into(),
            pallet: "Referenda".into(),
            storage_item: "ReferendumInfoFor".into(),
            returned: 1,
            limit: 16,
            referenda: vec![GovernanceReferendum {
                referendum_index: Some(12),
                storage_key: "0x1234".into(),
                raw_storage: Some("0x010203".into()),
                decoded: false,
            }],
        }
    }

    fn recent_blocks_fixture() -> RecentBlocks {
        RecentBlocks {
            source: "static_test".into(),
            finalized_head: BlockSummary {
                hash: format!("0x{}", "aa".repeat(32)),
                number: 42,
                extrinsic_count: 3,
            },
            lookback_blocks: 1,
            blocks: vec![
                BlockSummary {
                    hash: format!("0x{}", "aa".repeat(32)),
                    number: 42,
                    extrinsic_count: 3,
                },
                BlockSummary {
                    hash: format!("0x{}", "bb".repeat(32)),
                    number: 41,
                    extrinsic_count: 1,
                },
            ],
        }
    }

    fn block_events_fixture() -> BlockEventsLookup {
        BlockEventsLookup {
            source: "static_test".into(),
            block_hash: format!("0x{}", "aa".repeat(32)),
            block_number: Some(42),
            events: Some(BlockEvents {
                block_hash: format!("0x{}", "aa".repeat(32)),
                raw_storage: "0x00".into(),
                decoded: false,
            }),
        }
    }

    fn response_json(response: &McpToolResult) -> serde_json::Value {
        serde_json::from_str(&response.content[0].text).expect("tool response text is JSON")
    }

    fn temp_audit_log_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "lunes-mcp-{label}-{}-{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
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
    async fn get_asset_balance_requires_psp22_allowlist() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        let client = LunesClient::static_native_balance(NativeBalance::zero());
        let address = lunes_address(1);
        let asset_id = lunes_address(2);
        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_get_asset_balance".into(),
                arguments: serde_json::json!({
                    "address": address,
                    "asset_id": asset_id,
                }),
            },
            &kms,
            &client,
        )
        .await;

        assert!(response.is_error);
        assert!(response.content[0].text.contains("-32011"));
        assert!(response.content[0].text.contains("allowlisted"));
    }

    #[test]
    fn get_assets_lists_policy_allowed_contracts() {
        let contract = lunes_address(2);
        let recipient = lunes_address(3);
        let mut allowlist_contracts = std::collections::HashMap::new();
        allowlist_contracts.insert(
            contract.clone(),
            vec!["PSP22::balance_of".into(), "PSP22::transfer".into()],
        );
        let mut asset_policies = std::collections::HashMap::new();
        asset_policies.insert(
            contract.clone(),
            psp22_asset_policy(1_000, vec![recipient.clone()]),
        );
        let kms = AgentKms::new(
            AgentMode::PrepareOnly,
            PermissionsConfig {
                allowlist_contracts,
                asset_policies,
                ..permissions()
            },
        );

        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_get_assets".into(),
                arguments: serde_json::json!({}),
            },
            &kms,
        );

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["assets"]["native"]["symbol"], "LUNES");
        assert_eq!(data["assets"]["contracts"][0]["contract_address"], contract);
        assert_eq!(data["assets"]["contracts"][0]["metadata"]["symbol"], "POL");
        assert_eq!(data["assets"]["contracts"][0]["metadata"]["decimals"], 12);
        assert_eq!(
            data["assets"]["contracts"][0]["read_methods_allowed"][0],
            "PSP22::balance_of"
        );
        assert_eq!(
            data["assets"]["contracts"][0]["transfer_methods_allowed"][0],
            "PSP22::transfer"
        );
        assert_eq!(
            data["assets"]["contracts"][0]["transfer_policy"]["max_transfer_base_units"],
            "1000"
        );
        assert_eq!(
            data["assets"]["contracts"][0]["transfer_policy"]["allowed_recipients"][0],
            recipient
        );
        assert_eq!(data["policy"]["asset_specific_transfer_limits"], true);
    }

    #[test]
    fn get_assets_lists_asset_policy_contracts_without_read_allowlist() {
        let contract = lunes_address(2);
        let recipient = lunes_address(3);
        let mut asset_policies = std::collections::HashMap::new();
        asset_policies.insert(contract.clone(), psp22_asset_policy(1_000, vec![recipient]));
        let kms = AgentKms::new(
            AgentMode::PrepareOnly,
            PermissionsConfig {
                asset_policies,
                ..permissions()
            },
        );

        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_get_assets".into(),
                arguments: serde_json::json!({}),
            },
            &kms,
        );

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["assets"]["contracts"][0]["contract_address"], contract);
        assert_eq!(data["assets"]["contracts"][0]["metadata"]["symbol"], "POL");
        assert_eq!(
            data["assets"]["contracts"][0]["read_methods_allowed"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
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
    async fn get_validator_profiles_reports_nomination_eligibility() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        let first = lunes_address(8);
        let second = lunes_address(9);
        let client = LunesClient::static_validator_profiles(vec![
            ValidatorProfile {
                address: first.clone(),
                active_session_validator: true,
                commission_perbill: Some(100_000_000),
                commission_percent: Some("10.0000".into()),
                blocked: false,
                eligible_for_nomination: true,
                nomination_warnings: vec![],
                lookup: "live_lunes_rpc_validator_profile_storage".into(),
            },
            ValidatorProfile {
                address: second.clone(),
                active_session_validator: true,
                commission_perbill: Some(250_000_000),
                commission_percent: Some("25.0000".into()),
                blocked: true,
                eligible_for_nomination: false,
                nomination_warnings: vec!["validator_blocks_new_nominations".into()],
                lookup: "live_lunes_rpc_validator_profile_storage".into(),
            },
        ]);

        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_get_validator_profiles".into(),
                arguments: serde_json::json!({ "validators": [first, second] }),
            },
            &kms,
            &client,
        )
        .await;

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["returned"], 2);
        assert_eq!(data["summary"]["eligible_for_nomination"], 1);
        assert_eq!(data["summary"]["blocked"], 1);
        assert_eq!(data["profiles"][0]["commission_percent"], "10.0000");
        assert_eq!(data["profiles"][1]["eligible_for_nomination"], false);
    }

    #[tokio::test]
    async fn get_validator_scores_returns_partial_observable_score() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        let first = lunes_address(8);
        let second = lunes_address(9);
        let client = LunesClient::static_validator_profiles(vec![
            ValidatorProfile {
                address: first.clone(),
                active_session_validator: true,
                commission_perbill: Some(10_000_000),
                commission_percent: Some("1.0000".into()),
                blocked: false,
                eligible_for_nomination: true,
                nomination_warnings: vec![],
                lookup: "live_lunes_rpc_validator_profile_storage".into(),
            },
            ValidatorProfile {
                address: second.clone(),
                active_session_validator: false,
                commission_perbill: Some(200_000_000),
                commission_percent: Some("20.0000".into()),
                blocked: true,
                eligible_for_nomination: false,
                nomination_warnings: vec!["not_in_active_validator_set".into()],
                lookup: "live_lunes_rpc_validator_profile_storage".into(),
            },
        ]);

        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_get_validator_scores".into(),
                arguments: serde_json::json!({ "validators": [first, second] }),
            },
            &kms,
            &client,
        )
        .await;

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["scores"][0]["address"], first);
        assert_eq!(data["scores"][0]["exposure"]["decoded"], false);
        assert_eq!(data["scores"][0]["score_confidence"], "partial");
        assert!(
            data["scores"][0]["score"].as_u64().unwrap()
                > data["scores"][1]["score"].as_u64().unwrap()
        );
        assert_eq!(
            data["scores"][1]["risk_flags"][0],
            "not_in_active_validator_set"
        );
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
    async fn get_staking_account_returns_live_staking_fields() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, staking_permissions());
        let stash = lunes_address(8);
        let controller = lunes_address(9);
        let target = lunes_address(10);
        let client = LunesClient::static_staking_account(StakingAccount {
            address: stash.clone(),
            stash_address: stash.clone(),
            controller_address: Some(controller.clone()),
            bonded: true,
            roles: vec![StakingRole::Bonded, StakingRole::Validator],
            ledger: Some(StakingLedger {
                stash_account_id: [8u8; 32],
                stash_address: stash.clone(),
                total_base_units: 5_000_000_000_000,
                active_base_units: 4_000_000_000_000,
                unlocking_or_inactive_base_units: 1_000_000_000_000,
                unlocking: vec![UnlockChunk {
                    value_base_units: 1_000_000_000_000,
                    era: 120,
                }],
                claimed_rewards: vec![100, 101],
                raw_extra_bytes: 0,
            }),
            reward_destination: Some(StakingRewardDestination {
                destination: StakingRewardDestinationKind::Staked,
                account: None,
            }),
            nominations: Some(Nominations {
                targets: vec![target],
                submitted_in: Some(77),
                suppressed: Some(false),
            }),
            validator_prefs: Some(ValidatorPrefs {
                commission_perbill: 390_625,
                commission_percent: "0.0391".into(),
                blocked: false,
            }),
            lookup: "live_lunes_rpc_staking_storage".into(),
        });

        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_get_staking_account".into(),
                arguments: serde_json::json!({ "address": stash }),
            },
            &kms,
            &client,
        )
        .await;

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["bonded"], true);
        assert_eq!(data["roles"][1], "validator");
        assert_eq!(data["ledger"]["total_lunes"], "50000");
        assert_eq!(data["ledger"]["unlocking"][0]["value_lunes"], "10000");
        assert_eq!(data["ledger"]["unlocking"][0]["era"], 120);
        assert_eq!(data["reward_destination"]["destination"], "staked");
        assert_eq!(data["nominations"]["target_count"], 1);
        assert_eq!(data["validator_prefs"]["commission_perbill"], 390_625);
        assert_eq!(data["agent_actions"]["can_prepare_staking_actions"], true);
    }

    #[tokio::test]
    async fn get_governance_overview_reports_prepare_only_policy() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, governance_permissions());
        let client = LunesClient::static_governance_referenda(governance_referenda_fixture());

        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_get_governance_overview".into(),
                arguments: serde_json::json!({}),
            },
            &kms,
            &client,
        )
        .await;

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["write_status"], "prepare_only");
        assert_eq!(data["governance_storage"]["returned"], 1);
        assert_eq!(
            data["agent_actions"]["can_prepare_governance_actions"],
            true
        );
        assert_eq!(
            data["agent_actions"]["can_broadcast_governance_transactions"],
            false
        );
    }

    #[tokio::test]
    async fn get_referenda_rejects_limit_above_cap() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        let client = LunesClient::static_governance_referenda(governance_referenda_fixture());

        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_get_referenda".into(),
                arguments: serde_json::json!({
                    "limit": MAX_GOVERNANCE_REFERENDA_LIMIT + 1,
                }),
            },
            &kms,
            &client,
        )
        .await;

        assert!(response.is_error);
        assert!(response.content[0].text.contains("limit"));
    }

    #[tokio::test]
    async fn get_referenda_returns_raw_governance_storage() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        let client = LunesClient::static_governance_referenda(governance_referenda_fixture());

        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_get_referenda".into(),
                arguments: serde_json::json!({ "limit": 16 }),
            },
            &kms,
            &client,
        )
        .await;

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["source"], "static_test");
        assert_eq!(data["referenda"][0]["referendum_index"], 12);
        assert_eq!(data["referenda"][0]["decoded"], false);
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
            events: Some(BlockEvents {
                block_hash: format!("0x{}", "22".repeat(32)),
                raw_storage: "0x00".into(),
                decoded: false,
            }),
            events_lookup_error: None,
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
        assert_eq!(data["events"]["raw_storage"], "0x00");
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
            events: None,
            events_lookup_error: None,
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
            events: None,
            events_lookup_error: None,
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

    #[tokio::test]
    async fn get_recent_blocks_returns_static_summaries() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        let client = LunesClient::static_recent_blocks(recent_blocks_fixture());

        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_get_recent_blocks".into(),
                arguments: serde_json::json!({ "lookback_blocks": 1 }),
            },
            &kms,
            &client,
        )
        .await;

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["source"], "static_test");
        assert_eq!(data["finalized_head"]["number"], 42);
        assert_eq!(data["returned"], 2);
        assert_eq!(data["blocks"][0]["extrinsic_count"], 3);
    }

    #[tokio::test]
    async fn get_recent_blocks_rejects_lookback_above_limit() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        let client = LunesClient::static_recent_blocks(recent_blocks_fixture());

        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_get_recent_blocks".into(),
                arguments: serde_json::json!({
                    "lookback_blocks": MAX_ARCHIVE_TX_LOOKBACK_BLOCKS + 1,
                }),
            },
            &kms,
            &client,
        )
        .await;

        assert!(response.is_error);
        assert!(response.content[0].text.contains("lookback_blocks"));
    }

    #[tokio::test]
    async fn get_block_events_returns_static_raw_events() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        let client = LunesClient::static_block_events(block_events_fixture());

        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_get_block_events".into(),
                arguments: serde_json::json!({
                    "block_hash": format!("0x{}", "aa".repeat(32)),
                }),
            },
            &kms,
            &client,
        )
        .await;

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["source"], "static_test");
        assert_eq!(data["block_number"], 42);
        assert_eq!(data["events"]["raw_storage"], "0x00");
        assert_eq!(data["events"]["decoded"], false);
    }

    #[tokio::test]
    async fn get_block_events_rejects_ambiguous_reference() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        let client = LunesClient::static_block_events(block_events_fixture());

        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_get_block_events".into(),
                arguments: serde_json::json!({
                    "block_hash": format!("0x{}", "aa".repeat(32)),
                    "block_number": 42,
                }),
            },
            &kms,
            &client,
        )
        .await;

        assert!(response.is_error);
        assert!(response.content[0]
            .text
            .contains("block_hash or block_number"));
    }

    #[tokio::test]
    async fn get_block_events_rejects_invalid_hash() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        let client = LunesClient::static_block_events(block_events_fixture());

        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_get_block_events".into(),
                arguments: serde_json::json!({ "block_hash": "0x1234" }),
            },
            &kms,
            &client,
        )
        .await;

        assert!(response.is_error);
        assert!(response.content[0].text.contains("expected 32 bytes"));
    }

    #[tokio::test]
    async fn submit_signed_extrinsic_requires_explicit_confirmation() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        let client = LunesClient::static_native_balance(NativeBalance::zero());

        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_submit_signed_extrinsic".into(),
                arguments: serde_json::json!({
                    "signed_extrinsic": "0x01020304",
                    "confirm_broadcast": false
                }),
            },
            &kms,
            &client,
        )
        .await;

        assert!(response.is_error);
        assert!(response.content[0].text.contains("confirm_broadcast"));
    }

    #[tokio::test]
    async fn submit_signed_extrinsic_requires_preapproved_hash() {
        let _guard = ENV_LOCK.lock().await;
        std::env::set_var(BROADCAST_OPT_IN_ENV, "1");
        std::env::remove_var(BROADCAST_HASH_ALLOWLIST_ENV);

        let hash = signed_extrinsic_payload_hash("0x01020304").unwrap();
        let response =
            validate_broadcast_preapproval(&serde_json::json!({}), "0x01020304").unwrap_err();

        std::env::remove_var(BROADCAST_OPT_IN_ENV);
        std::env::remove_var(BROADCAST_HASH_ALLOWLIST_ENV);

        assert!(response.is_error);
        assert!(response.content[0].text.contains(&hash));
        assert!(response.content[0]
            .text
            .contains(BROADCAST_HASH_ALLOWLIST_ENV));
    }

    #[tokio::test]
    async fn submit_signed_extrinsic_requires_agent_broadcast_policy() {
        let _guard = ENV_LOCK.lock().await;
        let hash = signed_extrinsic_payload_hash("0x01020304").unwrap();
        std::env::set_var(BROADCAST_OPT_IN_ENV, "1");
        std::env::set_var(BROADCAST_HASH_ALLOWLIST_ENV, hash.clone());
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        let client = LunesClient::static_submission(signed_submission());

        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_submit_signed_extrinsic".into(),
                arguments: serde_json::json!({
                    "signed_extrinsic": "0x01020304",
                    "expected_tx_hash": hash,
                    "confirm_broadcast": true,
                    "wait_blocks": 0
                }),
            },
            &kms,
            &client,
        )
        .await;

        std::env::remove_var(BROADCAST_OPT_IN_ENV);
        std::env::remove_var(BROADCAST_HASH_ALLOWLIST_ENV);

        assert!(response.is_error);
        assert!(response.content[0]
            .text
            .contains(BROADCAST_POLICY_EXTRINSIC));
    }

    #[tokio::test]
    async fn submit_signed_extrinsic_allows_preapproved_human_signed_payload() {
        let _guard = ENV_LOCK.lock().await;
        let hash = signed_extrinsic_payload_hash("0x01020304").unwrap();
        std::env::set_var(BROADCAST_OPT_IN_ENV, "1");
        std::env::set_var(BROADCAST_HASH_ALLOWLIST_ENV, hash.clone());
        let kms = AgentKms::new(AgentMode::PrepareOnly, broadcast_permissions());
        let client = LunesClient::static_submission(signed_submission());

        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_submit_signed_extrinsic".into(),
                arguments: serde_json::json!({
                    "signed_extrinsic": "0x01020304",
                    "expected_tx_hash": hash,
                    "confirm_broadcast": true,
                    "wait_blocks": 0
                }),
            },
            &kms,
            &client,
        )
        .await;

        std::env::remove_var(BROADCAST_OPT_IN_ENV);
        std::env::remove_var(BROADCAST_HASH_ALLOWLIST_ENV);

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(
            data["tx_hash"],
            "0x1111111111111111111111111111111111111111111111111111111111111111"
        );
        assert_eq!(data["signed_extrinsic_hash"], hash);
        assert_eq!(data["broadcasted"], true);
    }

    #[tokio::test]
    async fn search_account_activity_rejects_lookback_above_limit() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        let client = LunesClient::static_native_balance(NativeBalance::zero());

        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_search_account_activity".into(),
                arguments: serde_json::json!({
                    "address": lunes_address(1),
                    "lookback_blocks": MAX_ARCHIVE_TX_LOOKBACK_BLOCKS + 1,
                }),
            },
            &kms,
            &client,
        )
        .await;

        assert!(response.is_error);
        assert!(response.content[0].text.contains("lookback_blocks"));
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
    async fn read_contract_requires_message_allowlist() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        let client = LunesClient::static_native_balance(NativeBalance::zero());

        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_read_contract".into(),
                arguments: serde_json::json!({
                    "contract_address": lunes_address(1),
                    "method": "PSP22::balance_of"
                }),
            },
            &kms,
            &client,
        )
        .await;

        assert!(response.is_error);
        assert!(response.content[0].text.contains("allowlisted"));
    }

    #[test]
    fn search_contract_includes_local_policy_and_asset_metadata() {
        let contract = lunes_address(2);
        let recipient = lunes_address(3);
        let mut allowlist_contracts = std::collections::HashMap::new();
        allowlist_contracts.insert(
            contract.clone(),
            vec!["PSP22::balance_of".into(), "PSP22::transfer".into()],
        );
        let mut asset_policies = std::collections::HashMap::new();
        asset_policies.insert(contract.clone(), psp22_asset_policy(1_000, vec![recipient]));
        let kms = AgentKms::new(
            AgentMode::PrepareOnly,
            PermissionsConfig {
                allowlist_contracts,
                asset_policies,
                ..permissions()
            },
        );

        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_search_contract".into(),
                arguments: serde_json::json!({
                    "contract_address": contract,
                }),
            },
            &kms,
        );

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["policy"]["contract_allowlisted"], true);
        assert_eq!(data["policy"]["allowed_messages"][0], "PSP22::balance_of");
        assert_eq!(data["psp22_asset_metadata"]["symbol"], "POL");
        assert_eq!(
            data["psp22_transfer_policy"]["max_transfer_base_units"],
            "1000"
        );
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

    #[tokio::test]
    async fn native_transfer_with_chain_requires_internal_signing_opt_in_before_broadcast() {
        let _guard = ENV_LOCK.lock().await;
        std::env::set_var(BROADCAST_OPT_IN_ENV, "1");
        std::env::remove_var("LUNES_MCP_ENABLE_INTERNAL_SIGNING");
        std::env::remove_var(AUDIT_LOG_PATH_ENV);
        let to = lunes_address(1);
        let kms = AgentKms::new(AgentMode::Autonomous, transfer_broadcast_permissions(&to));
        kms.provision_key().unwrap();
        let client = LunesClient::static_submission(signed_submission());

        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_transfer_native".into(),
                arguments: serde_json::json!({
                    "to": to,
                    "amount": 10,
                    "confirm_broadcast": true,
                    "wait_blocks": 0
                }),
            },
            &kms,
            &client,
        )
        .await;

        std::env::remove_var(BROADCAST_OPT_IN_ENV);
        std::env::remove_var("LUNES_MCP_ENABLE_INTERNAL_SIGNING");
        std::env::remove_var(AUDIT_LOG_PATH_ENV);

        assert!(response.is_error);
        assert!(response.content[0]
            .text
            .contains("LUNES_MCP_ENABLE_INTERNAL_SIGNING"));
        assert_eq!(kms.spent_today(), 0);
    }

    #[tokio::test]
    async fn native_transfer_with_chain_requires_persistent_audit_before_broadcast() {
        let _guard = ENV_LOCK.lock().await;
        std::env::set_var(BROADCAST_OPT_IN_ENV, "1");
        std::env::set_var("LUNES_MCP_ENABLE_INTERNAL_SIGNING", "1");
        std::env::remove_var(AUDIT_LOG_PATH_ENV);
        let to = lunes_address(1);
        let kms = AgentKms::new(AgentMode::Autonomous, transfer_broadcast_permissions(&to));
        kms.provision_key().unwrap();
        let client = LunesClient::static_submission(signed_submission());

        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_transfer_native".into(),
                arguments: serde_json::json!({
                    "to": to,
                    "amount": 10,
                    "confirm_broadcast": true,
                    "wait_blocks": 0
                }),
            },
            &kms,
            &client,
        )
        .await;

        std::env::remove_var(BROADCAST_OPT_IN_ENV);
        std::env::remove_var("LUNES_MCP_ENABLE_INTERNAL_SIGNING");
        std::env::remove_var(AUDIT_LOG_PATH_ENV);

        assert!(response.is_error);
        assert!(response.content[0].text.contains(AUDIT_LOG_PATH_ENV));
        assert_eq!(kms.spent_today(), 0);
    }

    #[tokio::test]
    async fn native_transfer_with_chain_broadcasts_when_all_guards_pass() {
        let _guard = ENV_LOCK.lock().await;
        std::env::set_var(BROADCAST_OPT_IN_ENV, "1");
        std::env::set_var("LUNES_MCP_ENABLE_INTERNAL_SIGNING", "1");
        let audit_log_path = temp_audit_log_path("native-transfer");
        std::env::set_var(AUDIT_LOG_PATH_ENV, &audit_log_path);
        let to = lunes_address(1);
        let kms = AgentKms::new(AgentMode::Autonomous, transfer_broadcast_permissions(&to));
        kms.provision_key().unwrap();
        let client = LunesClient::static_submission(signed_submission());

        let response = dispatch_tool_call_with_chain(
            &ToolCallRequest {
                name: "lunes_transfer_native".into(),
                arguments: serde_json::json!({
                    "to": to,
                    "amount": 10,
                    "confirm_broadcast": true,
                    "wait_blocks": 0
                }),
            },
            &kms,
            &client,
        )
        .await;

        std::env::remove_var(BROADCAST_OPT_IN_ENV);
        std::env::remove_var("LUNES_MCP_ENABLE_INTERNAL_SIGNING");
        std::env::remove_var(AUDIT_LOG_PATH_ENV);

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["action"], "balances.transfer");
        assert_eq!(data["amount_lunes"], 10);
        assert_eq!(data["amount_base_units"], "1000000000");
        assert_eq!(data["broadcasted"], true);
        assert_eq!(data["status"], "finalized");
        assert_eq!(
            data["tx_hash"],
            "0x1111111111111111111111111111111111111111111111111111111111111111"
        );
        let audit_log = std::fs::read_to_string(&audit_log_path).unwrap();
        let _ = std::fs::remove_file(&audit_log_path);
        assert!(audit_log.contains("\"action\":\"SIGN\""));
        assert!(audit_log.contains("\"extrinsic\":\"balances.transfer\""));
        assert!(!audit_log.contains("lunes-mcp-static-native-transfer"));
    }

    #[test]
    fn prepare_governance_vote_returns_pending_without_signature() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, governance_permissions());

        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_prepare_governance_vote".into(),
                arguments: serde_json::json!({
                    "referendum_index": 12,
                    "vote": "aye",
                    "conviction": "locked1x",
                    "amount": 10
                }),
            },
            &kms,
        );

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["status"], "pending_human_approval");
        assert_eq!(data["data"]["action"], "conviction_voting.vote");
        assert_eq!(data["data"]["broadcasted"], false);
        assert_eq!(data["data"]["signing_status"], "not_signed_by_mcp");
        assert!(data["data"].get("signature").is_none());
        assert!(data["data"].get("tx_hash").is_none());
    }

    #[test]
    fn prepare_governance_vote_never_signs_in_autonomous_mode() {
        let kms = AgentKms::new(AgentMode::Autonomous, governance_permissions());
        kms.provision_key().unwrap();

        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_prepare_governance_vote".into(),
                arguments: serde_json::json!({
                    "referendum_index": 12,
                    "vote": "aye",
                    "conviction": "locked1x",
                    "amount": 10
                }),
            },
            &kms,
        );

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["data"]["signing_status"], "not_signed_by_mcp");
        assert!(data["data"].get("signature").is_none());
        assert_eq!(kms.spent_today(), 0);
    }

    #[test]
    fn prepare_governance_vote_rejects_broadcast_confirmation() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, governance_permissions());

        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_prepare_governance_vote".into(),
                arguments: serde_json::json!({
                    "referendum_index": 12,
                    "vote": "aye",
                    "conviction": "locked1x",
                    "amount": 10,
                    "confirm_broadcast": true
                }),
            },
            &kms,
        );

        assert!(response.is_error);
        assert!(response.content[0].text.contains("prepare-only"));
    }

    #[test]
    fn prepare_governance_vote_requires_explicit_policy() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());

        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_prepare_governance_vote".into(),
                arguments: serde_json::json!({
                    "referendum_index": 12,
                    "vote": "aye",
                    "conviction": "locked1x",
                    "amount": 10
                }),
            },
            &kms,
        );

        assert!(response.is_error);
        assert!(response.content[0]
            .text
            .contains("Governance vote preparation"));
    }

    #[test]
    fn prepare_governance_vote_enforces_referendum_direction_conviction_and_amount() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, governance_permissions());

        let blocked_referendum = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_prepare_governance_vote".into(),
                arguments: serde_json::json!({
                    "referendum_index": 13,
                    "vote": "aye",
                    "conviction": "locked1x",
                    "amount": 10
                }),
            },
            &kms,
        );
        assert!(blocked_referendum.is_error);
        assert!(blocked_referendum.content[0].text.contains("Referendum 13"));

        let blocked_vote = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_prepare_governance_vote".into(),
                arguments: serde_json::json!({
                    "referendum_index": 12,
                    "vote": "nay",
                    "conviction": "locked1x",
                    "amount": 10
                }),
            },
            &kms,
        );
        assert!(blocked_vote.is_error);
        assert!(blocked_vote.content[0].text.contains("direction"));

        let blocked_amount = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_prepare_governance_vote".into(),
                arguments: serde_json::json!({
                    "referendum_index": 12,
                    "vote": "aye",
                    "conviction": "locked1x",
                    "amount": 51
                }),
            },
            &kms,
        );
        assert!(blocked_amount.is_error);
        assert!(blocked_amount.content[0].text.contains("max_vote_lunes"));
    }

    #[test]
    fn prepare_governance_remove_vote_is_pending_and_policy_bound() {
        let kms = AgentKms::new(AgentMode::Autonomous, governance_permissions());
        kms.provision_key().unwrap();

        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_prepare_governance_remove_vote".into(),
                arguments: serde_json::json!({
                    "referendum_index": 12
                }),
            },
            &kms,
        );

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["data"]["action"], "conviction_voting.remove_vote");
        assert_eq!(data["data"]["broadcasted"], false);
        assert!(data["data"].get("signature").is_none());
        assert_eq!(kms.spent_today(), 0);
    }

    #[test]
    fn prepare_governance_delegate_returns_pending_without_signature() {
        let delegate = lunes_address(6);
        let kms = AgentKms::new(AgentMode::Autonomous, governance_permissions());

        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_prepare_governance_delegate".into(),
                arguments: serde_json::json!({
                    "track": 0,
                    "delegate": delegate,
                    "conviction": "locked1x",
                    "amount": 10,
                }),
            },
            &kms,
        );

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["status"], "pending_human_approval");
        assert_eq!(data["data"]["action"], "conviction_voting.delegate");
        assert_eq!(data["data"]["track"], 0);
        assert_eq!(data["data"]["broadcasted"], false);
        assert_eq!(data["data"]["signing_status"], "not_signed_by_mcp");
        assert!(data["data"].get("signature").is_none());
    }

    #[test]
    fn prepare_governance_delegate_enforces_delegate_policy() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, governance_permissions());

        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_prepare_governance_delegate".into(),
                arguments: serde_json::json!({
                    "track": 0,
                    "delegate": lunes_address(99),
                    "conviction": "locked1x",
                    "amount": 10,
                }),
            },
            &kms,
        );

        assert!(response.is_error);
        assert!(response.content[0].text.contains("not allowed"));
    }

    #[test]
    fn prepare_governance_delegate_rejects_broadcast_and_amount_over_policy() {
        let delegate = lunes_address(6);
        let kms = AgentKms::new(AgentMode::Autonomous, governance_permissions());

        let broadcast_attempt = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_prepare_governance_delegate".into(),
                arguments: serde_json::json!({
                    "track": 0,
                    "delegate": delegate,
                    "conviction": "locked1x",
                    "amount": 10,
                    "confirm_broadcast": true,
                }),
            },
            &kms,
        );
        assert!(broadcast_attempt.is_error);
        assert!(broadcast_attempt.content[0].text.contains("prepare-only"));

        let over_limit = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_prepare_governance_delegate".into(),
                arguments: serde_json::json!({
                    "track": 0,
                    "delegate": lunes_address(6),
                    "conviction": "locked1x",
                    "amount": 26,
                }),
            },
            &kms,
        );
        assert!(over_limit.is_error);
        assert!(over_limit.content[0].text.contains("max_delegation_lunes"));
    }

    #[test]
    fn prepare_governance_undelegate_is_pending_and_track_bound() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, governance_permissions());

        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_prepare_governance_undelegate".into(),
                arguments: serde_json::json!({
                    "track": 0,
                }),
            },
            &kms,
        );

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["status"], "pending_human_approval");
        assert_eq!(data["data"]["action"], "conviction_voting.undelegate");
        assert_eq!(data["data"]["broadcasted"], false);

        let denied = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_prepare_governance_undelegate".into(),
                arguments: serde_json::json!({
                    "track": 99,
                }),
            },
            &kms,
        );

        assert!(denied.is_error);
        assert!(denied.content[0].text.contains("track"));
    }

    #[test]
    fn psp22_transfer_requires_asset_specific_limit() {
        let contract = lunes_address(2);
        let to = lunes_address(3);
        let mut allowlist_contracts = std::collections::HashMap::new();
        allowlist_contracts.insert(contract.clone(), vec!["PSP22::transfer".into()]);
        let kms = AgentKms::new(
            AgentMode::Autonomous,
            PermissionsConfig {
                allowed_extrinsics: vec!["contracts.call".into()],
                whitelisted_addresses: vec![contract.clone()],
                daily_limit_lunes: 100,
                allowlist_contracts,
                asset_policies: Default::default(),
                governance: Default::default(),
                ttl_hours: 168,
                human_approval_required: true,
                approval_message_template: None,
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
        assert!(response.content[0]
            .text
            .contains("asset-specific transfer limit"));
    }

    #[test]
    fn psp22_transfer_enforces_asset_specific_limit() {
        let contract = lunes_address(2);
        let to = lunes_address(3);
        let mut allowlist_contracts = std::collections::HashMap::new();
        allowlist_contracts.insert(contract.clone(), vec!["PSP22::transfer".into()]);
        let mut asset_policies = std::collections::HashMap::new();
        asset_policies.insert(contract.clone(), psp22_asset_policy(5, vec![to.clone()]));
        let kms = AgentKms::new(
            AgentMode::PrepareOnly,
            PermissionsConfig {
                allowed_extrinsics: vec!["contracts.call".into()],
                whitelisted_addresses: vec![contract.clone()],
                daily_limit_lunes: 100,
                allowlist_contracts,
                asset_policies,
                governance: Default::default(),
                ttl_hours: 168,
                human_approval_required: true,
                approval_message_template: None,
            },
        );

        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_transfer_psp22".into(),
                arguments: serde_json::json!({
                    "contract_address": contract,
                    "to": to,
                    "amount_base_units": "10"
                }),
            },
            &kms,
        );

        assert!(response.is_error);
        assert!(response.content[0]
            .text
            .contains("exceeds asset-specific transfer limit"));
    }

    #[test]
    fn psp22_transfer_requires_asset_recipient_allowlist() {
        let contract = lunes_address(2);
        let to = lunes_address(3);
        let other_recipient = lunes_address(4);
        let mut allowlist_contracts = std::collections::HashMap::new();
        allowlist_contracts.insert(contract.clone(), vec!["PSP22::transfer".into()]);
        let mut asset_policies = std::collections::HashMap::new();
        asset_policies.insert(
            contract.clone(),
            psp22_asset_policy(1_000, vec![other_recipient]),
        );
        let kms = AgentKms::new(
            AgentMode::PrepareOnly,
            PermissionsConfig {
                allowed_extrinsics: vec!["contracts.call".into()],
                whitelisted_addresses: vec![contract.clone()],
                daily_limit_lunes: 100,
                allowlist_contracts,
                asset_policies,
                governance: Default::default(),
                ttl_hours: 168,
                human_approval_required: true,
                approval_message_template: None,
            },
        );

        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_transfer_psp22".into(),
                arguments: serde_json::json!({
                    "contract_address": contract,
                    "to": to,
                    "amount_base_units": "10"
                }),
            },
            &kms,
        );

        assert!(response.is_error);
        assert!(response.content[0].text.contains("not allowlisted"));
    }

    #[test]
    fn psp22_transfer_uses_asset_policy_without_consuming_native_budget() {
        let contract = lunes_address(2);
        let to = lunes_address(3);
        let mut allowlist_contracts = std::collections::HashMap::new();
        allowlist_contracts.insert(contract.clone(), vec!["PSP22::transfer".into()]);
        let mut asset_policies = std::collections::HashMap::new();
        asset_policies.insert(
            contract.clone(),
            psp22_asset_policy(1_000, vec![to.clone()]),
        );
        let kms = AgentKms::new(
            AgentMode::Autonomous,
            PermissionsConfig {
                allowed_extrinsics: vec!["contracts.call".into()],
                whitelisted_addresses: vec![contract.clone()],
                daily_limit_lunes: 0,
                allowlist_contracts,
                asset_policies,
                governance: Default::default(),
                ttl_hours: 168,
                human_approval_required: true,
                approval_message_template: None,
            },
        );
        kms.provision_key().unwrap();

        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_transfer_psp22".into(),
                arguments: serde_json::json!({
                    "contract_address": contract,
                    "to": to,
                    "amount_base_units": "10"
                }),
            },
            &kms,
        );

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["amount_base_units"], "10");
        assert_eq!(data["asset_metadata"]["symbol"], "POL");
        assert_eq!(data["broadcasted"], false);
        assert_eq!(kms.spent_today(), 0);
    }

    #[test]
    fn psp22_transfer_amount_base_units_must_match_amount() {
        let contract = lunes_address(2);
        let to = lunes_address(3);
        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_transfer_psp22".into(),
                arguments: serde_json::json!({
                    "contract_address": contract,
                    "to": to,
                    "amount": 10,
                    "amount_base_units": "11"
                }),
            },
            &AgentKms::new(AgentMode::PrepareOnly, permissions()),
        );

        assert!(response.is_error);
        assert!(response.content[0]
            .text
            .contains("amount_base_units must match amount"));
    }

    #[test]
    fn psp22_transfer_requires_contract_message_allowlist() {
        let contract = lunes_address(2);
        let to = lunes_address(3);
        let kms = AgentKms::new(
            AgentMode::PrepareOnly,
            PermissionsConfig {
                allowed_extrinsics: vec!["contracts.call".into()],
                whitelisted_addresses: vec![contract.clone()],
                daily_limit_lunes: 100,
                allowlist_contracts: Default::default(),
                asset_policies: Default::default(),
                governance: Default::default(),
                ttl_hours: 168,
                human_approval_required: true,
                approval_message_template: None,
            },
        );

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
        assert!(response.content[0].text.contains("transfer"));
    }

    #[test]
    fn generic_contract_call_requires_message_allowlist() {
        let contract = lunes_address(2);
        let kms = AgentKms::new(
            AgentMode::PrepareOnly,
            PermissionsConfig {
                allowed_extrinsics: vec!["contracts.call".into()],
                whitelisted_addresses: vec![contract.clone()],
                daily_limit_lunes: 100,
                allowlist_contracts: Default::default(),
                asset_policies: Default::default(),
                governance: Default::default(),
                ttl_hours: 168,
                human_approval_required: true,
                approval_message_template: None,
            },
        );

        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_call_contract".into(),
                arguments: serde_json::json!({
                    "contract_address": contract,
                    "message": "PSP22::approve",
                    "value": 0
                }),
            },
            &kms,
        );

        assert!(response.is_error);
        assert!(response.content[0].text.contains("PSP22::approve"));
    }

    #[test]
    fn generic_contract_call_blocks_autonomous_psp22_transfer_bypass() {
        let contract = lunes_address(2);
        let to = lunes_address(3);
        let mut allowlist_contracts = std::collections::HashMap::new();
        allowlist_contracts.insert(contract.clone(), vec!["PSP22::transfer".into()]);
        let mut asset_policies = std::collections::HashMap::new();
        asset_policies.insert(
            contract.clone(),
            psp22_asset_policy(1_000, vec![to.clone()]),
        );
        let kms = AgentKms::new(
            AgentMode::Autonomous,
            PermissionsConfig {
                allowed_extrinsics: vec!["contracts.call".into()],
                whitelisted_addresses: vec![contract.clone()],
                daily_limit_lunes: 100,
                allowlist_contracts,
                asset_policies,
                governance: Default::default(),
                ttl_hours: 168,
                human_approval_required: true,
                approval_message_template: None,
            },
        );
        kms.provision_key().unwrap();

        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_call_contract".into(),
                arguments: serde_json::json!({
                    "contract_address": contract,
                    "message": "PSP22::transfer",
                    "args": {"to": to, "amount_base_units": "10"},
                    "value": 0
                }),
            },
            &kms,
        );

        assert!(response.is_error);
        assert!(response.content[0].text.contains("lunes_transfer_psp22"));
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
        assert_eq!(tools.len(), 40);
        assert!(tools.iter().any(|tool| tool["name"] == "lunes_get_balance"));
        assert!(tools.iter().any(|tool| tool["name"] == "lunes_get_assets"));
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_get_asset_balance"));
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
            .any(|tool| tool["name"] == "lunes_get_validator_profiles"));
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_get_validator_scores"));
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_get_staking_overview"));
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_get_staking_account"));
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_get_governance_overview"));
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_get_referenda"));
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
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_submit_signed_extrinsic"));
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_search_account_activity"));
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_get_recent_blocks"));
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_get_block_events"));
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_read_contract"));
        assert!(tools.iter().any(|tool| tool["name"] == "lunes_stake_bond"));
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_stake_rebond"));
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_stake_payout"));
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_stake_nominate"));
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_prepare_governance_vote"));
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_prepare_governance_remove_vote"));
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_prepare_governance_delegate"));
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_prepare_governance_undelegate"));
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
                allowlist_contracts: Default::default(),
                asset_policies: Default::default(),
                governance: Default::default(),
                ttl_hours: 168,
                human_approval_required: true,
                approval_message_template: None,
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
    fn staking_rebond_prepares_human_review_payload() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, staking_permissions());
        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_stake_rebond".into(),
                arguments: serde_json::json!({
                    "amount": 25
                }),
            },
            &kms,
        );

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["data"]["action"], "staking.rebond");
        assert_eq!(data["data"]["amount_lunes"], 25);
        assert_eq!(data["data"]["broadcasted"], false);
    }

    #[test]
    fn staking_payout_requires_validator_whitelist() {
        let validator = lunes_address(8);
        let kms = AgentKms::new(
            AgentMode::PrepareOnly,
            PermissionsConfig {
                allowed_extrinsics: vec!["staking.payout_stakers".into()],
                whitelisted_addresses: vec!["staking".into()],
                daily_limit_lunes: 1_000,
                allowlist_contracts: Default::default(),
                asset_policies: Default::default(),
                governance: Default::default(),
                ttl_hours: 168,
                human_approval_required: true,
                approval_message_template: None,
            },
        );

        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_stake_payout".into(),
                arguments: serde_json::json!({
                    "validator_stash": validator,
                    "era": 42
                }),
            },
            &kms,
        );

        assert!(response.is_error);
        assert!(response.content[0].text.contains("not in the whitelist"));
    }

    #[test]
    fn staking_payout_prepares_when_validator_whitelisted() {
        let validator = lunes_address(8);
        let kms = AgentKms::new(AgentMode::PrepareOnly, staking_permissions());
        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_stake_payout".into(),
                arguments: serde_json::json!({
                    "validator_stash": validator,
                    "era": 42
                }),
            },
            &kms,
        );

        assert!(!response.is_error);
        let data = response_json(&response);
        assert_eq!(data["data"]["action"], "staking.payout_stakers");
        assert_eq!(data["data"]["era"], 42);
        assert_eq!(data["data"]["broadcasted"], false);
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
        assert!(validate_lunes_address(&lunes_address(4)).is_ok());
        assert!(validate_lunes_address("5Gxyz").is_err());
        assert!(
            validate_lunes_address("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY").is_err()
        );
    }
}
