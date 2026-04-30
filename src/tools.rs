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

use crate::kms::AgentKms;

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
/// Checks length and base58 characters only.
/// Checksum validation needs Lunes Network RPC integration.
fn is_valid_ss58(address: &str) -> bool {
    if address.len() < 46 || address.len() > 48 {
        return false;
    }
    // Base58 charset: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
    address
        .chars()
        .all(|c| "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c))
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
                "Invalid SS58 address for '{}': '{}'. Expected 46-48 base58 characters.",
                field_name, address
            ),
        ));
    }
    Ok(())
}

// --- Dispatcher ----------------------------------------------------------

/// Routes a tool call name to the matching handler.
pub fn dispatch_tool_call(request: &ToolCallRequest, kms: &AgentKms) -> McpToolResult {
    match request.name.as_str() {
        // Read-only queries
        "lunes_get_balance" => handle_get_balance(&request.arguments),
        "lunes_get_transaction_status" => handle_get_tx_status(&request.arguments),
        "lunes_search_contract" => handle_search_contract(&request.arguments),

        // Write operations that go through the KMS policy checks
        "lunes_transfer_native" => handle_transfer_native(&request.arguments, kms),
        "lunes_transfer_psp22" => handle_transfer_psp22(&request.arguments, kms),
        "lunes_call_contract" => handle_call_contract(&request.arguments, kms),

        // Agent wallet lifecycle
        "lunes_provision_agent_wallet" => handle_provision_wallet(kms),
        "lunes_revoke_agent_wallet" => handle_revoke_wallet(kms),

        _ => McpToolResult::error(-32601, format!("Unknown tool: '{}'", request.name)),
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
            "name": "lunes_get_transaction_status",
            "description": "Read transaction status and events by hash.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tx_hash": { "type": "string", "description": "Hexadecimal transaction hash." }
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
fn handle_get_balance(args: &Value) -> McpToolResult {
    let address = args.get("address").and_then(|v| v.as_str()).unwrap_or("");
    let asset_id = args.get("asset_id").and_then(|v| v.as_str());

    if let Err(e) = validate_address(address, "address") {
        return e;
    }

    // TODO: connect to Lunes Network RPC.
    McpToolResult::success(serde_json::json!({
        "address": address,
        "asset": asset_id.unwrap_or("LUNES (native)"),
        "free_balance": "0",
        "reserved_balance": "0",
        "note": "Lunes Network RPC integration pending"
    }))
}

/// `lunes_get_transaction_status` - reads transaction status by hash.
fn handle_get_tx_status(args: &Value) -> McpToolResult {
    let tx_hash = args.get("tx_hash").and_then(|v| v.as_str()).unwrap_or("");

    if tx_hash.is_empty() {
        return McpToolResult::error(-32001, "Missing required field: tx_hash".into());
    }

    // TODO: connect to Lunes Network RPC.
    McpToolResult::success(serde_json::json!({
        "tx_hash": tx_hash,
        "status": "pending_implementation",
        "note": "Will decode block events into human-readable format"
    }))
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
    use crate::config::{AgentMode, PermissionsConfig};

    fn permissions() -> PermissionsConfig {
        PermissionsConfig {
            allowed_extrinsics: vec!["balances.transfer".into(), "contracts.call".into()],
            whitelisted_addresses: vec!["5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".into()],
            daily_limit_lunes: 100,
            ttl_hours: 168,
        }
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

    #[test]
    fn get_balance_requires_valid_address() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());

        // Empty address
        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_get_balance".into(),
                arguments: serde_json::json!({}),
            },
            &kms,
        );
        assert!(response.is_error);

        // Invalid SS58 (too short)
        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_get_balance".into(),
                arguments: serde_json::json!({"address": "abc"}),
            },
            &kms,
        );
        assert!(response.is_error);
    }

    #[test]
    fn get_balance_with_valid_address_succeeds() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        // Valid SS58 format (48 chars, base58)
        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_get_balance".into(),
                arguments: serde_json::json!({"address": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"}),
            },
            &kms,
        );
        assert!(!response.is_error);
    }

    #[test]
    fn prepare_only_native_transfer_waits_for_human_approval() {
        let kms = AgentKms::new(AgentMode::PrepareOnly, permissions());
        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_transfer_native".into(),
                arguments: serde_json::json!({
                    "to": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
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

        let response = dispatch_tool_call(
            &ToolCallRequest {
                name: "lunes_transfer_native".into(),
                arguments: serde_json::json!({
                    "to": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
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
        let contract = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
        let to = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspK4vJC9Lky3UYGJ";
        let kms = AgentKms::new(
            AgentMode::Autonomous,
            PermissionsConfig {
                allowed_extrinsics: vec!["contracts.call".into()],
                whitelisted_addresses: vec![contract.into()],
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
        assert_eq!(tools.len(), 8);
        assert!(tools.iter().any(|tool| tool["name"] == "lunes_get_balance"));
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_transfer_native"));
        assert!(tools
            .iter()
            .any(|tool| tool["name"] == "lunes_revoke_agent_wallet"));
        assert!(tools.iter().all(|tool| tool.get("inputSchema").is_some()));
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
        // Valid SS58 address (Polkadot format, 48 chars)
        assert!(is_valid_ss58(
            "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
        ));
        // Too short
        assert!(!is_valid_ss58("5Gxyz"));
        // Contains invalid chars (0, O, I, l are not in base58)
        assert!(!is_valid_ss58(
            "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcN0HGKutQY"
        ));
    }
}
