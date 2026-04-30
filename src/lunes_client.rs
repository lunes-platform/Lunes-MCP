//! Minimal Lunes Network RPC client.

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use jsonrpsee::{
    core::client::ClientT,
    ws_client::{WsClient, WsClientBuilder},
};
use serde::Serialize;
use serde_json::Value;
use std::{convert::TryInto, sync::Arc, time::Duration};

const LUNES_ACCOUNT_STORAGE_PREFIX: &str =
    "26aa394eea5630e07c48ae0c9558cef7b99d880ec681799c0cf30e8886371da9";
pub const DEFAULT_ARCHIVE_TX_LOOKBACK_BLOCKS: u64 = 4;
pub const MAX_ARCHIVE_TX_LOOKBACK_BLOCKS: u64 = 64;

#[derive(Clone)]
pub struct LunesClient {
    endpoints: Arc<Vec<String>>,
    archive_endpoint: Option<String>,
    static_info: Option<ChainInfo>,
    static_native_balance: Option<NativeBalance>,
    static_transaction_status: Option<TransactionStatus>,
}

impl LunesClient {
    pub fn new(primary: String, failovers: Vec<String>, archive_endpoint: Option<String>) -> Self {
        let mut endpoints = vec![primary];
        endpoints.extend(failovers);
        endpoints.dedup();
        Self {
            endpoints: Arc::new(endpoints),
            archive_endpoint,
            static_info: None,
            static_native_balance: None,
            static_transaction_status: None,
        }
    }

    #[cfg(test)]
    pub fn static_info(info: ChainInfo) -> Self {
        Self {
            endpoints: Arc::new(vec![info.rpc_endpoint.clone()]),
            archive_endpoint: None,
            static_info: Some(info),
            static_native_balance: None,
            static_transaction_status: None,
        }
    }

    #[cfg(test)]
    pub fn static_native_balance(balance: NativeBalance) -> Self {
        Self {
            endpoints: Arc::new(vec!["memory://lunes".into()]),
            archive_endpoint: None,
            static_info: None,
            static_native_balance: Some(balance),
            static_transaction_status: None,
        }
    }

    #[cfg(test)]
    pub fn static_transaction_status(status: TransactionStatus) -> Self {
        Self {
            endpoints: Arc::new(vec!["memory://lunes".into()]),
            archive_endpoint: None,
            static_info: None,
            static_native_balance: None,
            static_transaction_status: Some(status),
        }
    }

    pub async fn chain_info(&self) -> Result<ChainInfo, LunesClientError> {
        if let Some(info) = &self.static_info {
            return Ok(info.clone());
        }

        let mut last_error = None;
        for endpoint in self.endpoints.iter() {
            match fetch_chain_info(endpoint).await {
                Ok(info) => return Ok(info),
                Err(error) => last_error = Some(error),
            }
        }

        Err(last_error.unwrap_or(LunesClientError::NoRpcEndpoints))
    }

    pub async fn native_balance(
        &self,
        account_id: [u8; 32],
    ) -> Result<NativeBalance, LunesClientError> {
        if let Some(balance) = self.static_native_balance {
            return Ok(balance);
        }

        let mut last_error = None;
        for endpoint in self.endpoints.iter() {
            match fetch_native_balance(endpoint, &account_id).await {
                Ok(balance) => return Ok(balance),
                Err(error) => last_error = Some(error),
            }
        }

        Err(last_error.unwrap_or(LunesClientError::NoRpcEndpoints))
    }

    pub async fn transaction_status(
        &self,
        tx_hash: &str,
    ) -> Result<TransactionStatus, LunesClientError> {
        self.transaction_status_with_archive_lookback(tx_hash, DEFAULT_ARCHIVE_TX_LOOKBACK_BLOCKS)
            .await
    }

    pub async fn transaction_status_with_archive_lookback(
        &self,
        tx_hash: &str,
        archive_lookback_blocks: u64,
    ) -> Result<TransactionStatus, LunesClientError> {
        let tx_hash = normalize_32_byte_hash(tx_hash)?;
        let archive_lookback_blocks = archive_lookback_blocks.min(MAX_ARCHIVE_TX_LOOKBACK_BLOCKS);

        if let Some(status) = &self.static_transaction_status {
            return Ok(status.clone());
        }

        let mut last_error = None;
        let mut current_not_found = None;
        for endpoint in self.endpoints.iter() {
            match fetch_transaction_status(endpoint, &tx_hash).await {
                Ok(status) if status.status != TransactionState::NotFound => return Ok(status),
                Ok(status) => current_not_found = Some(status),
                Err(error) => last_error = Some(error),
            }
        }

        if archive_lookback_blocks > 0 {
            if let Some(archive_endpoint) = &self.archive_endpoint {
                match fetch_archive_transaction_status(
                    archive_endpoint,
                    &tx_hash,
                    archive_lookback_blocks,
                )
                .await
                {
                    Ok(status) => return Ok(status),
                    Err(error) => last_error = Some(error),
                }
            }
        }

        current_not_found.ok_or_else(|| last_error.unwrap_or(LunesClientError::NoRpcEndpoints))
    }
}

async fn fetch_chain_info(endpoint: &str) -> Result<ChainInfo, LunesClientError> {
    let client = connect_client(endpoint).await?;

    let chain = rpc_request(&client, "system_chain").await?;
    let node_name = rpc_request(&client, "system_name").await?;
    let node_version = rpc_request(&client, "system_version").await?;
    let properties: Value = rpc_request(&client, "system_properties").await?;
    let runtime: Value = rpc_request(&client, "state_getRuntimeVersion").await?;

    Ok(ChainInfo {
        rpc_endpoint: endpoint.to_string(),
        chain,
        node_name,
        node_version,
        properties: ChainProperties::from_rpc(properties)?,
        runtime: RuntimeInfo::from_rpc(runtime)?,
    })
}

async fn fetch_native_balance(
    endpoint: &str,
    account_id: &[u8; 32],
) -> Result<NativeBalance, LunesClientError> {
    let client = connect_client(endpoint).await?;
    let key = native_balance_storage_key(account_id);
    let storage: Option<String> =
        rpc_request_params(&client, "state_getStorage", vec![Value::String(key)]).await?;

    NativeBalance::from_storage_hex(storage.as_deref())
}

async fn fetch_transaction_status(
    endpoint: &str,
    tx_hash: &str,
) -> Result<TransactionStatus, LunesClientError> {
    let client = connect_client(endpoint).await?;
    let pending_extrinsics: Vec<String> = rpc_request(&client, "author_pendingExtrinsics").await?;
    let best_hash: String = rpc_request(&client, "chain_getHead").await?;
    let finalized_hash: String = rpc_request(&client, "chain_getFinalizedHead").await?;

    let best_block = fetch_block(&client, &best_hash).await?;
    let finalized_block = if finalized_hash.eq_ignore_ascii_case(&best_hash) {
        best_block.clone()
    } else {
        fetch_block(&client, &finalized_hash).await?
    };

    Ok(TransactionStatus::from_blocks(
        tx_hash,
        &pending_extrinsics,
        best_block.as_ref(),
        finalized_block.as_ref(),
    ))
}

async fn fetch_archive_transaction_status(
    endpoint: &str,
    tx_hash: &str,
    lookback_blocks: u64,
) -> Result<TransactionStatus, LunesClientError> {
    let client = connect_client(endpoint).await?;
    let finalized_hash: String = rpc_request(&client, "chain_getFinalizedHead").await?;
    let finalized_block = fetch_block(&client, &finalized_hash).await?;
    let lookup_scope = format!("archive finalized blocks, last {lookback_blocks} blocks");

    if let Some(block) = finalized_block.as_ref() {
        if let Some(status) =
            TransactionStatus::finalized_in_block(tx_hash, block, lookup_scope.clone())
        {
            return Ok(status);
        }

        let oldest = block.number.saturating_sub(lookback_blocks);
        for number in (oldest..block.number).rev() {
            let Some(block_hash) = fetch_block_hash_at(&client, number).await? else {
                continue;
            };
            let Some(block) = fetch_block(&client, &block_hash).await? else {
                continue;
            };

            if let Some(status) =
                TransactionStatus::finalized_in_block(tx_hash, &block, lookup_scope.clone())
            {
                return Ok(status);
            }
        }
    }

    Ok(TransactionStatus::not_found(tx_hash, lookup_scope))
}
async fn connect_client(endpoint: &str) -> Result<WsClient, LunesClientError> {
    WsClientBuilder::default()
        .connection_timeout(Duration::from_secs(5))
        .request_timeout(Duration::from_secs(5))
        .build(endpoint)
        .await
        .map_err(|error| LunesClientError::RpcConnection {
            endpoint: endpoint.to_string(),
            message: error.to_string(),
        })
}

async fn rpc_request<T>(client: &WsClient, method: &str) -> Result<T, LunesClientError>
where
    T: serde::de::DeserializeOwned,
{
    client
        .request(method, Vec::<Value>::new())
        .await
        .map_err(|error| LunesClientError::RpcRequest {
            method: method.to_string(),
            message: error.to_string(),
        })
}

async fn rpc_request_params<T>(
    client: &WsClient,
    method: &str,
    params: Vec<Value>,
) -> Result<T, LunesClientError>
where
    T: serde::de::DeserializeOwned,
{
    client
        .request(method, params)
        .await
        .map_err(|error| LunesClientError::RpcRequest {
            method: method.to_string(),
            message: error.to_string(),
        })
}

async fn fetch_block_hash_at(
    client: &WsClient,
    number: u64,
) -> Result<Option<String>, LunesClientError> {
    rpc_request_params(
        client,
        "chain_getBlockHash",
        vec![Value::Number(serde_json::Number::from(number))],
    )
    .await
}

async fn fetch_block(
    client: &WsClient,
    block_hash: &str,
) -> Result<Option<RpcBlock>, LunesClientError> {
    let value: Value = rpc_request_params(
        client,
        "chain_getBlock",
        vec![Value::String(block_hash.to_string())],
    )
    .await?;

    if value.is_null() {
        return Ok(None);
    }

    RpcBlock::from_rpc(block_hash.to_string(), value).map(Some)
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ChainInfo {
    pub rpc_endpoint: String,
    pub chain: String,
    pub node_name: String,
    pub node_version: String,
    pub properties: ChainProperties,
    pub runtime: RuntimeInfo,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ChainProperties {
    pub ss58_format: u16,
    pub token_decimals: u8,
    pub token_symbol: String,
}

impl ChainProperties {
    fn from_rpc(value: Value) -> Result<Self, LunesClientError> {
        let ss58_format = value
            .get("ss58Format")
            .and_then(value_as_u64)
            .ok_or_else(|| LunesClientError::InvalidRpcResponse("missing ss58Format".into()))?
            as u16;
        let token_decimals = value
            .get("tokenDecimals")
            .and_then(value_as_u64)
            .ok_or_else(|| LunesClientError::InvalidRpcResponse("missing tokenDecimals".into()))?
            as u8;
        let token_symbol = value
            .get("tokenSymbol")
            .and_then(value_as_string)
            .ok_or_else(|| LunesClientError::InvalidRpcResponse("missing tokenSymbol".into()))?;

        Ok(Self {
            ss58_format,
            token_decimals,
            token_symbol,
        })
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RuntimeInfo {
    pub spec_name: String,
    pub impl_name: String,
    pub spec_version: u32,
    pub transaction_version: u32,
    pub state_version: u8,
}

impl RuntimeInfo {
    fn from_rpc(value: Value) -> Result<Self, LunesClientError> {
        Ok(Self {
            spec_name: required_string(&value, "specName")?,
            impl_name: required_string(&value, "implName")?,
            spec_version: required_u32(&value, "specVersion")?,
            transaction_version: required_u32(&value, "transactionVersion")?,
            state_version: required_u32(&value, "stateVersion")? as u8,
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct NativeBalance {
    pub free: u128,
    pub reserved: u128,
    pub frozen: u128,
    pub flags: u128,
}

impl NativeBalance {
    pub fn zero() -> Self {
        Self {
            free: 0,
            reserved: 0,
            frozen: 0,
            flags: 0,
        }
    }

    fn from_storage_hex(storage: Option<&str>) -> Result<Self, LunesClientError> {
        let Some(storage) = storage else {
            return Ok(Self::zero());
        };

        let bytes = hex_to_bytes(storage)?;
        if bytes.is_empty() {
            return Ok(Self::zero());
        }
        if bytes.len() < 80 {
            return Err(LunesClientError::InvalidRpcResponse(format!(
                "native balance storage is too short: {} bytes",
                bytes.len()
            )));
        }

        Ok(Self {
            free: read_u128_le(&bytes, 16)?,
            reserved: read_u128_le(&bytes, 32)?,
            frozen: read_u128_le(&bytes, 48)?,
            flags: read_u128_le(&bytes, 64)?,
        })
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TransactionStatus {
    pub tx_hash: String,
    pub status: TransactionState,
    pub block_hash: Option<String>,
    pub block_number: Option<u64>,
    pub extrinsic_index: Option<usize>,
    pub lookup_scope: String,
}

impl TransactionStatus {
    fn from_blocks(
        tx_hash: &str,
        pending_extrinsics: &[String],
        best_block: Option<&RpcBlock>,
        finalized_block: Option<&RpcBlock>,
    ) -> Self {
        Self::from_blocks_with_scope(
            tx_hash,
            pending_extrinsics,
            best_block,
            finalized_block,
            lookup_scope(),
        )
    }

    fn from_blocks_with_scope(
        tx_hash: &str,
        pending_extrinsics: &[String],
        best_block: Option<&RpcBlock>,
        finalized_block: Option<&RpcBlock>,
        lookup_scope: String,
    ) -> Self {
        if let Some(block) = finalized_block {
            if let Some(index) = block.find_extrinsic(tx_hash) {
                return Self::located(
                    tx_hash,
                    TransactionState::Finalized,
                    block.hash.clone(),
                    block.number,
                    index,
                    lookup_scope,
                );
            }
        }

        if let Some(block) = best_block {
            if let Some(index) = block.find_extrinsic(tx_hash) {
                return Self::located(
                    tx_hash,
                    TransactionState::InBestBlock,
                    block.hash.clone(),
                    block.number,
                    index,
                    lookup_scope,
                );
            }
        }

        if pending_extrinsics
            .iter()
            .any(|extrinsic| extrinsic_hash_matches(extrinsic, tx_hash))
        {
            return Self {
                tx_hash: tx_hash.to_string(),
                status: TransactionState::InPool,
                block_hash: None,
                block_number: None,
                extrinsic_index: None,
                lookup_scope,
            };
        }

        Self::not_found(tx_hash, lookup_scope)
    }

    fn finalized_in_block(tx_hash: &str, block: &RpcBlock, lookup_scope: String) -> Option<Self> {
        block.find_extrinsic(tx_hash).map(|index| {
            Self::located(
                tx_hash,
                TransactionState::Finalized,
                block.hash.clone(),
                block.number,
                index,
                lookup_scope,
            )
        })
    }

    fn not_found(tx_hash: &str, lookup_scope: String) -> Self {
        Self {
            tx_hash: tx_hash.to_string(),
            status: TransactionState::NotFound,
            block_hash: None,
            block_number: None,
            extrinsic_index: None,
            lookup_scope,
        }
    }

    fn located(
        tx_hash: &str,
        status: TransactionState,
        block_hash: String,
        block_number: u64,
        extrinsic_index: usize,
        lookup_scope: String,
    ) -> Self {
        Self {
            tx_hash: tx_hash.to_string(),
            status,
            block_hash: Some(block_hash),
            block_number: Some(block_number),
            extrinsic_index: Some(extrinsic_index),
            lookup_scope,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransactionState {
    Finalized,
    InBestBlock,
    InPool,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RpcBlock {
    hash: String,
    number: u64,
    extrinsics: Vec<String>,
}

impl RpcBlock {
    fn from_rpc(hash: String, value: Value) -> Result<Self, LunesClientError> {
        let block = value
            .get("block")
            .ok_or_else(|| LunesClientError::InvalidRpcResponse("missing block".into()))?;
        let header = block
            .get("header")
            .ok_or_else(|| LunesClientError::InvalidRpcResponse("missing block header".into()))?;
        let number = header
            .get("number")
            .and_then(|value| value.as_str())
            .ok_or_else(|| LunesClientError::InvalidRpcResponse("missing block number".into()))
            .and_then(hex_to_u64)?;
        let extrinsics = block
            .get("extrinsics")
            .and_then(|value| value.as_array())
            .ok_or_else(|| LunesClientError::InvalidRpcResponse("missing extrinsics".into()))?
            .iter()
            .map(|value| {
                value.as_str().map(str::to_string).ok_or_else(|| {
                    LunesClientError::InvalidRpcResponse("extrinsic is not a string".into())
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            hash,
            number,
            extrinsics,
        })
    }

    fn find_extrinsic(&self, tx_hash: &str) -> Option<usize> {
        self.extrinsics
            .iter()
            .position(|extrinsic| extrinsic_hash_matches(extrinsic, tx_hash))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LunesClientError {
    #[error("no Lunes RPC endpoints configured")]
    NoRpcEndpoints,
    #[error("failed to connect to Lunes RPC {endpoint}: {message}")]
    RpcConnection { endpoint: String, message: String },
    #[error("Lunes RPC request {method} failed: {message}")]
    RpcRequest { method: String, message: String },
    #[error("invalid Lunes RPC response: {0}")]
    InvalidRpcResponse(String),
    #[error("invalid transaction hash: {0}")]
    InvalidTransactionHash(String),
}

fn required_string(value: &Value, key: &str) -> Result<String, LunesClientError> {
    value
        .get(key)
        .and_then(value_as_string)
        .ok_or_else(|| LunesClientError::InvalidRpcResponse(format!("missing {key}")))
}

fn required_u32(value: &Value, key: &str) -> Result<u32, LunesClientError> {
    value
        .get(key)
        .and_then(value_as_u64)
        .map(|value| value as u32)
        .ok_or_else(|| LunesClientError::InvalidRpcResponse(format!("missing {key}")))
}

fn value_as_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64(),
        Value::Array(values) => values.first().and_then(value_as_u64),
        _ => None,
    }
}

fn value_as_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Array(values) => values.first().and_then(value_as_string),
        _ => None,
    }
}

fn native_balance_storage_key(account_id: &[u8; 32]) -> String {
    let account_hash = blake2_hash::<16>(account_id);
    format!(
        "0x{}{}{}",
        LUNES_ACCOUNT_STORAGE_PREFIX,
        hex::encode(account_hash),
        hex::encode(account_id)
    )
}

fn blake2_hash<const N: usize>(payload: &[u8]) -> [u8; N] {
    let mut hasher = Blake2bVar::new(N).expect("valid Blake2b output size");
    hasher.update(payload);

    let mut output = [0u8; N];
    hasher
        .finalize_variable(&mut output)
        .expect("Blake2b output buffer has the configured size");
    output
}

fn read_u128_le(bytes: &[u8], offset: usize) -> Result<u128, LunesClientError> {
    let end = offset + 16;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| LunesClientError::InvalidRpcResponse("missing balance field".into()))?;
    Ok(u128::from_le_bytes(
        value
            .try_into()
            .expect("slice length checked before conversion"),
    ))
}

fn hex_to_bytes(hex_value: &str) -> Result<Vec<u8>, LunesClientError> {
    decode_hex_string(hex_value).map_err(LunesClientError::InvalidRpcResponse)
}

fn transaction_hash_to_bytes(hex_value: &str) -> Result<Vec<u8>, LunesClientError> {
    decode_hex_string(hex_value).map_err(LunesClientError::InvalidTransactionHash)
}

fn decode_hex_string(hex_value: &str) -> Result<Vec<u8>, String> {
    let value = hex_value.strip_prefix("0x").unwrap_or(hex_value);
    if !value.len().is_multiple_of(2) {
        return Err("hex string must have an even number of characters".into());
    }
    hex::decode(value).map_err(|error| error.to_string())
}

fn normalize_32_byte_hash(hash: &str) -> Result<String, LunesClientError> {
    let bytes = transaction_hash_to_bytes(hash)?;
    if bytes.len() != 32 {
        return Err(LunesClientError::InvalidTransactionHash(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(format!("0x{}", hex::encode(bytes)))
}

fn lunes_payload_hash_hex(payload: &[u8]) -> String {
    format!("0x{}", hex::encode(blake2_hash::<32>(payload)))
}

fn extrinsic_hash_matches(extrinsic: &str, tx_hash: &str) -> bool {
    hex_to_bytes(extrinsic)
        .map(|bytes| lunes_payload_hash_hex(&bytes).eq_ignore_ascii_case(tx_hash))
        .unwrap_or(false)
}

fn hex_to_u64(hex_value: &str) -> Result<u64, LunesClientError> {
    let value = hex_value.strip_prefix("0x").unwrap_or(hex_value);
    u64::from_str_radix(value, 16)
        .map_err(|error| LunesClientError::InvalidRpcResponse(error.to_string()))
}

fn lookup_scope() -> String {
    "pending pool, current best block, and finalized head".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded_account_storage(free: u128, reserved: u128, frozen: u128, flags: u128) -> String {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&free.to_le_bytes());
        bytes.extend_from_slice(&reserved.to_le_bytes());
        bytes.extend_from_slice(&frozen.to_le_bytes());
        bytes.extend_from_slice(&flags.to_le_bytes());
        format!("0x{}", hex::encode(bytes))
    }

    #[test]
    fn parses_chain_properties_from_scalar_rpc_response() {
        let properties = ChainProperties::from_rpc(serde_json::json!({
            "ss58Format": 57,
            "tokenDecimals": 8,
            "tokenSymbol": "LUNES"
        }))
        .unwrap();

        assert_eq!(
            properties,
            ChainProperties {
                ss58_format: 57,
                token_decimals: 8,
                token_symbol: "LUNES".into(),
            }
        );
    }

    #[test]
    fn parses_chain_properties_from_array_rpc_response() {
        let properties = ChainProperties::from_rpc(serde_json::json!({
            "ss58Format": [57],
            "tokenDecimals": [8],
            "tokenSymbol": ["LUNES"]
        }))
        .unwrap();

        assert_eq!(properties.ss58_format, 57);
        assert_eq!(properties.token_decimals, 8);
        assert_eq!(properties.token_symbol, "LUNES");
    }

    #[test]
    fn decodes_native_balance_storage_payload() {
        let balance = NativeBalance::from_storage_hex(Some(&encoded_account_storage(
            1_500_000_000,
            200_000_000,
            300_000_000,
            0,
        )))
        .unwrap();

        assert_eq!(balance.free, 1_500_000_000);
        assert_eq!(balance.reserved, 200_000_000);
        assert_eq!(balance.frozen, 300_000_000);
    }

    #[test]
    fn missing_native_balance_storage_is_zero() {
        assert_eq!(
            NativeBalance::from_storage_hex(None).unwrap(),
            NativeBalance::zero()
        );
    }

    #[test]
    fn builds_lunes_account_storage_key_from_account_id() {
        let account_id = [7u8; 32];
        let key = native_balance_storage_key(&account_id);

        assert!(
            key.starts_with("0x26aa394eea5630e07c48ae0c9558cef7b99d880ec681799c0cf30e8886371da9")
        );
        assert!(key.ends_with(&hex::encode(account_id)));
    }

    #[test]
    fn finds_transaction_in_finalized_block_payload() {
        let extrinsic = "0x01020304";
        let tx_hash = lunes_payload_hash_hex(&hex_to_bytes(extrinsic).unwrap());
        let block = RpcBlock::from_rpc(
            "0xabc".into(),
            serde_json::json!({
                "block": {
                    "header": { "number": "0x2a" },
                    "extrinsics": ["0x00", extrinsic]
                }
            }),
        )
        .unwrap();

        let status = TransactionStatus::from_blocks(&tx_hash, &[], None, Some(&block));

        assert_eq!(status.status, TransactionState::Finalized);
        assert_eq!(status.block_number, Some(42));
        assert_eq!(status.extrinsic_index, Some(1));
    }

    #[test]
    fn finds_transaction_in_archive_block_payload() {
        let extrinsic = "0x09080706";
        let tx_hash = lunes_payload_hash_hex(&hex_to_bytes(extrinsic).unwrap());
        let archive_block = RpcBlock::from_rpc(
            "0xarchive".into(),
            serde_json::json!({
                "block": {
                    "header": { "number": "0x64" },
                    "extrinsics": [extrinsic]
                }
            }),
        )
        .unwrap();

        let status = TransactionStatus::finalized_in_block(
            &tx_hash,
            &archive_block,
            "archive finalized blocks, last 4 blocks".into(),
        )
        .unwrap();

        assert_eq!(status.status, TransactionState::Finalized);
        assert_eq!(status.block_hash, Some("0xarchive".into()));
        assert_eq!(status.block_number, Some(100));
        assert!(status.lookup_scope.contains("archive"));
    }
}
