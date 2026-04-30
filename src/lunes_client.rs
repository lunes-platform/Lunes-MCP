//! Minimal Lunes Network RPC client.

use crate::address::encode_lunes_address;
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
    static_account_next_index: Option<u64>,
    static_network_health: Option<NetworkHealth>,
    static_validator_set: Option<ValidatorSet>,
    static_staking_account: Option<StakingAccount>,
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
            static_account_next_index: None,
            static_network_health: None,
            static_validator_set: None,
            static_staking_account: None,
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
            static_account_next_index: None,
            static_network_health: None,
            static_validator_set: None,
            static_staking_account: None,
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
            static_account_next_index: None,
            static_network_health: None,
            static_validator_set: None,
            static_staking_account: None,
        }
    }

    #[cfg(test)]
    pub fn static_account_state(balance: NativeBalance, account_next_index: u64) -> Self {
        Self {
            endpoints: Arc::new(vec!["memory://lunes".into()]),
            archive_endpoint: None,
            static_info: None,
            static_native_balance: Some(balance),
            static_transaction_status: None,
            static_account_next_index: Some(account_next_index),
            static_network_health: None,
            static_validator_set: None,
            static_staking_account: None,
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
            static_account_next_index: None,
            static_network_health: None,
            static_validator_set: None,
            static_staking_account: None,
        }
    }

    #[cfg(test)]
    pub fn static_network_health(health: NetworkHealth) -> Self {
        Self {
            endpoints: Arc::new(vec![health.endpoint.clone()]),
            archive_endpoint: None,
            static_info: None,
            static_native_balance: None,
            static_transaction_status: None,
            static_account_next_index: None,
            static_network_health: Some(health),
            static_validator_set: None,
            static_staking_account: None,
        }
    }

    #[cfg(test)]
    pub fn static_validator_set(validator_set: ValidatorSet) -> Self {
        Self {
            endpoints: Arc::new(vec!["memory://lunes".into()]),
            archive_endpoint: None,
            static_info: None,
            static_native_balance: None,
            static_transaction_status: None,
            static_account_next_index: None,
            static_network_health: None,
            static_validator_set: Some(validator_set),
            static_staking_account: None,
        }
    }

    #[cfg(test)]
    pub fn static_staking_account(staking_account: StakingAccount) -> Self {
        Self {
            endpoints: Arc::new(vec!["memory://lunes".into()]),
            archive_endpoint: None,
            static_info: None,
            static_native_balance: None,
            static_transaction_status: None,
            static_account_next_index: None,
            static_network_health: None,
            static_validator_set: None,
            static_staking_account: Some(staking_account),
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

    pub async fn account_next_index(&self, address: &str) -> Result<u64, LunesClientError> {
        if let Some(account_next_index) = self.static_account_next_index {
            return Ok(account_next_index);
        }

        let mut last_error = None;
        for endpoint in self.endpoints.iter() {
            match fetch_account_next_index(endpoint, address).await {
                Ok(account_next_index) => return Ok(account_next_index),
                Err(error) => last_error = Some(error),
            }
        }

        Err(last_error.unwrap_or(LunesClientError::NoRpcEndpoints))
    }

    pub async fn network_health(&self) -> Result<NetworkHealth, LunesClientError> {
        if let Some(health) = &self.static_network_health {
            return Ok(health.clone());
        }

        let mut last_error = None;
        for endpoint in self.endpoints.iter() {
            match fetch_network_health(endpoint).await {
                Ok(health) => return Ok(health),
                Err(error) => last_error = Some(error),
            }
        }

        Err(last_error.unwrap_or(LunesClientError::NoRpcEndpoints))
    }

    pub async fn validator_set(&self) -> Result<ValidatorSet, LunesClientError> {
        if let Some(validator_set) = &self.static_validator_set {
            return Ok(validator_set.clone());
        }

        let mut last_error = None;
        for endpoint in self.endpoints.iter() {
            match fetch_validator_set(endpoint).await {
                Ok(validator_set) => return Ok(validator_set),
                Err(error) => last_error = Some(error),
            }
        }

        Err(last_error.unwrap_or(LunesClientError::NoRpcEndpoints))
    }

    pub async fn staking_account(
        &self,
        address: &str,
        account_id: [u8; 32],
    ) -> Result<StakingAccount, LunesClientError> {
        if let Some(staking_account) = &self.static_staking_account {
            return Ok(staking_account.clone());
        }

        let mut last_error = None;
        for endpoint in self.endpoints.iter() {
            match fetch_staking_account(endpoint, address, &account_id).await {
                Ok(staking_account) => return Ok(staking_account),
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

async fn fetch_account_next_index(endpoint: &str, address: &str) -> Result<u64, LunesClientError> {
    let client = connect_client(endpoint).await?;
    let value: Value = rpc_request_params(
        &client,
        "system_accountNextIndex",
        vec![Value::String(address.to_string())],
    )
    .await?;

    value_as_u64(&value).ok_or_else(|| {
        LunesClientError::InvalidRpcResponse("system_accountNextIndex returned no nonce".into())
    })
}

async fn fetch_network_health(endpoint: &str) -> Result<NetworkHealth, LunesClientError> {
    let client = connect_client(endpoint).await?;
    let chain = rpc_request(&client, "system_chain").await?;
    let node_name = rpc_request(&client, "system_name").await?;
    let node_version = rpc_request(&client, "system_version").await?;
    let health: Value = rpc_request(&client, "system_health").await?;
    let best_hash: String = rpc_request(&client, "chain_getHead").await?;
    let best_header: Value = rpc_request(&client, "chain_getHeader").await?;
    let finalized_hash: String = rpc_request(&client, "chain_getFinalizedHead").await?;
    let finalized_header: Value = rpc_request_params(
        &client,
        "chain_getHeader",
        vec![Value::String(finalized_hash.clone())],
    )
    .await?;
    let pending_extrinsics: Vec<String> = rpc_request(&client, "author_pendingExtrinsics")
        .await
        .unwrap_or_default();
    let methods: Value = rpc_request(&client, "rpc_methods")
        .await
        .unwrap_or(Value::Null);

    Ok(NetworkHealth {
        endpoint: endpoint.to_string(),
        chain,
        node_name,
        node_version,
        peers: required_u32(&health, "peers")?,
        is_syncing: required_bool(&health, "isSyncing")?,
        should_have_peers: required_bool(&health, "shouldHavePeers")?,
        best_block_hash: best_hash,
        best_block_number: header_number(&best_header)?,
        finalized_block_hash: finalized_hash,
        finalized_block_number: header_number(&finalized_header)?,
        pending_extrinsics: pending_extrinsics.len(),
        rpc_methods: methods
            .get("methods")
            .and_then(|value| value.as_array())
            .map(Vec::len)
            .unwrap_or(0),
    })
}

async fn fetch_validator_set(endpoint: &str) -> Result<ValidatorSet, LunesClientError> {
    let client = connect_client(endpoint).await?;
    let key = storage_prefix_key("Session", "Validators");
    let storage: Option<String> =
        rpc_request_params(&client, "state_getStorage", vec![Value::String(key)]).await?;
    let validators = decode_session_validators(storage.as_deref())?
        .into_iter()
        .map(encode_lunes_address)
        .collect();

    Ok(ValidatorSet {
        lookup: "session.validators".into(),
        validators,
    })
}

async fn fetch_staking_account(
    endpoint: &str,
    address: &str,
    account_id: &[u8; 32],
) -> Result<StakingAccount, LunesClientError> {
    let client = connect_client(endpoint).await?;
    let bonded_storage =
        staking_storage_for_account(&client, "Bonded", StorageHasher::Twox64Concat, account_id)
            .await?;
    let bonded_controller = bonded_storage
        .as_deref()
        .map(decode_account_id)
        .transpose()?;
    let controller_account_id = bonded_controller.unwrap_or(*account_id);

    let ledger_storage = staking_storage_for_account(
        &client,
        "Ledger",
        StorageHasher::Blake2_128Concat,
        &controller_account_id,
    )
    .await?;
    let ledger = ledger_storage
        .as_deref()
        .map(decode_staking_ledger)
        .transpose()?;
    let stash_account_id = ledger
        .as_ref()
        .map(|ledger| ledger.stash_account_id)
        .unwrap_or(*account_id);

    let payee_storage = staking_storage_for_account(
        &client,
        "Payee",
        StorageHasher::Twox64Concat,
        &stash_account_id,
    )
    .await?;
    let reward_destination = payee_storage
        .as_deref()
        .map(decode_reward_destination)
        .transpose()?;

    let nominations_storage = staking_storage_for_account(
        &client,
        "Nominators",
        StorageHasher::Twox64Concat,
        &stash_account_id,
    )
    .await?;
    let nominations = nominations_storage
        .as_deref()
        .map(decode_nominations)
        .transpose()?;

    let validator_storage = staking_storage_for_account(
        &client,
        "Validators",
        StorageHasher::Twox64Concat,
        &stash_account_id,
    )
    .await?;
    let validator_prefs = validator_storage
        .as_deref()
        .map(decode_validator_prefs)
        .transpose()?;

    let has_bond = bonded_storage.is_some() || ledger.is_some();
    let roles = staking_roles(has_bond, nominations.is_some(), validator_prefs.is_some());

    Ok(StakingAccount {
        address: address.to_string(),
        stash_address: encode_lunes_address(stash_account_id),
        controller_address: has_bond.then(|| encode_lunes_address(controller_account_id)),
        bonded: has_bond,
        roles,
        ledger,
        reward_destination,
        nominations,
        validator_prefs,
        lookup: "live_lunes_rpc_staking_storage".into(),
    })
}

async fn staking_storage_for_account(
    client: &WsClient,
    item: &str,
    hasher: StorageHasher,
    account_id: &[u8; 32],
) -> Result<Option<String>, LunesClientError> {
    let key = storage_map_key("Staking", item, hasher, account_id);
    rpc_request_params(client, "state_getStorage", vec![Value::String(key)]).await
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

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NetworkHealth {
    pub endpoint: String,
    pub chain: String,
    pub node_name: String,
    pub node_version: String,
    pub peers: u32,
    pub is_syncing: bool,
    pub should_have_peers: bool,
    pub best_block_hash: String,
    pub best_block_number: u64,
    pub finalized_block_hash: String,
    pub finalized_block_number: u64,
    pub pending_extrinsics: usize,
    pub rpc_methods: usize,
}

impl NetworkHealth {
    pub fn finality_lag_blocks(&self) -> u64 {
        self.best_block_number
            .saturating_sub(self.finalized_block_number)
    }

    pub fn status(&self) -> &'static str {
        if self.is_syncing || (self.should_have_peers && self.peers == 0) {
            "degraded"
        } else {
            "healthy"
        }
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
pub struct ValidatorSet {
    pub lookup: String,
    pub validators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StakingAccount {
    pub address: String,
    pub stash_address: String,
    pub controller_address: Option<String>,
    pub bonded: bool,
    pub roles: Vec<String>,
    pub ledger: Option<StakingLedger>,
    pub reward_destination: Option<StakingRewardDestination>,
    pub nominations: Option<Nominations>,
    pub validator_prefs: Option<ValidatorPrefs>,
    pub lookup: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StakingLedger {
    #[serde(skip)]
    pub stash_account_id: [u8; 32],
    pub stash_address: String,
    pub total_base_units: u128,
    pub active_base_units: u128,
    pub unlocking_or_inactive_base_units: u128,
    pub unlocking: Vec<UnlockChunk>,
    pub claimed_rewards: Vec<u32>,
    pub raw_extra_bytes: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UnlockChunk {
    pub value_base_units: u128,
    pub era: u32,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StakingRewardDestination {
    pub destination: String,
    pub account: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Nominations {
    pub targets: Vec<String>,
    pub submitted_in: Option<u32>,
    pub suppressed: Option<bool>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ValidatorPrefs {
    pub commission_perbill: u32,
    pub commission_percent: String,
    pub blocked: bool,
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

fn required_bool(value: &Value, key: &str) -> Result<bool, LunesClientError> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| LunesClientError::InvalidRpcResponse(format!("missing {key}")))
}

fn header_number(value: &Value) -> Result<u64, LunesClientError> {
    value
        .get("number")
        .and_then(|value| value.as_str())
        .ok_or_else(|| LunesClientError::InvalidRpcResponse("missing header number".into()))
        .and_then(hex_to_u64)
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

fn storage_prefix_key(pallet: &str, item: &str) -> String {
    let mut key = Vec::with_capacity(32);
    key.extend_from_slice(&twox128(pallet.as_bytes()));
    key.extend_from_slice(&twox128(item.as_bytes()));
    format!("0x{}", hex::encode(key))
}

#[derive(Debug, Clone, Copy)]
enum StorageHasher {
    Twox64Concat,
    Blake2_128Concat,
}

fn storage_map_key(
    pallet: &str,
    item: &str,
    hasher: StorageHasher,
    key_payload: &[u8; 32],
) -> String {
    let mut key = hex_to_bytes(&storage_prefix_key(pallet, item)).expect("storage prefix is hex");
    match hasher {
        StorageHasher::Twox64Concat => {
            key.extend_from_slice(&xxhash64(key_payload, 0).to_le_bytes());
            key.extend_from_slice(key_payload);
        }
        StorageHasher::Blake2_128Concat => {
            key.extend_from_slice(&blake2_hash::<16>(key_payload));
            key.extend_from_slice(key_payload);
        }
    }
    format!("0x{}", hex::encode(key))
}

fn twox128(input: &[u8]) -> [u8; 16] {
    let first = xxhash64(input, 0).to_le_bytes();
    let second = xxhash64(input, 1).to_le_bytes();
    let mut output = [0u8; 16];
    output[..8].copy_from_slice(&first);
    output[8..].copy_from_slice(&second);
    output
}

fn xxhash64(input: &[u8], seed: u64) -> u64 {
    const PRIME64_1: u64 = 11_400_714_785_074_694_791;
    const PRIME64_2: u64 = 14_029_467_366_897_019_727;
    const PRIME64_3: u64 = 1_609_587_929_392_839_161;
    const PRIME64_4: u64 = 9_650_029_242_287_828_579;
    const PRIME64_5: u64 = 2_870_177_450_012_600_261;

    let mut offset = 0;
    let mut hash;

    if input.len() >= 32 {
        let mut v1 = seed.wrapping_add(PRIME64_1).wrapping_add(PRIME64_2);
        let mut v2 = seed.wrapping_add(PRIME64_2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(PRIME64_1);

        while offset <= input.len() - 32 {
            v1 = xxhash64_round(v1, read_u64_le_unchecked(input, offset));
            v2 = xxhash64_round(v2, read_u64_le_unchecked(input, offset + 8));
            v3 = xxhash64_round(v3, read_u64_le_unchecked(input, offset + 16));
            v4 = xxhash64_round(v4, read_u64_le_unchecked(input, offset + 24));
            offset += 32;
        }

        hash = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
        hash = xxhash64_merge_round(hash, v1);
        hash = xxhash64_merge_round(hash, v2);
        hash = xxhash64_merge_round(hash, v3);
        hash = xxhash64_merge_round(hash, v4);
    } else {
        hash = seed.wrapping_add(PRIME64_5);
    }

    hash = hash.wrapping_add(input.len() as u64);

    while offset + 8 <= input.len() {
        let value = xxhash64_round(0, read_u64_le_unchecked(input, offset));
        hash ^= value;
        hash = hash
            .rotate_left(27)
            .wrapping_mul(PRIME64_1)
            .wrapping_add(PRIME64_4);
        offset += 8;
    }

    if offset + 4 <= input.len() {
        hash ^= (read_u32_le_unchecked(input, offset) as u64).wrapping_mul(PRIME64_1);
        hash = hash
            .rotate_left(23)
            .wrapping_mul(PRIME64_2)
            .wrapping_add(PRIME64_3);
        offset += 4;
    }

    while offset < input.len() {
        hash ^= (input[offset] as u64).wrapping_mul(PRIME64_5);
        hash = hash.rotate_left(11).wrapping_mul(PRIME64_1);
        offset += 1;
    }

    hash ^= hash >> 33;
    hash = hash.wrapping_mul(PRIME64_2);
    hash ^= hash >> 29;
    hash = hash.wrapping_mul(PRIME64_3);
    hash ^ (hash >> 32)
}

fn xxhash64_round(accumulator: u64, input: u64) -> u64 {
    const PRIME64_1: u64 = 11_400_714_785_074_694_791;
    const PRIME64_2: u64 = 14_029_467_366_897_019_727;
    accumulator
        .wrapping_add(input.wrapping_mul(PRIME64_2))
        .rotate_left(31)
        .wrapping_mul(PRIME64_1)
}

fn xxhash64_merge_round(accumulator: u64, value: u64) -> u64 {
    const PRIME64_1: u64 = 11_400_714_785_074_694_791;
    const PRIME64_4: u64 = 9_650_029_242_287_828_579;
    (accumulator ^ xxhash64_round(0, value))
        .wrapping_mul(PRIME64_1)
        .wrapping_add(PRIME64_4)
}

fn read_u64_le_unchecked(bytes: &[u8], offset: usize) -> u64 {
    let mut output = [0u8; 8];
    output.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(output)
}

fn read_u32_le_unchecked(bytes: &[u8], offset: usize) -> u32 {
    let mut output = [0u8; 4];
    output.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(output)
}

fn decode_session_validators(storage: Option<&str>) -> Result<Vec<[u8; 32]>, LunesClientError> {
    let Some(storage) = storage else {
        return Ok(Vec::new());
    };
    let bytes = hex_to_bytes(storage)?;
    if bytes.is_empty() {
        return Ok(Vec::new());
    }

    let (count, mut offset) = decode_compact_u32(&bytes)?;
    let required_len = offset + (count as usize * 32);
    if bytes.len() < required_len {
        return Err(LunesClientError::InvalidRpcResponse(format!(
            "session validators storage is too short: {} bytes",
            bytes.len()
        )));
    }

    let mut validators = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let mut account_id = [0u8; 32];
        account_id.copy_from_slice(&bytes[offset..offset + 32]);
        validators.push(account_id);
        offset += 32;
    }

    Ok(validators)
}

fn decode_compact_u32(bytes: &[u8]) -> Result<(u32, usize), LunesClientError> {
    let Some(first) = bytes.first() else {
        return Err(LunesClientError::InvalidRpcResponse(
            "missing compact length".into(),
        ));
    };

    match first & 0b11 {
        0 => Ok(((first >> 2) as u32, 1)),
        1 => {
            if bytes.len() < 2 {
                return Err(LunesClientError::InvalidRpcResponse(
                    "compact length is truncated".into(),
                ));
            }
            let encoded = u16::from_le_bytes([bytes[0], bytes[1]]);
            Ok(((encoded >> 2) as u32, 2))
        }
        2 => {
            if bytes.len() < 4 {
                return Err(LunesClientError::InvalidRpcResponse(
                    "compact length is truncated".into(),
                ));
            }
            let encoded = u32::from_le_bytes(bytes[..4].try_into().expect("slice length checked"));
            Ok((encoded >> 2, 4))
        }
        _ => Err(LunesClientError::InvalidRpcResponse(
            "large compact lengths are not supported".into(),
        )),
    }
}

fn decode_account_id(storage: &str) -> Result<[u8; 32], LunesClientError> {
    let bytes = hex_to_bytes(storage)?;
    account_id_from_slice(&bytes)
}

fn account_id_from_slice(bytes: &[u8]) -> Result<[u8; 32], LunesClientError> {
    let raw = bytes
        .get(..32)
        .ok_or_else(|| LunesClientError::InvalidRpcResponse("missing account id".into()))?;
    let mut account_id = [0u8; 32];
    account_id.copy_from_slice(raw);
    Ok(account_id)
}

fn decode_staking_ledger(storage: &str) -> Result<StakingLedger, LunesClientError> {
    let bytes = hex_to_bytes(storage)?;
    if bytes.len() < 34 {
        return Err(LunesClientError::InvalidRpcResponse(format!(
            "staking ledger storage is too short: {} bytes",
            bytes.len()
        )));
    }

    let stash_account_id = account_id_from_slice(&bytes)?;
    let mut offset = 32;
    let (total_base_units, total_offset) = decode_compact_u128_at(&bytes, offset)?;
    offset = total_offset;
    let (active_base_units, active_offset) = decode_compact_u128_at(&bytes, offset)?;
    offset = active_offset;

    let (unlocking, claimed_rewards, raw_extra_bytes) = decode_ledger_extra(&bytes[offset..]);

    Ok(StakingLedger {
        stash_account_id,
        stash_address: encode_lunes_address(stash_account_id),
        total_base_units,
        active_base_units,
        unlocking_or_inactive_base_units: total_base_units.saturating_sub(active_base_units),
        unlocking,
        claimed_rewards,
        raw_extra_bytes,
    })
}

fn decode_ledger_extra(bytes: &[u8]) -> (Vec<UnlockChunk>, Vec<u32>, usize) {
    if bytes.is_empty() {
        return (Vec::new(), Vec::new(), 0);
    }

    if bytes.len() == 2 && bytes == [0, 0] {
        return (Vec::new(), Vec::new(), 0);
    }

    if let Ok((unlocking, offset)) = decode_unlock_chunks(bytes) {
        if offset == bytes.len() {
            return (unlocking, Vec::new(), 0);
        }

        if let Ok((claimed_rewards, claimed_offset)) = decode_u32_vec(&bytes[offset..]) {
            if offset + claimed_offset == bytes.len() {
                return (unlocking, claimed_rewards, 0);
            }
        }
    }

    (Vec::new(), Vec::new(), bytes.len())
}

fn decode_reward_destination(storage: &str) -> Result<StakingRewardDestination, LunesClientError> {
    let bytes = hex_to_bytes(storage)?;
    let Some(kind) = bytes.first() else {
        return Err(LunesClientError::InvalidRpcResponse(
            "missing reward destination".into(),
        ));
    };

    let destination = match kind {
        0 => "staked",
        1 => "stash",
        2 => "controller",
        3 => "account",
        4 => "none",
        _ => "unknown",
    };
    let account = if *kind == 3 {
        let account_id = account_id_from_slice(&bytes[1..])?;
        Some(encode_lunes_address(account_id))
    } else {
        None
    };

    Ok(StakingRewardDestination {
        destination: destination.into(),
        account,
    })
}

fn decode_nominations(storage: &str) -> Result<Nominations, LunesClientError> {
    let bytes = hex_to_bytes(storage)?;
    let (targets_raw, mut offset) = decode_account_id_vec(&bytes)?;
    let submitted_in = if bytes.len() >= offset + 4 {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(&bytes[offset..offset + 4]);
        offset += 4;
        Some(u32::from_le_bytes(raw))
    } else {
        None
    };
    let suppressed = bytes.get(offset).map(|value| *value != 0);

    Ok(Nominations {
        targets: targets_raw.into_iter().map(encode_lunes_address).collect(),
        submitted_in,
        suppressed,
    })
}

fn decode_validator_prefs(storage: &str) -> Result<ValidatorPrefs, LunesClientError> {
    let bytes = hex_to_bytes(storage)?;
    let (commission_perbill, offset) = decode_compact_u128_at(&bytes, 0)?;
    let blocked = bytes.get(offset).map(|value| *value != 0).unwrap_or(false);
    let commission_perbill = u32::try_from(commission_perbill).map_err(|_| {
        LunesClientError::InvalidRpcResponse("validator commission is too large".into())
    })?;

    Ok(ValidatorPrefs {
        commission_perbill,
        commission_percent: format_perbill_percent(commission_perbill),
        blocked,
    })
}

fn format_perbill_percent(value: u32) -> String {
    let scaled = (value as u128 * 1_000_000 + 500_000_000) / 1_000_000_000;
    let whole = scaled / 10_000;
    let fractional = scaled % 10_000;
    format!("{whole}.{fractional:04}")
}

fn staking_roles(bonded: bool, nominator: bool, validator: bool) -> Vec<String> {
    let mut roles = Vec::new();
    if bonded {
        roles.push("bonded".into());
    }
    if nominator {
        roles.push("nominator".into());
    }
    if validator {
        roles.push("validator".into());
    }
    if roles.is_empty() {
        roles.push("idle".into());
    }
    roles
}

fn decode_account_id_vec(bytes: &[u8]) -> Result<(Vec<[u8; 32]>, usize), LunesClientError> {
    let (count, mut offset) = decode_compact_u32(bytes)?;
    let required_len = offset + (count as usize * 32);
    if bytes.len() < required_len {
        return Err(LunesClientError::InvalidRpcResponse(
            "account id vector is truncated".into(),
        ));
    }

    let mut accounts = Vec::with_capacity(count as usize);
    for _ in 0..count {
        accounts.push(account_id_from_slice(&bytes[offset..offset + 32])?);
        offset += 32;
    }

    Ok((accounts, offset))
}

fn decode_u32_vec(bytes: &[u8]) -> Result<(Vec<u32>, usize), LunesClientError> {
    let (count, mut offset) = decode_compact_u32(bytes)?;
    let required_len = offset + (count as usize * 4);
    if bytes.len() < required_len {
        return Err(LunesClientError::InvalidRpcResponse(
            "u32 vector is truncated".into(),
        ));
    }

    let mut values = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(&bytes[offset..offset + 4]);
        values.push(u32::from_le_bytes(raw));
        offset += 4;
    }

    Ok((values, offset))
}

fn decode_unlock_chunks(bytes: &[u8]) -> Result<(Vec<UnlockChunk>, usize), LunesClientError> {
    let (count, mut offset) = decode_compact_u32(bytes)?;
    let mut chunks = Vec::with_capacity(count as usize);

    for _ in 0..count {
        let (value_base_units, value_offset) = decode_compact_u128_at(bytes, offset)?;
        offset = value_offset;

        let raw_era = bytes.get(offset..offset + 4).ok_or_else(|| {
            LunesClientError::InvalidRpcResponse("unlock chunk era is truncated".into())
        })?;
        let era = u32::from_le_bytes(raw_era.try_into().expect("slice length checked"));
        offset += 4;

        chunks.push(UnlockChunk {
            value_base_units,
            era,
        });
    }

    Ok((chunks, offset))
}

fn decode_compact_u128_at(bytes: &[u8], offset: usize) -> Result<(u128, usize), LunesClientError> {
    let Some(first) = bytes.get(offset) else {
        return Err(LunesClientError::InvalidRpcResponse(
            "missing compact integer".into(),
        ));
    };

    match first & 0b11 {
        0 => Ok(((first >> 2) as u128, offset + 1)),
        1 => {
            let raw = bytes.get(offset..offset + 2).ok_or_else(|| {
                LunesClientError::InvalidRpcResponse("compact integer is truncated".into())
            })?;
            let encoded = u16::from_le_bytes(raw.try_into().expect("slice length checked"));
            Ok(((encoded >> 2) as u128, offset + 2))
        }
        2 => {
            let raw = bytes.get(offset..offset + 4).ok_or_else(|| {
                LunesClientError::InvalidRpcResponse("compact integer is truncated".into())
            })?;
            let encoded = u32::from_le_bytes(raw.try_into().expect("slice length checked"));
            Ok(((encoded >> 2) as u128, offset + 4))
        }
        _ => {
            let byte_len = ((first >> 2) + 4) as usize;
            if byte_len > 16 {
                return Err(LunesClientError::InvalidRpcResponse(
                    "compact integer exceeds u128".into(),
                ));
            }
            let raw = bytes
                .get(offset + 1..offset + 1 + byte_len)
                .ok_or_else(|| {
                    LunesClientError::InvalidRpcResponse("compact integer is truncated".into())
                })?;
            let mut output = [0u8; 16];
            output[..byte_len].copy_from_slice(raw);
            Ok((u128::from_le_bytes(output), offset + 1 + byte_len))
        }
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
    fn storage_prefix_key_matches_known_system_account_prefix() {
        assert_eq!(
            storage_prefix_key("System", "Account").trim_start_matches("0x"),
            LUNES_ACCOUNT_STORAGE_PREFIX
        );
    }

    #[test]
    fn decodes_session_validators_storage() {
        let first = [1u8; 32];
        let second = [2u8; 32];
        let mut storage = vec![2 << 2];
        storage.extend_from_slice(&first);
        storage.extend_from_slice(&second);

        let validators =
            decode_session_validators(Some(&format!("0x{}", hex::encode(storage)))).unwrap();

        assert_eq!(validators, vec![first, second]);
    }

    #[test]
    fn decodes_staking_ledger_storage() {
        let stash = [8u8; 32];
        let mut storage = stash.to_vec();
        storage.extend_from_slice(&compact_u128(5_000_000_000_000));
        storage.extend_from_slice(&compact_u128(4_000_000_000_000));
        storage.push(1 << 2);
        storage.extend_from_slice(&compact_u128(1_000_000_000_000));
        storage.extend_from_slice(&120u32.to_le_bytes());
        storage.push(2 << 2);
        storage.extend_from_slice(&100u32.to_le_bytes());
        storage.extend_from_slice(&101u32.to_le_bytes());

        let ledger = decode_staking_ledger(&format!("0x{}", hex::encode(storage))).unwrap();

        assert_eq!(ledger.stash_account_id, stash);
        assert_eq!(ledger.total_base_units, 5_000_000_000_000);
        assert_eq!(ledger.active_base_units, 4_000_000_000_000);
        assert_eq!(ledger.unlocking_or_inactive_base_units, 1_000_000_000_000);
        assert_eq!(ledger.unlocking.len(), 1);
        assert_eq!(ledger.unlocking[0].value_base_units, 1_000_000_000_000);
        assert_eq!(ledger.unlocking[0].era, 120);
        assert_eq!(ledger.claimed_rewards, vec![100, 101]);
        assert_eq!(ledger.raw_extra_bytes, 0);
    }

    #[test]
    fn decodes_reward_destination_and_validator_prefs() {
        let payee = decode_reward_destination("0x00").unwrap();
        assert_eq!(payee.destination, "staked");
        assert_eq!(payee.account, None);

        let mut prefs = compact_u128(390_625);
        prefs.push(0);
        let prefs = decode_validator_prefs(&format!("0x{}", hex::encode(prefs))).unwrap();
        assert_eq!(prefs.commission_perbill, 390_625);
        assert_eq!(prefs.commission_percent, "0.0391");
        assert!(!prefs.blocked);
    }

    fn compact_u128(value: u128) -> Vec<u8> {
        if value < 1 << 6 {
            return vec![(value as u8) << 2];
        }
        if value < 1 << 14 {
            return (((value as u16) << 2) | 0b01).to_le_bytes().to_vec();
        }
        if value < 1 << 30 {
            return (((value as u32) << 2) | 0b10).to_le_bytes().to_vec();
        }

        let mut raw = value.to_le_bytes().to_vec();
        while raw.last() == Some(&0) {
            raw.pop();
        }
        let mut encoded = vec![(((raw.len() - 4) as u8) << 2) | 0b11];
        encoded.extend(raw);
        encoded
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
