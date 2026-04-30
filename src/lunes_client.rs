//! Minimal Lunes Network RPC client.

use jsonrpsee::{
    core::client::ClientT,
    ws_client::{WsClient, WsClientBuilder},
};
use serde::Serialize;
use serde_json::Value;
use std::{sync::Arc, time::Duration};

#[derive(Clone)]
pub struct LunesClient {
    endpoints: Arc<Vec<String>>,
    static_info: Option<ChainInfo>,
}

impl LunesClient {
    pub fn new(primary: String, failovers: Vec<String>) -> Self {
        let mut endpoints = vec![primary];
        endpoints.extend(failovers);
        endpoints.dedup();
        Self {
            endpoints: Arc::new(endpoints),
            static_info: None,
        }
    }

    #[cfg(test)]
    pub fn static_info(info: ChainInfo) -> Self {
        Self {
            endpoints: Arc::new(vec![info.rpc_endpoint.clone()]),
            static_info: Some(info),
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
}

async fn fetch_chain_info(endpoint: &str) -> Result<ChainInfo, LunesClientError> {
    let client = WsClientBuilder::default()
        .connection_timeout(Duration::from_secs(5))
        .request_timeout(Duration::from_secs(5))
        .build(endpoint)
        .await
        .map_err(|error| LunesClientError::RpcConnection {
            endpoint: endpoint.to_string(),
            message: error.to_string(),
        })?;

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
