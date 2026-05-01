//! Lunes address validation.

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};

pub const LUNES_SS58_PREFIX: u16 = 57;
const SS58_PREFIX: &[u8] = b"SS58PRE";
const ACCOUNT_ID_LEN: usize = 32;
const CHECKSUM_LEN: usize = 2;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AddressError {
    #[error("address is not valid base58")]
    InvalidBase58,
    #[error("address payload length is not supported")]
    InvalidLength,
    #[error("address prefix is {actual}, expected Lunes prefix {expected}")]
    WrongPrefix { actual: u16, expected: u16 },
    #[error("address checksum is invalid")]
    InvalidChecksum,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LunesAddress {
    pub account_id: [u8; ACCOUNT_ID_LEN],
    pub ss58_prefix: u16,
}

pub fn validate_lunes_address(address: &str) -> Result<LunesAddress, AddressError> {
    let decoded = bs58::decode(address)
        .into_vec()
        .map_err(|_| AddressError::InvalidBase58)?;

    if decoded.len() != 1 + ACCOUNT_ID_LEN + CHECKSUM_LEN {
        return Err(AddressError::InvalidLength);
    }

    let ss58_prefix = decoded[0] as u16;
    if ss58_prefix != LUNES_SS58_PREFIX {
        return Err(AddressError::WrongPrefix {
            actual: ss58_prefix,
            expected: LUNES_SS58_PREFIX,
        });
    }

    let payload_len = 1 + ACCOUNT_ID_LEN;
    let expected_checksum = ss58_checksum(&decoded[..payload_len]);
    if decoded[payload_len..] != expected_checksum[..] {
        return Err(AddressError::InvalidChecksum);
    }

    let mut account_id = [0u8; ACCOUNT_ID_LEN];
    account_id.copy_from_slice(&decoded[1..payload_len]);

    Ok(LunesAddress {
        account_id,
        ss58_prefix,
    })
}

fn ss58_checksum(payload: &[u8]) -> [u8; CHECKSUM_LEN] {
    let mut hasher = Blake2bVar::new(64).expect("valid Blake2b output size");
    hasher.update(SS58_PREFIX);
    hasher.update(payload);

    let mut output = [0u8; 64];
    hasher
        .finalize_variable(&mut output)
        .expect("Blake2b output buffer has the configured size");

    [output[0], output[1]]
}

pub fn encode_lunes_address(account_id: [u8; ACCOUNT_ID_LEN]) -> String {
    let mut payload = Vec::with_capacity(1 + ACCOUNT_ID_LEN + CHECKSUM_LEN);
    payload.push(LUNES_SS58_PREFIX as u8);
    payload.extend_from_slice(&account_id);
    payload.extend_from_slice(&ss58_checksum(&payload));
    bs58::encode(payload).into_string()
}

#[cfg(test)]
pub fn encode_lunes_address_for_tests(account_id: [u8; ACCOUNT_ID_LEN]) -> String {
    encode_lunes_address(account_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_lunes_prefix_and_checksum() {
        let address = encode_lunes_address_for_tests([7u8; ACCOUNT_ID_LEN]);
        let parsed = validate_lunes_address(&address).expect("valid Lunes address");

        assert_eq!(parsed.ss58_prefix, LUNES_SS58_PREFIX);
        assert_eq!(parsed.account_id, [7u8; ACCOUNT_ID_LEN]);
    }

    #[test]
    fn rejects_non_lunes_prefix() {
        let wrong_network_address = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
        let error = validate_lunes_address(wrong_network_address).unwrap_err();

        assert_eq!(
            error,
            AddressError::WrongPrefix {
                actual: 42,
                expected: LUNES_SS58_PREFIX,
            }
        );
    }

    #[test]
    fn rejects_checksum_mismatch() {
        let mut address = encode_lunes_address_for_tests([9u8; ACCOUNT_ID_LEN]);
        address.pop();
        address.push('1');

        assert_eq!(
            validate_lunes_address(&address).unwrap_err(),
            AddressError::InvalidChecksum
        );
    }
}
