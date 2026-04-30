use serde::{Deserialize, Serialize};

/// Identifies a 4-byte Lunes contract message selector.
pub type Selector = [u8; 4];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContractMessage {
    pub interface: &'static str,
    pub name: &'static str,
    pub selector_hex: &'static str,
    pub mutates_state: bool,
}

/// Local registry for common Lunes contract interfaces.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AbiRegistry;

impl AbiRegistry {
    pub fn new() -> Self {
        Self
    }

    /// Resolves a known message name into its 4-byte selector.
    pub fn resolve_selector(&self, method_name: &str) -> Option<Selector> {
        match method_name {
            "PSP22::total_supply" => Some([0x16, 0x2d, 0xf8, 0xc2]),
            "PSP22::balance_of" => Some([0x65, 0x68, 0x38, 0x2f]),
            "PSP22::allowance" => Some([0x4d, 0x47, 0xd9, 0x21]),
            "PSP22::transfer" => Some([0x84, 0xa1, 0x5d, 0xa1]),
            "PSP22::transfer_from" => Some([0x0b, 0x39, 0x6f, 0x18]),
            "PSP22::approve" => Some([0xb2, 0x0f, 0x1b, 0xbd]),
            "PSP22::increase_allowance" => Some([0x96, 0xd6, 0xb5, 0x7a]),
            "PSP22::decrease_allowance" => Some([0xfe, 0xcb, 0x57, 0xd5]),

            "total_supply" => Some([0x16, 0x2d, 0xf8, 0xc2]),
            "balance_of" => Some([0x65, 0x68, 0x38, 0x2f]),
            "transfer" => Some([0x84, 0xa1, 0x5d, 0xa1]),

            _ => None,
        }
    }

    pub fn known_messages(&self) -> Vec<ContractMessage> {
        vec![
            ContractMessage {
                interface: "PSP22",
                name: "total_supply",
                selector_hex: "0x162df8c2",
                mutates_state: false,
            },
            ContractMessage {
                interface: "PSP22",
                name: "balance_of",
                selector_hex: "0x6568382f",
                mutates_state: false,
            },
            ContractMessage {
                interface: "PSP22",
                name: "allowance",
                selector_hex: "0x4d47d921",
                mutates_state: false,
            },
            ContractMessage {
                interface: "PSP22",
                name: "transfer",
                selector_hex: "0x84a15da1",
                mutates_state: true,
            },
            ContractMessage {
                interface: "PSP22",
                name: "transfer_from",
                selector_hex: "0x0b396f18",
                mutates_state: true,
            },
            ContractMessage {
                interface: "PSP22",
                name: "approve",
                selector_hex: "0xb20f1bbd",
                mutates_state: true,
            },
            ContractMessage {
                interface: "PSP22",
                name: "increase_allowance",
                selector_hex: "0x96d6b57a",
                mutates_state: true,
            },
            ContractMessage {
                interface: "PSP22",
                name: "decrease_allowance",
                selector_hex: "0xfecb57d5",
                mutates_state: true,
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_psp22_balance_selector() {
        let registry = AbiRegistry::new();

        assert_eq!(
            registry.resolve_selector("PSP22::balance_of"),
            Some([0x65, 0x68, 0x38, 0x2f])
        );
    }
}
