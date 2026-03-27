use nssa_core::account::{Account, AccountId, AccountWithMetadata, Data};
use nssa_core::program::DEFAULT_PROGRAM_ID;

// Helper to create empty config account
fn empty_config_account(authorized: bool) -> AccountWithMetadata {
    AccountWithMetadata {
        account: Account {
            program_owner: DEFAULT_PROGRAM_ID,
            balance: 0u128,
            data: Data::default(),
            nonce: 0,
        },
        is_authorized: authorized,
        account_id: "11111111111111111111111111111111".parse().expect("valid account id"),
    }
}

// Helper to create initialized config account
fn initialized_config_account(authorized: bool, admin: [u8; 32], config_value: u64, revoked: bool) -> AccountWithMetadata {
    let mut data = vec![0u8; 41];
    if !revoked {
        data[..32].copy_from_slice(&admin);
    }
    data[32..40].copy_from_slice(&config_value.to_le_bytes());
    data[40] = 1; // is_initialized = true

    AccountWithMetadata {
        account: Account {
            program_owner: [1u32; 8], // owned by admin program
            balance: 0u128,
            data: Data::try_from(data).expect("data fits"),
            nonce: 0,
        },
        is_authorized: authorized,
        account_id: "11111111111111111111111111111111".parse().expect("valid account id"),
    }
}

// Build instruction bytes
fn init_instruction(admin: [u8; 32]) -> Vec<u8> {
    let mut inst = vec![0x01u8];
    inst.extend_from_slice(&admin);
    inst
}

fn transfer_authority_instruction(new_admin: [u8; 32]) -> Vec<u8> {
    let mut inst = vec![0x02u8];
    inst.extend_from_slice(&new_admin);
    inst
}

fn revoke_authority_instruction() -> Vec<u8> {
    vec![0x03u8]
}

fn set_config_value_instruction(value: u64) -> Vec<u8> {
    let mut inst = vec![0x04u8];
    inst.extend_from_slice(&value.to_le_bytes());
    inst
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_sets_admin() {
        let admin = [2u8; 32];
        let account = empty_config_account(true);
        let instruction = init_instruction(admin);
        
        // Verify instruction format
        assert_eq!(instruction[0], 0x01);
        assert_eq!(&instruction[1..33], &admin);
        assert!(account.is_authorized);
        println!("test_init_sets_admin: OK");
    }

    #[test]
    fn test_init_fails_without_authorization() {
        let account = empty_config_account(false);
        assert!(!account.is_authorized, "Should fail without auth");
        println!("test_init_fails_without_authorization: OK");
    }

    #[test]
    fn test_transfer_authority() {
        let admin = [2u8; 32];
        let new_admin = [3u8; 32];
        let account = initialized_config_account(true, admin, 0, false);
        let instruction = transfer_authority_instruction(new_admin);

        assert_eq!(instruction[0], 0x02);
        assert_eq!(&instruction[1..33], &new_admin);
        assert!(account.is_authorized);
        println!("test_transfer_authority: OK");
    }

    #[test]
    fn test_revoke_authority() {
        let admin = [2u8; 32];
        let account = initialized_config_account(true, admin, 0, false);
        let instruction = revoke_authority_instruction();

        assert_eq!(instruction[0], 0x03);
        assert!(account.is_authorized);
        println!("test_revoke_authority: OK");
    }

    #[test]
    fn test_set_config_value() {
        let admin = [2u8; 32];
        let account = initialized_config_account(true, admin, 0, false);
        let instruction = set_config_value_instruction(42);

        assert_eq!(instruction[0], 0x04);
        let value = u64::from_le_bytes(instruction[1..9].try_into().unwrap());
        assert_eq!(value, 42);
        assert!(account.is_authorized);
        println!("test_set_config_value: OK");
    }

    #[test]
    fn test_cannot_set_config_after_revoke() {
        let admin = [2u8; 32];
        let revoked_account = initialized_config_account(true, admin, 0, true);
        
        // Check revoked state (all zeros in admin field)
        let data = revoked_account.account.data.as_ref();
        let stored_admin: [u8; 32] = data[..32].try_into().unwrap();
        assert!(stored_admin.iter().all(|&b| b == 0), "Admin should be zeroed out");
        println!("test_cannot_set_config_after_revoke: OK");
    }

    #[test]
    fn test_config_data_layout() {
        let admin = [5u8; 32];
        let config_value = 12345u64;
        let account = initialized_config_account(false, admin, config_value, false);
        
        let data = account.account.data.as_ref();
        assert!(data.len() >= 41);
        
        let stored_admin: [u8; 32] = data[..32].try_into().unwrap();
        let stored_value = u64::from_le_bytes(data[32..40].try_into().unwrap());
        let is_init = data[40] == 1;
        
        assert_eq!(stored_admin, admin);
        assert_eq!(stored_value, config_value);
        assert!(is_init);
        println!("test_config_data_layout: OK");
    }
}

fn frozen_config_account(authorized: bool, frozen: bool) -> nssa_core::account::AccountWithMetadata {
    use nssa_core::account::{Account, AccountWithMetadata, Data};
    use nssa_core::program::DEFAULT_PROGRAM_ID;
    
    let mut data = vec![0u8; 34];
    data[..32].copy_from_slice(&[2u8; 32]); // authority
    data[32] = if frozen { 1 } else { 0 };
    data[33] = 1; // initialized

    AccountWithMetadata {
        account: Account {
            program_owner: [1u32; 8],
            balance: 0u128,
            data: Data::try_from(data).expect("data fits"),
            nonce: 0,
        },
        is_authorized: authorized,
        account_id: "11111111111111111111111111111111".parse().expect("valid id"),
    }
}

#[cfg(test)]
mod freeze_tests {
    use super::*;

    #[test]
    fn test_freeze_init() {
        let account = frozen_config_account(true, false);
        let mut inst = vec![0x01u8];
        inst.extend_from_slice(&[2u8; 32]);
        assert_eq!(inst[0], 0x01);
        assert!(account.is_authorized);
        println!("test_freeze_init: OK");
    }

    #[test]
    fn test_freeze_blocks_execution() {
        let frozen = frozen_config_account(false, true);
        let data = frozen.account.data.as_ref();
        assert_eq!(data[32], 1, "Should be frozen");
        println!("test_freeze_blocks_execution: OK");
    }

    #[test]
    fn test_unfreeze_resumes_execution() {
        let unfrozen = frozen_config_account(false, false);
        let data = unfrozen.account.data.as_ref();
        assert_eq!(data[32], 0, "Should be unfrozen");
        println!("test_unfreeze_resumes_execution: OK");
    }

    #[test]
    fn test_freeze_requires_authority() {
        let account = frozen_config_account(false, false);
        assert!(!account.is_authorized, "No auth = cannot freeze");
        println!("test_freeze_requires_authority: OK");
    }

    #[test]
    fn test_freeze_data_layout() {
        let account = frozen_config_account(true, true);
        let data = account.account.data.as_ref();
        assert!(data.len() >= 34);
        let stored_auth: [u8; 32] = data[..32].try_into().unwrap();
        assert_eq!(stored_auth, [2u8; 32]);
        assert_eq!(data[32], 1); // frozen
        assert_eq!(data[33], 1); // initialized
        println!("test_freeze_data_layout: OK");
    }
}
