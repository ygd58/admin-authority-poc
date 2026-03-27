use nssa_core::program::{
    AccountPostState, DEFAULT_PROGRAM_ID, ProgramInput, read_nssa_inputs, write_nssa_outputs,
};

// Admin Authority PoC — RFP-001
//
// Instruction encoding:
//   byte[0] = opcode
//     0x01 = Init
//     0x02 = TransferAuthority (followed by 32-byte new admin pubkey)
//     0x03 = RevokeAuthority
//     0x04 = SetConfigValue (followed by 8-byte u64 little-endian)

// Config data layout (stored in account.data):
//   bytes[0..32]  = admin pubkey (all zeros = revoked)
//   bytes[32..40] = config_value (u64 little-endian)
//   bytes[40]     = is_initialized (0 or 1)

const CONFIG_SIZE: usize = 41;

fn get_admin(data: &[u8]) -> [u8; 32] {
    let mut admin = [0u8; 32];
    if data.len() >= 32 {
        admin.copy_from_slice(&data[..32]);
    }
    admin
}

#[allow(dead_code)]
fn get_config_value(data: &[u8]) -> u64 {
    if data.len() >= 40 {
        u64::from_le_bytes(data[32..40].try_into().unwrap())
    } else {
        0
    }
}

fn is_initialized(data: &[u8]) -> bool {
    data.len() >= 41 && data[40] == 1
}

fn is_revoked(admin: &[u8; 32]) -> bool {
    admin.iter().all(|&b| b == 0)
}

fn main() {
    let (
        ProgramInput {
            pre_states,
            instruction,
        },
        instruction_data,
    ) = read_nssa_inputs::<Vec<u8>>();

    let [config_account] = pre_states
        .try_into()
        .unwrap_or_else(|_| panic!("Expected exactly one config account"));

    let data = config_account.account.data.as_ref();
    let mut new_data = vec![0u8; CONFIG_SIZE];

    // Copy existing data if available
    if data.len() >= CONFIG_SIZE {
        new_data.copy_from_slice(&data[..CONFIG_SIZE]);
    }

    let opcode = instruction.first().copied().expect("Empty instruction");

    match opcode {
        // Init
        0x01 => {
            assert!(!is_initialized(&new_data), "Already initialized");
            assert!(config_account.is_authorized, "Missing authorization");
            // Set admin to signer (use first 32 bytes of instruction after opcode)
            let admin_bytes = if instruction.len() >= 33 {
                &instruction[1..33]
            } else {
                &[1u8; 32][..]
            };
            new_data[..32].copy_from_slice(admin_bytes);
            new_data[32..40].copy_from_slice(&0u64.to_le_bytes());
            new_data[40] = 1;
        }

        // TransferAuthority
        0x02 => {
            assert!(is_initialized(&new_data), "Not initialized");
            assert!(config_account.is_authorized, "Missing admin authorization");
            assert!(!is_revoked(&get_admin(&new_data)), "Authority already revoked");
            assert!(instruction.len() >= 33, "Missing new admin pubkey");
            new_data[..32].copy_from_slice(&instruction[1..33]);
        }

        // RevokeAuthority
        0x03 => {
            assert!(is_initialized(&new_data), "Not initialized");
            assert!(config_account.is_authorized, "Missing admin authorization");
            assert!(!is_revoked(&get_admin(&new_data)), "Authority already revoked");
            // Set admin to all zeros = revoked
            new_data[..32].copy_from_slice(&[0u8; 32]);
        }

        // SetConfigValue
        0x04 => {
            assert!(is_initialized(&new_data), "Not initialized");
            assert!(config_account.is_authorized, "Missing admin authorization");
            assert!(!is_revoked(&get_admin(&new_data)), "Authority has been revoked");
            assert!(instruction.len() >= 9, "Missing config value");
            let value = u64::from_le_bytes(instruction[1..9].try_into().unwrap());
            new_data[32..40].copy_from_slice(&value.to_le_bytes());
        }

        _ => panic!("Unknown opcode: {}", opcode),
    }

    let mut post_account = config_account.account.clone();
    post_account.data = new_data
        .try_into()
        .expect("Config data should fit within limits");

    let post_state = if post_account.program_owner == DEFAULT_PROGRAM_ID {
        AccountPostState::new_claimed(post_account)
    } else {
        AccountPostState::new(post_account)
    };

    write_nssa_outputs(instruction_data, vec![config_account], vec![post_state]);
}
