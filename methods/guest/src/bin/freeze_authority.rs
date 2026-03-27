use nssa_core::program::{
    AccountPostState, DEFAULT_PROGRAM_ID, ProgramInput, read_nssa_inputs, write_nssa_outputs,
};

// Freeze Authority PoC — RFP-002
//
// Circuit breaker / emergency stop mechanism for LEE programs.
//
// Instruction encoding:
//   byte[0] = opcode
//     0x01 = Init (set freeze authority)
//     0x02 = Freeze (disable all interactions)
//     0x03 = Unfreeze (resume interactions)
//     0x04 = Execute (any user — fails if frozen)
//
// Config data layout (stored in account.data):
//   bytes[0..32]  = freeze_authority pubkey (all zeros = revoked)
//   bytes[32]     = is_frozen (0 or 1)
//   bytes[33]     = is_initialized (0 or 1)

const CONFIG_SIZE: usize = 34;

fn get_authority(data: &[u8]) -> [u8; 32] {
    let mut auth = [0u8; 32];
    if data.len() >= 32 {
        auth.copy_from_slice(&data[..32]);
    }
    auth
}

fn is_frozen(data: &[u8]) -> bool {
    data.len() >= 33 && data[32] == 1
}

fn is_initialized(data: &[u8]) -> bool {
    data.len() >= 34 && data[33] == 1
}

fn is_revoked(auth: &[u8; 32]) -> bool {
    auth.iter().all(|&b| b == 0)
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

    if data.len() >= CONFIG_SIZE {
        new_data.copy_from_slice(&data[..CONFIG_SIZE]);
    }

    let opcode = instruction.first().copied().expect("Empty instruction");

    match opcode {
        // Init
        0x01 => {
            assert!(!is_initialized(&new_data), "Already initialized");
            assert!(config_account.is_authorized, "Missing authorization");
            let auth_bytes = if instruction.len() >= 33 {
                &instruction[1..33]
            } else {
                &[1u8; 32][..]
            };
            new_data[..32].copy_from_slice(auth_bytes);
            new_data[32] = 0; // not frozen
            new_data[33] = 1; // initialized
        }

        // Freeze
        0x02 => {
            assert!(is_initialized(&new_data), "Not initialized");
            assert!(config_account.is_authorized, "Missing freeze authority");
            assert!(!is_revoked(&get_authority(&new_data)), "Authority revoked");
            new_data[32] = 1; // frozen
        }

        // Unfreeze
        0x03 => {
            assert!(is_initialized(&new_data), "Not initialized");
            assert!(config_account.is_authorized, "Missing freeze authority");
            assert!(!is_revoked(&get_authority(&new_data)), "Authority revoked");
            new_data[32] = 0; // unfrozen
        }

        // Execute (fails if frozen)
        0x04 => {
            assert!(is_initialized(&new_data), "Not initialized");
            assert!(!is_frozen(&new_data), "Program is frozen — execution disabled");
            // Normal execution would happen here
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
