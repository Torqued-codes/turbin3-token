use std::num::NonZeroI8;

use anchor_lang::{
    prelude::Pubkey,
    solana_program::{instruction::Instruction, system_program},
    InstructionData, ToAccountMetas,
};
use litesvm::LiteSVM;
use proofext::instruction::ProofLocation;
use proofgen::{transfer::transfer_split_proof_data, withdraw::withdraw_proof_data};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;
use t22::{accounts, instruction, ID};
use t22new::{
    extension::{
        confidential_transfer::{
            instruction as ct_ix, ConfidentialTransferAccount, ConfidentialTransferMint,
        },
        cpi_guard::instruction::enable_cpi_guard,
        default_account_state::DefaultAccountState,
        metadata_pointer::MetadataPointer,
        mint_close_authority::MintCloseAuthority,
        permanent_delegate::PermanentDelegate,
        BaseStateWithExtensions, ExtensionType, StateWithExtensions,
    },
    instruction::{approve, initialize_account3, mint_to},
    state::{Account as TokenAccountState, AccountState, Mint as MintState},
};
use zk::{
    encryption::{
        auth_encryption::{AeCiphertext, AeKey},
        derivation::derive_confidential_keys,
        elgamal::{ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey},
    },
    zk_elgamal_proof_program::pubkey_validity::build_pubkey_validity_proof_data,
};
use zkif::{
    instruction::{ContextStateInfo, ProofInstruction},
    proof_data::ZkProofData,
};

const TOKEN_2022_PROGRAM_ID: Pubkey = anchor_spl::token_interface::spl_token_2022::ID;
const DECIMALS: u8 = 6;
const BASIS_POINTS: u16 = 250; // 2.5%
const MAXIMUM_FEE: u64 = 5_000;

struct ConfidentialHolder {
    account: Pubkey,
    elgamal: ElGamalKeypair,
    aes: AeKey,
}

fn setup() -> (LiteSVM, Keypair) {
    let mut svm = LiteSVM::new();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();

    let program_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/deploy/t22.so");
    assert!(
        program_path.exists(),
        "program binary not found at {}. Run anchor build / cargo-build-sbf first.",
        program_path.display()
    );
    svm.add_program_from_file(ID, program_path).unwrap();

    (svm, payer)
}

fn send(svm: &mut LiteSVM, payer: &Keypair, ixs: &[Instruction], extra_signers: &[&Keypair]) {
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra_signers);

    let blockhash = svm.latest_blockhash();
    let mut tx = Transaction::new_unsigned(Message::new(ixs, Some(&payer.pubkey())));
    tx.try_sign(&signers, blockhash).unwrap();

    if let Err(err) = svm.send_transaction(tx) {
        panic!("transaction failed:\n{:#?}", err.meta.logs);
    }
}

fn stage_proof<T: bytemuck::Pod + ZkProofData<U>, U: bytemuck::Pod>(
    svm: &mut LiteSVM,
    payer: &Keypair,
    proof_ix: ProofInstruction,
    proof_data: &T,
) -> Pubkey {
    let context_account = Keypair::new();
    let space = std::mem::size_of::<zkif::state::ProofContextState<U>>();
    let lamports = svm.minimum_balance_for_rent_exemption(space);

    let create_ix = solana_system_interface::instruction::create_account(
        &payer.pubkey(),
        &context_account.pubkey(),
        lamports,
        space as u64,
        &zkif::ID,
    );
    let verify_ix = proof_ix.encode_verify_proof(
        Some(ContextStateInfo {
            context_state_account: &context_account.pubkey(),
            context_state_authority: &payer.pubkey(),
        }),
        proof_data,
    );

    send(svm, payer, &[create_ix, verify_ix], &[&context_account]);
    context_account.pubkey()
}

fn read_ct(svm: &LiteSVM, account: &Pubkey) -> ConfidentialTransferAccount {
    let acct = svm.get_account(account).unwrap();
    let state = StateWithExtensions::<TokenAccountState>::unpack(&acct.data).unwrap();
    *state
        .get_extension::<ConfidentialTransferAccount>()
        .unwrap()
}

fn available_balance(ct: &ConfidentialTransferAccount, aes: &AeKey) -> u64 {
    let ciphertext: AeCiphertext = ct.decryptable_available_balance.try_into().unwrap();
    aes.decrypt(&ciphertext).unwrap()
}

fn pending_balance(ct: &ConfidentialTransferAccount, elgamal: &ElGamalKeypair) -> u64 {
    let lo: ElGamalCiphertext = ct.pending_balance_lo.try_into().unwrap();
    let hi: ElGamalCiphertext = ct.pending_balance_hi.try_into().unwrap();
    let lo_val = elgamal.secret().decrypt_u32(&lo).unwrap() as u64;
    let hi_val = elgamal.secret().decrypt_u32(&hi).unwrap() as u64;
    lo_val + (hi_val << 16)
}

/// Tasks 1, 2, 3, 4:
/// - Creates remittance mint stacking TransferFeeConfig, MetadataPointer (self),
///   DefaultAccountState (Frozen), and MintCloseAuthority.
/// - Creates frozen token accounts by default, thaws them post-KYC, and executes
///   transfer_checked_with_fee using calculate_epoch_fee.
#[test]
fn tasks_1_to_4_remittance_mint_kyc_thaw_and_fee_transfer() {
    let (mut svm, payer) = setup();
    let mint = Keypair::new();

    // Task 1: Create stacked remittance mint
    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::CreateRemittanceMint {
                payer: payer.pubkey(),
                mint: mint.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
            data: instruction::CreateRemittanceMint {
                decimals: DECIMALS,
                basis_points: BASIS_POINTS,
                maximum_fee: MAXIMUM_FEE,
            }
            .data(),
        }],
        &[&mint],
    );

    // Task 3: Inspect mint exclusively through StateWithExtensions
    let mint_acct = svm.get_account(&mint.pubkey()).unwrap();
    let mint_state = StateWithExtensions::<MintState>::unpack(&mint_acct.data).unwrap();
    let exts = mint_state.get_extension_types().unwrap();
    assert!(exts.contains(&ExtensionType::TransferFeeConfig));
    assert!(exts.contains(&ExtensionType::MetadataPointer));
    assert!(exts.contains(&ExtensionType::DefaultAccountState));
    assert!(exts.contains(&ExtensionType::MintCloseAuthority));

    let meta_ptr = mint_state.get_extension::<MetadataPointer>().unwrap();
    assert_eq!(
        Option::<Pubkey>::from(meta_ptr.metadata_address),
        Some(mint.pubkey())
    );

    let default_state = mint_state.get_extension::<DefaultAccountState>().unwrap();
    assert_eq!(default_state.state, AccountState::Frozen as u8);

    let close_auth = mint_state.get_extension::<MintCloseAuthority>().unwrap();
    assert_eq!(
        Option::<Pubkey>::from(close_auth.close_authority),
        Some(payer.pubkey())
    );

    // Create Alice & Bob token accounts (automatically Frozen due to DefaultAccountState)
    let alice_owner = payer.insecure_clone();
    let bob_owner = Keypair::new();
    let alice_ta = Keypair::new();
    let bob_ta = Keypair::new();

    let required_exts = ExtensionType::get_required_init_account_extensions(&exts);
    let ta_space =
        ExtensionType::try_calculate_account_len::<TokenAccountState>(&required_exts).unwrap();
    let ta_rent = svm.minimum_balance_for_rent_exemption(ta_space);

    for (ta, owner) in [(&alice_ta, &alice_owner), (&bob_ta, &bob_owner)] {
        send(
            &mut svm,
            &payer,
            &[
                solana_system_interface::instruction::create_account(
                    &payer.pubkey(),
                    &ta.pubkey(),
                    ta_rent,
                    ta_space as u64,
                    &TOKEN_2022_PROGRAM_ID,
                ),
                initialize_account3(
                    &TOKEN_2022_PROGRAM_ID,
                    &ta.pubkey(),
                    &mint.pubkey(),
                    &owner.pubkey(),
                )
                .unwrap(),
            ],
            &[ta],
        );

        let acct = svm.get_account(&ta.pubkey()).unwrap();
        let state = StateWithExtensions::<TokenAccountState>::unpack(&acct.data).unwrap();
        assert_eq!(state.base.state, AccountState::Frozen);
    }

    // Task 4: Thaw Alice and Bob after KYC clearance
    for ta in [&alice_ta, &bob_ta] {
        send(
            &mut svm,
            &payer,
            &[Instruction {
                program_id: ID,
                accounts: accounts::ThawKycAccount {
                    token_account: ta.pubkey(),
                    mint: mint.pubkey(),
                    freeze_authority: payer.pubkey(),
                    token_program: TOKEN_2022_PROGRAM_ID,
                }
                .to_account_metas(None),
                data: instruction::ThawKycAccount {}.data(),
            }],
            &[],
        );
    }

    // Mint 100,000 units to Alice
    send(
        &mut svm,
        &payer,
        &[mint_to(
            &TOKEN_2022_PROGRAM_ID,
            &mint.pubkey(),
            &alice_ta.pubkey(),
            &payer.pubkey(),
            &[],
            100_000,
        )
        .unwrap()],
        &[],
    );

    // Task 2: Transfer 10,000 units with dynamic epoch fee (2.5% = 250 units)
    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::TransferRemittance {
                source: alice_ta.pubkey(),
                mint: mint.pubkey(),
                destination: bob_ta.pubkey(),
                authority: alice_owner.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::TransferRemittance { amount: 10_000 }.data(),
        }],
        &[],
    );

    let bob_acct = svm.get_account(&bob_ta.pubkey()).unwrap();
    let bob_state = StateWithExtensions::<TokenAccountState>::unpack(&bob_acct.data).unwrap();
    assert_eq!(bob_state.base.amount, 9_750); // 10,000 - 250 fee
}

/// Tasks 5 & 6:
/// - Re-issues mint with PermanentDelegate + ConfidentialTransferMint (approve_policy = manual).
/// - Executes ConfigureAccount -> ApproveAccount -> DepositConfidentialTokens ->
///   ApplyPendingBalance -> Confidential Transfer -> ApplyPendingBalance -> WithdrawConfidentialTokens.
#[test]
fn tasks_5_and_6_seizable_confidential_mint_and_full_lifecycle() {
    let (mut svm, payer) = setup();
    let mint = Keypair::new();

    // Task 5: Create seizable confidential mint with approve_policy = manual
    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::CreateSeizableConfidentialMint {
                payer: payer.pubkey(),
                mint: mint.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
            data: instruction::CreateSeizableConfidentialMint {
                decimals: DECIMALS,
                basis_points: 0,
                maximum_fee: 0,
            }
            .data(),
        }],
        &[&mint],
    );

    let mint_acct = svm.get_account(&mint.pubkey()).unwrap();
    let mint_state = StateWithExtensions::<MintState>::unpack(&mint_acct.data).unwrap();
    let pd = mint_state.get_extension::<PermanentDelegate>().unwrap();
    assert_eq!(Option::<Pubkey>::from(pd.delegate), Some(payer.pubkey()));

    let ct_mint = mint_state
        .get_extension::<ConfidentialTransferMint>()
        .unwrap();
    assert!(!bool::from(ct_mint.auto_approve_new_accounts)); // manual policy verified

    let alice_owner = payer.insecure_clone();
    let bob_owner = Keypair::new();
    svm.airdrop(&bob_owner.pubkey(), 5_000_000_000).unwrap();

    let mut holders = Vec::new();
    for owner in [&alice_owner, &bob_owner] {
        let ta = Keypair::new();
        let space = ExtensionType::try_calculate_account_len::<TokenAccountState>(&[
            ExtensionType::TransferFeeAmount,
            ExtensionType::ConfidentialTransferAccount,
            ExtensionType::ConfidentialTransferFeeAmount,
        ])
        .unwrap();
        let lamports = svm.minimum_balance_for_rent_exemption(space);

        send(
            &mut svm,
            &payer,
            &[
                solana_system_interface::instruction::create_account(
                    &payer.pubkey(),
                    &ta.pubkey(),
                    lamports,
                    space as u64,
                    &TOKEN_2022_PROGRAM_ID,
                ),
                initialize_account3(
                    &TOKEN_2022_PROGRAM_ID,
                    &ta.pubkey(),
                    &mint.pubkey(),
                    &owner.pubkey(),
                )
                .unwrap(),
            ],
            &[&ta],
        );

        // Thaw KYC
        send(
            &mut svm,
            &payer,
            &[Instruction {
                program_id: ID,
                accounts: accounts::ThawKycAccount {
                    token_account: ta.pubkey(),
                    mint: mint.pubkey(),
                    freeze_authority: payer.pubkey(),
                    token_program: TOKEN_2022_PROGRAM_ID,
                }
                .to_account_metas(None),
                data: instruction::ThawKycAccount {}.data(),
            }],
            &[],
        );

        // Task 6a: ConfigureAccount (owner-only)
        let (elgamal, aes) = derive_confidential_keys(owner, b"remittance-ct").unwrap();
        let proof = build_pubkey_validity_proof_data(&elgamal).unwrap();
        let cfg_ixs = ct_ix::configure_account(
            &TOKEN_2022_PROGRAM_ID,
            &ta.pubkey(),
            &mint.pubkey(),
            &aes.encrypt(0).into(),
            65536,
            &owner.pubkey(),
            &[],
            ProofLocation::InstructionOffset(NonZeroI8::new(1).unwrap(), &proof),
        )
        .unwrap();
        send(&mut svm, &payer, &cfg_ixs, &[owner]);

        // Task 5/6b: Manual approval required because auto_approve = false
        send(
            &mut svm,
            &payer,
            &[Instruction {
                program_id: ID,
                accounts: accounts::ApproveConfidentialAccount {
                    token_account: ta.pubkey(),
                    mint: mint.pubkey(),
                    authority: payer.pubkey(),
                    token_program: TOKEN_2022_PROGRAM_ID,
                }
                .to_account_metas(None),
                data: instruction::ApproveConfidentialAccount {}.data(),
            }],
            &[],
        );

        holders.push(ConfidentialHolder {
            account: ta.pubkey(),
            elgamal,
            aes,
        });
    }

    let alice = &holders[0];
    let bob = &holders[1];

    // Mint 50,000 public tokens to Alice
    send(
        &mut svm,
        &payer,
        &[mint_to(
            &TOKEN_2022_PROGRAM_ID,
            &mint.pubkey(),
            &alice.account,
            &payer.pubkey(),
            &[],
            50_000,
        )
        .unwrap()],
        &[],
    );

    // Task 6c: DepositConfidentialTokens (50,000 -> pending)
    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::DepositConfidential {
                token_account: alice.account,
                mint: mint.pubkey(),
                authority: alice_owner.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::DepositConfidential {
                amount: 50_000,
                decimals: DECIMALS,
            }
            .data(),
        }],
        &[],
    );

    // Task 6d: ApplyPendingBalance on Alice
    let alice_ct = read_ct(&svm, &alice.account);
    let new_alice_bal: [u8; 36] = bytemuck::bytes_of(&t22new::extension::confidential_transfer::DecryptableBalance::from(
        alice.aes.encrypt(50_000),
    ))
    .try_into()
    .unwrap();
    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::ApplyPendingBalance {
                token_account: alice.account,
                authority: alice_owner.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::ApplyPendingBalance {
                expected_pending_balance_credit_counter: alice_ct
                    .pending_balance_credit_counter
                    .into(),
                new_decryptable_available_balance: new_alice_bal,
            }
            .data(),
        }],
        &[],
    );
    assert_eq!(
        available_balance(&read_ct(&svm, &alice.account), &alice.aes),
        50_000
    );

    // Task 6e: Confidential Transfer (20,000 from Alice to Bob)
    let transfer_amount = 20_000u64;
    let alice_ct = read_ct(&svm, &alice.account);
    let current_avail: ElGamalCiphertext = alice_ct.available_balance.try_into().unwrap();
    let current_dec: AeCiphertext = alice_ct.decryptable_available_balance.try_into().unwrap();
    let bob_pk: ElGamalPubkey = read_ct(&svm, &bob.account)
        .elgamal_pubkey
        .try_into()
        .unwrap();

    let proofs = transfer_split_proof_data(
        &current_avail,
        &current_dec,
        transfer_amount,
        &alice.elgamal,
        &alice.aes,
        &bob_pk,
        None,
    )
    .unwrap();

    let eq_ctx = stage_proof(
        &mut svm,
        &payer,
        ProofInstruction::VerifyCiphertextCommitmentEquality,
        &proofs.equality_proof_data,
    );
    let val_ctx = stage_proof(
        &mut svm,
        &payer,
        ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity,
        &proofs
            .ciphertext_validity_proof_data_with_ciphertext
            .proof_data,
    );
    let range_ctx = stage_proof(
        &mut svm,
        &payer,
        ProofInstruction::VerifyBatchedRangeProofU128,
        &proofs.range_proof_data,
    );

    let alice_after_tx = alice.aes.encrypt(50_000 - transfer_amount);
    let tx_ixs = ct_ix::transfer(
        &TOKEN_2022_PROGRAM_ID,
        &alice.account,
        &mint.pubkey(),
        &bob.account,
        &alice_after_tx.into(),
        &proofs
            .ciphertext_validity_proof_data_with_ciphertext
            .ciphertext_lo,
        &proofs
            .ciphertext_validity_proof_data_with_ciphertext
            .ciphertext_hi,
        &alice_owner.pubkey(),
        &[],
        ProofLocation::ContextStateAccount(&eq_ctx),
        ProofLocation::ContextStateAccount(&val_ctx),
        ProofLocation::ContextStateAccount(&range_ctx),
    )
    .unwrap();
    send(&mut svm, &payer, &tx_ixs, &[&alice_owner]);

    assert_eq!(
        pending_balance(&read_ct(&svm, &bob.account), &bob.elgamal),
        20_000
    );

    // Task 6f: ApplyPendingBalance on Bob BEFORE WithdrawConfidentialTokens
    let bob_ct = read_ct(&svm, &bob.account);
    let bob_avail_enc: [u8; 36] = bytemuck::bytes_of(&t22new::extension::confidential_transfer::DecryptableBalance::from(
        bob.aes.encrypt(20_000),
    ))
    .try_into()
    .unwrap();
    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::ApplyPendingBalance {
                token_account: bob.account,
                authority: bob_owner.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::ApplyPendingBalance {
                expected_pending_balance_credit_counter: bob_ct
                    .pending_balance_credit_counter
                    .into(),
                new_decryptable_available_balance: bob_avail_enc,
            }
            .data(),
        }],
        &[&bob_owner],
    );

    // Task 6g: WithdrawConfidentialTokens (5,000 from Bob's available confidential balance to public)
    let withdraw_amount = 5_000u64;
    let bob_ct = read_ct(&svm, &bob.account);
    let bob_current: ElGamalCiphertext = bob_ct.available_balance.try_into().unwrap();
    let wproofs =
        withdraw_proof_data(&bob_current, 20_000, withdraw_amount, &bob.elgamal).unwrap();

    let weq_ctx = stage_proof(
        &mut svm,
        &payer,
        ProofInstruction::VerifyCiphertextCommitmentEquality,
        &wproofs.equality_proof_data,
    );
    let wrange_ctx = stage_proof(
        &mut svm,
        &payer,
        ProofInstruction::VerifyBatchedRangeProofU64,
        &wproofs.range_proof_data,
    );

    let bob_after_withdraw = bob.aes.encrypt(20_000 - withdraw_amount);
    let w_ixs = ct_ix::withdraw(
        &TOKEN_2022_PROGRAM_ID,
        &bob.account,
        &mint.pubkey(),
        withdraw_amount,
        DECIMALS,
        &bob_after_withdraw.into(),
        &bob_owner.pubkey(),
        &[],
        ProofLocation::ContextStateAccount(&weq_ctx),
        ProofLocation::ContextStateAccount(&wrange_ctx),
    )
    .unwrap();
    send(&mut svm, &payer, &w_ixs, &[&bob_owner]);

    let bob_final_acct = svm.get_account(&bob.account).unwrap();
    let bob_final_state =
        StateWithExtensions::<TokenAccountState>::unpack(&bob_final_acct.data).unwrap();
    assert_eq!(bob_final_state.base.amount, 5_000);
    assert_eq!(
        available_balance(&read_ct(&svm, &bob.account), &bob.aes),
        15_000
    );
}

/// Extension Challenge:
/// - User grants top-level Approve authority to a delegate agent.
/// - User enables CpiGuard on their token account afterward.
/// - Confirms the delegate transfer path still executes unmodified.
#[test]
fn extension_challenge_cpi_guard_with_top_level_approve_delegate() {
    let (mut svm, payer) = setup();
    let mint = Keypair::new();

    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::CreateMintDeclarative {
                payer: payer.pubkey(),
                mint: mint.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
            data: instruction::CreateMintDeclarative { decimals: DECIMALS }.data(),
        }],
        &[&mint],
    );

    let user = payer.insecure_clone();
    let agent_delegate = Keypair::new();
    let recipient = Keypair::new();

    let space = ExtensionType::try_calculate_account_len::<TokenAccountState>(&[
        ExtensionType::CpiGuard,
    ])
    .unwrap();
    let rent = svm.minimum_balance_for_rent_exemption(space);

    let user_ta = Keypair::new();
    let recipient_ta = Keypair::new();

    for (ta, owner) in [(&user_ta, &user), (&recipient_ta, &recipient)] {
        send(
            &mut svm,
            &payer,
            &[
                solana_system_interface::instruction::create_account(
                    &payer.pubkey(),
                    &ta.pubkey(),
                    rent,
                    space as u64,
                    &TOKEN_2022_PROGRAM_ID,
                ),
                initialize_account3(
                    &TOKEN_2022_PROGRAM_ID,
                    &ta.pubkey(),
                    &mint.pubkey(),
                    &owner.pubkey(),
                )
                .unwrap(),
            ],
            &[ta],
        );
    }

    // Mint 10,000 tokens to user
    send(
        &mut svm,
        &payer,
        &[mint_to(
            &TOKEN_2022_PROGRAM_ID,
            &mint.pubkey(),
            &user_ta.pubkey(),
            &payer.pubkey(),
            &[],
            10_000,
        )
        .unwrap()],
        &[],
    );

    // 1. Top-level Approve to delegate agent
    send(
        &mut svm,
        &payer,
        &[approve(
            &TOKEN_2022_PROGRAM_ID,
            &user_ta.pubkey(),
            &agent_delegate.pubkey(),
            &user.pubkey(),
            &[],
            4_000,
        )
        .unwrap()],
        &[],
    );

    // 2. Enable CpiGuard on user's token account afterward
    send(
        &mut svm,
        &payer,
        &[enable_cpi_guard(&TOKEN_2022_PROGRAM_ID, &user_ta.pubkey(), &user.pubkey(), &[]).unwrap()],
        &[],
    );

    // 3. Execute delegated transfer through on-chain program CPI — succeeds unmodified
    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::ExecuteDelegatedTransfer {
                source: user_ta.pubkey(),
                mint: mint.pubkey(),
                destination: recipient_ta.pubkey(),
                delegate: agent_delegate.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::ExecuteDelegatedTransfer { amount: 2_500 }.data(),
        }],
        &[&agent_delegate],
    );

    let dest_acct = svm.get_account(&recipient_ta.pubkey()).unwrap();
    let dest_state = StateWithExtensions::<TokenAccountState>::unpack(&dest_acct.data).unwrap();
    assert_eq!(dest_state.base.amount, 2_500);
}



























