use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;
use anchor_spl::token_interface::{
    approve, default_account_state_initialize, initialize_mint2, metadata_pointer_initialize,
    mint_close_authority_initialize, permanent_delegate_initialize, spl_token_2022, thaw_account,
    transfer_checked, transfer_checked_with_fee, transfer_fee_initialize, Approve,
    DefaultAccountStateInitialize, InitializeMint2, MetadataPointerInitialize, Mint,
    MintCloseAuthorityInitialize, PermanentDelegateInitialize, ThawAccount, TokenInterface,
    TransferChecked, TransferCheckedWithFee, TransferFeeInitialize,
};
use spl_token_2022::{
    extension::{
        confidential_transfer::{instruction as confidential_instruction, DecryptableBalance},
        confidential_transfer_fee::instruction as confidential_fee_instruction,
        transfer_fee::TransferFeeConfig, BaseStateWithExtensions, ExtensionType,
        StateWithExtensions,
    },
    state::{Account as TokenAccountState, AccountState, Mint as MintState},
};

// The length of a ciphertext which is how a decryptable balance is represented in the account data
pub const AE_CIPHERTEXT_LEN: usize = 36;

declare_id!("7ChZdBFNEX38ece4Rkhf3A2qpYV1oiiarfEAKy2S4MML");

const SUPPORTED_EXTENSIONS: &[ExtensionType] = &[
    ExtensionType::MintCloseAuthority,
    ExtensionType::MetadataPointer,
    ExtensionType::TransferFeeConfig,
    ExtensionType::DefaultAccountState,
    ExtensionType::PermanentDelegate,
    ExtensionType::ConfidentialTransferMint,
];

#[program]
pub mod t22 {
    use super::*;

    /// The declarative path.
    pub fn create_mint_declarative(
        ctx: Context<CreateMintDeclarative>,
        decimals: u8,
    ) -> Result<()> {
        msg!(
            "mint {} created with {} decimals",
            ctx.accounts.mint.key(),
            decimals
        );
        Ok(())
    }

    /// Task 1: Create a remittance stablecoin mint stacking TransferFeeConfig,
    /// MetadataPointer (pointed at the mint itself), DefaultAccountState (Frozen),
    /// and MintCloseAuthority, all sized via ExtensionType::try_calculate_account_len
    /// before InitializeMint2.
    pub fn create_remittance_mint(
        ctx: Context<CreateRemittanceMint>,
        decimals: u8,
        basis_points: u16,
        maximum_fee: u64,
    ) -> Result<()> {
        let extensions = [
            ExtensionType::TransferFeeConfig,
            ExtensionType::MetadataPointer,
            ExtensionType::DefaultAccountState,
            ExtensionType::MintCloseAuthority,
        ];

        let space = ExtensionType::try_calculate_account_len::<MintState>(&extensions)?;
        let lamports = Rent::get()?.minimum_balance(space);

        anchor_lang::system_program::create_account(
            CpiContext::new(
                ctx.accounts.system_program.key(),
                anchor_lang::system_program::CreateAccount {
                    from: ctx.accounts.payer.to_account_info(),
                    to: ctx.accounts.mint.to_account_info(),
                },
            ),
            lamports,
            space as u64,
            &ctx.accounts.token_program.key(),
        )?;

        let mint_info = ctx.accounts.mint.to_account_info();
        let token_prog_info = ctx.accounts.token_program.to_account_info();
        let payer_key = ctx.accounts.payer.key();

        // 1. TransferFeeConfig
        transfer_fee_initialize(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                TransferFeeInitialize {
                    token_program_id: token_prog_info.clone(),
                    mint: mint_info.clone(),
                },
            ),
            Some(&payer_key),
            Some(&payer_key),
            basis_points,
            maximum_fee,
        )?;

        // 2. MetadataPointer (pointed at the mint itself)
        metadata_pointer_initialize(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                MetadataPointerInitialize {
                    token_program_id: token_prog_info.clone(),
                    mint: mint_info.clone(),
                },
            ),
            Some(payer_key),
            Some(ctx.accounts.mint.key()),
        )?;

        // 3. DefaultAccountState (Frozen until KYC)
        default_account_state_initialize(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                DefaultAccountStateInitialize {
                    token_program_id: token_prog_info.clone(),
                    mint: mint_info.clone(),
                },
            ),
            &AccountState::Frozen,
        )?;

        // 4. MintCloseAuthority
        mint_close_authority_initialize(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                MintCloseAuthorityInitialize {
                    token_program_id: token_prog_info,
                    mint: mint_info.clone(),
                },
            ),
            Some(&payer_key),
        )?;

        // 5. InitializeMint2 (must come after all extension initializers)
        initialize_mint2(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                InitializeMint2 { mint: mint_info },
            ),
            decimals,
            &payer_key,
            Some(&payer_key), // Freeze authority set to payer for KYC thawing
        )?;

        msg!(
            "remittance mint {} created at {} bytes",
            ctx.accounts.mint.key(),
            space
        );
        Ok(())
    }

    /// Task 2 & 3: Transfer function using transfer_checked_with_fee, computing the
    /// expected fee dynamically via calculate_epoch_fee(current_epoch, amount) and
    /// reading mint state exclusively through StateWithExtensions.
    pub fn transfer_remittance(ctx: Context<TransferRemittance>, amount: u64) -> Result<()> {
        let mint_info = ctx.accounts.mint.to_account_info();
        let mint_data = mint_info.try_borrow_data()?;
        let mint_state = StateWithExtensions::<MintState>::unpack(&mint_data)?;

        let decimals = mint_state.base.decimals;
        let fee_config = mint_state.get_extension::<TransferFeeConfig>()?;
        let current_epoch = Clock::get()?.epoch;
        let expected_fee = fee_config
            .calculate_epoch_fee(current_epoch, amount)
            .ok_or(MintError::FeeCalculationOverflow)?;
        drop(mint_data);

        transfer_checked_with_fee(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                TransferCheckedWithFee {
                    token_program_id: ctx.accounts.token_program.to_account_info(),
                    source: ctx.accounts.source.to_account_info(),
                    mint: mint_info,
                    destination: ctx.accounts.destination.to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                },
            ),
            amount,
            decimals,
            expected_fee,
        )?;

        msg!(
            "transferred {} (decimals: {}) with epoch fee {}",
            amount,
            decimals,
            expected_fee
        );
        Ok(())
    }

    /// Task 4: Unfreeze path where the freeze authority thaws an individual account
    /// after KYC clearance without changing the mint-level DefaultAccountState.
    pub fn thaw_kyc_account(ctx: Context<ThawKycAccount>) -> Result<()> {
        thaw_account(CpiContext::new(
            ctx.accounts.token_program.key(),
            ThawAccount {
                account: ctx.accounts.token_account.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                authority: ctx.accounts.freeze_authority.to_account_info(),
            },
        ))?;

        // Verify thawed state via StateWithExtensions
        let acct_info = ctx.accounts.token_account.to_account_info();
        let acct_data = acct_info.try_borrow_data()?;
        let acct_state = StateWithExtensions::<TokenAccountState>::unpack(&acct_data)?;
        require!(
            acct_state.base.state == AccountState::Initialized,
            MintError::AccountStillFrozen
        );

        msg!("thawed KYC-cleared account {}", ctx.accounts.token_account.key());
        Ok(())
    }

    /// Task 5: Re-issue the mint carrying forward the remittance extension set
    /// while adding PermanentDelegate (seizure authority) and ConfidentialTransferMint
    /// with approve_policy = manual (auto_approve_new_accounts = false).
    pub fn create_seizable_confidential_mint(
        ctx: Context<CreateSeizableConfidentialMint>,
        decimals: u8,
        basis_points: u16,
        maximum_fee: u64,
    ) -> Result<()> {
        let extensions = [
            ExtensionType::TransferFeeConfig,
            ExtensionType::MetadataPointer,
            ExtensionType::DefaultAccountState,
            ExtensionType::MintCloseAuthority,
            ExtensionType::PermanentDelegate,
            ExtensionType::ConfidentialTransferMint,
        ];

        let space = ExtensionType::try_calculate_account_len::<MintState>(&extensions)?;
        let lamports = Rent::get()?.minimum_balance(space);

        anchor_lang::system_program::create_account(
            CpiContext::new(
                ctx.accounts.system_program.key(),
                anchor_lang::system_program::CreateAccount {
                    from: ctx.accounts.payer.to_account_info(),
                    to: ctx.accounts.mint.to_account_info(),
                },
            ),
            lamports,
            space as u64,
            &ctx.accounts.token_program.key(),
        )?;

        let mint_info = ctx.accounts.mint.to_account_info();
        let token_prog_info = ctx.accounts.token_program.to_account_info();
        let payer_key = ctx.accounts.payer.key();

        // 1. TransferFeeConfig
        transfer_fee_initialize(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                TransferFeeInitialize {
                    token_program_id: token_prog_info.clone(),
                    mint: mint_info.clone(),
                },
            ),
            Some(&payer_key),
            Some(&payer_key),
            basis_points,
            maximum_fee,
        )?;

        // 2. MetadataPointer (self-referential)
        metadata_pointer_initialize(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                MetadataPointerInitialize {
                    token_program_id: token_prog_info.clone(),
                    mint: mint_info.clone(),
                },
            ),
            Some(payer_key),
            Some(ctx.accounts.mint.key()),
        )?;

        // 3. DefaultAccountState (Frozen)
        default_account_state_initialize(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                DefaultAccountStateInitialize {
                    token_program_id: token_prog_info.clone(),
                    mint: mint_info.clone(),
                },
            ),
            &AccountState::Frozen,
        )?;

        // 4. MintCloseAuthority
        mint_close_authority_initialize(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                MintCloseAuthorityInitialize {
                    token_program_id: token_prog_info.clone(),
                    mint: mint_info.clone(),
                },
            ),
            Some(&payer_key),
        )?;

        // 5. PermanentDelegate (seizure authority)
        permanent_delegate_initialize(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                PermanentDelegateInitialize {
                    token_program_id: token_prog_info.clone(),
                    mint: mint_info.clone(),
                },
            ),
            &payer_key,
        )?;

        // 6. ConfidentialTransferMint with approve_policy = manual (auto_approve = false)
        let ct_ix = confidential_instruction::initialize_mint(
            &ctx.accounts.token_program.key(),
            &ctx.accounts.mint.key(),
            Some(payer_key),
            false,
            None,
        )?;
        invoke(&ct_ix, &[mint_info.clone(), token_prog_info])?;

        // 7. InitializeMint2
        initialize_mint2(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                InitializeMint2 { mint: mint_info },
            ),
            decimals,
            &payer_key,
            Some(&payer_key),
        )?;

        msg!(
            "seizable confidential mint {} created at {} bytes",
            ctx.accounts.mint.key(),
            space
        );
        Ok(())
    }

    /// Task 5 & 6: Approve a configured confidential token account when approve_policy = manual.
    pub fn approve_confidential_account(ctx: Context<ApproveConfidentialAccount>) -> Result<()> {
        let ix = confidential_instruction::approve_account(
            &ctx.accounts.token_program.key(),
            &ctx.accounts.token_account.key(),
            &ctx.accounts.mint.key(),
            &ctx.accounts.authority.key(),
            &[],
        )?;
        invoke(
            &ix,
            &[
                ctx.accounts.token_account.to_account_info(),
                ctx.accounts.mint.to_account_info(),
                ctx.accounts.authority.to_account_info(),
                ctx.accounts.token_program.to_account_info(),
            ],
        )?;
        msg!(
            "approved confidential account {}",
            ctx.accounts.token_account.key()
        );
        Ok(())
    }

    /// Extension Challenge: Delegated transfer executed by an authorized delegate
    /// (works even after the user enables CPI Guard when Approve was signed top-level).
    pub fn execute_delegated_transfer(
        ctx: Context<ExecuteDelegatedTransfer>,
        amount: u64,
    ) -> Result<()> {
        let mint_info = ctx.accounts.mint.to_account_info();
        let mint_data = mint_info.try_borrow_data()?;
        let mint_state = StateWithExtensions::<MintState>::unpack(&mint_data)?;
        let decimals = mint_state.base.decimals;
        drop(mint_data);

        transfer_checked(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                TransferChecked {
                    from: ctx.accounts.source.to_account_info(),
                    mint: mint_info,
                    to: ctx.accounts.destination.to_account_info(),
                    authority: ctx.accounts.delegate.to_account_info(),
                },
            ),
            amount,
            decimals,
        )?;
        msg!("delegated transfer of {} completed", amount);
        Ok(())
    }

    // --- Existing Starter Instructions Preserved Below ---

    pub fn create_mint_with_fee(
        ctx: Context<CreateMintWithFee>,
        decimals: u8,
        basis_points: u16,
        maximum_fee: u64,
    ) -> Result<()> {
        let extensions = [
            ExtensionType::MintCloseAuthority,
            ExtensionType::TransferFeeConfig,
        ];

        let space = ExtensionType::try_calculate_account_len::<MintState>(&extensions)?;
        let lamports = Rent::get()?.minimum_balance(space);

        anchor_lang::system_program::create_account(
            CpiContext::new(
                ctx.accounts.system_program.key(),
                anchor_lang::system_program::CreateAccount {
                    from: ctx.accounts.payer.to_account_info(),
                    to: ctx.accounts.mint.to_account_info(),
                },
            ),
            lamports,
            space as u64,
            &ctx.accounts.token_program.key(),
        )?;

        mint_close_authority_initialize(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                MintCloseAuthorityInitialize {
                    token_program_id: ctx.accounts.token_program.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                },
            ),
            Some(&ctx.accounts.payer.key()),
        )?;

        transfer_fee_initialize(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                TransferFeeInitialize {
                    token_program_id: ctx.accounts.token_program.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                },
            ),
            Some(&ctx.accounts.payer.key()),
            Some(&ctx.accounts.payer.key()),
            basis_points,
            maximum_fee,
        )?;

        initialize_mint2(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                InitializeMint2 {
                    mint: ctx.accounts.mint.to_account_info(),
                },
            ),
            decimals,
            &ctx.accounts.payer.key(),
            None,
        )?;

        msg!(
            "mint {} created with {} bytes",
            ctx.accounts.mint.key(),
            space
        );
        Ok(())
    }

    pub fn create_confidential_mint(
        ctx: Context<CreateConfidentialMint>,
        decimals: u8,
        auto_approve_new_accounts: bool,
    ) -> Result<()> {
        let space = ExtensionType::try_calculate_account_len::<MintState>(&[
            ExtensionType::ConfidentialTransferMint,
        ])?;
        let lamports = Rent::get()?.minimum_balance(space);

        anchor_lang::system_program::create_account(
            CpiContext::new(
                ctx.accounts.system_program.key(),
                anchor_lang::system_program::CreateAccount {
                    from: ctx.accounts.payer.to_account_info(),
                    to: ctx.accounts.mint.to_account_info(),
                },
            ),
            lamports,
            space as u64,
            &ctx.accounts.token_program.key(),
        )?;

        let ix = confidential_instruction::initialize_mint(
            &ctx.accounts.token_program.key(),
            &ctx.accounts.mint.key(),
            Some(ctx.accounts.payer.key()),
            auto_approve_new_accounts,
            None,
        )?;
        invoke(
            &ix,
            &[
                ctx.accounts.mint.to_account_info(),
                ctx.accounts.token_program.to_account_info(),
            ],
        )?;

        initialize_mint2(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                InitializeMint2 {
                    mint: ctx.accounts.mint.to_account_info(),
                },
            ),
            decimals,
            &ctx.accounts.payer.key(),
            None,
        )?;

        msg!(
            "confidential mint {} at {} bytes",
            ctx.accounts.mint.key(),
            space
        );
        Ok(())
    }

    pub fn create_confidential_fee_mint(
        ctx: Context<CreateConfidentialFeeMint>,
        decimals: u8,
        basis_points: u16,
        maximum_fee: u64,
        withdraw_withheld_authority_elgamal_pubkey: [u8; 32],
    ) -> Result<()> {
        let space = ExtensionType::try_calculate_account_len::<MintState>(&[
            ExtensionType::TransferFeeConfig,
            ExtensionType::ConfidentialTransferMint,
            ExtensionType::ConfidentialTransferFeeConfig,
        ])?;
        let lamports = Rent::get()?.minimum_balance(space);

        anchor_lang::system_program::create_account(
            CpiContext::new(
                ctx.accounts.system_program.key(),
                anchor_lang::system_program::CreateAccount {
                    from: ctx.accounts.payer.to_account_info(),
                    to: ctx.accounts.mint.to_account_info(),
                },
            ),
            lamports,
            space as u64,
            &ctx.accounts.token_program.key(),
        )?;

        let mint_info = ctx.accounts.mint.to_account_info();
        let program_info = ctx.accounts.token_program.to_account_info();
        let infos = [mint_info.clone(), program_info.clone()];

        transfer_fee_initialize(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                TransferFeeInitialize {
                    token_program_id: program_info.clone(),
                    mint: mint_info.clone(),
                },
            ),
            Some(&ctx.accounts.payer.key()),
            Some(&ctx.accounts.payer.key()),
            basis_points,
            maximum_fee,
        )?;

        invoke(
            &confidential_instruction::initialize_mint(
                &ctx.accounts.token_program.key(),
                &ctx.accounts.mint.key(),
                Some(ctx.accounts.payer.key()),
                true,
                None,
            )?,
            &infos,
        )?;

        invoke(
            &confidential_fee_instruction::initialize_confidential_transfer_fee_config(
                &ctx.accounts.token_program.key(),
                &ctx.accounts.mint.key(),
                Some(ctx.accounts.payer.key()),
                &withdraw_withheld_authority_elgamal_pubkey.into(),
            )?,
            &infos,
        )?;

        initialize_mint2(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                InitializeMint2 { mint: mint_info },
            ),
            decimals,
            &ctx.accounts.payer.key(),
            None,
        )?;

        msg!(
            "confidential fee mint {} at {} bytes",
            ctx.accounts.mint.key(),
            space
        );
        Ok(())
    }

    pub fn deposit_confidential(
        ctx: Context<DepositConfidential>,
        amount: u64,
        decimals: u8,
    ) -> Result<()> {
        let ix = confidential_instruction::deposit(
            &ctx.accounts.token_program.key(),
            &ctx.accounts.token_account.key(),
            &ctx.accounts.mint.key(),
            amount,
            decimals,
            &ctx.accounts.authority.key(),
            &[],
        )?;
        invoke(
            &ix,
            &[
                ctx.accounts.token_account.to_account_info(),
                ctx.accounts.mint.to_account_info(),
                ctx.accounts.authority.to_account_info(),
                ctx.accounts.token_program.to_account_info(),
            ],
        )?;
        Ok(())
    }

    pub fn apply_pending_balance(
        ctx: Context<ApplyPendingBalance>,
        expected_pending_balance_credit_counter: u64,
        new_decryptable_available_balance: [u8; AE_CIPHERTEXT_LEN],
    ) -> Result<()> {
        let balance = DecryptableBalance::from(new_decryptable_available_balance);
        let ix = confidential_instruction::apply_pending_balance(
            &ctx.accounts.token_program.key(),
            &ctx.accounts.token_account.key(),
            expected_pending_balance_credit_counter,
            &balance,
            &ctx.accounts.authority.key(),
            &[],
        )?;
        invoke(
            &ix,
            &[
                ctx.accounts.token_account.to_account_info(),
                ctx.accounts.authority.to_account_info(),
                ctx.accounts.token_program.to_account_info(),
            ],
        )?;
        Ok(())
    }

    pub fn create_seizable_mint(ctx: Context<CreateSeizableMint>, decimals: u8) -> Result<()> {
        msg!(
            "seizable mint {} with {} decimals, permanent delegate",
            ctx.accounts.mint.key(),
            decimals,
        );
        Ok(())
    }

    pub fn delegate_to_program(ctx: Context<DelegateToProgram>, amount: u64) -> Result<()> {
        approve(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                Approve {
                    to: ctx.accounts.token_account.to_account_info(),
                    delegate: ctx.accounts.delegate.to_account_info(),
                    authority: ctx.accounts.owner.to_account_info(),
                },
            ),
            amount,
        )?;
        msg!("delegated {} to {}", amount, ctx.accounts.delegate.key());
        Ok(())
    }

    pub fn permanent_delegate_seize(
        ctx: Context<PermanentDelegateSeize>,
        amount: u64,
        decimals: u8,
    ) -> Result<()> {
        transfer_checked(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                TransferChecked {
                    from: ctx.accounts.source.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                    to: ctx.accounts.destination.to_account_info(),
                    authority: ctx.accounts.permanent_delegate.to_account_info(),
                },
            ),
            amount,
            decimals,
        )?;
        msg!("seized {} without holder consent", amount);
        Ok(())
    }

    pub fn assert_supported_mint(ctx: Context<AssertSupportedMint>) -> Result<()> {
        let account_info = ctx.accounts.mint.to_account_info();
        let data = account_info.try_borrow_data()?;
        let state = StateWithExtensions::<MintState>::unpack(&data)?;

        let decimals = state.base.decimals;

        for extension in state.get_extension_types()? {
            require!(
                SUPPORTED_EXTENSIONS.contains(&extension),
                MintError::UnsupportedExtension
            );
        }

        let basis_points = match state.get_extension::<TransferFeeConfig>() {
            Ok(config) => u16::from(
                config
                    .get_epoch_fee(Clock::get()?.epoch)
                    .transfer_fee_basis_points,
            ),
            Err(_) => 0,
        };

        msg!(
            "mint accepted: {} decimals, {} bps fee",
            decimals,
            basis_points
        );
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(decimals: u8)]
pub struct CreateMintDeclarative<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        init,
        payer = payer,
        mint::decimals = decimals,
        mint::authority = payer,
        mint::token_program = token_program,
        extensions::close_authority::authority = payer,
        extensions::metadata_pointer::authority = payer,
        extensions::metadata_pointer::metadata_address = payer,
    )]
    pub mint: InterfaceAccount<'info, Mint>,

    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CreateRemittanceMint<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: Created and initialized via CPI in handler
    #[account(mut, signer)]
    pub mint: UncheckedAccount<'info>,
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct TransferRemittance<'info> {
    /// CHECK: Validated via Token-2022 transfer_checked_with_fee CPI
    #[account(mut, owner = token_program.key())]
    pub source: UncheckedAccount<'info>,
    /// CHECK: Unpacked via StateWithExtensions in handler
    #[account(owner = token_program.key())]
    pub mint: UncheckedAccount<'info>,
    /// CHECK: Validated via Token-2022 transfer_checked_with_fee CPI
    #[account(mut, owner = token_program.key())]
    pub destination: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct ThawKycAccount<'info> {
    /// CHECK: Validated via Token-2022 thaw_account CPI and StateWithExtensions
    #[account(mut, owner = token_program.key())]
    pub token_account: UncheckedAccount<'info>,
    /// CHECK: Validated via Token-2022 thaw_account CPI
    #[account(owner = token_program.key())]
    pub mint: UncheckedAccount<'info>,
    pub freeze_authority: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct CreateSeizableConfidentialMint<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: Created and initialized via CPI in handler
    #[account(mut, signer)]
    pub mint: UncheckedAccount<'info>,
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ApproveConfidentialAccount<'info> {
    /// CHECK: Validated via Token-2022 approve_account CPI
    #[account(mut, owner = token_program.key())]
    pub token_account: UncheckedAccount<'info>,
    /// CHECK: Validated via Token-2022 approve_account CPI
    #[account(owner = token_program.key())]
    pub mint: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct ExecuteDelegatedTransfer<'info> {
    /// CHECK: Validated via Token-2022 transfer_checked CPI
    #[account(mut, owner = token_program.key())]
    pub source: UncheckedAccount<'info>,
    /// CHECK: Unpacked via StateWithExtensions in handler
    #[account(owner = token_program.key())]
    pub mint: UncheckedAccount<'info>,
    /// CHECK: Validated via Token-2022 transfer_checked CPI
    #[account(mut, owner = token_program.key())]
    pub destination: UncheckedAccount<'info>,
    pub delegate: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct CreateMintWithFee<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: created and initialized in the handler, and required to sign
    #[account(mut, signer)]
    pub mint: UncheckedAccount<'info>,

    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AssertSupportedMint<'info> {
    /// CHECK: ownership enforced below, contents allowlisted in the handler.
    #[account(owner = token_program.key())]
    pub mint: UncheckedAccount<'info>,

    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct CreateConfidentialMint<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: created and initialized in the handler
    #[account(mut, signer)]
    pub mint: UncheckedAccount<'info>,

    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CreateConfidentialFeeMint<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: created and initialized in the handler.
    #[account(mut, signer)]
    pub mint: UncheckedAccount<'info>,

    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct DepositConfidential<'info> {
    /// CHECK: validated by Token-2022
    #[account(mut, owner = token_program.key())]
    pub token_account: UncheckedAccount<'info>,

    /// CHECK: validated by Token-2022 during the deposit.
    #[account(owner = token_program.key())]
    pub mint: UncheckedAccount<'info>,

    pub authority: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct ApplyPendingBalance<'info> {
    /// CHECK: validated by Token-2022.
    #[account(mut, owner = token_program.key())]
    pub token_account: UncheckedAccount<'info>,

    pub authority: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
#[instruction(decimals: u8)]
pub struct CreateSeizableMint<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        init,
        payer = payer,
        mint::decimals = decimals,
        mint::authority = payer,
        mint::token_program = token_program,
        extensions::permanent_delegate::delegate = payer,
    )]
    pub mint: InterfaceAccount<'info, Mint>,

    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct DelegateToProgram<'info> {
    /// CHECK: validated by Token-2022 during Approve.
    #[account(mut, owner = token_program.key())]
    pub token_account: UncheckedAccount<'info>,

    /// CHECK: any address may receive delegation; Token-2022 stores it as is.
    pub delegate: UncheckedAccount<'info>,

    pub owner: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct PermanentDelegateSeize<'info> {
    /// CHECK: validated by Token-2022. Note it is not a signer.
    #[account(mut, owner = token_program.key())]
    pub source: UncheckedAccount<'info>,

    /// CHECK: validated by Token-2022.
    #[account(owner = token_program.key())]
    pub mint: UncheckedAccount<'info>,

    /// CHECK: validated by Token-2022.
    #[account(mut, owner = token_program.key())]
    pub destination: UncheckedAccount<'info>,

    pub permanent_delegate: Signer<'info>,

    pub token_program: Interface<'info, TokenInterface>,
}

#[error_code]
pub enum MintError {
    #[msg("mint carries an extension this program has not been written to handle")]
    UnsupportedExtension,
    #[msg("fee calculation overflow")]
    FeeCalculationOverflow,
    #[msg("token account is still frozen")]
    AccountStillFrozen,
}


