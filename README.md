
# 🪙 Solana Week 4: Token-2022 Remittance Stablecoin & Confidential Transfers

An Anchor and Token-2022 implementation of a compliant remittance stablecoin featuring stacked mint extensions, epoch-scheduled transfer fees, KYC account thawing, permanent delegate seizure authority, end-to-end zero-knowledge confidential transfers, and CPI Guard delegation verification.

---

## 🏗️ Architecture & Implementation Summary

### 1. Stacked Remittance Stablecoin Mint (`create_remittance_mint`)

- Allocates exact rent-exempt space using `ExtensionType::try_calculate_account_len::<MintState>` for four stacked extensions:
  1. **`TransferFeeConfig`**: Enforces protocol-level transfer fees on every remittance transfer.
  2. **`MetadataPointer`**: Points directly to the mint address itself (`Some(mint.key())`) for self-contained on-chain metadata discovery.
  3. **`DefaultAccountState`**: Initializes all new token accounts in the `AccountState::Frozen` state until KYC clearance.
  4. **`MintCloseAuthority`**: Authorizes the issuer to close the mint account if the stablecoin is ever decommissioned.
- Executes every extension initialization instruction strictly **before** `initialize_mint2`.

### 2. Epoch-Aware Fee Transfers (`transfer_remittance`)

- Unpacks mint state exclusively through `StateWithExtensions::<MintState>::unpack`.
- Computes the exact expected fee dynamically for the current epoch via `fee_config.calculate_epoch_fee(current_epoch, amount)` rather than relying on a cached fee rate.
- Executes transfers via `transfer_checked_with_fee`.

### 3. Exclusive `StateWithExtensions` Parsing

- All mint and token account inspections across on-chain handlers (`transfer_remittance`, `thaw_kyc_account`, `execute_delegated_transfer`, `assert_supported_mint`) and LiteSVM tests unpack state strictly through `StateWithExtensions` rather than raw account unpacking.

### 4. Individual KYC Account Unfreezing (`thaw_kyc_account`)

- Invokes `thaw_account` signed by the mint's `freeze_authority` to unfreeze individual KYC-approved accounts without altering the mint-level `DefaultAccountState::Frozen` policy for newly created accounts.

### 5. Re-Issued Seizable Confidential Mint (`create_seizable_confidential_mint`)

Re-issues the stablecoin mint carrying forward all four remittance extensions while adding:

- **`PermanentDelegate`**: Grants the issuer seizure authority over public token balances.
- **`ConfidentialTransferMint` (`approve_policy = manual`)**: Configures `auto_approve_new_accounts = false`, requiring explicit issuer approval via `approve_confidential_account` before an account can participate in confidential transfers.

### 6. End-to-End Confidential Lifecycle (`tests/remittance.rs`)

- **`ConfigureAccount`**: Owner-signed setup initializing ElGamal and AES keys (`PubkeyValidityProofData`), separate from account creation.
- **`ApproveAccount`**: Manual approval by the confidential transfer authority.
- **`DepositConfidentialTokens`**: Moves tokens from the public `base.amount` balance into the encrypted pending balance.
- **`ApplyPendingBalance`**: Applies pending encrypted credits into the spendable `available_balance`.
- **Confidential `Transfer`**: Transfers encrypted amounts between sender and receiver using staged ZK proofs:
  - `VerifyCiphertextCommitmentEquality`
  - `VerifyBatchedGroupedCiphertext3HandlesValidity`
  - `VerifyBatchedRangeProofU128`
- **`ApplyPendingBalance` before `WithdrawConfidentialTokens`**: Applies the recipient's incoming pending transfer before generating equality and range proofs to withdraw tokens back to the public balance.

### 7. Extension Challenge: Delegated Transfer with CPI Guard (`execute_delegated_transfer`)

Demonstrates the agent/automation pattern:

- A user issues a top-level `Approve` delegation to an agent keypair.
- The user enables `CpiGuard` on their token account afterward.
- The delegate executes `transfer_checked` via CPI without modification, since `CpiGuard` blocks CPI-originated `Approve` calls, not pre-authorized top-level delegates.

---

## 📝 Written Finding: Permanent Delegate vs. Confidential Balances

> **Question:** *What happens if a sanctioned user moves their balance into the confidential system before the permanent delegate acts?*

### Finding

Once a sanctioned user deposits their tokens from the public `base.amount` balance into their encrypted confidential balance (`pending_balance` or `available_balance` via `DepositConfidentialTokens`), **the `PermanentDelegate` cannot seize, transfer, or burn those confidential tokens**:

1. **Scope Limited to Public Balances:** The `PermanentDelegate` extension only authorizes the delegate to sign standard public SPL Token-2022 instructions (`Transfer`, `TransferChecked`, `TransferCheckedWithFee`, `Burn`, `BurnChecked`), which operate exclusively on the plaintext `base.amount` field.

2. **Zero-Knowledge Proof & Key Ownership Barrier:** Moving funds out of the confidential balance (via `ConfidentialTransfer` or `WithdrawConfidentialTokens`) requires valid zero-knowledge proofs (`CiphertextCommitmentEquality` and `BatchedRangeProof`) generated using the **account owner's ElGamal secret key** and **AES decryption key**. Because the permanent delegate does not hold the user's ElGamal/AES keys, it cannot construct valid proofs to withdraw or transfer confidential balances.

3. **Compliance Gap & Operational Mitigation:**
   - **Immediate Freeze:** While the permanent delegate cannot extract already-shielded funds, the issuer's `freeze_authority` can still freeze the sanctioned token account, trapping the funds inside the confidential balance so the user cannot spend or withdraw them.
   - **Preventative Controls:** Setting `approve_policy = manual` (`auto_approve_new_accounts = false`) prevents unvetted or sanctioned accounts from enabling confidential transfers without issuer sign-off, and configuring an **Auditor ElGamal Public Key** on `ConfidentialTransferMint` preserves regulatory visibility into encrypted transfer amounts.

---

## 🚀 Build & Run Tests

Run the following commands from the project root:

```bash
# 1. Build the Solana SBF program
anchor build

# 2. Run the LiteSVM test suite
cargo test --manifest-path programs/t22/Cargo.toml --test remittance
```

---

## 📂 Repository Structure

The implementation is organized around the Token-2022 program and its remittance integration tests.

```text
token-22-turbin3-q3-/
├── programs/
│   └── t22/
│       ├── src/
│       │   └── lib.rs
│       ├── tests/
│       │   └── remittance.rs
│       └── Cargo.toml
├── Anchor.toml
└── Cargo.toml
```

---

## 📤 Push to GitHub

Run these commands in PowerShell inside:

`C:\Users\ASUS\token-22-turbin3-q3-`

```powershell
# Set the GitHub repository as the remote origin
git remote set-url origin https://github.com/Torqued-codes/turbin3-token-.git

# Stage all changes
git add .

# Commit the Week 4 implementation
git commit -m "Complete Week 4 Token-2022 remittance stablecoin, CT lifecycle, CPI Guard, and written finding"

# Push to the main branch
git push -u origin main
```

---
