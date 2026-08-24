# BarePass TODO

## Project rules

* [x] Rust project.
* [x] Split runtime, application state, data model, cryptography, vault storage, and TUI rendering into focused modules from the first functional implementation.
* [x] Keep `main.rs` limited to terminal/runtime wiring rather than allowing the application to grow as a monolith.
* [x] Proper Ratatui TUI rather than numbered CLI menus.
* [x] Windows-first native terminal development target.
* [ ] Linux support.
* [ ] macOS support.
* [ ] Keep the project deliberately lean and low-bloat.
* [x] Use established, audited cryptographic primitives rather than home-grown cryptography.
* [x] Maintain this TODO on every development edit.
* [x] Use `git add .` for development slices.
* [x] Commit every development slice.
* [x] Push every development slice to GitHub.
* [x] Use `main` as the development/default branch.

## Phase 0 — encrypted vault proof of concept

* [x] Create a new encrypted vault.
* [x] Unlock an existing encrypted vault.
* [x] Mask master-password input inside the TUI.
* [x] Require master-password confirmation when creating a vault.
* [x] Do not persist the master password.
* [x] Derive the vault key using Argon2id.
* [x] Start new vaults at Argon2id 64 MiB / 3 iterations / 1 lane.
* [x] Store KDF parameters in the vault header for future migration/tuning.
* [x] Generate salts from the operating-system CSPRNG.
* [x] Encrypt the vault with XChaCha20-Poly1305.
* [x] Generate a fresh 192-bit nonce for each encryption.
* [x] Authenticate the vault header as AEAD associated data.
* [x] Reject incorrect master passwords.
* [x] Reject modified/tampered ciphertext.
* [x] Zeroize temporary plaintext serialization buffers.
* [x] Zeroize master-password input buffers.
* [x] Keep only the derived vault key while the vault is unlocked.
* [x] Zeroize the derived vault key when locking/dropping the unlocked vault.
* [x] Ignore local `*.vault` files in Git.
* [x] Provide tests for encryption/decryption round-trip.
* [x] Provide a test proving wrong passwords fail.
* [x] Provide a test proving ciphertext tampering fails.

## Phase 1 — usable password vault

* [x] Add password/login entries from the TUI.
* [x] Edit existing entries.
* [x] Delete entries through a confirmation dialog.
* [x] Build keyboard-navigable entry list.
* [x] Build entry detail panel.
* [ ] Search/filter entries live.
* [ ] Copy username to clipboard.
* [ ] Copy password to clipboard.
* [ ] Automatically clear copied secrets from the clipboard.
* [ ] Reveal/hide password action.
* [x] Persist edits without retaining the master password.
* [x] Update vault timestamps when contents change.
* [x] Generate unique stable entry IDs.
* [ ] Add crash-safe/atomic vault writes before normal CRUD is trusted.
* [ ] Protect against two BarePass processes modifying the same vault simultaneously.
* [ ] Move normal vault storage from the working directory to the OS-native application data location.
* [ ] Improve terminal cleanup so panics/errors cannot leave the terminal stuck in raw mode.
* [ ] Add automatic vault locking after configurable inactivity.
* [ ] Audit in-memory lifetime of usernames, passwords, notes, clipboard buffers, and temporary UI strings.

## Phase 2 — Recently Deleted and recovery

This is a pre-1.0 core requirement, not an optional stretch goal.

* [x] Deleted entries move to Recently Deleted instead of being immediately destroyed.
* [x] Show deletion timestamp.
* [x] Restore an item from Recently Deleted.
* [x] Permanently delete a selected item with an explicit confirmation.
* [ ] Empty Recently Deleted with an explicit confirmation.
* [ ] Add configurable automatic purge age.
* [x] Ensure ordinary accidental deletion cannot permanently destroy vault data.
* [x] Add recovery tests covering delete → restore → save → reopen.
* [ ] Design safe backup/recovery behavior for damaged or interrupted vault writes.

## Phase 3 — password tooling

* [ ] Built-in password generator.
* [ ] Allow password generation without creating or saving an entry.
* [ ] Configurable password length.
* [ ] Character-set controls.
* [ ] Avoid biased random character selection.
* [ ] Password strength feedback.
* [ ] Duplicate/reused-password analysis.
* [ ] Weak-password analysis.

## Phase 4 — additional secret types

* [ ] Secure notes.
* [ ] Credit-card records.
* [ ] File uploads / encrypted attachments.
* [ ] Design a versioned generic vault-item format before introducing multiple item types.
* [ ] Ensure attachments are encrypted before touching persistent storage.
* [ ] Decide sensible vault/attachment size limits.

## Phase 5 — multiple vaults

* [ ] Create multiple independent vaults.
* [ ] Vault chooser.
* [ ] Rename vaults.
* [ ] Separate personal/work/organization vaults.
* [ ] Independent master-password/key material per vault.
* [ ] Safe vault deletion workflow.
* [ ] Recently Deleted behavior must not disappear merely because multiple vaults exist.

## Phase 6 — cross-platform

* [x] Windows is the initial supported development target.
* [ ] Verify Windows Terminal behavior.
* [ ] Verify classic PowerShell/cmd terminal behavior where practical.
* [ ] Linux terminal support.
* [ ] macOS Terminal support.
* [ ] Cross-platform clipboard handling.
* [ ] Cross-platform application-data paths.
* [ ] Cross-platform file permissions and locking.
* [ ] Cross-platform CI build/test matrix.

## Phase 7 — Git remote synchronization

* [ ] Optional Git remote configuration per vault.
* [ ] Only encrypted data may ever be synchronized.
* [ ] Never write plaintext export/intermediate files into the Git repository.
* [ ] Pull/check remote state before pushing local changes.
* [ ] Detect divergent histories.
* [ ] Do not attempt normal text merges on opaque encrypted vault blobs.
* [ ] Design application-level conflict handling for two independently modified encrypted vault states.
* [ ] Preserve local recovery copies before resolving sync conflicts.
* [ ] Show sync status in the TUI.
* [ ] Manual sync command/action.
* [ ] Optional automatic sync later.
* [ ] Support normal authenticated Git transports without BarePass inventing its own Git credentials protocol.
* [ ] Threat-model what Git metadata reveals even though vault contents remain encrypted.

## Security hardening before 1.0

* [ ] Benchmark Argon2id unlock latency on representative machines.
* [ ] Tune new-vault KDF defaults while retaining old-vault compatibility.
* [ ] Define vault format migration rules.
* [ ] Fuzz malformed vault headers and ciphertext.
* [ ] Audit all error messages for secret leakage.
* [ ] Audit filesystem permissions on Windows/Linux/macOS.
* [ ] Audit clipboard behavior.
* [ ] Audit swap/pagefile exposure limitations and document them honestly.
* [ ] Audit crash dumps/core dumps and their relationship to unlocked secrets.
* [ ] Add authenticated backup/export format.
* [ ] Perform dependency security audit.
* [ ] Perform a dedicated cryptographic-design review.
* [ ] Treat BarePass as pre-audit software until independently reviewed.

## Later candidates

* [ ] TOTP support.
* [ ] Import from common password-manager formats.
* [ ] Encrypted export.
* [ ] Password history.
* [ ] Optional breach checking using a privacy-preserving lookup design.
* [ ] Themes/customization without turning BarePass into a 400 MB Electron app because absolutely not.
