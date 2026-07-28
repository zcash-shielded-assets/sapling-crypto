use core::fmt;

use alloc::string::String;
use alloc::vec::Vec;

use crate::{
    note::ExtractedNoteCommitment,
    note_encryption::ENC_CIPHERTEXT_SIZE,
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
    PaymentAddress, ProofGenerationKey,
};
use redjubjub::VerificationKey;
use zcash_note_encryption::{EphemeralKeyBytes, OutgoingCipherKey, OUT_CIPHERTEXT_SIZE};

use super::{Bundle, Output, Spend, Zip32Derivation};

impl Bundle {
    /// Updates the bundle with information provided in the given closure.
    pub fn update_with<F>(&mut self, f: F) -> Result<(), UpdaterError>
    where
        F: FnOnce(Updater<'_>) -> Result<(), UpdaterError>,
    {
        f(Updater(self))
    }
}

/// An updater for a Sapling PCZT bundle.
pub struct Updater<'a>(&'a mut Bundle);

impl Updater<'_> {
    /// Provides read access to the bundle being updated.
    pub fn bundle(&self) -> &Bundle {
        self.0
    }

    /// Updates the spend at the given index with information provided in the given
    /// closure.
    pub fn update_spend_with<F>(&mut self, index: usize, f: F) -> Result<(), UpdaterError>
    where
        F: FnOnce(SpendUpdater<'_>) -> Result<(), UpdaterError>,
    {
        f(SpendUpdater(
            self.0
                .spends
                .get_mut(index)
                .ok_or(UpdaterError::InvalidIndex)?,
        ))
    }

    /// Updates the output at the given index with information provided in the given
    /// closure.
    pub fn update_output_with<F>(&mut self, index: usize, f: F) -> Result<(), UpdaterError>
    where
        F: FnOnce(OutputUpdater<'_>) -> Result<(), UpdaterError>,
    {
        f(OutputUpdater(
            self.0
                .outputs
                .get_mut(index)
                .ok_or(UpdaterError::InvalidIndex)?,
        ))
    }
}

/// An updater for a Sapling PCZT spend.
pub struct SpendUpdater<'a>(&'a mut Spend);

impl SpendUpdater<'_> {
    /// Sets the proof generation key for this spend.
    ///
    /// Returns an error if the proof generation key does not match the spend.
    pub fn set_proof_generation_key(
        &mut self,
        proof_generation_key: ProofGenerationKey,
    ) -> Result<(), UpdaterError> {
        // TODO: Verify that the proof generation key matches the spend, if possible.
        self.0.proof_generation_key = Some(proof_generation_key);
        Ok(())
    }

    /// Sets the witness Merkle path for the spent note's proof.
    pub fn set_witness(&mut self, witness: incrementalmerkletree::MerklePath<crate::Node, 32>) {
        self.0.witness = Some(witness);
    }

    /// Sets the ZIP 32 derivation path for the spent note's signing key.
    pub fn set_zip32_derivation(&mut self, derivation: Zip32Derivation) {
        self.0.zip32_derivation = Some(derivation);
    }

    /// Stores the given proprietary value at the given key.
    pub fn set_proprietary(&mut self, key: String, value: Vec<u8>) {
        self.0.proprietary.insert(key, value);
    }

    /// Sets the value commitment for this spend.
    pub fn set_cv(&mut self, cv: ValueCommitment) {
        self.0.cv = cv;
    }

    /// Sets the randomized verification key for this spend.
    pub fn set_rk(&mut self, rk: VerificationKey<redjubjub::SpendAuth>) {
        self.0.rk = rk;
    }

    /// Sets the value commitment randomness for this spend.
    pub fn set_rcv(&mut self, rcv: ValueCommitTrapdoor) {
        self.0.rcv = Some(rcv);
    }

    /// Sets the spend authorization randomizer for this spend.
    pub fn set_alpha(&mut self, alpha: jubjub::Scalar) {
        self.0.alpha = Some(alpha);
    }

    /// Sets the seed randomness for the note being spent.
    pub fn set_rseed(&mut self, rseed: crate::Rseed) {
        self.0.rseed = Some(rseed);
    }

    /// Sets the recipient address for this spend.
    pub fn set_recipient(&mut self, recipient: PaymentAddress) {
        self.0.recipient = Some(recipient);
    }

    /// Sets the value of the note being spent.
    pub fn set_value(&mut self, value: NoteValue) {
        self.0.value = Some(value);
    }
}

/// An updater for a Sapling PCZT output.
pub struct OutputUpdater<'a>(&'a mut Output);

impl OutputUpdater<'_> {
    /// Sets the ZIP 32 derivation path for the new note's signing key.
    pub fn set_zip32_derivation(&mut self, derivation: Zip32Derivation) {
        self.0.zip32_derivation = Some(derivation);
    }

    /// Sets the user-facing address that the new note is being sent to.
    pub fn set_user_address(&mut self, user_address: String) {
        self.0.user_address = Some(user_address);
    }

    /// Stores the given proprietary value at the given key.
    pub fn set_proprietary(&mut self, key: String, value: Vec<u8>) {
        self.0.proprietary.insert(key, value);
    }

    /// Sets the value commitment for this output.
    pub fn set_cv(&mut self, cv: ValueCommitment) {
        self.0.cv = cv;
    }

    /// Sets the note commitment for this output.
    pub fn set_cmu(&mut self, cmu: ExtractedNoteCommitment) {
        self.0.cmu = cmu;
    }

    /// Sets the ephemeral key for this output.
    pub fn set_ephemeral_key(&mut self, epk: EphemeralKeyBytes) {
        self.0.ephemeral_key = epk;
    }

    /// Sets the encrypted note ciphertext for this output.
    pub fn set_enc_ciphertext(&mut self, enc: [u8; ENC_CIPHERTEXT_SIZE]) {
        self.0.enc_ciphertext = enc;
    }

    /// Sets the encrypted outgoing ciphertext for this output.
    pub fn set_out_ciphertext(&mut self, cout: [u8; OUT_CIPHERTEXT_SIZE]) {
        self.0.out_ciphertext = cout;
    }

    /// Sets the value commitment randomness for this output.
    pub fn set_rcv(&mut self, rcv: ValueCommitTrapdoor) {
        self.0.rcv = Some(rcv);
    }

    /// Sets the seed randomness for this output.
    pub fn set_rseed(&mut self, rseed: [u8; 32]) {
        self.0.rseed = Some(rseed);
    }

    /// Sets the outgoing cipher key for this output.
    pub fn set_ock(&mut self, ock: OutgoingCipherKey) {
        self.0.ock = Some(ock);
    }

    /// Sets the recipient address for this output.
    pub fn set_recipient(&mut self, recipient: PaymentAddress) {
        self.0.recipient = Some(recipient);
    }

    /// Sets the value of this output.
    pub fn set_value(&mut self, value: NoteValue) {
        self.0.value = Some(value);
    }
}

/// Errors that can occur while updating a Sapling bundle in a PCZT.
#[derive(Debug)]
#[non_exhaustive]
pub enum UpdaterError {
    /// An out-of-bounds index was provided when looking up a spend or output.
    InvalidIndex,
    /// The provided `proof_generation_key` does not match the spend.
    WrongProofGenerationKey,
}

impl fmt::Display for UpdaterError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            UpdaterError::InvalidIndex => write!(f, "Spend or output index is out-of-bounds"),
            UpdaterError::WrongProofGenerationKey => {
                write!(f, "`proof_generation_key` does not own the spent note")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UpdaterError {}
