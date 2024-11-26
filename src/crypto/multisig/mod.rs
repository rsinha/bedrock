//! This module implements multisigs, defined as follows (from https://eprint.iacr.org/2018/483.pdf).
//! Consider n parties where each party independently generates a key pair for a signature scheme. 
//! Some time later, all n parties want to sign the same message m. A multi-signature scheme is a protocol 
//! that enables the n signers to jointly generate a short signature σ on m so that σ convinces a verifier 
//! that all n parties signed m. Specifically, the verifier is given as input the n public keys, the message m, 
//! and the multi-signature σ. The algorithm either accepts or rejects σ. 
//! The multi-signature σ should be short; its length should be independent of the number of signers n.

use ark_crypto_primitives::Error;
use ark_serialize::CanonicalSerialize;
use ark_std::hash::Hash;
use ark_std::collections::HashMap;
use ark_std::rand::Rng;

pub mod bdn18;

#[allow(dead_code)]
pub trait MultiSigScheme {
    type Parameters: Clone + Send + Sync;
    type ProtocolState: Clone + Send + Sync;
    type ProtocolMessage: Clone + Send + Sync;
    type PublicKey: CanonicalSerialize + Hash + Eq + Clone + Default + Send + Sync;
    type AggregatePublicKey: CanonicalSerialize + Hash + Eq + Clone + Default + Send + Sync;
    type SecretKey: CanonicalSerialize + Clone + Default;
    type Signature: CanonicalSerialize + Clone + Default + Send + Sync;
    type AggregateSignature: CanonicalSerialize + Clone + Default + Send + Sync;

    /// Generates the public parameters for the scheme.
    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error>;

    /// Generates a public / private keypair for each party.
    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error>;

    /// Creates a new instance of the multiparty signing protocol.
    fn create_signing_protocol_instance<R: Rng>(
        pp: &Self::Parameters,
        pks: &[Self::PublicKey],
        sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self::ProtocolState, Error>;

    /// Computes the next message in the interactive signing protocol.
    fn protocol_next_message_function<R: Rng>(
        pp: &Self::Parameters,
        state: &Self::ProtocolState,
        sk: &Self::SecretKey,
        prev_round_message: HashMap<Self::PublicKey, Self::ProtocolMessage>,
        rng: &mut R,
    ) -> Result<(Self::ProtocolState, Option<Self::ProtocolMessage>, Option<Self::AggregateSignature>), Error>;

    /// Computes an aggregate public key from a list of public keys.
    fn aggregate_public_keys(
        pp: &Self::Parameters,
        pks: &[Self::PublicKey],
    ) -> Result<Self::AggregatePublicKey, Error>;

    /// Verifies the (aggregate) signature on the message
    fn verify(
        pp: &Self::Parameters,
        pks: &[Self::PublicKey],
        message: &[u8],
        signature: &Self::AggregateSignature,
    ) -> Result<bool, Error>;
}

#[cfg(test)]
mod test {
    use crate::crypto::multisig::{bdn18::*, *};
    use ark_secp256k1::Projective as Secp256k1;
    use ark_std::test_rng;


    fn execute_signing_protocol<S: MultiSigScheme>(message: &[u8]) -> S::AggregateSignature {

        let n = 3;

        let rng = &mut test_rng();
        let parameters = S::setup::<_>(rng).unwrap();

        // create 3 parties
        let (pks, sks): (Vec<S::PublicKey>, Vec<S::SecretKey>) = (0..n)
            .map(|_| S::keygen(&parameters, rng).unwrap())
            .collect::<Vec<(S::PublicKey, S::SecretKey)>>()
            .into_iter()
            .unzip();

        let mut parties = (0..n)
            .map(|i| S::create_signing_protocol_instance(&parameters, &pks, &sks[i], message, rng).unwrap())
            .collect::<Vec<S::ProtocolState>>();

        let mut input_messages: HashMap<S::PublicKey, S::ProtocolMessage> = HashMap::new();
        for _round in 0..3 {
            let mut messages: HashMap<S::PublicKey, S::ProtocolMessage> = HashMap::new();
            for i in 0..n {
                let (state, msg, _) = S::protocol_next_message_function(
                    &parameters, &parties[i], &sks[i], input_messages.clone(), rng
                ).unwrap();
                messages.insert(pks[i].clone(), msg.unwrap());
                parties[i] = state;
            }
            input_messages = messages;
        }

        // execute one more time and get the output
        let mut outputs: HashMap<S::PublicKey, S::AggregateSignature> = HashMap::new();
        for i in 0..n {
            let (_state, msg, out) = S::protocol_next_message_function(
                &parameters, &parties[i], &sks[i], input_messages.clone(), rng
            ).unwrap();
            assert!(msg.is_none());
            outputs.insert(pks[i].clone(), out.unwrap());
        }

        // verify message
        for output in outputs.values() {
            assert!(S::verify(&parameters, &pks, message, &output).unwrap());
        }

        return outputs.values().next().unwrap().clone();

    }

    #[test]
    fn schnorr_multisignature_test_secp256k1() {
        let message = "Hi, I am a Schnorr multisignature!";
        execute_signing_protocol::<BDN18<Secp256k1>>(message.as_bytes());
    }
}