//! This module implements the BDN18 scheme (c.f. https://eprint.iacr.org/2018/483.pdf)
//! We implement the discrete log scheme in section 5.1, but modified to use 
//! proof of possession as described in section 6.3. This results in simpler key aggregation.
//! Specifically, the key aggregation only requires linear number of group additions, and no
//! scalar multiplications -- this makes the verifier much more efficient, which is useful
//! if the verifier is embedded in a SNARK circuit or run on a smart contract, for instance.

use super::MultiSigScheme;
use ark_crypto_primitives::Error;
use ark_std::{Zero, ops::*};
use ark_ec::{AffineRepr, PrimeGroup, CurveGroup};
use ark_ff::{
    fields::PrimeField,
    UniformRand,
};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;
use ark_std::{hash::Hash, marker::PhantomData, vec::Vec, collections::HashMap};
use blake2::Blake2s;
use digest::Digest;

pub struct BDN18<C: CurveGroup> {
    _group: PhantomData<C>,
}

#[derive(Clone, Debug)]
pub struct Parameters<C: CurveGroup> {
    pub generator: C::Affine,
}

pub type PublicKey<C> = <C as CurveGroup>::Affine;

pub type SecretKey<C> = <C as PrimeGroup>::ScalarField;

pub type AggregatePublicKey<C> = <C as CurveGroup>::Affine;

#[derive(Clone, Default, Debug, CanonicalSerialize)]
pub struct Signature<C: CurveGroup> {
    pub prover_response: C::ScalarField,
    pub verifier_challenge: [u8; 32],
}

pub type AggregateSignature<C> = Signature<C>;

#[derive(Clone, Debug)]
pub struct ProtocolState<C: CurveGroup> {
    pub rounds_passed: usize, // number of elapsed rounds in the protocol
    public_keys: Vec<C::Affine>, // all participants' public keys (including self)
    nonce: C::ScalarField, // secret nonce for singing
    nonce_commitment: C::Affine, // public DLOG commitment to the above nonce
    message: Vec<u8>, // the message being signed
    verifier_challenge: [u8; 32], // the verifier challenge
    // all messages (including self) indexed by round and then by sender
    transcript: HashMap<usize, HashMap<C::Affine, ProtocolMessage<C>>>,
}

#[derive(Clone, Debug)]
pub enum ProtocolMessage<C: CurveGroup> {
    Round1Message([u8; 32]),
    Round2Message(C::Affine),
    Round3Message(Signature<C>),
}

impl<C: CurveGroup + Hash> MultiSigScheme for BDN18<C>
where
    C::ScalarField: PrimeField,
{
    type Parameters = Parameters<C>;
    type PublicKey = PublicKey<C>;
    type AggregatePublicKey = AggregatePublicKey<C>;
    type SecretKey = SecretKey<C>;
    type Signature = Signature<C>;
    type AggregateSignature = Signature<C>;
    type ProtocolState = ProtocolState<C>;
    type ProtocolMessage = ProtocolMessage<C>;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        let generator = C::generator().into();
        Ok(Parameters { generator })
    }

    fn keygen<R: Rng>(
        parameters: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error> {
        // Secret is a random scalar x
        // the pubkey is y = xG
        let secret_key = C::ScalarField::rand(rng);
        let public_key = parameters.generator.mul(secret_key).into();

        Ok(( public_key, secret_key ))
    }

    fn aggregate_public_keys(
        _pp: &Self::Parameters,
        pks: &[Self::PublicKey], // public keys for key aggregation
    ) -> Result<Self::AggregatePublicKey, Error> {
        Ok(pks.iter().fold(
            C::Affine::zero(),
            |acc, pk| (acc + pk).into()
        ))
    }

    fn create_signing_protocol_instance<R: Rng>(
        pp: &Self::Parameters, // public parameters
        pks: &[Self::PublicKey], // participants, including self
        _sk: &Self::SecretKey, // secret key of the current party
        message: &[u8], // message to be signed
        rng: &mut R,
    ) -> Result<Self::ProtocolState, Error> {

        let nonce: C::ScalarField = C::ScalarField::rand(rng);
        let nonce_commitment = pp.generator.mul(nonce).into_affine();

        // create an empty transcript for 3 rounds
        let mut transcript: HashMap<usize, HashMap<<C as CurveGroup>::Affine, ProtocolMessage<C>>> = HashMap::new();
        transcript.insert(1, HashMap::new());
        transcript.insert(2, HashMap::new());
        transcript.insert(3, HashMap::new());

        Ok(ProtocolState {
            rounds_passed: 0,
            nonce,
            nonce_commitment,
            message: message.to_vec(),
            public_keys: pks.to_vec(),
            transcript,
            verifier_challenge: [0u8; 32],
        })
    }

    fn protocol_next_message_function<R: Rng>(
        pp: &Self::Parameters,
        state: &Self::ProtocolState,
        sk: &Self::SecretKey,
        prev_round_messages: HashMap<Self::PublicKey, Self::ProtocolMessage>,
        _rng: &mut R,
    ) -> Result<(Self::ProtocolState, Option<Self::ProtocolMessage>, Option<Self::AggregateSignature>), Error> {

        if state.rounds_passed == 0 {

            /*
             * Round 1 logic: send out hash of the nonce commitment
             */

            // sanity check: no incoming messages in round 0
            assert!(prev_round_messages.len() == 0);

            // send out the hash
            let hash_commitment = compute_nonce_commitment_hash::<C>(&state.nonce_commitment);

            Ok((
                ProtocolState { // new state
                    rounds_passed: 1,
                    ..state.clone()
                },
                Some(ProtocolMessage::Round1Message(hash_commitment)), // outgoing message
                None // no output yet from the protocol
            ))
        } else if state.rounds_passed == 1 {
            /*
             * Round 2 logic: send out the nonce commitment
             */
            
            // sanity checks:
            //  1. expect a message from each participant
            //  2. all messages must be round 1 messages
            //  3. all senders must be known participants
            assert!(prev_round_messages.len() == state.public_keys.len()); // check 1
            for (pk, r1_msg) in prev_round_messages.iter() {
                assert!(matches!(r1_msg, ProtocolMessage::Round1Message(_))); // check 2
                assert!(state.public_keys.contains(pk)); // check 3
            }

            // add incoming messages to the in-state transcript
            let mut updated_transcript = state.transcript.clone();
            updated_transcript.insert(1, prev_round_messages.clone());

            Ok((
                ProtocolState { // new state
                    rounds_passed: 2,
                    transcript: updated_transcript,
                    ..state.clone()
                },
                Some(ProtocolMessage::Round2Message(state.nonce_commitment)), // outgoing message
                None // no output yet from the protocol
            ))
        } else if state.rounds_passed == 2 {
            /*
             * Round 3 logic: send out the (partial) signature
             */

            // sanity checks:
            //  1. expect a message from each participant
            //  2. all messages must be round 2 messages
            //  3. all senders must be known participants
            assert!(prev_round_messages.len() == state.public_keys.len()); // check 1
            for (pk, r2_msg) in prev_round_messages.iter() {
                assert!(matches!(r2_msg, ProtocolMessage::Round2Message(_))); // check 2
                assert!(state.public_keys.contains(pk)); // check 3
            }

            let mut aggregate_nonce_commitment = C::Affine::zero();

            // check that commitments match the hashes
            for (pk, r2_msg) in prev_round_messages.iter() {
                let r1_msg_from_pk = state.transcript.get(&1).unwrap().get(pk).unwrap();
                if let ProtocolMessage::Round1Message(nonce_commitment_hash) = r1_msg_from_pk {
                    if let ProtocolMessage::Round2Message(nonce_commitment) = r2_msg {
                        let computed_hash = compute_nonce_commitment_hash::<C>(nonce_commitment);
                        assert_eq!(*nonce_commitment_hash, computed_hash);

                        aggregate_nonce_commitment = aggregate_nonce_commitment.add(nonce_commitment).into();
                    }
                }
            }

            let aggregate_public_key = Self::aggregate_public_keys(pp, &state.public_keys)?;

            // produce the partial signature
            // Hash everything to get verifier challenge.
            // e := H(pubkey || r || msg);
            let verifier_challenge = compute_challenge_hash::<C>(
                &aggregate_public_key,
                &aggregate_nonce_commitment,
                &state.message
            );

            let verifier_challenge_fe = C::ScalarField::from_le_bytes_mod_order(&verifier_challenge);

            // k - xe;
            let prover_response = state.nonce - (verifier_challenge_fe * sk);
            
            let signature = Signature { prover_response, verifier_challenge};

            // add incoming messages to the in-state transcript
            let mut updated_transcript = state.transcript.clone();
            updated_transcript.insert(2, prev_round_messages.clone());

            Ok((
                ProtocolState {
                    rounds_passed: 3,
                    verifier_challenge,
                    transcript: updated_transcript,
                    ..state.clone()
                },
                Some(ProtocolMessage::Round3Message(signature)),
                None
            ))
        } else if state.rounds_passed == 3 {
            /*
             * Output: aggregate the partial signatures and output the aggregate signature
             */

             // sanity checks:
            //  1. expect a message from each participant
            //  2. all messages must be round 2 messages
            //  3. all senders must be known participants
            assert!(prev_round_messages.len() == state.public_keys.len()); // check 1
            for (pk, r3_msg) in prev_round_messages.iter() {
                assert!(matches!(r3_msg, ProtocolMessage::Round3Message(_))); // check 2
                assert!(state.public_keys.contains(pk)); // check 3
            }

            // check all have the same verifier challenge
            let mut aggregate_prover_response = C::ScalarField::zero();
            for (_pk, r3_msg) in prev_round_messages.iter() {
                if let ProtocolMessage::Round3Message(sig) = r3_msg {
                    assert_eq!(sig.verifier_challenge, state.verifier_challenge);

                    aggregate_prover_response += sig.prover_response;
                }
            }

            let multisignature = AggregateSignature {
                prover_response: aggregate_prover_response,
                verifier_challenge: state.verifier_challenge,
            };

            // add incoming messages to the in-state transcript
            let mut updated_transcript = state.transcript.clone();
            updated_transcript.insert(3, prev_round_messages.clone());

            Ok((
                ProtocolState {
                    rounds_passed: 4,
                    transcript: updated_transcript,
                    ..state.clone()
                },
                None, // no outgoing message
                Some(multisignature) // got our output
            ))

        } else {
            panic!("Called too many times");
        }
    }

    fn verify(
        parameters: &Self::Parameters,
        pks: &[Self::PublicKey],
        message: &[u8],
        signature: &Self::AggregateSignature,
    ) -> Result<bool, Error> {
        // let verify_time = start_timer!(|| "SchnorrSig::Verify");

        let apk = pks
            .iter()
            .fold(C::Affine::zero(), |acc, pk| (acc + pk).into());

        let AggregateSignature {
            prover_response,
            verifier_challenge,
        } = signature;
        let verifier_challenge_fe = C::ScalarField::from_le_bytes_mod_order(verifier_challenge);
        // sG = kG - eY
        // kG = sG + eY
        // so we first solve for kG.
        let mut claimed_prover_commitment = parameters.generator.mul(*prover_response);
        let public_key_times_verifier_challenge = apk.mul(verifier_challenge_fe);
        claimed_prover_commitment += &public_key_times_verifier_challenge;
        let claimed_prover_commitment = claimed_prover_commitment.into_affine();

        // e := H(pubkey || r || msg)
        let obtained_verifier_challenge = compute_challenge_hash::<C>(&apk, &claimed_prover_commitment, message);

        // The signature is valid iff the computed verifier challenge is the same as the one
        // provided in the signature
        Ok(*verifier_challenge == obtained_verifier_challenge)
    }
}

fn compute_nonce_commitment_hash<C: CurveGroup>(nonce_commitment: &C::Affine) -> [u8; 32] {
    let mut hash_input = Vec::new();
    [1u8; 1].serialize_compressed(&mut hash_input).unwrap(); //for domain separation
    nonce_commitment.serialize_compressed(&mut hash_input).unwrap();

    let hash_digest = Blake2s::digest(&hash_input);

    assert!(hash_digest.len() >= 32);
    let mut hash_commitment = [0u8; 32];
    hash_commitment.copy_from_slice(&hash_digest);

    hash_commitment
}

fn compute_challenge_hash<C: CurveGroup>(pk: &C::Affine, r: &C::Affine, msg: &[u8]) -> [u8; 32] {
    let mut hash_input = Vec::new();
    [2u8; 1].serialize_compressed(&mut hash_input).unwrap(); //for domain separation
    pk.serialize_compressed(&mut hash_input).unwrap();
    r.serialize_compressed(&mut hash_input).unwrap();
    msg.serialize_compressed(&mut hash_input).unwrap();

    let hash_digest = Blake2s::digest(&hash_input);

    assert!(hash_digest.len() >= 32);
    let mut verifier_challenge = [0u8; 32];
    verifier_challenge.copy_from_slice(&hash_digest);

    verifier_challenge
}