//! Implements the construction from https://eprint.iacr.org/2016/144.pdf (Figure 7)

#![allow(dead_code, unused)]
use super::PpssPcheme;
use ark_crypto_primitives::Error;
use ark_std::ops::*;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;
use ark_std::{Zero, hash::Hash, marker::PhantomData, vec::Vec};

use ark_bls12_381::g1::Config as G1Config;
use ark_bls12_381::g2::Config as G2Config;
use ark_bls12_381::{Fq2, G1Affine, G2Affine, G1Projective, G2Projective};
use ark_bls12_381::{Bls12_381, Fq, Fr};
use ark_ec::{CurveGroup, CurveConfig, AffineRepr, short_weierstrass::{Affine, Projective}};
use ark_ec::hashing::{HashToCurve, curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher};
use ark_ff::{Field, fields::PrimeField, UniformRand, field_hashers::DefaultFieldHasher, BigInteger256};

use blake2::Blake2s;
use digest::Digest;
use sha2::Sha256;

use super::sss;

pub const DST_G2: &str = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
pub const DST_G1: &str = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";

pub struct JKKX16 {
    _group: PhantomData<G1Config>,
}

#[derive(Clone, Debug)]
pub struct Parameters<C: CurveGroup> {
    pub generator: C::Affine,
}

pub type PublicKey<C> = <C as CurveGroup>::Affine;

pub type SecretKey = [u8; 16];

#[derive(Clone, Default, Debug, CanonicalSerialize)]
pub struct Ciphertext<C: CurveGroup> {
    encrypted_shares: Vec<(C::ScalarField, C::ScalarField)>,
    hash: C::ScalarField, 
}

#[derive(Clone, Default, Debug, CanonicalSerialize)]
pub struct PrfInput<C: CurveGroup> {
    pub blinded_prf_input: C::Affine,
    pub client_id: Vec<u8>,
}

#[derive(Clone, Default, Debug, CanonicalSerialize)]
pub struct PrfOutput<C: CurveGroup> {
    pub blinded_prf_output: C::Affine,
}

#[derive(Clone, Debug)]
pub struct ClientState<C: CurveGroup> {
    pub blind_scalar: C::ScalarField,
    pub client_id: Vec<u8>,
    pub password: Vec<u8>,
}

impl PpssPcheme for JKKX16
{
    type Parameters = Parameters<G1Projective>;
    type PublicKey = PublicKey<G1Projective>;
    type SecretKey = SecretKey;
    type PrfInput = PrfInput<G1Projective>;
    type PrfOutput = PrfOutput<G1Projective>;
    type Ciphertext = Ciphertext<G1Projective>;
    type ClientState = ClientState<G1Projective>;

    /// Generates the public parameters for the scheme.
    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        let generator = Affine::<G1Config>::generator().into();
        Ok(Parameters { generator })
    }

    /// Gemerates an keygen request for the server
    fn client_generate_keygen_request<R: Rng>(
        pp: &Self::Parameters,
        client_id: &[u8],
        password: &[u8],
        rng: &mut R,
    ) -> Result<(Self::ClientState, Self::PrfInput), Error> {
        // hash the password to a group element
        let password_hash: Affine::<G1Config> = hash_to_g1point(&password.to_vec(), &DST_G1.as_bytes().to_vec());

        let random_scalar = Fr::rand(rng);
        let blinded_prf_input = password_hash.mul(&random_scalar).into();

        let input = PrfInput { blinded_prf_input, client_id: client_id.to_vec() };
        let state = ClientState { 
            blind_scalar: random_scalar,
            client_id: client_id.to_vec(),
            password: password.to_vec(),
        };

        Ok((state, input))
    }

    fn server_process_keygen_request<R: Rng>(
        pp: &Self::Parameters,
        seed: &[u8; 32],
        client_id: &[u8],
        input: &Self::PrfInput,
    ) -> Result<(Self::PublicKey, Self::PrfOutput), Error> {
        let (client_secret_key, client_public_key) = {
            // TODO: do proper HKDF here. For now, Hash seed and client_id.
            // k := H(seed || client_id);
            let client_secret_key = hash_to_fr(&[], &[], &[seed.to_vec(), client_id.to_vec()])?;
            let client_public_key = pp.generator.mul(&client_secret_key).into();

            (client_secret_key, client_public_key)
        };

        let prf_output = PrfOutput {
            blinded_prf_output: input.blinded_prf_input.mul(&client_secret_key).into(),
        };
        Ok((client_public_key, prf_output))
    }

    fn client_keygen<R: Rng>(
        pp: &Self::Parameters,
        state: &Self::ClientState,
        server_responses: &[(Self::PublicKey, Self::PrfOutput)],
        num_servers: usize,
        threshold: usize,
        rng: &mut R,
    ) -> Result<(Self::SecretKey, Self::Ciphertext), Error> {
        assert!(server_responses.len() == num_servers);
        let secret = Fr::rand(rng);
        let shares = sss::share(secret, threshold, num_servers);
        let mut encrypted_shares = Vec::new();

        for (i, (server_pk, server_output)) in server_responses.iter().enumerate() {
            let prf_output: G1Affine = server_output.blinded_prf_output.mul(&state.blind_scalar.inverse().unwrap()).into();
            // e := H(password || prf_output);
            let mask_i = hash_to_fr(&[prf_output], &[], &[state.password.clone()])?;
            encrypted_shares.push((shares[i].0, shares[i].1 + mask_i));
        }

        let mut hash_input = Vec::new();
        Fr::zero().serialize_compressed(&mut hash_input)?;
        secret.serialize_compressed(&mut hash_input)?;
        let hash_digest = Blake2s::digest(&hash_input);
        assert!(hash_digest.len() >= 32);
        let mut trimmed_hash_digest = [0u8; 32];
        trimmed_hash_digest.copy_from_slice(&hash_digest.as_slice());

        let mut r = [0u8; 16]; r.copy_from_slice(&trimmed_hash_digest[0..16]);
        let mut key = [0u8; 16]; key.copy_from_slice(&trimmed_hash_digest[16..32]);

        let mut ys: Vec<Fr> = Vec::new();
        ys.extend(encrypted_shares.iter().map(|(x, y)| *y).collect::<Vec<Fr>>());
        ys.extend(shares.iter().map(|(x, y)| *y).collect::<Vec<Fr>>());

        let c = hash_to_fr(&[], &ys, &[state.password.to_vec(), r.to_vec()])?;

        let ctxt: Ciphertext<G1Projective> = Ciphertext {
            encrypted_shares,
            hash: c,
        };

        Ok((key, ctxt))
    }

    fn client_generate_reconstruct_request<R: Rng>(
        pp: &Self::Parameters,
        client_id: &[u8],
        password: &[u8],
        rng: &mut R
    ) -> Result<(Self::ClientState, Self::PrfInput), Error> {
        // hash the password to a group element
        let password_hash: Affine::<G1Config> = hash_to_g1point(&password.to_vec(), &DST_G1.as_bytes().to_vec());

        let random_scalar = Fr::rand(rng);
        let blinded_prf_input = password_hash.mul(&random_scalar).into();

        let input = PrfInput { blinded_prf_input, client_id: client_id.to_vec() };
        let state = ClientState { 
            blind_scalar: random_scalar,
            client_id: client_id.to_vec(),
            password: password.to_vec(),
        };

        Ok((state, input))
    }

    fn server_process_reconstruct_request<R: Rng>(
        pp: &Self::Parameters,
        seed: &[u8; 32],
        client_id: &[u8],
        input: &Self::PrfInput,
    ) -> Result<Self::PrfOutput, Error> {
        let (client_secret_key, client_public_key) = {
            // TODO: do proper HKDF here. For now, Hash seed and client_id.
            // k := H(seed || client_id);
            let client_secret_key = hash_to_fr(&[], &[], &[seed.to_vec(), client_id.to_vec()])?;
            let client_public_key: PublicKey<G1Projective> = pp.generator.mul(&client_secret_key).into();

            (client_secret_key, client_public_key)
        };

        let prf_output = PrfOutput {
            blinded_prf_output: input.blinded_prf_input.mul(&client_secret_key).into(),
        };
        Ok(prf_output)
    }

    fn client_reconstruct<R: Rng>(
        pp: &Self::Parameters,
        state: &Self::ClientState,
        server_responses: &[(Self::PublicKey, Self::PrfOutput)],
        ciphertext: &Self::Ciphertext,
        rng: &mut R,
    ) -> Result<Self::SecretKey, Error> {
        
        let mut shares = Vec::new();
        for (i, (server_pk, server_output)) in server_responses.iter().enumerate() {
            let prf_output: G1Affine = server_output.blinded_prf_output.mul(&state.blind_scalar.inverse().unwrap()).into();
            // e := H(password || prf_output);
            let mask_i = hash_to_fr(&[prf_output], &[], &[state.password.clone()])?;
            
            let e_i = ciphertext.encrypted_shares[i];
            shares.push((e_i.0, e_i.1 - mask_i));
        }

        // interpolate the shares to get the secret
        let secret = sss::recover(&shares);

        let mut hash_input = Vec::new();
        Fr::zero().serialize_compressed(&mut hash_input)?;
        secret.serialize_compressed(&mut hash_input)?;
        let hash_digest = Blake2s::digest(&hash_input);
        assert!(hash_digest.len() >= 32);
        let mut trimmed_hash_digest = [0u8; 32];
        trimmed_hash_digest.copy_from_slice(&hash_digest.as_slice());

        let mut r = [0u8; 16]; r.copy_from_slice(&trimmed_hash_digest[0..16]);
        let mut key = [0u8; 16]; key.copy_from_slice(&trimmed_hash_digest[16..32]);

        let mut ys: Vec<Fr> = Vec::new();
        ys.extend(ciphertext.encrypted_shares.iter().map(|(x, y)| *y).collect::<Vec<Fr>>());
        ys.extend(shares.iter().map(|(x, y)| *y).collect::<Vec<Fr>>());

        let c = hash_to_fr(&[], &ys, &[state.password.to_vec(), r.to_vec()])?;

        assert_eq!(c, ciphertext.hash);

        Ok(key)
    }

}

// Adapted from https://github.com/ArnaudBrousseau/bls_on_arkworks
/// ([spec link](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-1.3))
/// A cryptographic hash function that takes as input an arbitrary octet string and returns a point on an
/// elliptic curve. Functions of this kind are defined in [hash-to-curve-spec](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16).
///
/// Note: given we're using the "minimal-pubkey-size" variant of the spec, this function must output a point in G2.
///
/// XXX: this function doesn't take DST as an argument in the spec. It should!
fn hash_to_g2point(msg: &Vec<u8>, dst: &Vec<u8>) -> Affine<G2Config> {
    let g2_mapper = MapToCurveBasedHasher::<
        Projective<G2Config>,
        DefaultFieldHasher<Sha256, 128>,
        WBMap<G2Config>,
    >::new(dst)
    .unwrap();
    let q: Affine<G2Config> = g2_mapper.hash(msg).unwrap();
    q
}

fn hash_to_g1point(msg: &Vec<u8>, dst: &Vec<u8>) -> Affine<G1Config> {
    let g1_mapper = MapToCurveBasedHasher::<
        Projective<G1Config>,
        DefaultFieldHasher<Sha256, 128>,
        WBMap<G1Config>,
    >::new(dst)
    .unwrap();
    let q: Affine<G1Config> = g1_mapper.hash(msg).unwrap();
    q
}

fn hash_to_fr(affine_inputs: &[G1Affine], scalar_inputs: &[Fr], bytearray_inputs: &[Vec<u8>]) -> Result<Fr, Error> {
    let mut hash_input = Vec::new();

    for input in affine_inputs {
        input.serialize_compressed(&mut hash_input)?;
    }
    for input in scalar_inputs {
        input.serialize_compressed(&mut hash_input)?;
    }
    for input in bytearray_inputs {
        input.serialize_compressed(&mut hash_input)?;
    }
    
    let hash_digest = Blake2s::digest(&hash_input);
    assert!(hash_digest.len() >= 32);

    let mut trimmed_hash_digest = [0u8; 32];
    trimmed_hash_digest.copy_from_slice(&hash_digest.as_slice());
    
    Ok(Fr::from_le_bytes_mod_order(&trimmed_hash_digest))
}

fn interpolate<F: Field>(points: &[(F, F)], x: &F) -> F {
    let xs = points.iter().map(|(x, _)| *x).collect::<Vec<F>>();
    let ys = points.iter().map(|(_, y)| *y).collect::<Vec<F>>();

    let λs: Vec<F> = (0..xs.len()).map(|i| {
        // each lagrange coefficient is computed with respect to x = 0,
        // since that's where we are embedding the secret in our entire
        // construction. So the ith coefficient is w.r.t. xs[i].
        crate::crypto::ppss::lagrange::lagrange_coefficient(&xs, i, x)
    }).collect();

    // the reconstructed secret is a weighted sum of ys, 
    // with the lagrange coefficients as weights
    let secret = λs.iter().zip(ys.iter())
        .fold(F::zero(), |acc, (&λ_i, &y_i)| { acc + λ_i * y_i });

    secret
}