//! Implements the construction from https://eprint.iacr.org/2016/144.pdf (Figure 7)

#![allow(dead_code, unused)]
use super::PpssPcheme;
use ark_crypto_primitives::Error;
use ark_std::ops::*;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;
use ark_std::{hash::Hash, marker::PhantomData, vec::Vec};

use ark_bls12_381::g1::Config as G1Config;
use ark_bls12_381::g2::Config as G2Config;
use ark_bls12_381::{Fq2, G2Affine};
use ark_bls12_381::{Bls12_381, Fq, Fr};
use ark_ec::{CurveGroup, CurveConfig, short_weierstrass::{Affine, Projective}};
use ark_ec::hashing::{HashToCurve, curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher};
use ark_ff::{fields::PrimeField, UniformRand, field_hashers::DefaultFieldHasher, BigInteger256};

use blake2::Blake2s;
use digest::Digest;
use sha2::Sha256;

pub struct JKKX16<C: CurveGroup> {
    _group: PhantomData<C>,
}

#[derive(Clone, Debug)]
pub struct Parameters<C: CurveGroup> {
    pub generator: C::Affine,
}

pub type PublicKey<C> = <C as CurveGroup>::Affine;

pub type SecretKey = [u8; 16];

#[derive(Clone, Default, Debug, CanonicalSerialize)]
pub struct Ciphertext<C: CurveGroup> {
    encrypted_shares: Vec<C::ScalarField>,
    hash: [u8; 32], 
}

#[derive(Clone, Default, Debug, CanonicalSerialize)]
pub struct PrfInput<C: CurveGroup> {
    pub blinded_prf_input: C::Affine,
    pub client_id: [u8; 32],
}

#[derive(Clone, Default, Debug, CanonicalSerialize)]
pub struct PrfOutput<C: CurveGroup> {
    pub blinded_prf_output: C::Affine,
}

// impl<C: CurveGroup + Hash> PpssPcheme for JKKX16<C>
// where
//     C::ScalarField: PrimeField,
// {
//     type Parameters = Parameters<C>;
//     type PublicKey = PublicKey<C>;
//     type SecretKey = SecretKey<C>;
//     type PrfInput = PrfInput<C>;
//     type PrfOutput = PrfOutput<C>;
//     type Ciphertext = Ciphertext<C>;

//     /// Generates the public parameters for the scheme.
//     fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
//         let generator = C::generator().into();
//         Ok(Parameters { generator })
//     }

//     /// Gemerates an keygen request for the server
//     fn client_keygen_request_for_server<R: Rng>(
//         pp: &Self::Parameters,
//         client_id: &[u8],
//         password: &[u8],
//     ) -> Result<Self::PrfInput, Error> {

//     }
// }

/// ([spec link](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html#section-1.3))
/// A cryptographic hash function that takes as input an arbitrary octet string and returns a point on an
/// elliptic curve. Functions of this kind are defined in [hash-to-curve-spec](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16).
///
/// Note: given we're using the "minimal-pubkey-size" variant of the spec, this function must output a point in G2.
///
/// XXX: this function doesn't take DST as an argument in the spec. It should!
pub fn hash_to_g2point(msg: &Vec<u8>, dst: &Vec<u8>) -> Affine<G2Config> {
    let g2_mapper = MapToCurveBasedHasher::<
        Projective<G2Config>,
        DefaultFieldHasher<Sha256, 128>,
        WBMap<G2Config>,
    >::new(dst)
    .unwrap();
    let q: Affine<G2Config> = g2_mapper.hash(msg).unwrap();
    q
}

pub fn hash_to_g1point(msg: &Vec<u8>, dst: &Vec<u8>) -> Affine<G1Config> {
    let g1_mapper = MapToCurveBasedHasher::<
        Projective<G1Config>,
        DefaultFieldHasher<Sha256, 128>,
        WBMap<G1Config>,
    >::new(dst)
    .unwrap();
    let q: Affine<G1Config> = g1_mapper.hash(msg).unwrap();
    q
}