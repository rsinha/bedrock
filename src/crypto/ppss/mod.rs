use ark_crypto_primitives::Error;
use ark_serialize::CanonicalSerialize;
use ark_std::hash::Hash;
use ark_std::rand::Rng;

pub mod jkkx16;

#[allow(dead_code)]
pub trait PpssPcheme {
    type Parameters: Clone + Send + Sync;
    type PublicKey: CanonicalSerialize + Hash + Eq + Clone + Default + Send + Sync;
    type SecretKey: CanonicalSerialize + Clone + Default;
    type PrfInput: CanonicalSerialize + Clone + Default + Send + Sync;
    type PrfOutput: CanonicalSerialize + Clone + Default + Send + Sync;
    type Ciphertext: CanonicalSerialize + Clone + Default + Send + Sync;

    /// Generates the public parameters for the scheme.
    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error>;

    /// Gemerates an keygen request for the server
    fn client_keygen_request_for_server<R: Rng>(
        pp: &Self::Parameters,
        client_id: &[u8],
        password: &[u8],
    ) -> Result<Self::PrfInput, Error>;

    /// Computes a PRF evaluation on the server side,
    /// using a 256-bit server key and a unique client identifier.
    fn server_keygen<R: Rng>(
        pp: &Self::Parameters,
        seed: &[u8; 32],
        client_id: &[u8],
        input: &Self::PrfInput,
    ) -> Result<(Self::PublicKey, Self::PrfOutput), Error>;

    /// Performs the client-side keygen, using the servers' responses.
    fn client_keygen<R: Rng>(
        pp: &Self::Parameters,
        client_id: &[u8],
        password: &[u8],
        server_responses: &[(Self::PublicKey, Self::PrfOutput)],
        rng: &mut R,
    ) -> Result<Self::SecretKey, Error>;

    fn client_reconstruct_request_for_server<R: Rng>(
        pp: &Self::Parameters,
        client_id: &[u8],
        password: &[u8],
    ) -> Result<Self::PrfInput, Error>;

    fn server_reconstruct<R: Rng>(
        pp: &Self::Parameters,
        seed: &[u8; 32],
        client_id: &[u8],
        input: &Self::PrfInput,
    ) -> Result<Self::Ciphertext, Error>;

    fn client_reconstruct<R: Rng>(
        pp: &Self::Parameters,
        client_id: &[u8],
        password: &[u8],
        ciphertext: &Self::Ciphertext,
        rng: &mut R,
    ) -> Result<Self::SecretKey, Error>;
}