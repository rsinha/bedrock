use ark_crypto_primitives::Error;
use ark_serialize::CanonicalSerialize;
use ark_std::hash::Hash;
use ark_std::rand::Rng;

pub mod jkkx16;
mod sss;
mod lagrange;

#[allow(dead_code)]
pub trait PpssPcheme {
    type Parameters: Clone + Send + Sync;
    type PublicKey: CanonicalSerialize + Hash + Eq + Clone + Default + Send + Sync;
    type SecretKey: CanonicalSerialize + Clone + Default;
    type PrfInput: CanonicalSerialize + Clone + Default + Send + Sync;
    type PrfOutput: CanonicalSerialize + Clone + Default + Send + Sync;
    type Ciphertext: CanonicalSerialize + Clone + Default + Send + Sync;
    type ClientState: Clone + Send + Sync;

    /// Generates the public parameters for the scheme.
    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error>;

    /// Gemerates an keygen request for the server
    fn client_generate_keygen_request<R: Rng>(
        pp: &Self::Parameters,
        client_id: &[u8],
        password: &[u8],
        rng: &mut R,
    ) -> Result<(Self::ClientState, Self::PrfInput), Error>;

    /// Computes a PRF evaluation on the server side,
    /// using a 256-bit server key and a unique client identifier.
    fn server_process_keygen_request<R: Rng>(
        pp: &Self::Parameters,
        seed: &[u8; 32],
        client_id: &[u8],
        input: &Self::PrfInput,
    ) -> Result<(Self::PublicKey, Self::PrfOutput), Error>;

    /// Performs the client-side keygen, using the servers' responses.
    fn client_keygen<R: Rng>(
        pp: &Self::Parameters,
        client_state: &Self::ClientState,
        server_responses: &[(Self::PublicKey, Self::PrfOutput)],
        num_servers: usize,
        threshold: usize,
        rng: &mut R,
    ) -> Result<(Self::SecretKey, Self::Ciphertext), Error>;

    fn client_generate_reconstruct_request<R: Rng>(
        pp: &Self::Parameters,
        client_id: &[u8],
        password: &[u8],
        rng: &mut R,
    ) -> Result<(Self::ClientState, Self::PrfInput), Error>;

    fn server_process_reconstruct_request<R: Rng>(
        pp: &Self::Parameters,
        seed: &[u8; 32],
        client_id: &[u8],
        input: &Self::PrfInput,
    ) -> Result<Self::PrfOutput, Error>;

    fn client_reconstruct<R: Rng>(
        pp: &Self::Parameters,
        state: &Self::ClientState,
        server_responses: &[(Self::PublicKey, Self::PrfOutput)],
        ciphertext: &Self::Ciphertext,
        rng: &mut R,
    ) -> Result<Self::SecretKey, Error>;
}