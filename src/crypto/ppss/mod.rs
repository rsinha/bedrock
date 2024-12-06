use ark_crypto_primitives::Error;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;

pub mod jkkx16;
mod sss;
mod lagrange;

#[allow(dead_code)]
pub trait PpssPcheme {
    type Parameters: Clone + Send + Sync;
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
    fn server_process_keygen_request(
        pp: &Self::Parameters,
        seed: &[u8; 32],
        client_id: &[u8],
        input: &Self::PrfInput,
    ) -> Result<Self::PrfOutput, Error>;

    /// Performs the client-side keygen, using the servers' responses.
    fn client_keygen<R: Rng>(
        pp: &Self::Parameters,
        client_state: &Self::ClientState,
        server_responses: &[Self::PrfOutput],
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

    fn server_process_reconstruct_request(
        pp: &Self::Parameters,
        seed: &[u8; 32],
        client_id: &[u8],
        input: &Self::PrfInput,
    ) -> Result<Self::PrfOutput, Error>;

    fn client_reconstruct(
        pp: &Self::Parameters,
        state: &Self::ClientState,
        server_responses: &[Self::PrfOutput],
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::SecretKey, Error>;
}


#[cfg(test)]
mod test {
    use crate::crypto::ppss::{jkkx16::*, *};
    use ark_std::test_rng;

    #[test]
    fn test_ppss_one_server() {
        let pin = "198837";
        let client_id = b"alice@gmail.com";
        let server_seed = [0u8; 32];
        
        let rng = &mut test_rng();
        let pp = JKKX16::setup::<_>(rng).unwrap();

        let (client_state, prf_input) = JKKX16::client_generate_keygen_request(
            &pp, client_id, pin.as_bytes(), rng
        ).unwrap();
        let prf_output = JKKX16::server_process_keygen_request(
            &pp, &server_seed, client_id, &prf_input
        ).unwrap();
        let (key, ciphertext) = JKKX16::client_keygen(
            &pp, &client_state, &[prf_output], 1, 1, rng
        ).unwrap();

        let (client_state, prf_input) = JKKX16::client_generate_reconstruct_request(
            &pp, client_id, pin.as_bytes(), rng
        ).unwrap();
        let prf_output = JKKX16::server_process_reconstruct_request(
            &pp, &server_seed, client_id, &prf_input
        ).unwrap();
        let reconstructed_key = JKKX16::client_reconstruct(
            &pp, &client_state, &[prf_output], &ciphertext
        ).unwrap();

        assert_eq!(key, reconstructed_key);
    }

    #[test]
    fn test_ppss_multiple_servers() {
        let pin = "198837";
        let client_id = b"alice@gmail.com";
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];
        let seed3 = [3u8; 32];

        
        let rng = &mut test_rng();
        let pp = JKKX16::setup::<_>(rng).unwrap();

        let (client_state, prf_input) = JKKX16::client_generate_keygen_request(&pp, client_id, pin.as_bytes(), rng).unwrap();

        let prf_out1 = JKKX16::server_process_keygen_request(&pp, &seed1, client_id, &prf_input).unwrap();
        let prf_out2 = JKKX16::server_process_keygen_request(&pp, &seed2, client_id, &prf_input).unwrap();
        let prf_out3 = JKKX16::server_process_keygen_request(&pp, &seed3, client_id, &prf_input).unwrap();
        
        let (key, ctxt) = JKKX16::client_keygen(&pp, &client_state, &[prf_out1, prf_out2, prf_out3], 3, 3, rng).unwrap();

        let prf_out1 = JKKX16::server_process_reconstruct_request(&pp, &seed1, client_id, &prf_input).unwrap();
        let prf_out2 = JKKX16::server_process_reconstruct_request(&pp, &seed2, client_id, &prf_input).unwrap();
        let prf_out3 = JKKX16::server_process_reconstruct_request(&pp, &seed3, client_id, &prf_input).unwrap();

        let reconstructed_key = JKKX16::client_reconstruct(&pp, &client_state, &[prf_out1, prf_out2, prf_out3], &ctxt).unwrap();

        assert_eq!(key, reconstructed_key);
    }
}