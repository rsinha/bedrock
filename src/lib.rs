use aes_gcm::{aead::Aead, Aes128Gcm, Nonce, Key};
use aes::cipher::{typenum::*, KeyInit};
use protobuf::Message;
use std::error::Error;
use ark_serialize::*;
use crate::crypto::ppss::{*, jkkx16::*};

include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));
use vault::Vault;

mod crypto;
mod remote;

type PrfInput = crypto::ppss::jkkx16::PrfInput<ark_bls12_381::G1Projective>;
type PrfOutput = crypto::ppss::jkkx16::PrfOutput<ark_bls12_381::G1Projective>;
type PPSSCiphertext = crypto::ppss::jkkx16::Ciphertext<ark_bls12_381::G1Projective>;
type SecretKey = crypto::ppss::jkkx16::SecretKey;

pub struct BedrockClient {
    owner_id: String,
    server_url: String,
    debug_mode: bool,
}

impl BedrockClient {
    pub fn new(url: &str, owner: &str) -> Self {
        BedrockClient {
            owner_id: owner.to_string(),
            server_url: url.to_string(),
            debug_mode: false,
        }
    }

    pub fn new_debug(url: &str, owner: &str) -> Self {
        BedrockClient {
            owner_id: owner.to_string(),
            server_url: url.to_string(),
            debug_mode: true,
        }
    }

    pub async fn initialize(&self, password: &[u8], secret: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut rng = rand::thread_rng();
        let pp = JKKX16::setup::<_>(&mut rng).unwrap();

        let (client_state, prf_input) = 
            JKKX16::client_generate_keygen_request(&pp, &self.owner_id.as_bytes(), password, &mut rng)?;

        let prf_output = if self.debug_mode {
            simulate_prf_locally(&prf_input)?
        } else {
            invoke_prf_service(&self.server_url, &prf_input).await?
        };

        let (key, kem_ciphertext) =
            JKKX16::client_keygen(&pp, &client_state, &[prf_output], 1, 1, &mut rng)?;
        
        let mut kem_ciphertext_serialized = Vec::new();
        kem_ciphertext.serialize_compressed(&mut kem_ciphertext_serialized).unwrap();
        let dem_ciphertext_serialized = encrypt_message(secret, &key);

        // create the vault
        let mut vault = Vault::new();
        vault.owner = self.owner_id.clone();
        vault.dem_ciphertext = dem_ciphertext_serialized;
        vault.kem_ciphertext = kem_ciphertext_serialized;

        Ok(vault.write_to_bytes().expect("failed to serialize vault"))
    }

    pub async fn recover(&self, vault: impl AsRef<[u8]>, password: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let vault = Vault::parse_from_bytes(vault.as_ref()).expect("failed to parse vault");

        let ctxt: PPSSCiphertext = PPSSCiphertext::deserialize_compressed(vault.kem_ciphertext.as_slice()).unwrap();
        
        let mut rng = rand::thread_rng();
        let pp = JKKX16::setup::<_>(&mut rng).unwrap();

        let (client_state, prf_input) =
            JKKX16::client_generate_reconstruct_request(&pp, vault.owner.as_bytes(), password, &mut rng)?;

        let prf_output = if self.debug_mode {
            simulate_prf_locally(&prf_input)?
        } else {
            invoke_prf_service(&self.server_url, &prf_input).await?
        };

        let key = JKKX16::client_reconstruct(&pp, &client_state, &[prf_output], &ctxt)?;

        let secret = decrypt_message(vault.dem_ciphertext.as_slice(), &key).unwrap();

        Ok(secret)
    }
}

fn encrypt_message(msg: &[u8], key: &SecretKey) -> Vec<u8> {
    let key: &Key<Aes128Gcm> = key.into();
    let cipher = Aes128Gcm::new(&key);
    let nonce = Nonce::<U12>::default();

    cipher.encrypt(&nonce, msg).unwrap()
}

fn decrypt_message(ctxt: &[u8], key: &SecretKey) -> aead::Result<Vec<u8>> {
    let key: &Key<Aes128Gcm> = key.into();
    let cipher = Aes128Gcm::new(&key);
    let nonce = Nonce::<U12>::default();

    cipher.decrypt(&nonce, ctxt)
}

fn simulate_prf_locally(input: &PrfInput) -> Result<PrfOutput, Box<dyn Error>> {
    let seed = [0u8; 32];
    let mut rng = rand::thread_rng();
    let pp = JKKX16::setup::<_>(&mut rng).unwrap();

    // serialize the input
    let mut api_request = Vec::new();
    input.serialize_compressed(&mut api_request)?;

    // we are not really sending the request anywhere, just pretending

    // deserialize the request on the pretend server
    let prf_input_deserialized = PrfInput::deserialize_compressed(api_request.as_slice())?;

    // process the request
    let prf_output = JKKX16::server_process_keygen_request(
        &pp, &seed, input.client_id.as_slice(), &prf_input_deserialized
    )?;

    // serialize the response
    let mut api_response = Vec::new();
    prf_output.serialize_compressed(&mut api_response)?;

    // pretend to send the response back to the client

    // deserialize the response on the client
    let prf_output = PrfOutput::deserialize_compressed(api_response.as_slice())?;
    Ok(prf_output)
}

async fn invoke_prf_service(server_url: &str, input: &PrfInput) -> Result<PrfOutput, Box<dyn Error>> {
    let mut api_request = Vec::new();
    input.serialize_compressed(&mut api_request)?;

    let remote = remote::Remote::new(server_url.to_string());
    let api_response = remote.get(&api_request).await?;

    let output = PrfOutput::deserialize_compressed(api_response.as_slice())?;
    Ok(output)
}

#[cfg(test)]
mod tests {

    use base64::{engine::general_purpose::URL_SAFE, Engine as _};
    use warp::Filter;
    use tokio::sync::oneshot;
    use super::*;

    fn server_computation(api_request: &[u8]) -> Vec<u8> {
        let seed = [0u8; 32];
        let mut rng = rand::thread_rng();
        let pp = JKKX16::setup::<_>(&mut rng).unwrap();

        let prf_input_deserialized = PrfInput::deserialize_compressed(api_request).unwrap();
        // process the request
        let prf_output = JKKX16::server_process_keygen_request(
            &pp, &seed, prf_input_deserialized.client_id.as_slice(), &prf_input_deserialized
        ).unwrap();

        // serialize the response
        let mut api_response = Vec::new();
        prf_output.serialize_compressed(&mut api_response).unwrap();

        api_response
    }

    #[tokio::test]
    async fn test_initialize_recover_local_server_mode() {
        let password = "password";
        let secret = "topsecret";
        let userid = "alice@gmail.com";

        let decrypt = warp::path!("decrypt" / String)
            .map(|api_request: String| {
                println!("Received request: {}", api_request);
                let api_request = URL_SAFE.decode(api_request.as_bytes()).unwrap();
                server_computation(api_request.as_slice())
            });

        let (tx, rx) = oneshot::channel::<()>();

        // Chosen port for local server
        let addr = ([127, 0, 0, 1], 3030);

        // Spawn the server in a separate async task
        let server = warp::serve(decrypt)
            .bind_with_graceful_shutdown(addr, async {
                // Wait for the shutdown signal
                rx.await.ok();
            });

        let server_handle = tokio::spawn(server.1);

        // Wait a bit for the server to start (usually very fast, but good to be safe)
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let client = super::BedrockClient::new("http://127.0.0.1:3030/decrypt", userid);

        let vault_encoded = client.initialize(password.as_bytes(), secret.as_bytes()).await.unwrap();
        let recovered = client.recover(vault_encoded, password.as_bytes()).await.unwrap();
        assert_eq!(secret.as_bytes(), recovered.as_slice());
        println!("recovered {:?}", recovered);

        // Test passed, now we signal the server to shut down
        let _ = tx.send(());

        // Wait for the server to complete gracefully
        let _ = server_handle.await;
    }


    #[tokio::test]
    async fn test_initialize_recover_debug_mode() {
        let client = super::BedrockClient::new_debug(
            "",
            "alice@gmail.com"
        );
        let password = b"password";
        let secret = b"topsecret";
        let vault_encoded = client.initialize(password, secret).await.unwrap();
        let recovered = client.recover(vault_encoded, password).await.unwrap();
        assert_eq!(secret, recovered.as_slice());
        println!("recovered {:?}", recovered);
    }
}
