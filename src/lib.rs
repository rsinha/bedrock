//use aead::Result;
use aes_gcm::{aead::Aead, Aes128Gcm, Nonce, Key};
use aes::cipher::{typenum::*, KeyInit};
use std::fs::File;
use std::io::{self, Write};
use std::error::Error;
use std::path::PathBuf;
use protobuf::{well_known_types::api, EnumOrUnknown, Message};
use ark_serialize::*;
use crate::crypto::ppss::{*, jkkx16::*};

include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));
use initialize::{InitializeRequest, InitializeResponse};

mod crypto;
mod remote;

type PrfInput = crypto::ppss::jkkx16::PrfInput<ark_bls12_381::G1Projective>;
type PrfOutput = crypto::ppss::jkkx16::PrfOutput<ark_bls12_381::G1Projective>;
type PPSSCiphertext = crypto::ppss::jkkx16::Ciphertext<ark_bls12_381::G1Projective>;
type SecretKey = crypto::ppss::jkkx16::SecretKey;

const DECRYPT_API: &str = "https://zkbricks-vault-worker.rohit-fd0.workers.dev/decrypt";

pub struct BedrockClient {
    server_url: String,
    kem_ciphertext_path: PathBuf,
    dem_ciphertext_path: PathBuf,
}

impl BedrockClient {
    pub fn new(url: &str, kem_filepath: &PathBuf, dem_filepath: &PathBuf) -> Self {
        BedrockClient {
            server_url: url.to_string(),
            kem_ciphertext_path: kem_filepath.clone(),
            dem_ciphertext_path: dem_filepath.clone(),
        }
    }

    pub fn initialize(&self, password: &[u8], secret: &[u8]) -> Result<(), Box<dyn Error>> {
        let client_id = b"whatever";
        
        let mut rng = rand::thread_rng();
        let pp = JKKX16::setup::<_>(&mut rng).unwrap();

        let (client_state, prf_input) = JKKX16::client_generate_keygen_request(&pp, client_id, password, &mut rng)?;
        let prf_output = invoke_prf_local(&prf_input)?;
        let (key, kem_ciphertext) = JKKX16::client_keygen(&pp, &client_state, &[prf_output], 1, 1, &mut rng)?;
        
        let mut kem_ciphertext_serialized = Vec::new();
        kem_ciphertext.serialize_compressed(&mut kem_ciphertext_serialized).unwrap();
        let dem_ciphertext_serialized = encrypt_message(secret, &key);
        
        print!("key: "); for b in &key { print!("{:02X} ", b); }
        write_data_to_disk(&kem_ciphertext_serialized, &self.kem_ciphertext_path)?;
        write_data_to_disk(&dem_ciphertext_serialized, &self.dem_ciphertext_path)?;

        Ok(())
    }

    pub fn recover(&self, password: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let client_id = b"whatever";

        let kem_ciphertext = read_data_from_disk(&self.kem_ciphertext_path)?;
        let dem_ciphertext = read_data_from_disk(&self.dem_ciphertext_path)?;

        let ctxt: PPSSCiphertext = PPSSCiphertext::deserialize_compressed(&kem_ciphertext[..]).unwrap();
        
        let mut rng = rand::thread_rng();
        let pp = JKKX16::setup::<_>(&mut rng).unwrap();

        let (client_state, prf_input) = JKKX16::client_generate_reconstruct_request(&pp, client_id, password, &mut rng)?;
        let prf_output = invoke_prf_local(&prf_input)?;
        let key = JKKX16::client_reconstruct(&pp, &client_state, &[prf_output], &ctxt)?;

        let secret = decrypt_message(&dem_ciphertext, &key).unwrap();

        Ok(secret)
    }
}

fn read_data_from_disk(path: &PathBuf) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(data)
}

fn write_data_to_disk(data: &[u8], path: &PathBuf) -> io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(data)?;
    Ok(())
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

fn invoke_prf_local(input: &PrfInput) -> Result<PrfOutput, Box<dyn Error>> {
    let seed = [0u8; 32];
    let mut rng = rand::thread_rng();
    let pp = JKKX16::setup::<_>(&mut rng).unwrap();
    let prf_output = JKKX16::server_process_keygen_request(
        &pp, &seed, input.client_id.as_slice(), input
    )?;

    return Ok(prf_output);
}

fn invoke_prf_service(input: &PrfInput) -> Result<PrfOutput, Box<dyn Error>> {
    let mut api_request = InitializeRequest::new();
    api_request.client_id = "whatever".to_string();
    input.blinded_prf_input.serialize_compressed(&mut api_request.prf_input).unwrap();

    let api_request_serialized: Vec<u8> = api_request.write_to_bytes().unwrap();
    println!("Message request in bytes:\nout_bytes {:?}", api_request_serialized);

    let remote = remote::Remote::new(DECRYPT_API.to_string());
    let api_response_serialized = remote.get(&api_request_serialized)?;
    let decoded_response = InitializeResponse::parse_from_bytes(&api_response_serialized)?;
    let prf_output = ark_bls12_381::G1Projective::deserialize_compressed(decoded_response.prf_output.as_slice())?;
    let pk = ark_bls12_381::G1Projective::deserialize_compressed(decoded_response.public_key.as_slice())?;

    return Ok(PrfOutput { blinded_prf_output: prf_output.into(), public_key: pk.into() });
}

#[cfg(test)]
mod tests {
    use std::path::*;

    #[test]
    fn test_initialize_recover() {
        let client = super::BedrockClient::new(
            "https://zkbricks-vault-worker.rohit-fd0.workers.dev/decrypt", 
            &Path::new("/tmp/vault/kem_ciphertext").to_path_buf(),
            &Path::new("/tmp/vault/dem_ciphertext").to_path_buf(),
        );
        let password = b"password";
        let secret = b"topsecret";
        client.initialize(password, secret).unwrap();
        let recovered = client.recover(password).unwrap();
        assert_eq!(secret, recovered.as_slice());
        println!("recovered {:?}", recovered);
    }
}
