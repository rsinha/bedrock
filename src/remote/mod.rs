use std::fmt;
use reqwest::blocking::Client;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use reqwest::Error;

pub struct Remote {
    pub url: String, // url for reaching the api service
}

impl Remote {
    pub fn new(url: String) -> Remote {
        Remote { url, }
    }

    pub fn get(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        // Base64 encode the request in URL-safe mode
        let encoded_request = URL_SAFE.encode(&data);

        // Construct the full URL with the Base64 encoded data as a parameter
        let api_url = format!("{}/{}", self.url, encoded_request);

        // Send the GET request to the API and capture the response
        let api_response = Client::new().get(&api_url).send()?;

        // Check if the request was successful
        if api_response.status().is_success() {
            Ok(api_response.bytes()?.to_vec())
        } else {
            Ok(vec![]) // empty means server didnt reply for some reason
        }
    }
}