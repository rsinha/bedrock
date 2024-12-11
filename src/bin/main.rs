use clap::{Command, Arg, value_parser};
use std::{fs, path::PathBuf};

const VAULT_DIR_NAME: &str = ".bedrock";
const VAULT_FILE_NAME : &str = "vault";

#[tokio::main]
async fn main() {
    let matches = Command::new("Vault")
        .version("1.0")
        .about("A simple vault application that allows you to store and retrieve secrets")
        .arg(
            Arg::new("mode")
                .short('m')
                .long("mode")
                .help("Sets the operation mode")
                .value_parser(["reload", "init"])
                .required(true)
        )
        .arg(
            Arg::new("pincode")
                .short('p')
                .long("pincode")
                .help("6-digit numeric pincode")
                .required(true)
                .value_parser(value_parser!(String))
        )
        .arg(
            Arg::new("secret")
                .short('s')
                .long("secret")
                .help("Secret of any length")
                .value_parser(value_parser!(String))
        )
        .get_matches();

    // Get the values of the arguments
    let mode = matches.get_one::<String>("mode").expect("invalid args: mode is required");
    let pin = matches.get_one::<String>("pincode").expect("invalid args: pincode is required");

    let vault_path = get_vault_path();

    // Process based on the mode
    match mode.as_str() {
        "reload" => {
            //read the vault file
            let vault = fs::read(&vault_path)
                .expect(format!("Failed to read vault file at {:?}", vault_path).as_str());
            println!("Reloading secret from vault using pincode {}", pin);
            let client = bedrock_vault::BedrockClient::new_debug(
                "https://zkbricks-vault-worker.rohit-fd0.workers.dev/decrypt",
                "alice@gmail.com",
            );
            let recovered_secret = client.recover(vault, pin.as_bytes()).await.unwrap();
            println!("Recovered secret: {:?}", String::from_utf8(recovered_secret).unwrap());
        },
        "init" => {
            let secret = matches.get_one::<String>("secret").expect("invalid args: secret is required");

            println!("Creating a vault with pincode {}", pin);
            let client = bedrock_vault::BedrockClient::new_debug(
                "https://zkbricks-vault-worker.rohit-fd0.workers.dev/decrypt", 
                "alice@gmail.com"
            );

            let vault_data = client.initialize(pin.as_bytes(), secret.as_bytes()).await.unwrap();
            fs::write(vault_path, vault_data).expect("Failed to write vault file");
        },
        _ => unreachable!(), // This won't happen due to value_parser restriction
    }
}

fn get_vault_path() -> PathBuf {
        // Get the user's home directory
        let home_dir = directories::BaseDirs::new().unwrap().home_dir().to_path_buf();
    
        // Define the app directory
        let app_dir = home_dir.join(VAULT_DIR_NAME);
    
        // Create the directory if it doesn't exist
        if !app_dir.exists() {
            match fs::create_dir_all(&app_dir) {
                Ok(_) => println!("Directory created successfully at: {:?}", app_dir),
                Err(e) => eprintln!("Failed to create directory: {}", e),
            }
        } else {
            println!("Directory already exists at: {:?}", app_dir);
        }
        
        app_dir.join(VAULT_FILE_NAME)
}