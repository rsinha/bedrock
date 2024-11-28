# Bedrock Vault Design Doc

The key idea behind Bedrock is to marry safety with recoverability.
Safety is achieved via the familiar MFA mechanism found in popular vaults today.
Recovery is achieved via a threshold cryptosystem based on user-chosen guardians.

## User Journey

### Registration
This creates a new vault for the user -- think of this as "creating a new account".
1. user signs in with OIDC provider, thus binding their vault to an identity.
2. user is presented with an empty, initialized vault

### Vault Operations

The user can read their existing vault contents, which is a set of objects.
The user can also write to their vault, via operations to add new objects or modify / delete existing objects.

### Recovery Configuration

Recovery operations can only be configured 
We provide the following options:
- Guardians: The user can choose a set of guardians along with the reconstruction threshold (defualt half). Guardians are identified by their social identity.
- Pin: The user can specify a 6 digit pin along with the helper services.
Both the guardian configuration and pin can be modified at any time.

## Protocol

Session Start: This happens each time the user needs to refresh their credential (which expires every few minutes).
	- 

Vault Registration:
1. user signs in with OIDC provider (e.g. Google), thus binding their vault to an identity.
	- user generates an ephemeral signing keypair (esk, epk) and sets H(epk) to be the nonce field of the OIDC login.
	- OIDC replies with a signed attestation, binding H(epk) with the user's OIDC username (e.g. alice@gmail.com).
	- user assembles 

## System Components



## API 

Each of our API calls is signed using the user-generated ephemeral key, which is attested using the OpenID Connect protocol.
A credential is an (ephemeral) public key bound a social identity. It has the following structure:
credential = json! {
	id: oidc_subscriber_id,
	attestation: oidc_jwt_token,
	epk: schnorr_public_key
}
For example, an API call f(input) is signed using Schnorr.sign(esk, msg = ["f", serialize(input)]).


### Keyper API:

### Storage API:
- create_vault(credential)



## Threat Model

## Design Requirements

- Helpers are unaware of each other,
- Helpers do not maintain any per-user state, i.e., their storage is constant size.
- Ciphertexts are stored independently of helpers.
- Versioning using git for multi-device consistency and historical reads (no rollback support for simplicity).

## Login:

The login protocol is entered whenever the user goes on a new device or has an expired credential on an existing device.
The purpose of the login protocol is to bind a proof of account ownership (PAO) [1] with an ephemeral signing key (as opposed to a bearer token which only works for single verifier settings). This is done by supplying the hash of the ephemeral signature public key `epk` to the PAO prover.
We provide both OpenID and webauthn authentication mechanisms.

 For instance, the user's client supplies the hash as the OpenID connect protocol nonce field -- similar thing should be possible with passkeys hopefully. The login protocol has the following steps:
- user invokes key generation of a signature scheme `(epk, esk) <- Ed25519.keygen()`
- user authenticates as username@google.com to Google OIDC service supplying `H(epk)` as the challenge nonce
- Google replies with `(X509_certificate_of_google_public_key, RSA.sign(google_private_key, SHA256(claim)), claim)` where `claim = { nonce: H(epk), time: ..., uid: username@google.com, ... }`. We call this tuple a credential, and is stored by the user locally, though it will expire after a few hours for security reasons.

The ability to login only provides access to the vault's encrypted contents. It does not give access to the vault's data, including the administrative keys.

## Vault Initialization:
Sets the admin signing and encryption keys. This step occurs when the vault is created. Steps include:
- Sample BLS secret keys sk_sign, sk_encrypt. Let secret s = sk_sign || sk_encrypt.
- Encrypt `s` under a decryption policy, which can be some combination (AND / OR) of:
	- PIN-based decryption: 6 digit pin, similar to WhatsApp
	- Guardian-based decryption: t out of n (e.g. 3 out of 5) guardians agree to let the user decrypt
  Sample policies include: 1) "PIN" for vault access on a new device without guardian involvement; 2) "PIN OR 3-out-of-5" for enabling recovery via guardians in case the user forgets their pin; 3) "PIN AND 3-out-of-5" for defense-in-depth, for vault access on a new device only under the approval of a committee; 4) "PIN AND 1-out-of-1", for access on a new device but only under approval from an existing device also hosting that vault; 5) "(PIN AND 1-out-of-1) OR 3-out-of-5" for similar access policy as the previous case, but also allowing for guardian-based recovery; and so on.
  ANDs are handled by additive sharing, and encrypting each share under the respective policy, while ORs are handled by encrypting the same secret value under each policy.
  Note that an implicit condition in all these policies is the ability to authenticate to the OpenID or passkey account.
  Therefore, these policies provide an additional layer of defense for high-value vaults.
- Send the API request `Ed25519.sign(esk, json!{ operation: vault_init, encrypted_admin_keys: encryption_of_s })`


### PIN-based recovery
- We use the threshold design adapted from https://eprint.iacr.org/2024/887, which is based on the PPSS protocol from https://eprint.iacr.org/2016/144. The PIN UX is roughly similar to WhatsApp -- Similar to Whatsapp, the Bedrock app can periodically prompt the user to enter their PIN code to check their memory.
- interactive symmetric encryption protocol where the servers hold a (threshold secret sharing of) secret key `k` and the client has a pin guess -- the servers must limit the number of guesses before the vault is locked. 
- Protocol steps (from https://eprint.iacr.org/2016/144):
	- client sends servers `H(pin)^r`, thus hiding the pin guess from the server
	- server sends `H(pin)^(r * k)`; in the threshold setting, each server uses their share `k_i` of `k` and computes `H(pin)^(r * k_i)`, and the client must combine a threshold number of responses to compute `H(pin)^(r * k)`.
	- client multiplies with `r^(-1)` to obtain `H(pin)^k`. Finally, the client computes the PRF output `H(pin, H(pin)^k)`.
- The final ciphertext has the form `PRG(H(pin, H(pin)^k)) \xor s` and is stored by the Bedrock storage server.

### Guardian-based recovery
- We use the silent threshold encryption scheme from https://eprint.iacr.org/2024/263
- For the special case of 1-out-of-1 policy, we use a simpler BF-IBE scheme as suggested in the 2024/263 paper.
	- Given a BLS key pair (pk, sk), encryption 
	- PRG(e(g^sk, RO(tag)^a)) \xor sk_encoded; decryption: PRG(e(g^a, RO(tag)^sk)) \xor sk_encoded


## Vault View:
After login, a user can use the view functionality to retrieve encrypted files.

## Vault Reload:





[1] optionally, the proof of account ownership can be wrapped with a ZK proof (e.g. zkLogin) for hiding the user's social identity -- we will explore privacy from the service provider in the next version.