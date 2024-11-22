use ark_crypto_primitives::Error;
use ark_serialize::CanonicalSerialize;
use ark_std::hash::Hash;
use ark_std::rand::Rng;

pub mod schnorr;

#[allow(dead_code)]
pub trait SignatureScheme {
    type Parameters: Clone + Send + Sync;
    type PublicKey: CanonicalSerialize + Hash + Eq + Clone + Default + Send + Sync;
    type SecretKey: CanonicalSerialize + Clone + Default;
    type Signature: CanonicalSerialize + Clone + Default + Send + Sync;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error>;

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error>;

    fn sign<R: Rng>(
        pp: &Self::Parameters,
        sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self::Signature, Error>;

    fn verify(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool, Error>;
}

#[cfg(test)]
mod test {
    use crate::crypto::signature::{schnorr, *};
    use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
    use ark_std::test_rng;

    fn sign_and_verify<S: SignatureScheme>(message: &[u8]) {
        let rng = &mut test_rng();
        let parameters = S::setup::<_>(rng).unwrap();
        let (pk, sk) = S::keygen(&parameters, rng).unwrap();
        let sig = S::sign(&parameters, &sk, &message, rng).unwrap();
        assert!(S::verify(&parameters, &pk, &message, &sig).unwrap());
    }

    fn failed_verification<S: SignatureScheme>(message: &[u8], bad_message: &[u8]) {
        let rng = &mut test_rng();
        let parameters = S::setup::<_>(rng).unwrap();
        let (pk, sk) = S::keygen(&parameters, rng).unwrap();
        let sig = S::sign(&parameters, &sk, message, rng).unwrap();
        assert!(!S::verify(&parameters, &pk, bad_message, &sig).unwrap());
    }

    #[test]
    fn schnorr_signature_test() {
        let message = "Hi, I am a Schnorr signature!";
        sign_and_verify::<schnorr::Schnorr<JubJub>>(message.as_bytes());
        failed_verification::<schnorr::Schnorr<JubJub>>(
            message.as_bytes(),
            "Bad message".as_bytes(),
        );
    }
}