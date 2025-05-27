use ecdsa::{
    SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use k256::Secp256k1;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::sha256::Hash;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature(pub ecdsa::Signature<Secp256k1>);

impl Signature {
    pub fn sign_output(output_hash: &Hash, private_key: &PrivateKey) -> Self {
        let signing_key = &private_key.0;
        let signature = signing_key.sign(&output_hash.as_bytes());
        Self(signature)
    }

    pub fn verify(&self, output_hash: &Hash, public_key: &PublicKey) -> bool {
        public_key
            .0
            .verify(&output_hash.as_bytes(), &self.0)
            .is_ok()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKey(pub VerifyingKey<Secp256k1>);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateKey(#[serde(with = "signkey_serde")] pub SigningKey<Secp256k1>);

impl PrivateKey {
    pub fn new_key() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        PrivateKey(signing_key)
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(*self.0.verifying_key())
    }
}

mod signkey_serde {
    use super::*;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(key: &SigningKey<Secp256k1>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&key.to_bytes())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SigningKey<Secp256k1>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::<u8>::deserialize(deserializer)?;
        Ok(SigningKey::from_slice(&bytes).unwrap())
    }
}
