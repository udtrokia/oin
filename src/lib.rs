use ed25519_dalek::{
    Keypair, PublicKey, Signature, SignatureError, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH,
    SIGNATURE_LENGTH,
};
use rand::rngs::OsRng;
use rand_core::RngCore;
use std::{collections::HashMap, convert::From};

type PublicKeyBytes = [u8; PUBLIC_KEY_LENGTH];
type SignatureBytes = [u8; SIGNATURE_LENGTH];
type TokenBytes = [u8; 64];

/// Identity schema
///
/// + pkey: https://oin.example.com/pkey
/// + name: https://oin.example.com/pkey/name
pub struct Identity {
    pub name: String,
    pub pkey: PublicKeyBytes,
    pub sigs: HashMap<PublicKeyBytes, SignatureBytes>,
}

impl Identity {
    /// Generate a new identity
    pub fn new() -> (Identity, [u8; SECRET_KEY_LENGTH]) {
        let mut csprng = OsRng {};
        let keypair = Keypair::generate(&mut csprng);

        (
            Identity {
                name: "".to_string(),
                pkey: keypair.public.to_bytes(),
                sigs: HashMap::new(),
            },
            keypair.secret.to_bytes(),
        )
    }

    /// Generate random token
    pub fn token() -> TokenBytes {
        let mut rng = [0; 64];
        let mut orng = rand::rngs::OsRng {};
        orng.fill_bytes(&mut rng);

        rng
    }

    /// Make the msg is signed by the publickey
    pub fn auth(
        &mut self,
        // services id
        id: PublicKeyBytes,
        // login token
        tk: TokenBytes,
        // user signature with token
        sig: SignatureBytes,
    ) -> Result<(), Error> {
        PublicKey::from_bytes(&self.pkey)?.verify(&tk, &Signature::from_bytes(&sig)?)?;
        self.sigs.insert(id, sig);
        Ok(())
    }

    /// Check if identity token paired
    pub fn state(&self, id: PublicKeyBytes, sig: SignatureBytes) -> Result<(), Error> {
        if let Some(s) = self.sigs.get(&id) {
            if s.to_vec() == sig.to_vec() {
                return Ok(());
            }

            return Err(Error::TokenError);
        }

        Err(Error::TokenError)
    }

    /// Update token for id
    pub fn update(&mut self, id: PublicKeyBytes, sig: SignatureBytes) -> Result<(), Error> {
        if self.sigs.insert(id, sig).is_some() {
            return Ok(());
        }

        Err(Error::TokenError)
    }
}

/// Generete identity from public key
impl From<PublicKeyBytes> for Identity {
    fn from(b: PublicKeyBytes) -> Identity {
        Identity {
            name: "".to_string(),
            pkey: b,
            sigs: HashMap::new(),
        }
    }
}

/// Abstract Errors
#[derive(Debug)]
pub enum Error {
    LoginError,
    TokenError,
}

impl From<SignatureError> for Error {
    fn from(_: SignatureError) -> Self {
        Error::LoginError
    }
}
