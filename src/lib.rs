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
    pub name: &'static str,
    pub pkey: PublicKeyBytes,
    pub tokens: HashMap<PublicKeyBytes, SignatureBytes>,
}

impl Identity {
    /// Generate a new identity
    pub fn new() -> (Identity, [u8; SECRET_KEY_LENGTH]) {
        let mut csprng = OsRng {};
        let keypair = Keypair::generate(&mut csprng);

        (
            Identity {
                name: "",
                pkey: keypair.public.to_bytes(),
                tokens: HashMap::new(),
            },
            keypair.secret.to_bytes(),
        )
    }

    /// Generate random token
    pub fn token() -> TokenBytes {
        let mut rng: [u8; 64] = [0; 64];
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
        msg: &[u8],
        // user signature with token
        sig: SignatureBytes,
    ) -> Result<(), Error> {
        PublicKey::from_bytes(&self.pkey)?.verify(msg, &Signature::from_bytes(&sig)?)?;
        self.tokens.insert(id, sig);
        Ok(())
    }
}

impl From<PublicKeyBytes> for Identity {
    fn from(b: PublicKeyBytes) -> Identity {
        Identity {
            name: "",
            pkey: b,
            tokens: HashMap::new(),
        }
    }
}

/// Errors
pub enum Error {
    LoginError,
}

impl From<SignatureError> for Error {
    fn from(_: SignatureError) -> Self {
        Error::LoginError
    }
}
