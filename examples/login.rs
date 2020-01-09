use ed25519_dalek::{Keypair, PublicKey, SecretKey, PUBLIC_KEY_LENGTH};
use oin::Identity;

fn main() {
    // sk is for client
    // id if for server
    let (mut id, sk) = Identity::new();
    let client = Keypair {
        secret: SecretKey::from_bytes(&sk).unwrap(),
        public: PublicKey::from_bytes(&id.pkey).unwrap(),
    };

    // 1. client send auth request
    // 2. server receive the request and response a token
    let token = Identity::token();
    let sig = client.sign(&token).to_bytes();

    // 3. client sign the token and send it back to the server
    let dev = [0; PUBLIC_KEY_LENGTH];
    assert!(id.auth(dev, token, sig).is_ok());

    // 4. login successfully.

    // more checks
    let tk2 = Identity::token();
    let sig2 = client.sign(&tk2).to_bytes();
    assert!(id.state(dev, sig).is_ok());
    assert!(id.update(dev, sig2).is_ok());
    assert!(id.state(dev, sig2).is_ok());
}
