# oin

Every user has a ed25519 keypair in oin, verifying signatures instead of username/password.

## Authorization Schema

```rust
se ed25519_dalek::{Keypair, PublicKey, SecretKey, PUBLIC_KEY_LENGTH};
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
    assert!(id.auth([0; PUBLIC_KEY_LENGTH], &token, sig).is_ok());

    // 4. login successfully.
}
```
