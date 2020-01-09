# oin
[![doc](https://img.shields.io/badge/current-docs-green.svg)](https://docs.rs/oin/)
[![Crates.io](https://img.shields.io/crates/v/oin.svg)](https://crates.io/crates/oin)
[![Crates.io](https://img.shields.io/crates/d/oin.svg)](https://crates.io/crates/oin)
[![LICENSE](https://img.shields.io/crates/l/oin.svg)](https://choosealicense.com/licenses/mit/)

Every user has a ed25519 keypair in oin, verifying signatures instead of username/password.

## Authorization Schema

```rust
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
    assert!(id.state(dev, token).is_ok());
    assert!(id.update(dev, tk2).is_ok());
    assert!(id.state(dev, tk2).is_ok());
}
```

## TODO

+ ser && de
