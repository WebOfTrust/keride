#### Signing

`keride` supports the following signing algorithms:
- Ed25519 ([ed25519-dalek](https://docs.rs/ed25519-dalek))
- Secp256k1 ([k256](https://docs.rs/k256))
- Secp256r1 ([p256](https://docs.rs/p256))

We have planned support for Ed448.

The ECDSA curves (Secp256k1 and Secp256r1) use randomized signatures. Ed25519 is always deterministic.
This means that if you need to avoid correlation and want to use Ed25519, you'll need to salt your data
for every use case that you do not want correlated. ACDC, for example, takes this into account, allowing for
configurable use of Ed25519 by injecting salty nonces in the data to be signed where privacy is a concern.
