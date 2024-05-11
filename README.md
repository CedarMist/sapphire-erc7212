# ERC-7212 for Oasis Sapphire

Oasis Sapphire provides built-in support for secp256r1 via a precompile, however
the precompile isn't directly compatible with the 7212 precompile as internally
it uses DER encoded signatures and points.

The `P256Verifier` contract implemented in this repository provides a small
compatibility layer, translating 7212 calls to use the Sapphire secp256r1
precompile.

It is tested against the [Wycheproof] vectors.

[Wycheproof]: https://github.com/google/wycheproof

## References

 * https://github.com/daimo-eth/p256-verifier
 * https://daimo.com/blog/p256verifier
 * https://eips.ethereum.org/EIPS/eip-7212
