# bip340

BIP-340 tagged hash implementation for Schnorr signatures.

Implements the tagged hashing scheme from [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) where the hash is prefixed with `SHA256(tag) || SHA256(tag)`.

## Usage

```go
h := bip340.NewBip340HashChallenge()
h.Write(data)
digest := h.Sum(nil)
```