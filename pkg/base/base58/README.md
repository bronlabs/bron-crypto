# base58

Package `base58` implements [Bitcoin-flavor Base58 and Base58Check](https://en.bitcoin.it/wiki/Base58Check_encoding) encoding for binary data such as version-tagged addresses and key material.

## What this package is — and is not

Base58 is **not a cryptographic primitive**. It is a binary-to-text encoding optimised for human transcription:

- It does **not** provide confidentiality.
- Plain `Encode` / `Decode` does **not** provide integrity.
- `CheckEncode` / `CheckDecode` provides integrity against *accidental* corruption — typos, bit-flips on a noisy channel — via a 4-byte truncated double-SHA-256 checksum. It does **not** provide cryptographic authentication: the checksum is unkeyed, so anyone with the version byte and payload can recompute it. Don't use Base58Check as a MAC, don't use it as a signature, and don't rely on it to detect adversarial tampering. If you need authentication, use a MAC or a signature; if you need authenticated encoding for a transcript, use `pkg/encryption/hpke` or a dedicated AEAD.

## Alphabet

The alphabet is the canonical Bitcoin alphabet:

```
123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
```

The characters `0` (zero), `O` (capital o), `I` (capital i), and `l` (lowercase L) are intentionally omitted to reduce visual confusability when humans transcribe encoded data. Other Base58 dialects (Ripple, Flickr, IPFS) use different alphabets and are **not** interoperable with this package.

## Encoding

Given an input byte string $b = b_0 \, b_1 \cdots b_{n-1}$:

1. Interpret $b$ as a non-negative big-endian integer $X$.
2. Iteratively let $X_{i+1} = \lfloor X_i / 58 \rfloor$ and $r_i = X_i \bmod 58$, starting from $X_0 = X$, until $X_i = 0$.
3. Map each $r_i$ to its alphabet character.
4. For every leading zero byte in $b$ (which is otherwise lost in step 1), emit the character `'1'`.
5. Reverse the digit sequence to produce the output string with most-significant digit first.

Decoding is the inverse: convert each character $c_j$ to its alphabet index $d_j \in \{0, \dots, 57\}$, evaluate $X = \sum_{j=0}^{n-1} d_j \cdot 58^{\,n-1-j}$, materialise as a big-endian byte string, and prepend one `0x00` byte for each leading `'1'` character.

The encoding is bijective on byte strings: distinct inputs map to distinct outputs once the leading-zero handling in step 4 is taken into account. Both `Encode("")` and `Encode(nil)` return the empty string, and `Decode("")` returns the empty byte slice.

## Base58Check

`CheckEncode(payload, version)` returns

$$\text{Base58}\big(\text{version} \,\Vert\, \text{payload} \,\Vert\, \text{SHA-256}\big(\text{SHA-256}(\text{version} \,\Vert\, \text{payload})\big)[0\!:\!4]\big).$$

The 1-byte `version` serves as a one-byte domain separator. Bitcoin uses distinct version bytes for each address type (mainnet P2PKH `0x00`, testnet P2PKH `0x6F`, P2SH `0x05`, WIF `0x80`, …); reusing the same payload bytes with a different version produces a different encoded string and a different checksum, so a P2PKH address cannot be silently mis-parsed as a WIF private key. This is a *use-site* convention, not a property the package enforces — callers must agree on the version-byte allocation across their system.

The checksum is the first four bytes of $\text{SHA-256}(\text{SHA-256}(\cdot))$. Four bytes give roughly $2^{-32}$ probability of accepting a uniformly random corruption, which is sufficient to catch typos but **not** sufficient to resist an adversary: a 4-byte tag is well within reach of brute force, and (more importantly) anyone can compute the correct tag for a chosen payload because the construction is unkeyed. The double-SHA-256 here mirrors Bitcoin's convention; from a typo-detection standpoint a single SHA-256 truncation would be equally effective.

`CheckDecode` rejects:

- Strings containing non-alphabet characters (`ErrInvalidCharacter`).
- Decoded payloads shorter than `VersionLen + ChecksumLen` (`ErrInvalidLength`).
- Payloads whose recomputed checksum does not match (`ErrChecksumMismatch`).

The checksum comparison uses a fixed-length constant-time compare (`Checksum.Equal` → `ct.SliceEqual`), which avoids creating a one-byte-at-a-time oracle on the checksum bytes. The error variants are still distinguishable, so the *kind* of failure is observable to the caller — the right trade-off for a non-secret integrity tag, but worth keeping in mind in callers that propagate the error verbatim to a remote party.

## Side-channel notes

`Encode` and `Decode` are **variable-time** in both the length and the content of their argument:

- `Encode` performs a sequence of big-integer Euclidean divisions by 58. The iteration count and per-iteration cost depend on the magnitude of the input, not just its length.
- `Decode` accumulates $\sum_j d_j \cdot 58^j$ via big-integer multiplications and additions; per-iteration cost grows with $j$.

This is acceptable for the package's intended use — encoding *public* payloads (addresses, version-tagged data) and decoding strings already on the wire. It is **not** safe for inputs whose length or content is secret. Decoding a user-supplied WIF private key with this package leaks per-character timing on the WIF string; that leakage is generally tolerated in wallet software because the WIF is treated as just-as-secret as the key it carries, but callers who must avoid even that leakage should not feed secret-bearing strings through `Decode`.

`Base58.Equal` uses `ct.SliceEqual` on the underlying byte slices: same-length pairs are compared in constant time, but a length mismatch is observable from outside (it short-circuits to `false`). `Checksum.Equal` operates on a fixed-size `[ChecksumLen]byte` array and is fully constant-time.

The lookup table `b58[256]byte` initialised in `init()` is indexed by the input character at every step of `Decode`. The index is the public ciphertext byte, not a secret, so the cache-line access pattern is not a leakage concern here.

## API

| Function                                       | Purpose                                                                                            |
|------------------------------------------------|----------------------------------------------------------------------------------------------------|
| `Encode(data []byte) Base58`                   | Bare Base58 encoding. Empty input → empty output.                                                  |
| `Decode(s Base58) ([]byte, error)`             | Bare Base58 decoding. Errors only on invalid characters.                                           |
| `CheckEncode(input []byte, version VersionPrefix) Base58` | Prepend version, append 4-byte SHA-256d checksum, encode.                               |
| `CheckDecode(s Base58) ([]byte, VersionPrefix, error)` | Decode, verify minimum length and checksum, return version + payload.                      |
| `DeriveChecksum(input []byte) Checksum`        | First 4 bytes of $\text{SHA-256}(\text{SHA-256}(\text{input}))$. Exported for callers that build their own framing on top. |

`Base58` is a typed `string` so the type system distinguishes encoded text from arbitrary `string`s. `VersionPrefix` is a typed `byte`; `Checksum` is `[ChecksumLen]byte` (i.e. `[4]byte`).

## References

<!-- spec: https://en.bitcoin.it/wiki/Base58Check_encoding -->
<!-- code: https://github.com/bitcoin/bitcoin/blob/master/src/base58.cpp -->
- Satoshi Nakamoto et al., Bitcoin source code (`base58.h` / `base58.cpp`), 2009 onward — original Base58 and Base58Check definition.
- [Base58Check encoding — Bitcoin Wiki](https://en.bitcoin.it/wiki/Base58Check_encoding).
- A. M. Antonopoulos, *Mastering Bitcoin* (2nd ed.), Ch. 4 "Keys, Addresses".
