# znstar

Package `znstar` provides multiplicative groups of units modulo n, denoted (Z/nZ)*, for cryptographic applications such as RSA, Paillier encryption, and the CGGMP21 ring-Pedersen zero-knowledge proof system.

## Overview

An element of Z/nZ is a *unit* iff it is coprime with n; the units form a multiplicative group (Z/nZ)*. This package implements that group under two concrete ambient moduli:

- **RSA groups**: Units modulo N = p·q (the primes are generic).
- **Paillier groups**: Units modulo N² = (p·q)². Paillier ciphertexts and their homomorphic products live here.

Both group types come in two flavours that differ in whether the factorisation trapdoor is available:

- **Known-order**: p and q are retained inside the arithmetic backend, enabling CRT-accelerated modular exponentiation and exact quadratic-residuosity decisions. This is the view held by a party that generated the modulus.
- **Unknown-order**: only the modulus is known. All arithmetic goes through Barrett-style reduction; QR-ness is conjectured-hard (the QR assumption). This is the view held by counterparties / verifiers.

The known/unknown distinction is carried at the Go type level, so a verifier can never accidentally receive a value typed as known-order and a prover never has to remember which trapdoor they hold.

## Sampling Constructors

Choose the constructor whose structural constraint matches the protocol:

| Function | Prime structure | Typical use |
| --- | --- | --- |
| `SampleRSAGroup` | generic primes | baseline RSA modulus |
| `SampleSafeRSAGroup` | safe primes (`p = 2p' + 1`) | ring-Pedersen CRS; QR_N has prime order p'q' |
| `SampleBlumRSAGroup` | Blum primes (`p ≡ 3 mod 4`) | Blum-integer moduli (canonical square roots, Rabin commitments) |
| `SamplePaillierGroup` | generic primes | baseline Paillier |
| `SampleSafePaillierGroup` | safe primes | Paillier with prime-order N-th residue subgroup (CGGMP21 `Π^{enc}`, `Π^{log*}`) |
| `SamplePaillierBlumGroup` | Blum primes + `gcd(N, φ(N)) = 1` | CGGMP21 Paillier: soundness of `Π^{mod}` / `Π^{fac}` relies on `x ↦ x^N` being bijective on (Z/N²Z)* |
| `SamplePedersenParameters` | safe primes | ring-Pedersen CRS (N̂, s, t, λ) |

`SamplePedersenParameters` returns the full setup (N̂, s, t, p, q, λ): public commitment bases s, t ∈ QR_{N̂} together with the trapdoor material (the primes and the secret exponent λ = log_t(s)). The trapdoor fully reveals the factorisation and the commitment-opening secret — it must be kept secret alongside p, q and zeroised when no longer needed.

## Key Types

### RSA Groups
- **`RSAGroupKnownOrder`**: factorisation retained, CRT-accelerated.
- **`RSAGroupUnknownOrder`**: modulus-only view.
- **`RSAGroupElementKnownOrder`** / **`RSAGroupElementUnknownOrder`**: elements of the respective groups.

### Paillier Groups
- **`PaillierGroupKnownOrder`**: trapdoor-aware; supports `Representative`, `NthResidue`, `EmbedRSA`.
- **`PaillierGroupUnknownOrder`**: public-key view; homomorphic addition and re-randomisation only.
- **`PaillierGroupElementKnownOrder`** / **`PaillierGroupElementUnknownOrder`**: elements of the respective groups.

### Interfaces
- **`UnitGroup[U]`**: the abstract multiplicative unit group. Used by the ZK-proof layer so that a single proof can be written against "any ring-Pedersen-style modulus".
- **`Unit[U]`**: group element with multiplication, (bounded) exponentiation, inversion, and integer scalar action.
- **`KnowledgeOfOrder[A, G, U]`**: captures the prover/verifier asymmetry — the arithmetic `A` exposes the trapdoor internally, and `ForgetOrder` projects down to the unknown-order view `G`.

## Architecture

Generics with a trait-based design:

- **`UnitGroupTrait[A, W, WT]`**: shared group-side implementation — sampling, hashing, deserialisation, identity.
- **`UnitTrait[A, W, WT]`**: shared element-side implementation — Mul, Exp, Inv, Jacobi, IsTorsionFree.

Arithmetic is delegated to the `modular` package:

- **`modular.OddPrimeFactors`** — CRT mod p and q for RSA-flavour known-order groups.
- **`modular.OddPrimeSquareFactors`** — CRT mod p² and q² for Paillier-flavour known-order groups.
- **`modular.SimpleModulus`** — generic Barrett / Montgomery reduction for unknown-order groups.

## Paillier-Specific Operations

- **`Representative(m)`**: computes `(1 + mN) mod N²`, the deterministic noise-free encoding of a plaintext `m ∈ (-N/2, N/2)`. A full encryption is `Representative(m) · r^N` for a random `r ∈ (Z/NZ)*`.
- **`NthResidue(u)`**: computes `u^N mod N²` — the N-th-residue factor of u, central to Paillier decryption. Uses the CRT fast path in the known-order view.
- **`EmbedRSA(u)`**: lifts an element of (Z/NZ)* into (Z/N²Z)* by reinterpreting its modulus, used when a randomiser sampled in the RSA group feeds into a Paillier encryption.

## Residuosity and Subgroups

- **`RandomQuadraticResidue`**: samples uniformly from `QR_N` by squaring a uniform unit.
- **`RandomWithJacobi(j)`**: samples a unit with Jacobi symbol `j ∈ {±1}`.
- **`IsQuadraticResidue`** (known-order only): exact decision via Legendre symbols mod p and q. Refuses to answer under the unknown-order view (that is the QR assumption).
- **`Jacobi`**: Jacobi symbol (u / N); `+1` is necessary but not sufficient for QR membership over a composite modulus.
- **`IsTorsionFree`**: membership in the torsion-free (odd-order, i.e. QR) component. Exact when the arithmetic carries the factorisation; falls back to a Jacobi check (necessary-but-not-sufficient) otherwise.

## Serialization

All group and element types implement `cbor.Marshaler` / `cbor.Unmarshaler` with distinct CBOR tags for known-order vs. unknown-order payloads. This prevents a payload from being silently promoted across views on the wire — a malformed known-order payload would require smuggling (p, q), and re-checks (primality, coprimality with N, `N² = N·N`) are re-run on decode.

## Usage Notes

- Minimum prime size is 1024 bits for RSA/Paillier group creation (2048-bit modulus).
- `ForgetOrder()` on a group or element drops the trapdoor view. This is the canonical operation when exporting a value to a counterparty.
- `LearnOrder(knownOrderGroup)` promotes an unknown-order element into the known-order group of the same modulus. It creates no cryptographic information — the caller must already hold the trapdoor.
- The factorisation and the ring-Pedersen trapdoor returned by `SamplePedersenParameters` are secret; wipe them after use.
