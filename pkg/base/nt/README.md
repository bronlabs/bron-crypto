# nt - Number Theory

Foundational number theory primitives for cryptographic applications.

## Subpackages

- **numct** - Constant-time arbitrary precision integers (`Nat`, `Int`, `Modulus`) built on `crypto/internal/edwards25519/field`-style word arithmetic
- **num** - Typed number structures with algebraic semantics (`N`, `Z`, `Q`, `NatPlus`, `Uint`, `ZMod`), wrapping `numct` with type-level invariants (positivity, coprimality, modulus-binding)
- **cardinal** - Cardinal numbers for representing group orders (known, unknown, infinite); used to describe the order of a group without requiring it to be computable
- **modular** - Modular arithmetic backends; includes `SimpleModulus` (no trapdoor), `OddPrimeFactors` (CRT-accelerated arithmetic mod N = p·q), and `OddPrimeSquareFactors` (CRT arithmetic mod N² = (p·q)², for Paillier)
- **crt** - Chinese Remainder Theorem machinery: lifting / recombining residues across coprime moduli
- **znstar** - Multiplicative unit groups `(Z/nZ)*` for RSA, Paillier, and ring-Pedersen constructions

## Prime Generation

This package exposes a family of prime and prime-pair generators, each producing primes with different structural constraints required by various cryptographic protocols:

| Function | Output | Constraint | Typical use |
| --- | --- | --- | --- |
| `GeneratePrime` | single prime | bit length only | keys where only primality matters |
| `GeneratePrimePair` | (p, q) with `bitlen(pq) = keyLen` | equal-length primes | plain RSA / Paillier moduli |
| `GenerateBlumPrime` | single Blum prime | `p ≡ 3 (mod 4)` | components of Blum integers |
| `GenerateBlumPrimePair` | Blum pair (p, q) | both `≡ 3 (mod 4)` | Blum-integer moduli (canonical square roots, Rabin commitments) |
| `GeneratePaillierBlumModulus` | (N, p, q) | Blum + `gcd(N, φ(N)) = 1` | CGGMP21 Paillier instances; required for `Π^{mod}` / `Π^{fac}` soundness |
| `GenerateSafePrime` | single safe prime | `p = 2p' + 1` with `p'` prime | generators of prime-order subgroups |
| `GenerateSafePrimePair` | safe pair (p, q) | both safe | strong RSA moduli (ring-Pedersen CRS, proofs over QR_N with prime-order structure) |

`MillerRabinChecks(bits)` returns the number of Miller-Rabin rounds appropriate for the requested bit length, targeting the standard false-acceptance bound for cryptographic primes. It's used internally by the prime generators and exposed for callers that run additional probable-primality checks.

### Safe-prime generation

`GenerateSafePrime` and `GenerateSafePrimePair` implement the parallelised safe-prime variant of Joye and Paillier (CHES 2006, §4.2 / Figure 6). Candidates are constructed so that both `q` and `(q−1)/2` are simultaneously coprime to a smooth modulus `Π = ∏ pᵢ` of small odd primes, eliminating per-candidate trial division. On rejection, the next candidate is obtained by multiplying an internal seed `k` by a fixed quadratic-residue `a ∈ QR(m)` with `a ≡ 1 (mod 4)`, which preserves every sieve invariant without resampling. The bit-length-dependent setup constants `(Π, m, m', l, u)` are derived once and cached per bit length; `Π` is chosen as the longest prefix of `smallPrimes` (`joyepaillier.go`) that fits the algorithm's geometric bound `Π ≤ 2^(bits−5)`. Expected primality tests scale as `(n · ln 2 · φ(Π)/Π)²` for an `n`-bit safe prime.

## Usage

```go
// Generate a plain RSA prime pair
p, q, _ := nt.GeneratePrimePair(num.NPlus(), 2048, rand.Reader)

// Generate a CGGMP21-ready Paillier-Blum modulus
N, p, q, _ := nt.GeneratePaillierBlumModulus(num.NPlus(), 2048, rand.Reader)

// Generate a safe-prime RSA pair for ring-Pedersen
p, q, _ := nt.GenerateSafePrimePair(num.NPlus(), 2048, rand.Reader)

// Wrap primes into a group
rsa, _ := znstar.NewRSAGroup(p, q)
paillier, _ := znstar.NewPaillierGroup(p, q)
```

All generators are parameterised over a target structure (`PrimeSamplable[E]`) so that the raw `big.Int` output is immediately lifted into a typed set (e.g. `*num.NatPlus`) where downstream modular arithmetic is defined.

## Reference

<!-- paper: docs/paper/JP06pgen.pdf -->
- [Marc Joye, Pascal Paillier. Fast generation of prime numbers on portable devices: an update](https://dl.acm.org/doi/10.1007/11894063_13)
