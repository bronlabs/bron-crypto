# nt - Number Theory

Foundational number theory primitives for cryptographic applications.

## Subpackages

- **numct** - Constant-time arbitrary precision integers (`Nat`, `Int`, `Modulus`) built on
  `crypto/internal/edwards25519/field`-style word arithmetic
- **num** - Typed number structures with algebraic semantics (`N`, `Z`, `Q`, `NatPlus`, `Uint`, `ZMod`),
  wrapping `numct` with type-level invariants (positivity, coprimality, modulus-binding)
- **cardinal** - Cardinal numbers for representing group orders (known, unknown, infinite); used to describe
  the order of a group without requiring it to be computable
- **modular** - Modular arithmetic backends; includes `SimpleModulus` (no trapdoor), `OddPrimeFactors`
  (CRT-accelerated arithmetic mod N = p·q), and `OddPrimeSquareFactors` (CRT arithmetic mod N² = (p·q)²,
  for Paillier)
- **crt** - Chinese Remainder Theorem machinery: lifting / recombining residues across coprime moduli
- **znstar** - Multiplicative unit groups `(Z/nZ)*` for RSA, Paillier, and ring-Pedersen constructions

## Prime Generation

This package exposes a family of prime and prime-pair generators, each producing primes with different
structural constraints required by various cryptographic protocols:

| Function                | Output                            | Constraint                    | Typical use                                                                        |
|-------------------------|-----------------------------------|-------------------------------|------------------------------------------------------------------------------------|
| `GeneratePrime`         | single prime                      | bit length only               | keys where only primality matters                                                  |
| `GeneratePrimePair`     | (p, q) with `bitlen(pq) = keyLen` | equal-length primes           | plain RSA / Paillier moduli                                                        |
| `GenerateBlumPrime`     | single Blum prime                 | `p ≡ 3 (mod 4)`               | components of Blum integers                                                        |
| `GenerateBlumPrimePair` | Blum pair (p, q)                  | both `≡ 3 (mod 4)`            | Blum-integer moduli (canonical square roots, Rabin commitments)                    |
| `GenerateSafePrime`     | single safe prime                 | `p = 2p' + 1` with `p'` prime | generators of prime-order subgroups                                                |
| `GenerateSafePrimePair` | safe pair (p, q)                  | both safe                     | strong RSA moduli (ring-Pedersen CRS, proofs over QR_N with prime-order structure) |

`MillerRabinChecks(bits)` returns the number of Miller-Rabin rounds appropriate for the requested bit
length, targeting the standard false-acceptance bound for cryptographic primes. It's used internally by
the prime generators and exposed for callers that run additional probable-primality checks.

### How generation works

All variants share one sieved core (`internal/primegen`) whose output is **exactly uniform** over the
primes of the requested class and bit length. Candidates are assembled by Chinese remaindering from
residues sampled uniformly over the classes a conformant prime can actually occupy — `{1, …, pᵢ−1}` modulo
each small sieve prime for plain and Blum primes, `{2, …, pᵢ−1}` for safe primes (`q ≡ 1 (mod pᵢ)` would
put `pᵢ` in `(q−1)/2`) — so every candidate is coprime to the sieve product `Π` by construction, with no
per-candidate trial division against `Π`. A uniformly chosen multiple of the CRT modulus then places the
candidate in `[2^(bits−1), 2^bits)`. Surviving candidates are trial-divided against the table primes
beyond `Π` (uint64-packed, up to a bit-length-scaled cutoff) and only then pay for BPSW plus the
FIPS 186-5 Appendix C Miller-Rabin rounds. Expected primality tests scale as `n · ln 2 · φ(Π)/Π` for an
`n`-bit prime, squared for safe primes. The search runs parallel workers (scaled to the expected search
size, up to one per CPU core); successes are consumed in canonical candidate order rather than arrival
order — a first-past-the-post race would favour primes whose BPSW/Lucas verification happens to run
faster (a value-dependent time) and measurably bias small-size outputs toward fast-verifying residue
classes. All PRNG reads happen
sequentially on the calling goroutine (workers receive pre-cut entropy and never touch the reader), so a
single generation call accepts any `io.Reader`; a PRNG shared across *concurrent* generation calls must
still be safe for concurrent use — `crypto/rand.Reader` is, and `csprng.NewThreadSafePrng` wraps one that
isn't.

### Relation to the reference paper

The reference (Clavier, Feix, Thierry, Paillier — PKC 2012) describes two **provable**-prime generators,
Algorithm 3.1 (*Efficient-Square-Root-Generation*) and Algorithm 3.2 (*Efficient-Cube-Root-Generation*),
which grow a chain of Pocklington/Brillhart-Lehmer-Selfridge-certified primes of the form `n = 2rp + 1`.
**Neither algorithm is implemented here.** What this package borrows is the candidate-selection subroutine
the two algorithms share — §3, "Selection and Update of r and n", in its second ("constructive") solution:
assemble each candidate from prescribed residues via the Chinese Remainder Theorem, so that coprimality to
`Π` holds by construction and no candidate is ever trial-divided against `Π`. Everything around that core
deviates deliberately:

| Aspect          | Paper (§3)                                 | This package                                             | Why                                                                                                    |
|-----------------|--------------------------------------------|----------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| Output          | provable primes (Pocklington/BLS chain)    | probable primes (BPSW + FIPS 186-5 M-R rounds)           | uniform primes for moduli; no certificate needed                                                       |
| Prime classes   | coprimality to `Π` only (`{1, …, pᵢ−1}`)   | plain, Blum (`≡ 3 mod 4`), safe (also `{2, …, pᵢ−1}`)    | safe-prime adaptation per audit TOB-BLCG-4                                                             |
| Next candidate  | recycle the unit: `x ← 2x mod Π`           | fresh uniform residues for every candidate               | recycling needs extra structure (cf. Joye-Paillier's QNR sieve); fresh sampling gives exact uniformity |
| Unit generation | Carmichael-function trick (their ref [15]) | rejection sampling per prime + precomputed CRT basis     | simpler, exactly uniform; entropy pre-cut sequentially by the calling goroutine                        |
| Range placement | `r ∈ [I+1, 2I]`, tied to the chain prime   | window shift `q = x + b·m`, exact-bit-length rejection   | uniform over `[2^(bits−1), 2^bits)`; FIPS `√2` bound for pairs, checked before any test                |
| Beyond `Π`      | —                                          | trial division by remaining table primes (uint64-packed) | kills ~half the doomed candidates at a fraction of a BPSW test                                         |
| Execution       | sequential (embedded-device target)        | parallel workers; winner picked in canonical order       | server-class throughput                                                                                |

**The "window shift", spelled out.** The CRT sieve determines a candidate only modulo `m` (= `2Π` or `4Π`):
the residue vector picks one admissible position `x ∈ [0, m)`, and that same position repeats in every
window `[b·m, (b+1)·m)` of the integer line. Drawing the window index `b` uniformly from `[0, ⌈2^bits/m⌉)`
— so the windows tile `[0, 2^bits)` completely — and rejecting `q = x + b·m` unless it has exactly `bits`
bits gives an exactly uniform sample over the admissible set in range, because every integer decomposes
uniquely as `x + b·m`. The ingredient "translate by a multiple of the sieve modulus to reach the target
range" appears in both reference papers, but in different forms: CFTP12 uses it deterministically (step
5(c) of the constructive solution: "add appropriate multiple of `2pΠ` to `r` to get `r ∈ [I+1, 2I]`"), and
Joye-Paillier (CHES 2006, §2.1) uses a random shift `t = b·Π` with `b ∈ [b_min, b_max]`, which covers the
target range only up to a coverage gap `ε`. The exact-tiling-plus-rejection form used here is this
package's own: it keeps the random shift's spread but loses no part of the range and no uniformity.

This construction replaced the Joye-Paillier safe-prime generator (CHES 2006), whose quadratic-non-residue
sieve restricted safe primes to half of the admissible residue classes per sieve prime and thereby lost
≈ 1 bit of output entropy per sieve prime (≈ 178 bits at 1536 bits; audit finding TOB-BLCG-4). The uniform
construction has no such bias: every candidate is freshly sampled and every conformant prime is equally
likely.

### Prime Pair generation

Prime pair generation satisfies the IFC key requirements of FIPS 186-5 A.1.1, enforced where a rejection
is cheapest: candidates below `⌈√2·2^(keyLen/2−1)⌉` are rejected before any primality test (this also
makes `bitlen(pq) = keyLen` exact), and the pair collector enforces `p ≠ q`, the Fermat-factorisation
distance `|p−q| > 2^(keyLen/2−100)`, and `gcd(N, φ(N)) = 1` (i.e. `p ∤ q−1` and `q ∤ p−1` — required by
Paillier decryption and CGGMP21's Π^mod; provably automatic for equal-length primes, enforced anyway as
defense-in-depth). Both primes of a pair are drawn from a single shared worker pool, so all cores work on
whichever prime is still missing.

## Usage

```go
// Generate a plain RSA prime pair
p, q, _ := nt.GeneratePrimePair(num.NPlus(), 2048, rand.Reader)

// Generate a safe-prime RSA pair for ring-Pedersen
p, q, _ := nt.GenerateSafePrimePair(num.NPlus(), 2048, rand.Reader)

// Wrap primes into a group
rsa, _ := znstar.NewRSAGroup(p, q)
paillier, _ := znstar.NewPaillierGroup(p, q)
```

All generators are parameterised over a target structure (`PrimeSamplable[E]`) so that the raw `big.Int`
output is immediately lifted into a typed set (e.g. `*num.NatPlus`) where downstream modular arithmetic
is defined.

## Reference

<!-- paper: docs/papers/CFTP12provableprimes.pdf -->
- [Christophe Clavier, Benoit Feix, Loïc Thierry, Pascal Paillier. Generating provable primes efficiently on embedded devices](https://link.springer.com/chapter/10.1007/978-3-642-30057-8_22)
<!-- spec: docs/papers/NIST.FIPS.186-5.pdf -->
- [NIST FIPS 186-5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf)
