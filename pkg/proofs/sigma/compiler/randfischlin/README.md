# Randomised Fischlin Transform

Compiles a sigma protocol into a non-interactive zero-knowledge proof of knowledge with straight-line (non-rewinding) extraction in the random oracle model, following Figure 9 of [KS22]. It differs from `fischlin` in one respect: the prover walks the challenge space in uniformly random order instead of counting up from zero. This removes the quasi-unique responses requirement of [Fis05], so the transform applies to every strongly 2-special sound sigma protocol, including OR compositions.

## Construction

The parameters are fixed: $\lambda = 128$, $\ell = 8$ (hash output bits), $r = \lambda / \ell = 16$ (repetitions) and $t = \lceil \log_2 \lambda \rceil \cdot \ell = 56$ (challenge bits). $H$ is SHA3-256 truncated to $\ell$ bits and applied to index-and-length-prefixed inputs. Let $\Sigma = (P_a, P_z, V)$ be the sigma protocol, $x$ the statement and $w$ the witness.

**Prover.**

1. Append the session id and $x$ to the session transcript and extract a 32-byte $\mathsf{crs}$ from it.
2. For $i \in [r]$ compute $(a_i, \sigma_i) \leftarrow P_a(x, w)$ and set $\vec a = (a_1, \ldots, a_r)$.
3. For $i \in [r]$: sample $e_i \leftarrow \{0,1\}^t$ without replacement, compute $z_i \leftarrow P_z(x, w, \sigma_i, e_i)$ and repeat until $H(\mathsf{crs}, \vec a, i, e_i, z_i, x) = 0^\ell$.
4. Output $\pi = (\vec a, \vec e, \vec z)$, CBOR-encoded.

**Verifier.** Recompute $\mathsf{crs}$ and accept iff $\pi$ has exactly $r$ repetitions, every $e_i$ has the sigma protocol's challenge length, and for every $i$ both $H(\mathsf{crs}, \vec a, i, e_i, z_i, x) = 0^\ell$ and $V(x, a_i, e_i, z_i) = 1$.

### Challenge encoding

$e_i$ is a byte string of the sigma protocol's challenge length whose first $t / 8 = 7$ bytes are random and whose remaining bytes are zero. It is hashed and handed to the sigma protocol as is.

### Deviations from Figure 9

- Figure 9 hashes $(\vec a, i, e_i, z_i)$. The implementation also hashes $x$ and the transcript-derived $\mathsf{crs}$, which itself depends on $x$, the session id and the transcript position. Without $x$ a prover could grind the repetitions first and choose the statement afterwards; the extractor of Figure 10 assumes $x$ is fixed before the oracle queries, and for statements with more degrees of freedom than repetitions the adaptive choice yields accepting proofs without a witness. Fischlin's original transform hashes $x$ as well.
- The verifier checks the length of every $e_i$. The hash is computed over the raw challenge bytes while the sigma protocol may parse several byte strings (e.g. with leading zero bytes) to the same challenge; accepting such encodings would let a prover re-encode a single simulated transcript until the repetition hashes to zero, forging proofs with about $r \cdot 2^\ell$ hash evaluations and no witness. $a_i$ and $z_i$ need no such check because the verifier hashes their canonical re-serialisation.

## Requirements

`NewCompiler` rejects a sigma protocol unless

- `SpecialSoundness() == 2`. Theorem 6.4 of [KS22] is stated for strongly 2-special sound protocols, and the fixed parameters give $2^{-\ell r} = 2^{-128}$ only in that case: against an $n$-special sound protocol a cheating prover can prepare $n - 1$ accepting transcripts per commitment, each an independent oracle query, so the per-repetition success probability grows to $(n - 1) \cdot 2^{-\ell}$. Standard `fischlin` compensates by enlarging $b$; this package does not, so batched protocols such as `dlog/batch_schnorr` must use `fischlin`.
- `SoundnessError() >= 128`.

Strong 2-special soundness ([KS22], Definition 3.2) means the extractor succeeds on any two distinct accepting transcripts $(a, e, z) \ne (a, e', z')$, with $e = e'$ allowed. Unique-response protocols (Schnorr, Okamoto) satisfy it trivially; OR compositions of such protocols satisfy it as well.

## Security

- **Knowledge soundness.** A prover that queries at most one accepting transcript per repetition succeeds with probability $2^{-\ell}$ per repetition, so with $|Q|$ oracle queries the knowledge error is at most $|Q| \cdot 2^{-\ell r} = |Q| \cdot 2^{-128}$ ([KS22], Theorem 6.4).
- **Completeness.** The prover samples until it succeeds; the probability that a repetition exhausts all $2^t$ challenges is below $2^{-\lambda}$.
- **Zero knowledge.** Statistical, by programming the random oracle. Because challenges are tried in random order, the published $e_i$ are uniform in $\{0,1\}^t$ regardless of how many queries the prover made. This is what makes the proof retrace-proof even against a distinguisher holding the witness, and hence removes the need for quasi-unique responses ([KS22], Section 6.4).
- **Binding.** $x$ enters every repetition directly and through $\mathsf{crs}$; the session id and transcript position enter through $\mathsf{crs}$.

## Transcript

`Prove` and `Verify` append a domain separator containing the session id and then $x$ before extracting $\mathsf{crs}$, and append $\vec a$ and $\vec e$ afterwards. Responses are not appended. `NewProver` and `NewVerifier` add a domain separator containing the sigma protocol name and the session id.

## Usage

```go
nizk, err := randfischlin.NewCompiler(sigmaProtocol, prng)

prover, err := nizk.NewProver(ctx) // ctx *session.Context
proof, err := prover.Prove(statement, witness)

verifier, err := nizk.NewVerifier(ctx)
err = verifier.Verify(statement, proof)
```

`compiler.Compile(randfischlin.Name, sigmaProtocol, prng)` selects this transform by name.

## References

<!-- paper: docs/papers/2022-393_20220401_233222.pdf [Section 6, Figures 9 to 11] -->
- [KS22] Kondi, Y., shelat, a. [Improved Straight-Line Extraction in the Random Oracle Model With Applications to Signature Aggregation](https://eprint.iacr.org/2022/393.pdf). ASIACRYPT 2022.
<!-- paper: docs/papers/Fischl05b.pdf -->
- [Fis05] Fischlin, M. [Communication-Efficient Non-Interactive Proofs of Knowledge with Online Extractors](https://link.springer.com/chapter/10.1007/11535218_10). CRYPTO 2005.
