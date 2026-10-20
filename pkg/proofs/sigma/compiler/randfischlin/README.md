# Randomised Fischlin Transform

Compiles a sigma protocol into a non-interactive zero-knowledge proof of knowledge with straight-line (non-rewinding) extraction in the random oracle model, following Figure 9 of [KS22]. It differs from `fischlin` in one respect: the prover walks the challenge space in uniformly random order instead of counting up from zero. This removes the quasi-unique responses requirement of [Fis05], so the transform applies to every strongly special sound sigma protocol, including OR compositions.

## Construction

Let $\Sigma = (P_a, P_z, V)$ be a strongly $n$-special sound sigma protocol, $x$ the statement and $w$ the witness. The parameters are $r$ (repetitions), $\ell$ (hash output bits) and $t$ (challenge bits); they are derived from $n$ as described below. $H$ is SHA3-256 truncated to $\ell$ bits and applied to index-and-length-prefixed inputs.

**Prover.**

1. Append the session id and $x$ to the session transcript and extract a 32-byte $\mathsf{crs}$ from it.
2. For $i \in [r]$ compute $(a_i, \sigma_i) \leftarrow P_a(x, w)$ and set $\vec a = (a_1, \ldots, a_r)$.
3. For $i \in [r]$: sample $e_i \leftarrow \{0,1\}^t$ without replacement, compute $z_i \leftarrow P_z(x, w, \sigma_i, e_i)$ and repeat until $H(\mathsf{crs}, \vec a, i, e_i, z_i, x) = 0^\ell$.
4. Output $\pi = (\vec a, \vec e, \vec z)$, CBOR-encoded.

**Verifier.** Recompute $\mathsf{crs}$ and accept iff $\pi$ has exactly $r$ repetitions, every $e_i$ has the sigma protocol's challenge length, and for every $i$ both $H(\mathsf{crs}, \vec a, i, e_i, z_i, x) = 0^\ell$ and $V(x, a_i, e_i, z_i) = 1$.

### Challenge encoding

$e_i$ is a byte string of the sigma protocol's challenge length whose first $t / 8$ bytes are random and whose remaining bytes are zero. It is hashed and handed to the sigma protocol as is.

### Deviations from Figure 9

- Figure 9 hashes $(\vec a, i, e_i, z_i)$. The implementation also hashes $x$ and the transcript-derived $\mathsf{crs}$, which itself depends on $x$, the session id and the transcript position. Without $x$ a prover could grind the repetitions first and choose the statement afterwards; the extractor of Figure 10 assumes $x$ is fixed before the oracle queries, and for statements with more degrees of freedom than repetitions the adaptive choice yields accepting proofs without a witness. Fischlin's original transform hashes $x$ as well.
- The verifier checks the length of every $e_i$. The hash is computed over the raw challenge bytes while the sigma protocol may parse several byte strings (e.g. with leading zero bytes) to the same challenge; accepting such encodings would let a prover re-encode a single simulated transcript until the repetition hashes to zero, forging proofs with about $r \cdot 2^\ell$ hash evaluations and no witness. $a_i$ and $z_i$ need no such check because the verifier hashes their canonical re-serialisation.
- Figure 9 fixes $r \cdot \ell = \lambda$ for strongly 2-special sound protocols. The implementation derives $\ell$ from the special soundness $n$ of the sigma protocol so that $n$-special sound protocols are supported, see below.

## Parameters

`NewCompiler` derives the parameters from the sigma protocol's special soundness $n$ (`SpecialSoundness()`), with $\lambda = 128$ and $r = 16$ fixed:

$$
\ell = \left\lceil \frac{\lambda}{r} \right\rceil + \lceil \log_2 (n - 1) \rceil,
\qquad
t = 8 \left\lceil \frac{\lceil \log_2 \lambda \rceil \cdot \ell}{8} \right\rceil .
$$

Figure 9 of [KS22] fixes $r \cdot \ell = \lambda$ and $t = \lceil \log_2 \lambda \rceil \cdot \ell$ for strongly 2-special sound protocols. The $\lceil \log_2(n - 1) \rceil$ term carries the soundness argument over to $n$-special soundness in the same way as Section 5.1 of [CL24] does for the standard transform: the straight-line extractor needs $n$ accepting transcripts with the same commitment, so a cheating prover may query up to $n - 1$ accepting transcripts per repetition without enabling extraction, and the per-repetition probability of a zero hash grows from $2^{-\ell}$ to $(n - 1) \cdot 2^{-\ell}$. Requiring $r \cdot (\ell - \log_2(n - 1)) \ge \lambda$ restores the knowledge error $2^{-\lambda}$. $t$ follows the rule of Figure 9, rounded up to whole bytes. For $n = 2$ this reproduces the previously hard-coded $\ell = 8$, $t = 56$, so proofs for 2-special sound protocols are unchanged.

| $n$ | $\ell$ | $t$ | Example |
|---|---|---|---|
| 2 | 8 | 56 | `dlog/schnorr`, `okamoto`, AND and OR compositions of these |
| 3 | 9 | 64 | `dlog/batch_schnorr` with $k = 2$ |
| 5 | 10 | 72 | `dlog/batch_schnorr` with $k = 4$ |
| 17 | 12 | 88 | `dlog/batch_schnorr` with $k = 16$ |

`NewCompiler` rejects $n < 2$, sigma protocols whose challenge is shorter than $t / 8$ bytes, and `SoundnessError() < 128`. Parameters are not carried in the proof, so prover and verifier must be created from compilers over the same sigma protocol.

Expected prover cost is $r$ evaluations of $P_a$ plus $r \cdot 2^\ell$ evaluations of $P_z$ and $H$, i.e. up to $2(n - 1)$ times the cost for a 2-special sound protocol. Verification costs $r$ evaluations of $V$ and $H$ regardless of $n$.

## Requirements

- **Strong $n$-special soundness.** The extractor succeeds on any $n$ pairwise distinct accepting transcripts $(a, e_j, z_j)$ with the same first message $a$, where equal challenges are allowed ([KS22], Definition 3.2 for $n = 2$ and Definition A.1.1 in general). Unique-response protocols (Schnorr, batch Schnorr, Okamoto under the discrete logarithm assumption) satisfy it trivially; OR compositions of such protocols satisfy it as well. The compositions in `compose/` report the special soundness of the composed protocol: AND inherits $n$, while an OR of $m$ branches of an $n$-special sound protocol is $((n - 1)^m + 1)$-special sound.
- `SoundnessError() >= 128`.

## Security

- **Knowledge soundness.** A prover that queries at most $n - 1$ accepting transcripts per repetition (the most it can do without enabling extraction, and exactly what an $(n - 1)$-simulatable protocol such as batch Schnorr allows) succeeds with probability at most $(n - 1) \cdot 2^{-\ell}$ per repetition, so with $|Q|$ oracle queries the knowledge error is at most $|Q| \cdot \left((n - 1) \cdot 2^{-\ell}\right)^r \le |Q| \cdot 2^{-128}$ ([KS22], Theorem 6.4; [CL24], Section 5.1).
- **Completeness.** A repetition exhausts all $2^t$ challenges without a hit with probability $(1 - 2^{-\ell})^{2^t} < e^{-2^{t - \ell}}$, which is below $2^{-\lambda}$ because $t \ge \ell + \log_2 \lambda$ (the bound used in the proof of [KS22], Theorem 6.4). The prover samples without replacement, so it never retries a challenge.
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

<!-- paper: docs/papers/2022-393_20220401_233222.pdf [Section 6, Figures 9 to 11; Appendix A] -->
- [KS22] Kondi, Y., shelat, a. [Improved Straight-Line Extraction in the Random Oracle Model With Applications to Signature Aggregation](https://eprint.iacr.org/2022/393.pdf). ASIACRYPT 2022.
<!-- paper: docs/papers/2024-526_20260318_094603.pdf [Section 5.1] -->
- [CL24] Chen, Y.-H., Lindell, Y. [Optimizing and Implementing Fischlin's Transform for UC-Secure Zero Knowledge](https://eprint.iacr.org/2024/526.pdf). IACR ePrint 2024/526.
<!-- paper: docs/papers/Fischl05b.pdf -->
- [Fis05] Fischlin, M. [Communication-Efficient Non-Interactive Proofs of Knowledge with Online Extractors](https://link.springer.com/chapter/10.1007/11535218_10). CRYPTO 2005.
