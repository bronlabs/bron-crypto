# Fischlin Transform

Compiles a sigma protocol into a non-interactive zero-knowledge proof of knowledge with straight-line (non-rewinding) extraction in the random oracle model. This is the simplified presentation of [CL24], i.e. Fischlin's transform [Fis05] with the slack parameter fixed to $S = 0$: every repetition must hash to zero. Straight-line extraction is what makes the proofs usable under concurrent composition (UC), where the rewinding extractor of Fiat-Shamir is not available.

## Construction

Let $\Sigma = (P_a, P_z, V)$ be the sigma protocol, $x$ the statement, $w$ the witness, $\mathsf{sid}$ the session id and $H$ a random oracle (SHA3-256). The parameters are $\rho$ (repetitions), $b$ (hash difficulty in bits) and $t$ (prover search bound in bits).

**Prover.**

1. For $i \in [\rho]$ compute $(a_i, \sigma_i) \leftarrow P_a(x, w)$ and set $\vec a = (a_1, \ldots, a_\rho)$.
2. Compute $h \leftarrow H(k, x, \vec a, \mathsf{sid})$, where $k$ is a 32-byte key extracted from the session transcript after $\rho$ and $x$ have been appended to it.
3. For $i \in [\rho]$ and $e_i = 0, 1, \ldots, 2^t - 1$ in order: compute $z_i \leftarrow P_z(x, w, \sigma_i, e_i)$ and stop at the first $e_i$ with $H_b(h, i, e_i, z_i) = 0^b$, where $H_b$ denotes the first $b$ bits of $H$. If some $i$ exhausts all $2^t$ challenges, restart from step 1 with fresh commitments.
4. Output $\pi = (\vec a, \vec e, \vec z)$, CBOR-encoded.

**Verifier.** Recompute $h$ and accept iff $\vec a$, $\vec e$, $\vec z$ have $\rho$ elements each, every $e_i$ is exactly $\lceil t/8 \rceil$ bytes long, and for every $i$ both $H_b(h, i, e_i, z_i) = 0^b$ and $V(x, a_i, e_i, z_i) = 1$.

### Challenge encoding

$e_i$ is the integer $e_i < 2^t$ in big-endian form. The proof carries only its $\lceil t/8 \rceil$ low-order bytes, and this short form is what gets hashed. Before calling $P_z$ or $V$, prover and verifier left-pad it with zero bytes to the sigma protocol's challenge length. Because the verifier rebuilds the padded challenge itself and hashes the canonical re-serialisation of the deserialised $a_i$ and $z_i$, a proof cannot present the same transcript under several encodings to obtain extra oracle queries ([CL24], Section 2.2, "verifying the range"). Values $e_i \ge 2^t$ that still fit in $\lceil t/8 \rceil$ bytes are accepted; they are distinct challenges, so this does not weaken soundness.

## Parameters

$\rho$ is fixed per sigma protocol in `params.go`, and $b$, $t$ follow from it:

$$
b = \left\lceil \frac{\lambda}{\rho} \right\rceil + \lceil \log_2 (n - 1) \rceil,
\qquad
t = \begin{cases} b + 5 & \rho \le 64 \\ b + 6 & \rho > 64 \end{cases}
$$

with $\lambda = 128$ and $n$ the sigma protocol's special soundness. `NewCompiler` rejects $\rho < 2$, $b < 2$ or $t \ge 64$. Parameters are not carried in the proof, so prover and verifier must be created from compilers over the same sigma protocol.

| Sigma protocol | $n$ | $\rho$ | $b$ | $t$ |
|---|---|---|---|---|
| `dlog/schnorr` | 2 | 16 | 8 | 13 |
| `paillier/nthroot` | 2 | 32 | 4 | 9 |
| `paillier/range` | 2 | 16 | 8 | 13 |
| any other | $n$ | 16 | $8 + \lceil \log_2(n-1) \rceil$ | $b + 5$ |

Expected prover cost is $\rho$ evaluations of $P_a$ plus $\rho \cdot 2^b$ evaluations of $P_z$ and $H$. Verification costs $\rho$ evaluations of $V$ and $H$.

## Security

- **Knowledge soundness.** A prover that never queries $H$ on two accepting transcripts with the same prefix $(h, i)$ succeeds with probability $2^{-b}$ per repetition, so with $Q$ oracle queries the knowledge error is at most $(Q + 1) \cdot 2^{-\rho (b - \log_2(n - 1))}$ ([CL24], Sections 3 and 5). The $\lceil \log_2(n-1) \rceil$ term in $b$ pays exactly for $n$-special soundness, so every supported protocol has knowledge error $2^{-128}$ per query.
- **Completeness.** One attempt fails with probability at most $\rho \cdot e^{-2^{t-b}} \le 2^{-40}$ for the rule above ([CL24], Section 3). The prover restarts on failure, so it always outputs an accepting proof.
- **Zero knowledge.** Statistical, by programming the random oracle. The prover enumerates $e_i$ from zero and publishes the first hit, so the proof leaks nothing beyond $\vec e$ itself.
- **Quasi-unique responses.** The extraction argument needs that no efficient prover can find two accepting responses $z \ne z'$ for the same $(x, a, e)$ ([Fis05], Definition 1); otherwise the prover could grind over $z$ instead of $e$ and never answer two distinct challenges. This holds for the protocols in the table but fails for OR compositions, whose response contains a simulated challenge chosen freely by the prover. Use `randfischlin` for those.
- **Binding.** $x$, $\vec a$ and $\mathsf{sid}$ enter every repetition through $h$, and the transcript key $k$ binds the proof to its position in the session transcript. A proof therefore verifies only for the statement, session and transcript state it was produced for.

## Transcript

`Prove` and `Verify` append $\rho$ and $x$ to the session transcript before extracting $k$, and append $\vec a$, $\vec e$ and $\vec z$ afterwards, so later protocol messages are bound to the proof. `NewProver` and `NewVerifier` add a domain separator containing the sigma protocol name and the session id.

## Usage

```go
nizk, err := fischlin.NewCompiler(sigmaProtocol, prng)

prover, err := nizk.NewProver(ctx) // ctx *session.Context
proof, err := prover.Prove(statement, witness)

verifier, err := nizk.NewVerifier(ctx)
err = verifier.Verify(statement, proof)
```

`compiler.Compile(fischlin.Name, sigmaProtocol, prng)` selects this transform by name.

## References

<!-- paper: docs/papers/2024-526_20260318_094603.pdf -->
- [CL24] Chen, Y.-H., Lindell, Y. [Optimizing and Implementing Fischlin's Transform for UC-Secure Zero Knowledge](https://eprint.iacr.org/2024/526.pdf). IACR ePrint 2024/526.
<!-- paper: docs/papers/Fischl05b.pdf -->
- [Fis05] Fischlin, M. [Communication-Efficient Non-Interactive Proofs of Knowledge with Online Extractors](https://link.springer.com/chapter/10.1007/11535218_10). CRYPTO 2005.
