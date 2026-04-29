# Pedersen Commitments

This package provides two flavors of Pedersen commitments behind a uniform `Scheme` / `Committer` / `Verifier` API:

- **Prime-order group flavor**: classical Pedersen over a prime-order group $\mathbb{G}$ (e.g. an elliptic curve). Commitments are *perfectly hiding* and *computationally binding* under the discrete-logarithm assumption.
- **CGGMP21 ring-Pedersen flavor** (cf. [Canetti–Gennaro–Goldfeder–Makriyannis–Peled, *UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts*](https://eprint.iacr.org/2021/060)): Pedersen over the unknown-order quadratic-residue subgroup $\mathrm{QR}(\hat N)$ of an RSA modulus $\hat N = pq$ for safeprime $p$ and $q$. Commitments are *statistically hiding* and *computationally binding* under the strong-RSA assumption.

Each flavor has an `EquivocableScheme` companion that retains the trapdoor $\lambda$ with $h = g^{\lambda}$, enabling simulation-style openings. All public types implement CBOR encoding for transport and persistence.

## Common API

- `Key`: the public CRS, a pair $(g, h)$ in the underlying group. The constructor rejects nil/identity/equal/torsion-bearing generators. `NewRingPedersenCommitmentKey` and `NewPrimeGroupCommitmentKey` derive the CRS deterministically from a transcript so that the discrete log $\log_g h$ remains hidden.
- `Trapdoor`: the secret CRS $(g, h, \lambda)$ with $h = g^{\lambda}$. Knowledge of $\lambda$ enables `Equivocate`.
- `Message[S]`, `Witness[S]`: typed wrappers over scalar values.
- `Commitment[E, S]`: a group element representing $C = g^m \cdot h^r$.
- `Scheme[E, S]`: wires a committer/verifier pair around a fixed `Key`. Carries flavor-specific message/witness samplers and range checks.
- `EquivocableScheme[E, S]`: a `Scheme` that also retains the trapdoor.

## Prime-order group flavor

```go
trapdoor, _ := pedersen.SamplePrimeGroupTrapdoorKey(basePoint, prng)
scheme,   _ := pedersen.NewPrimeGroupScheme(trapdoor.CommitmentKey())
committer, _ := scheme.Committer()
commitment, witness, _ := committer.Commit(msg, prng)
```

- Messages and witnesses live in the group's scalar field. Range checks reduce to "value is canonical (cardinal < field order)"; every field element is a valid input.
- `Commit(message, prng)` samples $r$ uniformly from the scalar field and returns $(g^m h^r, r)$.

## Ring-Pedersen flavor

```go
trapdoor, _ := pedersen.SampleRingPedersenTrapdoorKey(2048, prng)              // |N̂| in bits
scheme,   _ := pedersen.NewRingPedersenScheme(trapdoor.CommitmentKey(), 1792)  // messageSlack = |N̂| − ℓ
verifier, _ := scheme.Verifier()
```

The CRS lives in $\mathrm{QR}(\hat N)$. The commitment is

$$
C = s^{m} \cdot t^{r} \pmod{\hat N}, \qquad s = t^{\lambda}.
$$

Two protocol-level parameters control security:

- **`messageSlack`** — bits of headroom reserved between the accepted message size and $|\hat N|$. A message $m$ is accepted iff $|m|_\text{bits} + \texttt{messageSlack} < |\hat N|$, so the effective bit budget is $\ell = |\hat N| - \texttt{messageSlack} - 1$. The public floor is `messageSlack ≥ 2` (keeps $\ell < |\mathrm{ord}(t)| \approx |\hat N|-2$, which is what strong-RSA binding requires). Consuming Σ-protocols extract witnesses of size $\approx \ell + |\text{challenge}| + \sigma$, so for soundness pick `messageSlack ≥ |challenge| + σ + 2`; in CGGMP21 that is $\lambda + \sigma + 2$. A safe default for curve-scalar-sized messages over $|\hat N| = 2048$ is `messageSlack = |N̂| − |q|` ≈ 1792.
- **Statistical hiding slack** — `Commit` samples $r$ from $[-\hat N \cdot 2^{\sigma}, \hat N \cdot 2^{\sigma})$ with $\sigma$ = `base.StatisticalSecurityBits`, ensuring the distribution of $t^{r}$ is statistically close to uniform on $\mathrm{QR}(\hat N)$.

If `messageSlack` is set at the floor (2), binding still holds but any layered Σ-protocol's extractor can wrap mod $\mathrm{ord}(t)$, voiding its soundness.

## Trapdoor and equivocation

`Trapdoor.Equivocate(message, witness, newMessage)` returns $r'$ such that
$$
g^{m} h^{r} = g^{m'} h^{r'}, \qquad r' = r + \lambda^{-1}(m - m') \pmod{\mathrm{ord}(g)}.
$$

For ring-Pedersen, the new witness $r'$ must still pass the scheme's range check; equivocation is therefore *not* unrestricted — only message pairs $(m, m')$ within the bit bound (and producing a witness within the statistical range) yield a valid alternative opening. This is exactly the binding property: outside that window, equivocation requires breaking strong-RSA.

For the prime-group flavor, $\mathrm{ord}(g)$ is the scalar field order $q$, so equivocation is a single field operation.

## Homomorphism

Multiplying two commitments adds their messages and witnesses; `ScalarOp` raises a commitment to a scalar (in the message space). `ReRandomise` blinds an existing commitment with fresh randomness without changing the committed message — useful for linear proof systems and aggregation.

## CBOR encoding

`Key`, `Commitment`, `Message`, `Witness` and `Trapdoor` all expose `MarshalCBOR` / `UnmarshalCBOR`. Trapdoor encoding stores only $(g, \lambda)$ and recomputes $h = g^{\lambda}$ on decode, re-running the constructor invariants.
