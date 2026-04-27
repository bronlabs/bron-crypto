# Pedersen Commitments

This package provides two flavors of Pedersen commitments behind a uniform `Scheme` / `Committer` / `Verifier` API:

- **Prime-order group flavor**: classical Pedersen over a prime-order group $\mathbb{G}$ (e.g. an elliptic curve). Commitments are *perfectly hiding* and *computationally binding* under the discrete-logarithm assumption.
- **CGGMP21 ring-Pedersen flavor** (cf. [Canetti–Gennaro–Goldfeder–Makriyannis–Peled, *UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts*](https://eprint.iacr.org/2021/060)): Pedersen over the unknown-order quadratic-residue subgroup $\mathrm{QR}(\hat N)$ of an RSA modulus $\hat N = pq$. Commitments are *statistically hiding* and *computationally binding* under the strong-RSA assumption.

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
trapdoor, _ := pedersen.SampleRingPedersenTrapdoorKey(2048, prng) // |N̂| in bits
scheme,   _ := pedersen.NewRingPedersenScheme(trapdoor.CommitmentKey(), 256)  // ℓ
verifier, _ := scheme.Verifier()
```

The CRS lives in $\mathrm{QR}(\hat N)$. The commitment is

$$
C = s^{m} \cdot t^{r} \pmod{\hat N}, \qquad s = t^{\lambda}.
$$

Two protocol-level parameters control security:

- **`messageBitBound` (ℓ)** — the maximum bit length of $m$ that the scheme will accept. Must stay strictly below $|\mathrm{ord}(t)| \approx |\hat N| - 2$. The constructor enforces a public conservative gap (`messageBitBound < |\hat N| - 2`).
- **Statistical hiding slack** — `Commit` samples $r$ from $[-\hat N \cdot 2^{\sigma}, \hat N \cdot 2^{\sigma})$ with $\sigma$ = `base.StatisticalSecurityBits`, ensuring the distribution of $t^{r}$ is statistically close to uniform on $\mathrm{QR}(\hat N)$.
- **Computational binding slack** — the modulus must exceed `base.ComputationalSecurityBits`; the constructor refuses moduli that are too small to support the strong-RSA reduction.

If $\ell$ is set too close to $|\hat N|$ (i.e. close to $|\mathrm{ord}(t)|$) the strong-RSA reduction collapses and a prover can equivocate by exploiting wrap-around mod $\mathrm{ord}(t)$.

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
