# Canetti DKG

Distributed key generation following the CGGMP21 / Canetti et al. line of work,
adapted here to generic monotone access structures represented as MSPs. Each
party acts as a Feldman dealer over the supplied access structure, commits to
its opening material with a hash-based commitment, and proves consistency of the
published verification vector with a batch Schnorr proof. The implementation is
inspired by [Canetti et al., “UC Non-Interactive, Proactive, Threshold ECDSA with
Identifiable Aborts”](https://eprint.iacr.org/2021/060.pdf) and the 2024 revision,
while generalising the sharing layer beyond threshold access structures.

## Protocol Overview

1. **Commit**: Each party samples a random dealer function, computes its Feldman
   verification vector, samples `rho`, creates a batch Schnorr commitment, and
   broadcasts only a hash commitment to the opening material.
2. **Open & Distribute**: Parties open the commitment with
   `CommitmentMessage + witness` and privately send each receiver its share.
3. **Verify & Respond**: Everyone verifies commitments and shares, XORs all
   `rho` values into a common challenge, aggregates the verification vectors and
   shares, and broadcasts the batch Schnorr response.
4. **Finalize**: Parties verify every proof response against the common
   challenge and output an `mpc.BaseShard` containing the aggregated share and
   verification vector.

## Implementation Notes

- The protocol uses `sharing/vss/feldman`, so the resulting shard is tied
  to the MSP induced by the provided access structure.
- `rho` length and the batch Schnorr challenge length both scale with the MSP
  dimension `D`, matching the batched proof soundness requirements.
- `Participant` exposes the round API directly; `NewRunner` wraps the same logic
  behind a `network.Runner`.

## Usage

1. Build a `session.Context` for each party and choose a monotone access
   structure.
2. Create a `Participant` with `NewParticipant`, or use `NewRunner` for
   fully-managed execution over a `network.Router`.
3. Exchange `Round1Broadcast`, then `Round2Broadcast` plus `Round2P2P`, then
   `Round3Broadcast`.
4. Call `Round4` to obtain the final `mpc.BaseShard`.

## Spec

This generalises CGGMP21 Figure 6 from a single key share to a Feldman dealing
over an MSP of dimension $D$. Each party $P_i$ holds a secret random column
$\vec{c}_i = (c_{i,0}, \dots, c_{i,D-1})$ with lifted verification vector
$\vec{X}_i = (g^{c_{i,0}}, \dots, g^{c_{i,D-1}})$. The discrete-log proof
$\Pi^{sch}$ is the **batch** Schnorr of `proofs/dlog/batch_schnorr` over the whole
vector $\vec{X}_i$ (witness $\vec{c}_i$), compiled non-interactively with the
Fiat–Shamir `zkmodule`; the common coin toss $\rho$ is folded into its transcript.

### Round 1
1. Sample a random dealer function; set the Feldman verification vector $\vec{X}_i = g^{\vec{c}_i}$.
2. Sample $\rho_i \leftarrow \{0,1\}^{\ell_\rho}$ and compute the batch Schnorr commitment $(A_i, \tau) \leftarrow \mathcal{M}(com, \Pi^{sch}, \vec{X}_i)$.
3. Sample $u_i$ and set $V_i = \mathcal{H}(sid, i, \rho_i, \vec{X}_i, A_i, u_i)$ (hash commitment).
4. Broadcast $(sid, i, V_i)$.

### Round 2
1. When obtaining $V_j$ from all $\mathcal{P}_j$, open by sending $(sid, i, \rho_i, \vec{X}_i, A_i, u_i)$ to all, and privately send each $\mathcal{P}_j$ its Feldman share.

### Round 3
1. Verify every opening against $V_j$ and Feldman-verify each received share against $\vec{X}_j$.
2. Set $\rho = \bigoplus_j \rho_j$, aggregate the verification vectors and shares, and compute the batch Schnorr response $\psi_i = \mathcal{M}(prove, \Pi^{sch}, (sid, i, \rho), \vec{X}_i; \vec{c}_i, \tau)$.
3. Send $(sid, i, \psi_i)$ to all $\mathcal{P}_j$.

### Output
1. For each $\mathcal{P}_j$ interpret $\psi_j = (\hat{A}_j, \dots)$ and verify $\hat{A}_j = A_j$ and $\mathcal{M}(vrfy, \Pi^{sch}, (sid, j, \rho), \vec{X}_j, \psi_j) = 1$.
2. When all verify, output an `mpc.BaseShard` holding the aggregated share and verification vector.

## Security

$\Pi^{sch}$ is the GLSY batch Schnorr over the $D$-entry verification vector, so it
is $(D{+}1)$-special-sound (`batch_schnorr.SpecialSoundness` returns $k{+}1$). This
is deliberate, and the challenge length is sized to absorb the extra degree.

**The Fiat–Shamir knowledge error is negligible**, for the following reasons:

- `batch_schnorr.NewProtocol` sets the challenge length to $\kappa + \lceil\log_2 D\rceil$ bits, i.e. a challenge space of size $|C| \approx 2^{\kappa}\cdot D$.
- A $k$-special-sound $\Sigma$-protocol has knowledge error $(k-1)/|C|$ (special soundness and the two-transcript $\Sigma$-extractor are due to [CDS94]; the tight $(k-1)/|C|$ error is stated in [AFK23, Eq. (1)]). Here that is $D / (2^{\kappa}\cdot D) = 2^{-\kappa}$ — the $\lceil\log_2 D\rceil$ padding is exactly the term that cancels the batch degree (equivalently, the code's `soundnessError` $= 8\cdot\text{bytes} - \log_2 D = \kappa$).
- $\Pi^{sch}$ is a single-round (3-move, $\mu=1$) $\Sigma$-protocol, so its Fiat–Shamir compilation multiplies the knowledge error by only $(Q+1)$, where $Q$ is the number of random-oracle queries [AFK23, Thm. 2]. The naive $Q^{\mu}$ blow-up is a multi-round ($\mu \ge 2$) concern — itself tightened by [AFK23] — and does not arise here.

Hence the FS knowledge error is $(Q+1)\cdot 2^{-\kappa}$, negligible for any
polynomially bounded $Q$ — no worse in the $Q$ factor than plain Fiat–Shamir
Schnorr.

**Extraction (simulation).** The simulator recovers each corrupt dealer's column
$\vec{c}_j$ — hence its secret contribution $c_{j,0}$ — by rewinding the coin toss.
$A_j$ is fixed after Round 1 by the binding of the hash commitment $V_j$, so
re-running the adversary from the Round 2/3 boundary with a fresh honest
$\rho$-contribution yields fresh challenges $e_\ell$ on a fixed $A_j$. Collecting
$D{+}1$ accepting transcripts $(A_j, e_\ell, z_\ell)$ gives the Vandermonde system
$z_\ell = s + \sum_i e_\ell^{\,i}\,c_{j,i}$, which inverts to recover all of
$\vec{c}_j$. The single shared coin toss drives every party's challenge, so the
same $D$ rewinds extract all corrupt dealers at once; extraction runs in expected
$O(D)$ re-runs.

**What batching does not touch.** Binding of each contribution and resistance to
adaptive key-biasing come from the Round-1 hash commitment (commit-then-reveal)
and the $\hat{A}_j = A_j$ check — not from the Schnorr proof. Honest-verifier
zero-knowledge is provided by the batch protocol's own simulator. Neither depends
on the special-soundness degree.

**Cost / caveats.** Versus a vector of independent $2$-special-sound Schnorr
proofs, the batch trades reduction *tightness* for proof size: extraction needs
$D{+}1$ transcripts instead of $2$, so the security loss scales with $D$ (this is
the "efficient extraction" CGGMP21 Remark 4.4 optimises for — a tightness, not a
feasibility, property). The argument holds for polynomial $D$ with a rewinding
extractor; it would **not** suffice under a model requiring straight-line/online
extraction, or for super-polynomial $D$. Neither applies here: the proofs are
Fiat–Shamir + coin-toss (rewinding), and $D$ is bounded by the MSP dimension.

## Reference

<!-- paper: docs/papers/2021-060_20241021_172019.pdf [section 4.1 and figure 6] -->
- [CGGMP21, Section 4.1 and Figure 6](https://eprint.iacr.org/2021/060.pdf)
<!-- paper: docs/papers/afk23.pdf [Theorem 2; Eq. (1)] -->
- [AFK23] Attema, Fehr, Klooß — *Fiat–Shamir Transformation of Multi-Round Interactive Proofs*, TCC 2022 (extended version, J. Cryptology 2023). Theorem 2 gives the Fiat–Shamir knowledge error $\kappa_{fs}(Q) = (Q+1)\kappa$; Eq. (1) states the interactive $\Sigma$-protocol error $\mathrm{Er}(k;N) = (k-1)/N$ (the general multi-round tight result is credited there to Attema–Cramer–Kohl).
<!-- paper: docs/papers/crypto94.pdf -->
- [CDS94] Cramer, Damgård, Schoenmakers — *Proofs of Partial Knowledge and Simplified Design of Witness Hiding Protocols*, CRYPTO 1994. Origin of the special-soundness notion and the $\Sigma$-protocol two-transcript knowledge extractor (e.g. Schnorr).
