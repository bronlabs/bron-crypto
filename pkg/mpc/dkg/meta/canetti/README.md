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

- The protocol uses `sharing/vss/meta/feldman`, so the resulting shard is tied
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
### Round 1
1. Sample $x_i \leftarrow \mathbb{F}_q$ and set $X_i = g^{x_i}$.
2. Sample $\rho_i \leftarrow \{0,1\}^{\kappa}$ and compute $(A_i, \tau) \leftarrow \mathcal{M}(com, \Pi^{sch})$.
3. Sample $u_i \leftarrow \{0,1\}^{\kappa}$ and set $V_i = \mathcal{H}(sid, i, \rho_i, X_i, A_i, u_i)$.
4. Broadcast $(sid, i, V_i)$.

### Round 2
1. When obtaining $(sid, j, V_j)$ from all $\mathcal{P}_j$, send $(sid, i, \rho_i, X_i, A_i, u_i)$ to all.

### Round 3
1. Upon receiving $(sid, j, \rho_j, X_j, A_j, u_j)$ from $\mathcal{P}_j$, do:
   1. Verify $\mathcal{H}(sid, j, \rho_j, X_j, A_j, u_j) = V_j$.
2. When obtaining the above from all $\mathcal{P}_j$, do:
   1. Set $\rho = \bigoplus_j \rho_j$.
   2. Compute $\psi_i = \mathcal{M}(prove, \Pi^{sch}, (sid, i, \rho), X_i; x_i, \tau)$.
3. Send $(sid, i, \psi_i)$ to all $\mathcal{P}_j$.

### Output
1. Upon receiving $(sid, j, \psi_j)$ from $\mathcal{P}_j$, interpret $\psi_j = (\hat{A}_j, ...)$, and do:
   1. Verify ${\hat{A}_j} = A_j$.
   2. Verify $\mathcal{M}(vrfy, \Pi^{sch}, (sid, j, \rho), X_j, \psi_j) = 1$.
2. When passing above verification from all $\mathcal{P}_j$, output $X = \prod_jX_j$.
3. Store $\vec{X} = (X_1, \dots, X_n)$ and $x_i$.
