# `mrr21`: Batching Base Oblivious Transfers

This package implements the batched 1-out-of-2 Oblivious Transfer of Figure 3 of
[MRR21](https://eprint.iacr.org/2021/682) in its one-flow form (Theorem 11), to run
Random OTs (ROT) for a batch of L choice bits in a single round trip. It is the base
OT of the `ot` stack: its outputs seed the `iknp03` and `softspoken` extensions.

The protocol provides **endemic** security in the sense of
[MR19](https://eprint.iacr.org/2019/706) (Definition 2.4, functionality $F_{OT}^E$): a
malicious sender learns nothing about the receiver's choice bits, a malicious receiver
learns nothing about the unchosen message of any OT, but a corrupt party may choose its
own outputs rather than receive uniform ones. Endemic OT is the weakest flavour that
suffices as base OT for OT extension (MR19, Section 5, Lemma 5.8), and every stronger
flavour (sender-chosen, receiver-chosen, uniform) can be derived from it with the
transformations of MR19, Section 3.

## Protocol

The batch is parameterised by the number of OTs L, a positive multiple of 8, and by the
message type M of `ot` (`Message128` or `Message256`), which fixes the message length
K. Both parties share a prime-order group G with generator G and scalar field $Z_q$.

```
Sender                                            Receiver (choice bits c_1..c_L)
a <- Z_q*                                         for i in [L]:
m_S = a·G                                           b_i <- Z_q*
                                                    φ_i = Program(c_i, b_i·G)
        ---- m_S ---->          <---- φ_1..φ_L ----          (round 1, both at once)

for i in [L], j in {0,1}:                         for i in [L]:
  r_{i,j} = H(a·Eval(φ_i, j), i‖j)                  r_{i,c_i} = H(b_i·m_S, i‖c_i)
```

- **Round 1.** The sender samples its key-agreement secret and sends $m_S = a·G$. The
  receiver samples one secret $b_i$ per OT and sends the POPF $φ_i$ programmed on its
  choice bit to $b_i·G$. Neither message depends on the other, which is what makes the
  protocol one-flow (MRR21, Theorem 11): a rushing sender only gets to bias its own
  outputs, which endemic security permits.
- **Round 2.** The sender evaluates every POPF on both bits and derives both messages
  of every OT; the receiver derives its chosen message from $m_S$. The instance index
  and branch enter the key derivation as the tag $i‖j$ of the tagged key agreement
  (MRR21, Section 4.1), so keys of different OTs and branches are independent even
  though $a$ is reused across the batch (tag non-malleability, Definition 3, from the
  tagged ODH assumption, Definition 21).

### Building blocks

- **POPF.** `MasnyRindalPopf` is the batch 2-POPF of MRR21, Figure 6, which generalises
  the one-round OT of MR19, Section 4 (Figure 8): $φ = (s_0, s_1)$ over G with
  $\mathrm{Eval}(φ, x) = s_x · H_x(s_{1-x})$, programmed by sampling $s_{1-x^*}$ uniformly
  and setting $s_{x^*} = y^* · H_{x^*}(s_{1-x^*})^{-1}$. The random oracles $H_0, H_1 : G \to G$
  are instantiated by the group's hash-to-group function with a label and the bit, the
  second of the two POPF/KA compatibility options of MRR21, Section 6.1. Programming is
  not constant time in the choice bit.
- **Key agreement.** Plain Diffie–Hellman in G, which is one-flow and has uniform
  responses in G as Figure 3 requires (Definition 4). The key derivation $H(·, τ)$ is
  HKDF-SHA256 over the encoding of the shared point, with the tag in the HKDF `info`
  and a salt extracted from the session transcript after $m_S$ and all $φ_i$ are bound
  to it, so every key is also bound to the whole exchange.
- **Messages.** `SenderRound1P2P` carries $m_S$; `ReceiverRound1P2P` carries
  $φ_1..φ_L$. Both validate their origin and their contents: group elements are
  decoded into the prime-order group, and the identity is rejected everywhere, for
  $m_S$, for both POPF elements and for every POPF evaluation, since an identity would
  make the corresponding key derivable by anyone. A POPF that passes validation but
  evaluates to the identity is an identifiable abort attributed to the receiver.

### Outputs

The sender obtains a `ot.SenderOutput[M]` with both messages of every OT, the
receiver a `ot.ReceiverOutput[M]` with its choice bits and chosen messages. Messages
are K-bit strings derived by HKDF, not group elements, so they can be used directly as
PRG seeds by the extensions.

## Differences from the papers

- Keys are derived with HKDF-SHA256 and a transcript salt instead of a bare hash of the
  shared point and tag; both parties hold the same transcript, so correctness is
  unaffected and the derivation only gains inputs.
- The tag is encoded as the branch bit followed by the little-endian instance index,
  an injective, fixed-length encoding of $i‖j$.
- Identity elements are rejected where the papers sample or accept them, which changes
  the distributions by $1/|G|$.
- Aborts caused by the receiver's message are identifiable and attributed to it.

## References
<!-- paper[MRR21]: docs/papers/2021-682_20210525_203843.pdf [Figures 3, 6; Sections 4.1, 4.3, 5.3, 6; Theorems 9, 11, 14; Definitions 3, 4, 21] -->
- [MRR21] Ian McQuoid, Mike Rosulek, Lawrence Roy, "Batching Base Oblivious Transfers",
  ASIACRYPT 2021, [eprint 2021/682](https://eprint.iacr.org/2021/682): the batch OT
  protocol (Figure 3), its one-flow variant (Theorem 11), the Masny–Rindal POPF
  (Figure 6, Theorem 14) and the tagged key agreement (Section 4.1, Section 6).
<!-- paper[MR19]: docs/papers/2019-706_20210713_190330.pdf [Definitions 2.4, 2.6; Sections 3, 4, 5; Figure 8; Lemma 5.8] -->
- [MR19] Daniel Masny, Peter Rindal, "Endemic Oblivious Transfer", CCS 2019,
  [eprint 2019/706](https://eprint.iacr.org/2019/706): the endemic OT functionality and
  security notion (Definitions 2.4, 2.6), the relations to the other OT flavours
  (Section 3), the one-round OT from key agreement that the POPF generalises
  (Section 4, Figure 8) and the sufficiency of endemic base OTs for OT extension
  (Section 5, Lemma 5.8).
