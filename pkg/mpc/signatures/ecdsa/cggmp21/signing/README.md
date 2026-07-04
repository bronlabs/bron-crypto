# CGGMP21 Signing

This package implements the online CGGMP21 threshold ECDSA signing protocol.

The runner executes the four signing rounds. On success each party receives its own partial signature and a session-bound `PartialSignatureAggregator`; callers exchange the partial signatures at the application layer and aggregate them into the final ECDSA signature.

## Protocol Flow

Each signer samples nonzero $k_i,\gamma_i \in \mathbb{F}_q$ and broadcasts Paillier encryptions

$$
K_i=\operatorname{Enc}_{N_i}(k_i),\qquad G_i=\operatorname{Enc}_{N_i}(\gamma_i),
$$

with ElGamal commitments to the same values and $\Pi^{\mathsf{enc\text{-}elg}}$ proofs.

After the zero-sharing step, the implementation works with unanimous additive signing shares $x_i$. For every counterparty $j$, signer $i$ sends the two affine products

$$
D_{ij}=K_j^{\gamma_i}\operatorname{Enc}_{N_j}(-\beta_{ij}),\qquad
F_{ij}=\operatorname{Enc}_{N_i}(\beta_{ij}),
$$

and

$$
\widehat{D}_{ij}=K_j^{x_i}\operatorname{Enc}_{N_j}(-\widehat{\beta}_{ij}),\qquad
\widehat{F}_{ij}=\operatorname{Enc}_{N_i}(\widehat{\beta}_{ij}),
$$

with $\Pi^{\mathsf{aff\text{-}g}}$ proofs. The received plaintexts are accumulated into

$$
\delta_i = k_i\gamma_i + \sum_{j \ne i} \alpha_{ji} + \sum_{j \ne i}\beta_{ij},
\qquad
\chi_i = k_ix_i + \sum_{j \ne i} \widehat{\alpha}_{ji} + \sum_{j \ne i}\widehat{\beta}_{ij}.
$$

Round 3 broadcasts $\delta_i$, $\Delta_i = k_i\Gamma$, and $S_i=\chi_i\Gamma$ with the required ElGamal exponent proof. Round 4 checks

$$
g^{\sum_i \delta_i} \stackrel{?}{=} \sum_i \Delta_i,\qquad
Y^{\sum_i \delta_i} \stackrel{?}{=} \sum_i S_i,
$$

then returns the local partial signature

$$
\sigma_i = k_i\delta^{-1}m + r\chi_i\delta^{-1}.
$$

If either round 4 consistency equation fails, the runner enters the internal red-alert path. Nonce red alert opens the $\delta$ equation; chi red alert opens the $\chi$ equation. In both modes each party reveals the relevant $D_{ij},F_{ij}$ values, proves the aggregate Paillier decryption with $\Pi^{\mathsf{dec}}$, and proves each revealed affine product with $\Pi^{\mathsf{aff\text{-}g*}}$. Received red-alert broadcasts are checked against the round 2 private messages before proof verification.

## Aggregation

`SignResult.PartialSignature` returns the local partial signature. `SignResult.PartialSignatureOnlineAggregator` returns an aggregator bound to the successful online session and its transcript-derived state.

`NewOfflineAggregator` constructs a stateless aggregator for already validated partial signatures. It checks that all partial signatures use the same $\Gamma$ and sums their $\sigma_i$ values.

## Transcript Binding

The signing transcript starts with the package domain separator, public key, and refresh identifier. Broadcast messages are appended after the following round receives and validates them, so proofs created in a round are bound to the transcript available at that point while later rounds still commit to all previous broadcasts.

## Reference

- Canetti, Gennaro, Goldfeder, Makriyannis, Peled.
  [UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts](https://eprint.iacr.org/2021/060).
