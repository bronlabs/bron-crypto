
# Multiparty Schnorr Signing
This implements `PROTOCOL 4.4` as seen in the [Simple Three-Round Multiparty Schnorr Signing with Full Simulatability][Lin22]
with Zero Schnorr Signing as described in [On the Classic Protocol for MPC Schnorr Signatures][Mak22].

## PROTOCOL 4.4 (Multiparty Schnorr Signing)
### Input
Each party $P_i$ in the set $S$ of parties has the Schnorr public-key $Q = (Q_x, Q_y)$, the set of participating parties $S$, a session identifier $sid$, the party identifier $pid_i$, the message to be signed $m$, and its private input $d_i$ which is a Shamir share of the private-key $d$ where $Q = d \cdot G$.

### Protocol

#### Round 1
Each party $P_i$:
1. chooses a random $k_i \leftarrow \mathbb{Z}_q$
2. computes $R_i = (R_{x_i}, R_{y_i}) = k_i \cdot G$
3. computes $R_i$ commitment, $R_i^{mcom} = commit(R_i, pid_i, sid, S)$,
4. broadcasts $R_i^{mcom}$,
5. runs PRZS round 1.

#### Round 2
Each party $P_i$:
1. computes proof of knowledge of dlog of $R_i$, $R_i^{dl} = prove(k_i, R_i, S)$,
2. broadcasts $R_i^{dl}$ and opening of $R_i^{mcom}$ revealing $R_i$,
3. runs PRZS round 2.

#### Round 3
Each party $P_i$:
1. for every $j \in S$ verifies $R_j^{mcom}$,
2. for every $j \in S$ verifies $R_j^{dl}$,
3. runs PRZS round 3 to get zero share $z$,
4. computes:
   1. $R = (R_x, R_y) = \sum_{j \in S}R_j$,  
      a) (BIP-0340) if $R_y$ is odd: $k_i = -k_i$, $R=(R_x, -R_y)$
   2. $e$  
      a) (EdDSA) $e = H(R \mathrel{\Vert} Q \mathrel{\Vert} m)$,  
      b) (BIP-0340) $e = H(R_x \mathrel{\Vert} Q_x \mathrel{\Vert} m)$
   3. additive share $d_i' = \lambda_i d_i$, where $d_i$ is $P_i$'s shamir share and $\lambda_i$ is Lagrange coefficient,
      a) (BIP-0340) if $Q_y$ is odd: $d_i' = -d_i'$
   4. $s_i = k_i + e \times d_i' + z$
5. returns $\sigma_i = \left(R_i, s_i \right)$ as partial signature.

#### Aggregate
For every $i \in S$:
1. compute $r = \sum_{i \in S}R_i$ and $s = \sum_{i \in S}s_i$,
2. return $\sigma = \left(r, s\right)$ as full signature.

[Lin22]: <https://eprint.iacr.org/2022/374.pdf>
[Mak22]: <https://eprint.iacr.org/2022/1332>
