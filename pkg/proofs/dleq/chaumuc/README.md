# Chaum-Pedersen Zero-Knowledge proof of equality of two discrete logs, Made non-interactive via Randomized Fischlin transform

This NIZK convinces a verifier that k = log_g x = log_h y. The proof is originally written in [CP93]. We will however make it non-interactive via Randomized Fischlin from [KS22] to achieve straightline extraction.


## Reference
[CP93] David Chaum and Torben P. Pedersen. Wallet databases with observers. In Ernest F. Brickell, editor, CRYPTO’92, volume 740 of LNCS, pages 89–105. Springer, Heidelberg, August 1993.
[GLOW] D. Galindo, J. Liu, M. Ordean, J. Wong, Fully distributed verifiable random functions and their application to decentralised random beacons, https://eprint.iacr.org/2020/096 (2020).

## Configuration

**Players** 2 Parties, Prover and Verifier

**Parameters**:
- $\lambda$: Security parameter. In our case it's 128.
- $k$: $\left \lceil \log_2 \lambda \right \rceil$
- $L$: Length of the Hash function which has to be zero.
- $R$: Total number of challenges produced.
- $T$: Length of the sampled challenge.

such that $L \times S = \lambda$ and $T=\left \lceil log(\lambda** \right \rceil \times L$.

**Input**:
- H1, H2: Base of the log
- P1, P2: Points whose dlog to the base H1, H2 we will prove to be equal.
- Hash: An agreed upon hash function whose length is $\geq L$

## Protocol:
- Prover (x is the dlog):
    1. Sample random elements $a \leftarrow \mathbb{Z}_q^{r}$
    2. Compute commitments $A1 = a \cdot H1 and $A2 = a \codt H2"
    3. For each $i \in \[ r \]$:
        1. Set $\mathcal{E}_i = \emptyset$
        2. Sample challenge $e_i \leftarrow \{0,1\}^t \backslash \mathcal{E}_i$
        3. Compute response $z_i = a_i + x \times e_i$
        4. Do work $h = Hash(G, A1, A2, P1, P2, i, e_i, z_i, extra...)[:L]$
        5. If $h \neq 0^l$ then add $e_i$ to $\mathcal{E}_i$ and repeat from 3.2, else, record $e_i$ and $z_i$.
    4. Output $\pi = (A1_i, A2_i, H1, H2, P1, P2, e_i, z_i)_{i \in \[r\]}$

- Verifier (verifying $\pi$ as a proof of `dlog_H1(P1) == dlog_H2(P2)`):
    1. Parse $(A1_i, A2_i, H1, H2, P1, P2, e_i, z_i)_{i \in \[r\]} = \pi$ and set $A = (A_i)_{i \in \[r\]}$.
    2. For each $i \in \[ r \]$:
        1. **ABORT** if $Hash(G, A1, A2, P1, P2, i, e_i, z_i, extra...)[:L] \neq 0^l$.
        2. **ABORT** if $A1_i \neq z_i \cdot H1 - e_i \cdot P1$
        3. **ABORT** if $A2_i \neq z_i \cdot H2 - e_i \cdot P2$
    3. Accept the proof.

