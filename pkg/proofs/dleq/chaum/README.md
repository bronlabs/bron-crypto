# Chaum-Pedersen Zero-Knowledge proof of equality of two discrete logs, Made non-interactive via Fiat-Shamir transform

This NIZK convinces a verifier that k = log_g x = log_h y. The proof is originally written in [CP93]. We will however make it non-interactive via Fiat-Shamir transform. This is not UC-secure, but will have essentially no overhead so will be faster.


## Reference
[CP93] David Chaum and Torben P. Pedersen. Wallet databases with observers. In Ernest F. Brickell, editor, CRYPTO’92, volume 740 of LNCS, pages 89–105. Springer, Heidelberg, August 1993.

## Configuration

**Players** 2 Parties, Prover and Verifier

**Input**:
- H1, H2: Base of the log
- P1, P2: Points whose dlog to the base H1, H2 we will prove to be equal.
- Hash: An agreed upon hash function whose length is $\geq L$

## Protocol:
- Prover (x is the dlog, input is H1 and H2):
    1. Compute P1 = x * H1
    2. Compute P2 = x * H2
    3. Sample a random scalar k.
    4. Compute R1 = k * R1
    5. Compute R2 = k * R2
    6. Compute the challenge c = Hash(H1, H2, P1, P2, R1, R2).
    7. Compute s = k + c*x
    8. Proof is (c, s)

- Verifier (verifying $\pi$ as a proof of `dlog_H1(P1) == dlog_H2(P2)`):
    1. Compute R1 = s * H1 - c * P1
    2. Compute R2 = s * H2 - c * P2
    3. Recompute the challenge c' = Hash(H1, H2, P1, P2, R1, R2)
    4. **ABORT** if c != c'
    5. Accept the proof

