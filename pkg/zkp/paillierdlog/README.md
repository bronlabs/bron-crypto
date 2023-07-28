# Zero-Knowledge proof of a Paillier encryption of a discrete log (PDL)
Zero-knowledge proof that a value encrypted in a given Paillier ciphertext is
the discrete log of a given Elliptic curve point. This doesn’t need to be a proof of
knowledge. See section 3.1 of [Fast Secure Two-Party ECDSA Signing][Lin17] for details.

## Protocol for $L_{PDL}$
Input:
* $pk$ - Paillier public-key
* $Q$ - value $Q = x \cdot G$

$P$ input:
* $sk$ - Paillier secret-key
* x - scalar

$V$ input:
* $c, r$ - c is encrypted value of x, such that $c = Enc_{pk}(x;r)$

Steps:
1. V chooses a random $a \leftarrow \mathbb{Z} _q$ and $b \leftarrow \mathbb{Z} _{q^2}$
    1. computes $c' = (a \odot c) \oplus Enc_{pk}(b; r)$ for a random $r \in Z_N^*$ (verifying explicitly that $\gcd(r, N) = 1$),
    2. computes $c'' = commit(a, b)$,
    3. computes $Q' = a \cdot Q + b \cdot G$,
    4. sends $(c' , c'')$ to $P$.
2. $P$ receives $(c' , c'')$ from $V$,
    1. decrypts it to obtain $\alpha = Dec_{sk}(c')$, and computes $\hat{Q} = \alpha \cdot G$,
    2. sends $\hat{c} = commit(\hat{Q})$ to $V$.
3. $V$ decommits $c''$, revealing $(a, b)$.
4. $P$ checks that $\alpha = a \cdot x + b$ (over the integers). If not, it aborts. Else, it decommits $\hat{c}$ revealing $\hat{Q}$,
    1. Range-ZK proof: In parallel to the above, proves in zero knowledge that $x \in \mathbb{Z}_q$ (protocol $L_P$).
5. $V$ accepts if and only if it accepts the range proof and $\hat{Q} = Q'$

[Lin17]: <https://eprint.iacr.org/2017/552>
