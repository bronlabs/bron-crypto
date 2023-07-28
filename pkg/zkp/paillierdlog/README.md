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
1. V chooses a random $a \leftarrow \mathbb{Z}_q$ and $b ← \mathbb{Z}_{q^2}$
   1.a. computes $c' = (a \odot c) \oplus Enc_{pk}(b; r)$ for a random $r \in Z_N^*$ (verifying explicitly that $\gcd(r, N) = 1$),
   1.b computes $c'' = commit(a, b)$,
   1.c computes $Q' = a \cdot Q + b \cdot G$.
   1.d sends $(c' , c'')$ to $P$.
2. $P$ receives $(c' , c'')$ from $V$ ,
   2.a decrypts it to obtain $\alpha = Dec_{sk}(c')$, and computes $\hat{Q} = \alpha \cdot G$,
   2.b sends $\hat{c} = commit(\hat{Q})$ to $V$ .
3. $V$ decommits $c''$ , revealing $(a, b)$.
4. $P$ checks that $\alpha = a \cdot x + b$ (over the integers). If not, it aborts. Else, it decommits $\hat{c}$ revealing $\hat{Q}$,
   4.a. Range-ZK proof: In parallel to the above, proves in zero knoledge that $x \in \mathbb{Z}_q$ (protocol $L_P$)

[Lin17]: <https://eprint.iacr.org/2017/552>
