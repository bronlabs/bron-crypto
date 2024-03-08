# Zero-Knowledge Range Proof
Zero-Knowledge range proof that $x \in \lbrace 0, ..., \frac{q}{3} \rbrace$ where $c=Enc_{pk}(x; r)$.
See appendix A of [Fast Secure Two-Party ECDSA Signing][Lin17] for details.
The proof is based on [https://www.iacr.org/archive/eurocrypt2000/1807/18070437-new.pdf][Bou2000]

## Protocol for $L_{P}$
Input:
* $t$ - security parameter (cheating prover can succeed with probability $\le 2^{-t}$)
* $q$ - defines the range $\left[0; \frac{q}{3})$

$P$ input:
* $sk$ - Paillier private-key
* $x$
* $r$

$V$ input:
* $pk$ - Paillier public-key
* $c$ - Paillier encrypted value of $x$, i.e. $c = Enc_{pk}(x; r)$

Sigma protocol steps:
1. Commit:
    1. chooses random $w^0_1, ..., w^{t-1}_1 \leftarrow \lbrace l, \dotsc, 2l \rbrace$ and computes $w^i_2 = w^i_1 − l$ for every $i = 0, ..., t-1$,
    2. for every $i = 0, ..., t-1$, switches the values of $w^i_1$ and $w^i_2$ with probability $\frac{1}{2}$ (independently for each $i$),
    3. for every $i = 0, ..., t-1$ computes $c^i_1 = Enc_{pk}(w^i_1; r^i_1)$ and $c^i_2 = Enc_{pk}(w^i_2; r^i_2)$, where $r^i_1, r^i_2 ← \mathbb{Z}_N$ are the randomness used in Paillier encryption,
    4. sends $c^0_1, c^0_2, ..., c^{t-1}_1, c^{t-1}_2$ to $V$.
2. Response (challenge $e = (e_0, e_1, ..., e_{t-1})$)
    1. If $e_i = 0$ sets $z_i = \left(w^i_1, r^i_1, w^i_2, r^i_2\right)$,
    2. If $e_i = 1$ sets $z_i$ as follows. Let $j \in \lbrace 1, 2 \rbrace$ be the unique value of $j$ such that $x + w^i_j \in \lbrace l,..., 2l \rbrace$. Then sets $z_i = (j, x + w^i_j , r \cdot r^i_j \mod N)$,
    3. sends $z_i$ to $V$.
3. Verify:
    1. $V$ parses $z_i$ appropriately according to the value of $e_i$. Then for $i = 0, ..., t - 1$:
    2. If $e_i = 0$ checks that $c^i_1 = Enc_{pk}(w^i_1; r^i_1)$ and $c^i_2 = Enc_{pk}(w^i_2; r^i_2)$ and that one of $w^i_1, w^i_2 \in \lbrace l, ..., 2l \rbrace$ while the other is in $\lbrace 0, ..., l \rbrace$, where $z_i = (w^i_1, r^i_1, w^i_2, r^i_2)$,
    3. If $e_i = 1$ checks that $c \oplus c^i_j = Enc_{pk}(w^i; r^i)$ and $w^i \in \lbrace l,...,2l \rbrace$, where $z_i = (j, w^i, r^i)$,
    4. accepts if and only if all the checks pass.

[Lin17]: <https://eprint.iacr.org/2017/552> 
[Bou2000]: <https://www.iacr.org/archive/eurocrypt2000/1807/18070437-new.pdf>
