# Zero-Knowledge Range Proof
Sigma protocol ZK-proof that proves for $x \in [0, l)$ where $c = Enc_{pk}(x; r)$ that it is in the range $[-l, 2l)$.
Stated differently the input is $x \in [0, l)$ and the proof guarantees that $x \in [-l, 2l)$.

## Input
The prover $P$ has input $(c, x, r)$ where $c = Enc_{pk}(x; r)$
and the Paillier secret key $sk = (N, \phi(N))$.
The verifier $V$ has input $c$ and the Paillier public key $pk = N$.
Both parties have $l$ which defines the range.

## Protocol
$P$:
* chooses random $w_1 \leftarrow [l, 2l)$ and computes $w_2 = w_1 - l$,
* switches the values $w_1$ and $w_2$ with probability $1/2$,
* computes $c_1 = Enc_{pk}(w_1; r_1)$, $c_2 = Enc_{pk}(w_2; r_2)$
where $r_1, r_2$ are the randomness (nonces) used in Paillier encryptions,
* sends $(c_1, c_2)$ to $V$.

$V$:
* chooses a random $e \leftarrow \{0, 1\}$

$P$:
* if $e = 0$ then sets $z = (w_1, r_1, w_2, r_2)$,
* if $e = 1$ then sets $z$ as follows.
Let $j \in \{1, 2\}$ be the unique value of $j$ such that $x + w_j \in [l, 2l)$.
Then sets $z = (j, x + w_j, r \cdot r_j \mod N)$,
* sends $z$ to $V$.

$V$:
* parses $z$ according to the value of $e$. Then:
* if $e = 0$ checks that $c_1 = Enc_{pk}(w_1; r_1)$ and $c_2 = Enc{pk}(w_2; r_2)$
and that one of $w_1, w_2 \in [l, 2l)$ while the other is in $[0, l)$, where $z = (w_1, r_1, w_2, r_2)$.
* if $e = 1$ checks that $c \oplus c_j = Enc_{pk}(w; r)$ and $w \in [l, 2l)$, where $z = (j, w, r)$.
* accepts if and only if all of the checks pass.

## Security, Soundness for $x \notin [-l, 2l)$
$V$ accepts with probability at most $2^{-1}$. The proof has to be run in parallel sufficiently number of times
to achieve desired soundness error (e.g. $80$).

# References
* [Lin17] (appendix A Zero-Knowledge Range Proof)
* [Bou00] (chapter 1.2.2 BCDG Proof)

[Lin17]: <https://eprint.iacr.org/2017/552>
[Bou00]: <https://www.iacr.org/archive/eurocrypt2000/1807/18070437-new.pdf>
