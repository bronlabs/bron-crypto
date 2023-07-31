# Lindell 2017 DKG
* In the subprotocol 3.1 of [Fast Secure Two-Party ECDSA Signing][Lin17] paper, step `1.a` $P$ chooses a random $x: \frac{q}{3} \le x < \frac{2q}{3}$. However in our use case the $x$ is given from the previous DKG so we cannot assume it is in the range (as this will serve as a backup protocol) so instead we split $x$ such that $x = 3 \cdot x' + x''$ and both $x'$ and $x''$ are in the specified range and proceed with these value as if they were $x$.
* Because of what is described above in the last step instead of storing $c_{key} = Enc_{pk}(x)$ we store $c_{key} = 3 \odot Enc_{pk}(x') \oplus Enc_{pk}(x'')$, $\odot$ being homomorphic scalar multiplication and $\oplus$ being homomorphic addition.
* The altered protocol is outlined below to serve as backup DKG protocol (i.e. using existing sharing).

## Backup protocol
$P_i$ input (from previously ran DKG):
* $x_i$ - Shamir share of secret-key $x$
* $\lbrace y_0, y_1, ..., y_{n-1} \rbrace$ - public-key shares

Rounds:
1. Each $P_i$:
   1. chooses randomly $x_i'$ and $x_i''$ such that $x_i', x_i'' \in \left[\frac{q}{3}, \frac{2q}{3} \right)$ and $x_i = 3 \cdot x_i' + x_i''$,
   2. calculates $R_i' = x_i' \cdot G$ and $R_i'' = x_i'' \cdot G$
   3. calculates commitments $R_{com_i}' = commit(R_i')$ and $R_{com_i}'' = commit(R_i'')$,
   4. broadcasts $R_{com_i}', R_{com_i}''$.
2. Each $P_i$:
   1. calculates proofs of dlog knowledge $R_{dl_i}' = dlogProof(R_i'', x_i'')$ and $R_{dl_i}'' = dlogProof(R_i'', x_i'')$,
   2. broadcasts openings of $(R_{com_i}', R_{com_i}'')$ revealing $(R_i', R_i'')$,
   3. broadcasts  $R_{dl_i}', R_{dl_i}''$.
3. Each $P_i$:
   1. verifies $R_{dl_j}', R_{dl_j}''$ received from every $P_j$ and aborts if any fails to verify,
   2. verifies that $y_j \overset{?}{=} 3 \cdot R_j' + R_j''$ and aborts if fails to verify,
   3. generates Paillier key pair $(pk_i, sk_i)$,
   4. calculates $c_{key_i}' = Enc_{pk_i}(x_i'; r_i')$ and $c_{key_i}'' = Enc_{pk_i}(x_i''; r_i'')$,
   5. start the ZK proof process with every $P_j$ (pairwise) that $pk_i$ was generated correctly (protocol $L_P$) and that $c_{key_i}'$ and $c_{key_i}''$ encrypt dlogs of $R_i'$ and $R_i''$ respectively (protocol $L_{PDL}$),
   6. broadcasts $(pk_i, c_{key_i}', c_{key_i}'')$.
4. Each $P_i$:
   1. calculates $c_{key_j} = 3 \odot c_{key_j}' \oplus c_{key_j}''$ for every $P_j$,
   2. $L_P$ and $L_{PDL}$ continue.
5. $L_P$ and $L_{PDL}$ continue.
6. $L_P$ and $L_{PDL}$ continue.
7. $L_P$ and $L_{PDL}$ continue.
8. Each $P_i$:
   1. stores $(sk_i, pk_0, pk_{1}, ..., pk_{n-1}, c_{key_0}, c_{key_1}, ..., c_{key_{n-1}})$ alongside $(x_i, y_0, y_1, ..., y_{n-1})$ as its share.

[Lin17]: <https://eprint.iacr.org/2017/552.pdf>
