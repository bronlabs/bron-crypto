This implements `PROTOCOL 3.1` (DKG) from [Fast Secure Two-Party ECDSA Signing][Lin17] with some changes:
* In step `1.a` $P$ chooses a random $x: \frac{q}{3} \le x < \frac{2q}{3}$. However in our use case the $x$ is given from the previous DKG so we cannot assume it is in the range (as this will serve as a backup protocol) so instead we split $x$ such that $x = 3 \cdot x' + x''$ and both $x'$ and $x''$ are in the specified range and proceed with these value as if they were $x$.
* Because of what is described above in the last step instead of storing $c_{key} = Enc_{pk}(x)$ we store $c_{key} = 3 \odot Enc_{pk}(x') \oplus Enc_{pk}(x'')$, $\odot$ being homomorphic scalar multiplication and $\oplus$ being homomorphic addition.

[Lin17]: <https://eprint.iacr.org/2017/552.pdf>
