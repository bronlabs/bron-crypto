
# Zero-knowledge proof that a Paillier public-key was generated correctly
As shown in [Fast Secure Two-Party ECDSA Signing][Lin17] (section 3.1) this is sufficient to require that $N$ and $\phi(N)$ are co-prime for some integer $N$ and this protocol implements $\pi_{RSA}$ from [Efficient RSA Key Generation and Threshold Paillier in the Two-Party Setting][HMRT12] (section 3.3) to zero-knowledge prove just that.

## Protocol for $\pi_{RSA}$
Input:
* $k$ - security parameter (cheating prover can succeed with probability $\le 2^{-k}$
* $pk$ - Paillier public-key (consist of $N$)

$P$ input:
* $sk$ - Paillier private-key (consist of $\lambda = \phi(N)$)

Steps:
1. $V$ picks $x = y^N \mod N^2$ and proves the knowledge of an $N$th root of $x$,
2. $P$ returns a $y'$, the $N$th root of $x$,
3. $V$ aborts if $y \ne y'$,
4. Repeat steps above $k$ times, $V$ accepts if there were no aborts in step 3.

Notably, if $\gcd(N, \phi(N)) = 1$, then $y$ is unique, hence $y = y'$ . Otherwise there are multiple candidates, and the probability that $y = y'$ is $\le \frac{1}{2}$.

[Lin17]: <https://eprint.iacr.org/2017/552.pdf>
[HMRT12]: <https://eprint.iacr.org/2011/494.pdf>
