# Zero-knowledge proof that a Paillier public-key was generated correctly
As shown in [Fast Secure Two-Party ECDSA Signing][Lin17] (section 3.1) this is sufficient to require that $N$ and $\phi(N)$ are co-prime for some integer $N$.
This protocol is based on the NIZK protocol in [Efficient Noninteractive Certification of RSA Moduli and Beyond][GRS+19] (chapter 3.2)
for parameters $\alpha=6370$, $m=11$.

## Protocol $L_{paillier-N}$ (interactive):
Common Input:
* $pk$ - Paillier public-key (consist of $N$) - statement

Prover input:
* $sk$ - Paillier private-key (consist of $\phi \left( N \right) $) - witness

Steps:
1. The verifier chooses $m$ random values $\rho_i \in \mathbb{Z}_N^{*}$ and sends them to prover.
2. The prover sends back $N$-th roots of $\rho_i$ modulo $N$: ($\sigma_i = \rho_i^{N^{-1} \mod \phi(N)} \mod N$)
3. The verifier accepts that $N \in L_{paillier-N}$ iff all the following checks pass:
    * $N$ is not divisible by all the primes less than $\alpha$.
    * $\rho_i = (\sigma_i)^N \mod N$

Transformation of this 2-message public-coin HVZK interactive protocol presented above into a non-interactive zero-knowledge (NIZK) protocol
is very simple, because the first message in the protocol consists of the verifier sending some challenges to the prover.
The challenges are uniformly distributed in some space with easy membership testing ($Z_N^{*}$ in this case).
Thus, to make this noninteractive, Prover samples $\rho_i$ by herself using the random oracle.
To make sure values $\rho_i$ are in the correct space, the prover performs rejection sampling for each $\rho_i$,
trying multiple random-oracle outputs until obtaining the first one that lands in the desired space.

[Lin17]: <https://eprint.iacr.org/2017/552.pdf>
[GRS+19]: <https://eprint.iacr.org/2018/057.pdf>
