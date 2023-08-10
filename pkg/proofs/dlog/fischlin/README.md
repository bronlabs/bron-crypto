# ZKPoK DLOG made non-interactive with randomized Fischlin transform

Since the regular Fiat-Shamir requires rewinding, it is not UC-Secure. To get a UC-secure dlog proof, this package implements
the randomized Fischlin transform, from Figure 9 of [KS22](https://eprint.iacr.org/2022/393.pdf).

The idea behind Fischlin, is essentially proof of work over the transcript. Essentially, we are running the same Schnorr protocol with Fiat-Shamir many times, but instead of the FS challenge, we produce a random challenge and we accept it in each iteration, if the hash of all commitments alongside the challenge is zero, for a suitably defined hash function.

## Configuration

**Players** 2 Parties, Prover and Verifier

**Parameters**:
- $\lambda$: Security parameter. In our case it's 256.
- $L$: Length of the Hash function which has to be zero.
- $R$: Total number of challenges produced.
- $T$: Length of the sampled challenge.

such that $L \times S = \lambda$ and $T=\left \lceil log(\lambda** \right \rceil \times L$.

**Input**:
- BasePoint: some generator of a curve. Maybe the standard generator.
- Hash: An agreed upon hash function whose length is $\geq L$

## Protocol

- Prover (wants to prove `x` and consequently, the statement is `X=xG`):
    1. Sample random elements $a \leftarrow \mathbb{Z}_q^{r}$
    2. Compute commitments $A = a \cdot G$
    3. For each $i \in \[ r \]$:
        1. Set $\mathcal{E}_i = \emptyset$
        2. Sample challenge $e_i \leftarrow \{0,1\}^t \backslash \mathcal{E}_i$
        3. Compute response $z_i = a_i + x \times e_i$
        4. Do work $h = Hash(A, i, e_i, z_i)[:L]$
        5. If $h \neq 0^l$ then add $e_i$ to $\mathcal{E}_i$ and repeat from 3.2, else, record $e_i$ and $z_i$.
    4. Output $\pi = (A_i, e_i, z_i)_{i \in \[r\]}$

- Verifier (verifying $\pi$ as a proof of the statement `X`):
    1. Parse $(A_i, e_i, z_i)_{i \in \[r\]} = \pi$ and set $A = (A_i)_{i \in \[r\]}$.
    2. For each $i \in \[ r \]$:
        1. **ABORT** if $Hash(A, i, e_i, z_i)[:L] \neq 0^l$.
        2. **ABORT** if $A_i \neq z_i \cdot G - e_i \cdot X$
    3. Accept the proof.

