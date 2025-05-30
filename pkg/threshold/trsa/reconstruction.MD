# RSA Private key reconstruction
In the threshold setting the effective private key consists of two RSA keys $(N_1, e, d_1)$ and $(N_2, e, d_2)$.
The decryption exponents $d_1$ and $d_2$ are secretly shared between the parties.
The procedure to reconstruct a valid private RSA key is as follows:
* reconstruct $d_1$ and $d_2$ from respective shares,
* compute $p_1$, $q_1$, $p_2$, $q_2$ s.t. $N_1=p_1 \times q_1$, $N_2=p_2 \times q_2$ (the procedure how to
  factorize $N_i$ knowing $d_i$ and $e$ is below),
* compute $\phi(N) = (p_1 - 1) \times (q_1 - 1) \times (p_2 - 1) \times (q_2 - 1)$
  (this assumes all four primes are different),
* compute $d = e^{-1} \mod \phi(N)$,
* return $k = (N, e, d)$ - this is effectively the valid multi-prime RSA private key.

## N factorization
Input: $(N, e, d)$ s.t. $d = e^{-1} \mod \phi(N)$, Output: $p$, $q$ s.t. $N = p \times q$.
* Compute $f = ed-1$. What's interesting about $f$ is that $x^f = 1 \mod N$ for (almost) any $x$.
* Write $f$ as $2^{s}g$ for an odd value $g$.
* Select a random value $a$, and compute $b=a^g \mod N$.
* If $b=1$ or $-1$, then go back and select another random value $a$.
* Repeatedly (in practice up to $s$ times):
  * Compute $c=b^2 \mod N$.
  * If $c=1$ then the factors for $N$ are $gcd(n, b-1)$ and $gcd(n, b+1)$.
  * If $c=-1$ then go back and select another random value of $a$.
  * Otherwise, set $b=c$, and go through another iteration of the loop.
