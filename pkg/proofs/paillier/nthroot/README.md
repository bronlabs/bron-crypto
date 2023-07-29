# Zero-Knowledge proof of knowledge of $N$'th root $\mod N^2$
Prover proves the knowledge of $y$ where $x=y^N \mod N^2$. This implements protocol for $n^s$'th powers of [A generalisation, a simplification and some applications of paillier’s probabilistic public-key system][DJ01] for $s=1$ (section 4.2).

## Protocol for $N$'th powers
Input:
* $N$
* $x$

$P$ input:
* $y$, such that $x=y^N \mod N^2$

Steps:
1. $P$ chooses $r$ at random $\mod N^2$ and sends $a = r^N \mod N^2$ to $V$
2. $V$ chooses $e$, a random $k$ bit number (where $k$ is bit length of $N$), and sends $e$ to the $P$.
3. $P$ sends $z = rv^e \mod N^2$ to $V$
4. $V$ checks that $z^N = au^e \mod N^2$, and accepts if and only if this is the case.

[DJ01]: <https://www.brics.dk/RS/00/45/BRICS-RS-00-45.pdf>
