# Pedersen Parameters Proof

Sigma protocol for proving that public ring-Pedersen parameters $(\hat N, s, t)$ satisfy
$s \in \langle t \rangle \subseteq \mathbb{Z}_{\hat N}^*$. The prover owns a trapdoor $\lambda$ such that
$s = t^\lambda \pmod{\hat N}$.

## Input

The common input is the Pedersen commitment key $(\hat N, s, t)$. In code this is
carried by `Statement` as an `*intcom.CommitmentKey`:

* provers and verifiers instantiate the protocol with fixed amplification parameter $m = 128$,
* provers and verifiers pass the Pedersen commitment key in `Statement`,
* provers pass `*intcom.TrapdoorKey` in the witness.

The prover validates that the witness trapdoor key has the same public parameters as the statement key.
$\hat N$, $s$, and $t$ are bound through `Statement.Bytes()` and therefore through the Fiat-Shamir transcript.

## Protocol

This implements CGGMP21 Figure 13 with $m = 128$. The verifier challenge is represented as 16 bytes and
interpreted as 128 challenge bits $e_i \in \{0,1\}$.

For each challenge bit, the prover samples $a_i \in \mathbb{Z}_{\varphi(\hat N)}$,
sends $A_i = t^{a_i} \pmod{\hat N}$, and responds with:

$$
z_i = a_i + e_i \lambda \pmod{\varphi(\hat N)}.
$$

The verifier checks:

$$
t^{z_i} \equiv A_i s^{e_i} \pmod{\hat N}
$$

for every $i \in [m]$.

## Security

For an invalid statement, CGGMP21 bounds the accepting probability by $2^{-m}$. This implementation fixes $m = 128$,
matching the repository's computational soundness requirement for Fiat-Shamir proofs.

The repository's `intcom.TrapdoorKey` stores $\lambda$ modulo $|\mathrm{QR}_{\hat N}| = \varphi(\hat N)/4$
because `intcom` samples $s$ and $t$ inside the quadratic-residue subgroup. The proof response is still computed
modulo $\varphi(\hat N)$, as in Figure 13; the QR trapdoor representative is lifted into $\mathbb{Z}_{\varphi(\hat N)}$.

`RunSimulator` implements the honest-verifier simulator from Figure 13 by sampling $z_i \leftarrow \pm \hat N$
and setting $A_i = t^{z_i}s^{-e_i}$.

## Reference

* [CGGMP21, Section 5.3 and Figure 13](https://eprint.iacr.org/2021/060.pdf)
