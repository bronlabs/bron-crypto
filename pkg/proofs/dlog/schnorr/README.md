# Schnorr Proof of Knowledge of a Discrete Logarithm

Sigma protocol for the relation

$$
R = \{\, (x, w) : x = g^w \,\}
$$

in a group $\mathbb{G}$ of prime order $q$, where the base $g \in \mathbb{G}$ is fixed at construction time (it need not be the group's designated generator). The protocol is Schnorr's identification scheme [Sch91] instantiated through Maurer's framework [Mau09] with the homomorphism $\varphi : \mathbb{Z}_q \to \mathbb{G}$, $\varphi(w) = g^w$. Notation is multiplicative; for elliptic curves read $g^w$ as $w \cdot G$.

## Protocol

1. **Commitment.** The prover samples $s \leftarrow \mathbb{Z}_q$ and sends $a = g^s$.
2. **Challenge.** The verifier sends $e \leftarrow \{0,1\}^{128}$.
3. **Response.** The prover sends $z = s + e \cdot w \bmod q$.
4. **Verification.** Accept iff $g^z = a \cdot x^e$.

The simulator samples $z \leftarrow \mathbb{Z}_q$ and sets $a = g^z \cdot x^{-e}$.

## Properties

- **Special soundness.** Two accepting transcripts $(a, e_1, z_1)$, $(a, e_2, z_2)$ with $e_1 \ne e_2$ give $w = (z_1 - z_2) / (e_1 - e_2)$. `Extract` computes this through the generic Maurer extractor with anchor $L = q$ and $\varphi^{-1}(x^q) = 0$, i.e. $w = \beta (z_1 - z_2)$ where $\beta$ comes from the extended GCD of $q$ and $e_1 - e_2$.
- **Strong special soundness and unique responses.** For fixed $(a, e)$ exactly one $z$ verifies, so the protocol satisfies the strong 2-special soundness required by `randfischlin` and the quasi-unique responses required by `fischlin`.
- **Soundness error.** The challenge space has $2^{128}$ elements, so `SoundnessError()` is 128 bits and the protocol may be compiled to a non-interactive proof.
- **Honest-verifier zero knowledge.** Perfect, via the simulator above.

## Challenge encoding

A challenge is exactly 16 bytes, read as a big-endian integer $e < 2^{128} < q$. `ComputeProverResponse` and `Verify` reject any other length. The bytes are parsed as an unbounded natural number, so a longer string with leading zero bytes would denote the same $e$; a non-injective encoding would let a prover feed one accepting transcript to a hash-based compiler under many encodings and break its extraction argument.

## Validation

- `ValidateStatement` checks $g^w = x$.
- Statement, commitment and response deserialise through the group element and scalar types, which validate their encodings; the wrappers additionally reject nil values.

## Usage

```go
protocol, err := schnorr.NewProtocol(curve.Generator(), prng)

statement := schnorr.NewStatement(x) // x = g^w
witness := schnorr.NewWitness(w)

// interactive: sigma.NewProver / sigma.NewVerifier
// non-interactive: compiler.Compile(fischlin.Name, protocol, prng)
```

The protocol name is `SCHNORR-dlog_pok-`; `dlog.IsProvingKnowledgeOfDiscreteLog` recognises it. It is used by the Lindell17 and Lindell22 signing protocols and, with base $h$, inside `elgamal/elog`.

## References

<!-- paper: docs/papers/schnorr91.pdf -->
- [Sch91] Schnorr, C.P. [Efficient Signature Generation by Smart Cards](https://link.springer.com/article/10.1007/BF00196725). Journal of Cryptology, 1991.
<!-- paper: docs/papers/Maurer09.pdf -->
- [Mau09] Maurer, U. [Unifying Zero-Knowledge Proofs of Knowledge](https://crypto-test.ethz.ch/publications/files/Maurer09.pdf). AFRICACRYPT 2009.
