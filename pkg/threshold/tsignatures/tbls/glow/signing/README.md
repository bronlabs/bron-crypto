# Threshold BLS Signing

This package implements threshold BLS using [GLOW20](https://eprint.iacr.org/2020/096.pdf). The output signature is verifiable with [official spec](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html).


The threshold protocol supports the following variant of the BLS signatures:

- **Short public keys, long signatures**: Signatures are longer and slower to create, verify, and aggregate but public keys are small and fast to aggregate. Used when signing and verification operations not computed as often or for minimizing storage or bandwidth for public keys.

Specifically, public keys live in G1. This requirement is necessary because because the protocol avoid verifications of POP and instead verifies dleq proofs which is comparably cheaper to do.

If you need the other variant, or more flexibility, use the standard Boldyreva02 protocol.


**Remark**: Regular BLS, or Boldyreva02, do not need a prng. Here, due to dleq being made noninteractive via Fischlin, we need a prng.


### Non-interactivity

Unlike threshold ECDSA or Schnorr which can be made noninteractive by preprocessing n-1 rounds in batches (= presignatures), threshold BLS is fully non-interactive. Effectively, The first round of signing is what leads to creation of the partial signature which then can be aggregated by a signature aggregator. Note that in BLS terminology, this role is commonly denoted as "combiner", but for consistency we'll use signature aggregator, knowing that "aggregation" term here is overloaded.

## Configuration

**Players**:
- `n` players where at least `t` of them are present during the signing session.
- At least one signature aggregator, who may or may not be in the cohort.

**Parameters**:
- Choice of curve is hardcoded to BLS 123-81.
- Choice of hash function used in message expansion of hash to curve is hardcoded to Sha256.

**Functionalities**:
-  `HashG1(x)` hashes a scalar to a point on G1. Similarly `HashG2(x)` for G2.
- `Send(x)` Send message x to party P.
- `ProveDLEQ(sk)` outputs equality of discrete log of publicKeyShare and partialSignature
- `VerifyDLEQ(pk, proof)` validates dleq proof
- `Verify(pk, sigma, m)` verifies BLS signature from pk given message m.

**Input**:
- UniqueSessionId
- Message $m$ (given before the start of the 1st round)

**Output**:
- Partial Signature (end of round 1)
- Signature (end of signature aggregation - which may happen immediately after round 1)

## Protocol

This protocol is symmetric: In every round, all parties do the same thing. Wlog we'll write the protocol down for short public keys.

0. Init.
   1. DKG

1. Round 1:
   1. compute $\sigma_i = x_i \cdot HashG2(M)$ where $M$ is the message and $x_i$ signing key share of $P_i$. This is just a regular BLS signing process, with private key being the signing key share of each party.
   2. compute dleq proof $\pi = ProveDLEQ(x_i)$ with respect to bases $G_1$ and $HashG2(m)$
   3. $Send(\sigma_i , \pi)$ to signature aggregator, where psig is the tuple of p and $\sigma_i$.
   4. That's it.

2. Aggregation:
   0. Receives all psigs from all participating parties and parse it into $\sigma_i$ and $\pi_i$.
   1. For each $P_i$: **ABORT and IDENTIFY** if $VerifyDLEQ(pk_i, \pi_i)$ fails, where $pk_i = x_i \cdot G$.
   2. Compute the signature $\sigma = \sum \lambda_i \cdot \sigma_i$ where $\lambda_i$ is the lagrange coefficient of $P_i$.
   3. Output $\sigma$.
