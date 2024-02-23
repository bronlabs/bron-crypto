# Threshold BLS Signing

This package implements threshold BLS using [Boldyreva03](https://www.iacr.org/archive/pkc2003/25670031/25670031.pdf). The output signature is verifiable with [official spec](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html).


The threshold implementation supports both variants of the BLS signatures:

- **Short public keys, long signatures**: Signatures are longer and slower to create, verify, and aggregate but public keys are small and fast to aggregate. Used when signing and verification operations not computed as often or for minimizing storage or bandwidth for public keys.
- **Short signatures, long public keys**: Signatures are short and fast to create, verify, and aggregate but public keys are bigger and slower to aggregate. Used when signing and verification operations are computed often or for minimizing storage or bandwidth for signatures.

User will have to specify G1 as the key/signature subgroup for the public key/signature to be short.

This protocol is quite natural: It's essentially just the regular BLS signature aggregation, except the aggregator converts the shamir shares to additive ones in the exponent.

### Non-interactivity

Unlike threshold ECDSA or Schnorr which can be made noninteractive by preprocessing n-1 rounds in batches (= presignatures), threshold BLS is fully non-interactive. Effectively, The first round of signing is what leads to creation of the partial signature which then can be aggregated by a signature aggregator. Note that in BLS terminology, this role is commonly denoted as "combiner", but for consistency we'll use signature aggregator, knowing that "aggregation" term here is overloaded.

## Configuration

**Players**:
- `n` players where at least `t` of them are present during the signing session.
- At least one signature aggregator, who may or may not be a player.

**Parameters**:
- Choice of curve is hardcoded to BLS 123-81.

**Functionalities**:
- `HashG1(x)` hashes a scalar to a point on G1. Similarly `HashG2(x)` for G2.
- `Send(x)` Send message x to party P.
- `ProvePOP(sk)` outputs proof of possession of sk.
- `VerifyPOP(pk, pop)` validates POP given a public key.
- `Verify(pk, sigma, m)` verifies BLS signature from pk given message m.

**Input**:
- UniqueSessionId
- Message $m$ (given before the start of the 1st round)
- Signature variant: Short keys or short signatures.

**Output**:
- Partial Signature (end of round 1)
- Signature (end of signature aggregation - which may happen immediately after round 1)

## Protocol

This protocol is symmetric: In every round, all parties do the same thing. Wlog we'll write the protocol down for short public keys.

0. Init.
    1. DKG

Signing and Verification process comes with different tags, depending on the rogue key prevention scheme used. The tags are: (All tag values are in [the paper](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html))
- DstSignatureBasicInG2
- DstSignatureBasicInG1
- DstSignatureAugInG2
- DstSignatureAugInG1
- DstSignaturePopInG2
- DstSignaturePopInG1
- DstPopProofInG2
- DstPopProofInG1

1. Round 1:
    1. Set $\pi_i$ = ProvePOP($x_i$) where $x_i$ is signing key share of $P_i$
    2. Depending on the rogue key prevention scheme: (This is just a regular BLS signing process, with private key being the signing key share of each party)
        1. Basic Scheme: compute partial signature $\sigma_i = x_i \cdot HashG2(M, DstSignatureBasic)$ where $M$ is the message and $x_i$ signing key share of $P_i$.
        2. MessageAugmentation scheme: compute partial signature $\sigma_i = x_i \cdot HashG2(pks || M, DstSignatureAug)$ where $M$ is the message, $x_i$ signing key share of $P_i$ and $pks$ is main public key.
        3. POP scheme: compute partial signature $\sigma_i = x_i \cdot HashG2(M,DstSignaturePop)$ and $\sigma^{POP}_i = x_i \cdot HashG2(pks, DstPopProof)$ where $x_i$ signing key share of $P_i$ and $pks$ is main public key.
    3. $Send(psig)$ to signature aggregator, where psig is the tuple of p, $\sigma_i$ and $\sigma^{POP}_i$ if using POP scheme.

2. Aggregation:
    0. Receives all psigs from all participating parties and parse it into $\sigma_i$ and $\pi_i$ (and $\sigma^{POP}_i$ if using POP scheme).
    1. For each $P_i$:
        1. **ABORT and IDENTIFY** if $VerifyPOP(pk_i, \pi_i)$ fails, where $pk_i = x_i \cdot G$.
        2. Depending on the rogue key prevention scheme:
            1. Basic scheme: **ABORT and IDENTIFY** if $Verify(pk_i, \sigma_i, m, DstSignatureBasic)$ fails, where $pk_i = x_i \cdot G$.
            2. MessageAugmentation scheme: **ABORT and IDENTIFY** if $Verify(pk_i, \sigma_i, pks || m, DstSignatureAug)$ fails, where $pk_i = x_i \cdot G$ and $pks$ is main public key.
            3. POP scheme: **ABORT and IDENTIFY** if $Verify(pk_i, \sigma_i, m, DstSignaturePop)$ or $Verify(pk_i, \sigma^{POP}_i, pks, DstPopProof)$ fails, where $pk_i = x_i \cdot G$ and $pks$ is main public key.
    2. Compute the signature $\sigma = \sum \lambda_i \cdot \sigma_i$ where $\lambda_i$ is the lagrange coefficient of $P_i$.
    3. Compute the signature $\sigma^{POP} = \sum \lambda_i \cdot \sigma^{POP}_i$ where $\lambda_i$ is the lagrange coefficient of $P_i$ if using POP scheme.
    4. If using POP scheme, calculate and return $\sigma$ and $\sigma^{POP}$, otherwise return $\sigma$. 
