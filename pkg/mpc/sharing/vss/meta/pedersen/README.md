# Pedersen Verifiable Secret Sharing

Generalised Pedersen VSS over a Karchmer-Wigderson MSP-based LSSS.

Classical Pedersen VSS (`vss/pedersen`) is built over Shamir's polynomial secret sharing and is therefore limited to (t, n) threshold access structures. This package replaces Shamir with the KW MSP-based scheme (`scheme/kw`), lifting Pedersen verification to any monotone access structure that admits a monotone span programme — including threshold, unanimity, CNF, hierarchical conjunctive, and boolean-expression structures.

## How it works

| | Classical Pedersen (over Shamir) | Meta Pedersen (over KW) |
|---|---|---|
| **Dealer randomness** | polynomials f(x), r(x) of degree t−1 | random columns r_g, r_h ∈ F^D |
| **Shares** | (f(xᵢ), r(xᵢ)) — scalar pair per shareholder | (M_i · r_g, M_i · r_h) — vector pair (one per MSP row) |
| **Verification vector** | Vⱼ = [aⱼ]G + [bⱼ]H (lifted polynomial coefficients) | V = [r_g]G + [r_h]H (lifted columns) |
| **Verification equation** | ∏ Vⱼ^{xᵢ^j} = Com(f(xᵢ), r(xᵢ)) | M_i · V = Com(λ_g_i, λ_h_i) |
| **Degree/dimension check** | deg(V) + 1 = t | dim(V) = D = cols(M) |
| **Access structures** | threshold only | any linear access structure |

The two are algebraically equivalent for threshold access structures: the Vandermonde MSP matrix turns the left module action M_i · V into a polynomial evaluation in the exponent.

## Security

- **Perfectly hiding**: V = [r_g]G + [r_h]H reveals no information about the secret, even to a computationally unbounded adversary. This is the key advantage over Feldman VSS, where V[0] = [secret]G leaks the secret in the exponent.
- **Computationally binding**: opening the commitment to a different secret requires computing the discrete-log relation between G and H.
- **Public verifiability**: any party can verify shares given the verification vector and the public MSP.

## Usage

```go
// Create a Pedersen commitment key (G, H must be independent generators).
key, _ := pedcom.NewCommitmentKey(g, h)

// Any linear access structure works.
ac, _ := boolexpr.NewThresholdGateAccessStructure(
    boolexpr.Threshold(2,
        boolexpr.And(boolexpr.ID(1), boolexpr.ID(2)),
        boolexpr.Or(boolexpr.ID(3), boolexpr.ID(4)),
    ),
)
scheme, _ := pedersen.NewScheme(key, ac)

// Deal shares with verification vector.
output, _ := scheme.Deal(secret, prng)
shares := output.Shares()
V := output.VerificationMaterial()

// Verify a share (checks Com(λ_i) == M_i · V).
err := scheme.Verify(share, V)

// Reconstruct from a qualified set.
recovered, _ := scheme.ReconstructAndVerify(V, share1, share2, ...)
```

## Reference

- Pedersen, T. P. "Non-interactive and Information-Theoretic Secure Verifiable Secret Sharing." CRYPTO, 1991.
- Karchmer, M. and Wigderson, A. "On Span Programs." Structure in Complexity Theory Conference, 1993.
