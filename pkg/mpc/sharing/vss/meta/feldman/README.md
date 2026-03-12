# Meta Feldman Verifiable Secret Sharing

Generalised Feldman VSS over a Karchmer-Wigderson MSP-based LSSS.

Classical Feldman VSS (`vss/feldman`) is built over Shamir's polynomial secret sharing and is therefore limited to (t, n) threshold access structures. This package replaces Shamir with the KW MSP-based scheme (`scheme/kw`), lifting Feldman verification to any monotone access structure that admits a monotone span programme — including threshold, unanimity, CNF, hierarchical conjunctive, and boolean-expression structures.

## How it works

| | Classical Feldman (over Shamir) | Meta Feldman (over KW) |
|---|---|---|
| **Dealer randomness** | polynomial coefficients (a₀, …, a_{t−1}) | random column vector r ∈ F^D |
| **Shares** | f(xᵢ) — single scalar per shareholder | λᵢ = Mᵢ · r — vector of scalars (one per MSP row) |
| **Verification vector** | Vⱼ = [aⱼ]G (lifted polynomial) | V = [r]G (lifted column) |
| **Verification equation** | ∏ Vⱼ^{xᵢ^j} = [f(xᵢ)]G | Mᵢ · V = [Mᵢ · r]G = [λᵢ]G |
| **Degree/dimension check** | deg(V) + 1 = t | dim(V) = D = cols(M) |
| **Access structures** | threshold only | any linear access structure |

The two are algebraically equivalent for threshold access structures: the Vandermonde MSP matrix turns the left module action Mᵢ · V into a polynomial evaluation in the exponent.

## Security

- **Not hiding**: V[0] = [secret]G directly reveals the secret in the exponent.
- **Computationally binding**: opening the commitment to a different secret requires breaking DLog.
- **Not equivocable**: a simulator cannot produce V and later choose which secret to open it to. For a hiding, equivocable scheme, see Pedersen VSS.
- **Public verifiability**: any party can verify shares given the verification vector.
- **Dahlgren attack prevention**: the left module action enforces dim(V) = D, rejecting extended verification vectors. This is the generalisation of the polynomial degree check.

## Usage

```go
// Any linear access structure works.
ac, _ := boolexpr.NewThresholdGateAccessStructure(
    boolexpr.Threshold(2,
        boolexpr.And(boolexpr.ID(1), boolexpr.ID(2)),
        boolexpr.Or(boolexpr.ID(3), boolexpr.ID(4)),
    ),
)
scheme, _ := feldman.NewScheme(curve, ac)

// Deal shares with verification vector.
output, _ := scheme.Deal(secret, prng)
shares := output.Shares()
V := output.VerificationMaterial()

// Verify a share.
err := scheme.Verify(share, V)

// Reconstruct from a qualified set.
recovered, _ := scheme.ReconstructAndVerify(V, share1, share2, ...)
```

## Reference

- Feldman, P. "A Practical Scheme for Non-interactive Verifiable Secret Sharing." FOCS, 1987.
- Karchmer, M. and Wigderson, A. "On Span Programs." Structure in Complexity Theory Conference, 1993.
