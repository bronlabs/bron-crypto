// Package pedersen implements Pedersen's verifiable secret sharing (VSS) scheme
// generalised to arbitrary linear access structures via Karchmer-Wigderson
// monotone span programmes (MSPs).
//
// Classical Pedersen VSS is defined over Shamir's polynomial-based scheme and
// is therefore restricted to (t, n) threshold access structures. This package
// replaces Shamir with the KW MSP-based LSSS, lifting Pedersen verification to
// any monotone access structure that admits an MSP — including threshold,
// unanimity, CNF, hierarchical conjunctive, and boolean-expression structures.
//
// # Dealing
//
// The dealer samples two independent random column vectors r_g, r_h ∈ F^D
// (with r_g[0] = secret) and computes share vectors λ_g = M · r_g and
// λ_h = M · r_h, where M is the MSP matrix (n × D). Each shareholder i
// receives the entries of (λ_g, λ_h) corresponding to their MSP rows. The
// dealer publishes the verification vector V = [r_g]G + [r_h]H, a D × 1
// column of Pedersen commitments.
//
// # Verification
//
// Given V and the public MSP, any party can verify the share of shareholder i
// by computing the expected lifted share via the left module action:
//
//	M_i · V = [M_i · r_g]G + [M_i · r_h]H = Com(λ_g_i, λ_h_i)
//
// and comparing it against the manually lifted scalar share
// Com(secret_j, blinding_j) = [secret_j]G + [blinding_j]H computed from the
// share's components. This is the direct generalisation of the classical
// Pedersen check, which is itself the left module action of a Vandermonde row
// on V.
//
// # Security
//
// The verification vector V = [r_g]G + [r_h]H is perfectly hiding: V reveals
// no information about the secret, even to a computationally unbounded
// adversary. This is the key advantage over Feldman VSS, where V[0] = [secret]G
// reveals the secret in the exponent.
//
// The commitment is computationally binding under the discrete logarithm
// assumption: opening it to a different secret requires computing the
// discrete-log relation between G and H. Shares are publicly verifiable:
// any party can check a share against V using only the public MSP.
package pedersen
