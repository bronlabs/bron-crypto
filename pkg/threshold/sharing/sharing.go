package sharing

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
)

// Name is a human-readable identifier for a secret sharing scheme.
type Name string

// ID uniquely identifies a shareholder. IDs must be non-zero for polynomial-based schemes
// since they serve as evaluation points.
type ID uint64

// Secret is a value that can be shared among shareholders.
type Secret[W any] base.Equatable[W]

// Share represents a single shareholder's portion of a shared secret.
type Share[S any] interface {
	ID() ID
	base.Hashable[S]
}

// VerificationMaterial is public information that allows shareholders to verify
// their shares without interaction. For Feldman/Pedersen VSS, this is the
// verification vector of group element commitments.
type VerificationMaterial any

// DealerOutput contains the result of a dealing operation.
type DealerOutput[S Share[S]] interface {
	Shares() ds.Map[ID, S]
}

// VerifiableDealerOutput extends DealerOutput with verification material.
type VerifiableDealerOutput[S Share[S], V VerificationMaterial] DealerOutput[S]

// SSS (Secret Sharing Scheme) is the base interface for all secret sharing schemes.
// It provides dealing (splitting a secret into shares) and reconstruction
// (recovering the secret from authorized shares).
type SSS[S Share[S], W Secret[W], DO DealerOutput[S], AC MonotoneAccessStructure] interface {
	Name() Name
	Deal(secret W, prng io.Reader) (DO, error)
	DealRandom(prng io.Reader) (DO, W, error)
	Reconstruct(shares ...S) (secret W, err error)
	AccessStructure() AC
}

// VSSS (Verifiable Secret Sharing Scheme) extends SSS with the ability to verify
// shares against public verification material. This allows shareholders to detect
// a malicious dealer who distributes inconsistent shares.
type VSSS[S Share[S], W Secret[W], V VerificationMaterial, DO VerifiableDealerOutput[S, V], AC MonotoneAccessStructure] interface {
	SSS[S, W, DO, AC]
	Reconstruct(shares ...S) (secret W, err error)
	ReconstructAndVerify(reference V, shares ...S) (secret W, err error)
	Verify(share S, reference V) (err error)
}

// ThresholdSSS is a secret sharing scheme with a threshold access structure.
type ThresholdSSS[S Share[S], W Secret[W], DO DealerOutput[S]] SSS[S, W, DO, *ThresholdAccessStructure]

// HomomorphicShare is a share that supports the group operation, allowing shares
// to be combined homomorphically. If parties hold shares of secrets a and b,
// they can locally compute shares of a+b.
type HomomorphicShare[S interface {
	Share[S]
	algebra.HomomorphicLike[S, SV]
}, SV any, // To support CNF/DNF variants, the share value type is not constrained to a specific algebraic structure.
	AC MonotoneAccessStructure,
] interface {
	Share[S]
	algebra.HomomorphicLike[S, SV]
}

// LinearShare extends HomomorphicShare with scalar operation and conversion
// to additive shares. This enables threshold-to-additive share conversion using
// Lagrange coefficients, which is essential for many MPC protocols.
type LinearShare[S interface {
	HomomorphicShare[S, SV, AC]
	algebra.Actable[S, SC]
	ToAdditive(unanimity *UnanimityAccessStructure) (SA, error)
}, SV any,
	SA HomomorphicShare[SA, SAV, *UnanimityAccessStructure],
	SAV algebra.GroupElement[SAV],
	SC any, // To support packed variants, scalar type is not constrained.
	AC MonotoneAccessStructure,
] interface {
	HomomorphicShare[S, SV, AC]
	algebra.Actable[S, SC]
	ToAdditive(unanimity *UnanimityAccessStructure) (SA, error)
}

// LSSS (Linear Secret Sharing Scheme) is a scheme where shares form a vector space.
// It supports revealing the dealer function (polynomial) for protocols that need it.
type LSSS[
	S LinearShare[S, SV, SA, SAV, SC, AC], SV any,
	SA HomomorphicShare[SA, SAV, *UnanimityAccessStructure], SAV algebra.GroupElement[SAV],
	W interface {
		Secret[W]
		base.Transparent[WV]
	}, WV algebra.GroupElement[WV], DO DealerOutput[S], SC any, AC MonotoneAccessStructure, DF any,
] interface {
	SSS[S, W, DO, AC]
	DealAndRevealDealerFunc(secret W, prng io.Reader) (DO, DF, error)
	DealRandomAndRevealDealerFunc(prng io.Reader) (DO, W, DF, error)
}

// PolynomialLSSS is an LSSS based on polynomial evaluation, such as Shamir's scheme.
// The dealer function is a polynomial f(x) where f(0) is the secret and f(i) is
// shareholder i's share.
type PolynomialLSSS[
	S LinearShare[S, SV, SA, SAV, SC, AC], SV algebra.PrimeFieldElement[SV], SA HomomorphicShare[SA, SAV, *UnanimityAccessStructure], SAV algebra.GroupElement[SAV],
	W interface {
		Secret[W]
		base.Transparent[WV]
	}, WV algebra.PrimeFieldElement[WV], DO DealerOutput[S], SC any, AC MonotoneAccessStructure,
] LSSS[S, SV, SA, SAV, W, WV, DO, SC, AC, *polynomials.Polynomial[SV]]
