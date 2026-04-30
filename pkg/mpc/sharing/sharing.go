package sharing

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/internal"
)

// Name is a human-readable identifier for a secret sharing scheme.
type Name string

// Secret is a value that can be shared among shareholders.
type Secret[W any] base.Equatable[W]

// ID uniquely identifies a shareholder. IDs must be non-zero for polynomial-based schemes
// since they serve as evaluation points.
type ID = internal.ID

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
type SSS[S Share[S], W Secret[W], DO DealerOutput[S]] interface {
	Name() Name
	Deal(secret W, prng io.Reader) (DO, error)
	DealRandom(prng io.Reader) (DO, W, error)
	Reconstruct(shares ...S) (secret W, err error)
	CanReconstruct(ids ...ID) bool
	Shareholders() ds.Set[ID]
}

// VSSS (Verifiable Secret Sharing Scheme) extends SSS with the ability to verify
// shares against public verification material. This allows shareholders to detect
// a malicious dealer who distributes inconsistent shares.
type VSSS[S Share[S], W Secret[W], V VerificationMaterial, DO VerifiableDealerOutput[S, V]] interface {
	SSS[S, W, DO]
	Reconstruct(shares ...S) (secret W, err error)
	ReconstructAndVerify(reference V, shares ...S) (secret W, err error)
	Verify(share S, reference V) (err error)
}

// LinearShare extends HomomorphicShare with scalar operation and conversion
// to additive shares. This enables threshold-to-additive share conversion using
// Lagrange coefficients, which is essential for many MPC protocols.
type LinearShare[S interface {
	Share[S]
	algebra.HomomorphicLike[S, SV]
}, SV any,
] interface {
	Share[S]
	algebra.HomomorphicLike[S, SV]
	algebra.Actable[S, algebra.UnsignedNumeric]
}

// LSSS (Linear Secret Sharing Scheme) is a scheme where shares form a vector space.
// It supports revealing the dealer function (polynomial) for protocols that need it.
type LSSS[
	S LinearShare[S, SV], SV any,
	W interface {
		Secret[W]
		base.Transparent[WV]
	}, WV algebra.GroupElement[WV], DO DealerOutput[S], DF any,
] interface {
	SSS[S, W, DO]
	DealAndRevealDealerFunc(secret W, prng io.Reader) (DO, DF, error)
	DealRandomAndRevealDealerFunc(prng io.Reader) (DO, W, DF, error)
	ConvertShareToAdditive(S, *unanimity.Unanimity) (*internal.AdditiveShare[WV], error)
}
