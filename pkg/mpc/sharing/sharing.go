package sharing

import (
	"io"
	"iter"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
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
type SSS[S Share[S], W Secret[W], DO DealerOutput[S], AC accessstructures.Monotone] interface {
	Name() Name
	AccessStructure() AC
	Deal(secret W, prng io.Reader) (DO, error)
	DealRandom(prng io.Reader) (DO, W, error)
	Reconstruct(shares ...S) (secret W, err error)
}

// VSSS (Verifiable Secret Sharing Scheme) extends SSS with the ability to verify
// shares against public verification material. This allows shareholders to detect
// a malicious dealer who distributes inconsistent shares.
type VSSS[S Share[S], W Secret[W], V VerificationMaterial, DO VerifiableDealerOutput[S, V], AC accessstructures.Monotone] interface {
	SSS[S, W, DO, AC]
	ReconstructAndVerify(reference V, shares ...S) (secret W, err error)
	Verify(share S, reference V) (err error)
}

// ThresholdSSS is a secret sharing scheme with a threshold access structure.
type ThresholdSSS[S Share[S], W Secret[W], DO DealerOutput[S]] SSS[S, W, DO, *accessstructures.Threshold]

// LinearShare extends Share with group operation, scalar action, and a representation
// iterator. The representation allows meta-schemes to access share components generically.
type LinearShare[S interface {
	Share[S]
	algebra.Operand[S]
	algebra.Actable[S, algebra.Numeric]
	Repr() iter.Seq[SV]
}, SV algebra.GroupElement[SV],
] interface {
	Share[S]
	algebra.Operand[S]
	algebra.Actable[S, algebra.Numeric]
	Repr() iter.Seq[SV]
}

// DealerFunc represents a dealer function that maps shareholder IDs to shares
// and can verify compatibility with an access structure. Used by meta-schemes
// for verification.
type DealerFunc[S Share[S], SV algebra.GroupElement[SV], AC accessstructures.Monotone] interface {
	ShareOf(id ID) S
	Repr() iter.Seq[SV]
	Accepts(AC) bool
}

// LSSS (Linear Secret Sharing Scheme) is a scheme where shares form a vector space.
// It supports revealing the dealer function for protocols that need it.
type LSSS[
	S LinearShare[S, SV], SV algebra.GroupElement[SV],
	W interface {
		Secret[W]
		base.Transparent[WV]
	}, WV algebra.GroupElement[WV], DO DealerOutput[S], AC accessstructures.Monotone, DF DealerFunc[S, SV, AC],
] interface {
	SSS[S, W, DO, AC]
	DealAndRevealDealerFunc(secret W, prng io.Reader) (DO, DF, error)
	DealRandomAndRevealDealerFunc(prng io.Reader) (DO, W, DF, error)
	ConvertShareToAdditive(input S, unanimity *accessstructures.Unanimity) (*internal.AdditiveShare[WV], error)
}

type LiftableLSSS[
	S LinearShare[S, SV], SV algebra.RingElement[SV],
	W interface {
		Secret[W]
		base.Transparent[WV]
	}, WV algebra.GroupElement[WV], DO DealerOutput[S], AC accessstructures.Monotone, DF DealerFunc[S, SV, AC],
	LFTS LinearShare[LFTS, LFTSV], LFTSV algebra.ModuleElement[LFTSV, SV], LFTDF interface {
		algebra.Operand[LFTDF]
		DealerFunc[LFTS, LFTSV, AC]
	},
] interface {
	LSSS[S, SV, W, WV, DO, AC, DF]
	LiftDealerFunc(DF, LFTSV) (LFTDF, error)
	LiftShare(S, LFTSV) (LFTS, error)
	ConvertLiftedShareToAdditive(input LFTS, unanimity *accessstructures.Unanimity) (*internal.AdditiveShare[LFTSV], error)
}
