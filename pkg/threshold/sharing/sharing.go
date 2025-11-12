package sharing

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
)

type Name string
type ID uint64
type Secret[W any] base.Equatable[W]
type Share[S any] interface {
	ID() ID
	base.Hashable[S]
}

type VerificationMaterial any

type DealerOutput[S Share[S]] interface {
	Shares() ds.Map[ID, S]
}

type VerifiableDealerOutput[S Share[S], V VerificationMaterial] DealerOutput[S]

type AccessStructure interface {
	IsAuthorized(...ID) bool
	Shareholders() ds.Set[ID]
}

type ThresholdAccessStructure interface {
	AccessStructure
	Threshold() uint
}

// TODO: remove parametrization of access structure
type SSS[S Share[S], W Secret[W], DO DealerOutput[S], AC AccessStructure] interface {
	Name() Name
	Deal(secret W, prng io.Reader) (DO, error)
	DealRandom(prng io.Reader) (DO, W, error)
	Reconstruct(shares ...S) (secret W, err error)
	AccessStructure() AC
}

type VSSS[S Share[S], W Secret[W], V VerificationMaterial, DO VerifiableDealerOutput[S, V], AC AccessStructure] interface {
	SSS[S, W, DO, AC]
	Reconstruct(shares ...S) (secret W, err error)
	ReconstructAndVerify(reference V, shares ...S) (secret W, err error)
	Verify(share S, reference V) (err error)
}

type ThresholdSSS[S Share[S], W Secret[W], DO DealerOutput[S], AC ThresholdAccessStructure] SSS[S, W, DO, AC]

// =========
type AdditiveShare[S interface {
	Share[S]
	algebra.HomomorphicLike[S, SV]
}, SV algebra.GroupElement[SV], AC AccessStructure,
] interface {
	Share[S]
	algebra.HomomorphicLike[S, SV]
}

type AdditivelyShareableSecret[W Secret[W], WV algebra.GroupElement[WV]] interface {
	Secret[W]
	base.Transparent[WV]
}

type AdditiveSSS[
	S AdditiveShare[S, SV, AC], SV algebra.GroupElement[SV],
	W AdditivelyShareableSecret[W, WV], WV algebra.GroupElement[WV],
	DO DealerOutput[S], AC AccessStructure,
] SSS[S, W, DO, AC]

// =========

type LinearShare[S interface {
	AdditiveShare[S, SV, AC]
	algebra.AdditivelyHomomorphicLike[S, SV]
	algebra.AdditivelyActable[S, SV]
	ToAdditive(*MinimalQualifiedAccessStructure) (SA, error)
}, SV algebra.AdditiveGroupElement[SV], SA AdditiveShare[SA, SV, *MinimalQualifiedAccessStructure], SC algebra.PrimeFieldElement[SC],
	AC AccessStructure,
] interface {
	AdditiveShare[S, SV, AC]
	algebra.AdditivelyHomomorphicLike[S, SV]
	algebra.AdditivelyActable[S, SV]
	ToAdditive(*MinimalQualifiedAccessStructure) (SA, error)
}

type LinearlyShareableSecret[W Secret[W], WV algebra.PrimeFieldElement[WV]] AdditivelyShareableSecret[W, WV]

type LSSS[
	S LinearShare[S, SV, SA, WV, AC], SV algebra.AdditiveGroupElement[SV], SA AdditiveShare[SA, SV, *MinimalQualifiedAccessStructure],
	W LinearlyShareableSecret[W, WV], WV algebra.PrimeFieldElement[WV], DO DealerOutput[S], AC AccessStructure, DF any,
] interface {
	AdditiveSSS[S, SV, W, WV, DO, AC]
	DealAndRevealDealerFunc(secret W, prng io.Reader) (DO, DF, error)
	DealRandomAndRevealDealerFunc(prng io.Reader) (DO, W, DF, error)
}

type PolynomialLSSS[
	S LinearShare[S, SV, SA, WV, AC], SV algebra.PrimeFieldElement[SV], SA AdditiveShare[SA, SV, *MinimalQualifiedAccessStructure],
	W LinearlyShareableSecret[W, WV], WV algebra.PrimeFieldElement[WV], DO DealerOutput[S], AC AccessStructure,
] LSSS[S, SV, SA, W, WV, DO, AC, *polynomials.Polynomial[SV]]
