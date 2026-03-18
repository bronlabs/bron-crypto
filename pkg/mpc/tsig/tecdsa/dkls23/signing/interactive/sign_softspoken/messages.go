package sign_softspoken

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	rvole_softspoken "github.com/bronlabs/bron-crypto/pkg/mpc/rvole/softspoken"
)

// Round1Broadcast carries round 1 broadcast messages.
type Round1Broadcast struct {
	BigRCommitment hash_comm.Commitment `cbor:"bigRCommitment"`
}

func (*Round1Broadcast) Validate(any) error { return nil }

// Round1P2P carries round 1 peer-to-peer messages.
type Round1P2P struct {
	MulR1 *rvole_softspoken.Round1P2P `cbor:"mulR1"`
}

func (*Round1P2P) Validate(any) error { return nil }

// Round2Broadcast carries round 2 broadcast messages.
type Round2Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigR        P                 `cbor:"bigR"`
	BigRWitness hash_comm.Witness `cbor:"bigRWitness"`
	Pk          P                 `cbor:"pk"`
}

func (*Round2Broadcast[P, B, S]) Validate(*Cosigner[P, B, S]) error { return nil }

// Round2P2P carries round 2 peer-to-peer messages.
type Round2P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	MulR2  *rvole_softspoken.Round2P2P[S] `cbor:"mulR2"`
	GammaU P                              `cbor:"gammaU"`
	GammaV P                              `cbor:"gammaV"`
	Psi    S                              `cbor:"psi"`
}

func (*Round2P2P[P, B, S]) Validate(*Cosigner[P, B, S]) error { return nil }
