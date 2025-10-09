package sign_softspoken

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	rvole_softspoken "github.com/bronlabs/bron-crypto/pkg/threshold/rvole/softspoken"
)

type Round1Broadcast struct {
	BigRCommitment hash_comm.Commitment `cbor:"bigRCommitment"`
}

func (r1b *Round1Broadcast) Bytes() []byte {
	// TODO
	panic("not implemented")
}

type Round1P2P struct {
	MulR1 *rvole_softspoken.Round1P2P `cbor:"mulR1"`
}

func (r1u *Round1P2P) Bytes() []byte {
	// TODO
	panic("not implemented")
}

type Round2Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigR        P                 `cbor:"bigR"`
	BigRWitness hash_comm.Witness `cbor:"bigRWitness"`
	Pk          P                 `cbor:"pk"`
}

func (r2b *Round2Broadcast[P, B, S]) Bytes() []byte {
	// TODO
	panic("not implemented")
}

type Round2P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	MulR2  *rvole_softspoken.Round2P2P[S] `cbor:"mulR2"`
	GammaU P                              `cbor:"gammaU"`
	GammaV P                              `cbor:"gammaV"`
	Psi    S                              `cbor:"psi"`
}

func (r2u *Round2P2P[P, B, S]) Bytes() []byte {
	// TODO
	panic("not implemented")
}
