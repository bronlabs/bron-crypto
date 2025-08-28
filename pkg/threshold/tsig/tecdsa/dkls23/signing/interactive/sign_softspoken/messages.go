package sign_softspoken

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/threshold/mul_softspoken"
)

type Round1Broadcast struct {
	bigRCommitment hash_comm.Commitment
}

func (r1b *Round1Broadcast) Bytes() []byte {
	// TODO
	panic("not implemented")
}

type Round1P2P struct {
	mulR1 *mul_softspoken.Round1P2P
}

func (r1u *Round1P2P) Bytes() []byte {
	// TODO
	panic("not implemented")
}

type Round2Broadcast[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	bigR        P
	bigRWitness hash_comm.Witness
	pk          P
}

func (r2b *Round2Broadcast[P, B, S]) Bytes() []byte {
	// TODO
	panic("not implemented")
}

type Round2P2P[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	mulR2  *mul_softspoken.Round2P2P[S]
	gammaU P
	gammaV P
	psi    S
}

func (r2u *Round2P2P[P, B, S]) Bytes() []byte {
	// TODO
	panic("not implemented")
}
