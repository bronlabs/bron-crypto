package dkg

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro"
	przsSetup "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs/setup"
)

type Round1Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	gennaroR1 *gennaro.Round1Broadcast[P, S]
	zeroR1    *przsSetup.Round1Broadcast
}

type Round1P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	otR1 *vsot.Round1P2P[P, B, S]
}

type Round2Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	gennaroR2 *gennaro.Round2Broadcast[P, S]
}

type Round2P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	gennaroR2 *gennaro.Round2Unicast[P, S]
	zeroR2    *przsSetup.Round2P2P
	otR2      *vsot.Round2P2P[P, B, S]
}

type Round3P2P struct {
	otR3 *vsot.Round3P2P
}

type Round4P2P struct {
	otR4 *vsot.Round4P2P
}

type Round5P2P struct {
	otR5 *vsot.Round5P2P
}

func (r1b *Round1Broadcast[P, B, S]) Bytes() []byte {
	// TODO
	panic("not implemented")
}

func (r1u *Round1P2P[P, B, S]) Bytes() []byte {
	// TODO
	panic("not implemented")
}

func (r2b *Round2Broadcast[P, B, S]) Bytes() []byte {
	// TODO
	panic("not implemented")
}

func (r2u *Round2P2P[P, B, S]) Bytes() []byte {
	// TODO
	panic("not implemented")
}

func (r3u *Round3P2P) Bytes() []byte {
	// TODO
	panic("not implemented")
}

func (r4u *Round4P2P) Bytes() []byte {
	// TODO
	panic("not implemented")
}

func (r5u *Round5P2P) Bytes() []byte {
	// TODO
	panic("not implemented")
}
