package dkg

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro"
	przsSetup "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs/setup"
)

type Round1Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	GennaroR1 *gennaro.Round1Broadcast[P, S] `cbor:"1"`
	ZeroR1    *przsSetup.Round1Broadcast     `cbor:"2"`
}

type Round1P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	OtR1 *vsot.Round1P2P[P, B, S] `cbor:"1"`
}

type Round2Broadcast[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	GennaroR2 *gennaro.Round2Broadcast[P, S] `cbor:"1"`
}

type Round2P2P[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	GennaroR2 *gennaro.Round2Unicast[P, S] `cbor:"1"`
	ZeroR2    *przsSetup.Round2P2P         `cbor:"2"`
	OtR2      *vsot.Round2P2P[P, B, S]     `cbor:"3"`
}

type Round3P2P struct {
	OtR3 *vsot.Round3P2P `cbor:"1"`
}

type Round4P2P struct {
	OtR4 *vsot.Round4P2P `cbor:"1"`
}

type Round5P2P struct {
	OtR5 *vsot.Round5P2P `cbor:"1"`
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
