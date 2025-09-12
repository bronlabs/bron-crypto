package gennaro

import (
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	pedersenVSS "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/pedersen"
)

type Round1Broadcast[E GroupElement[E, S], S Scalar[S]] struct {
	PedersenVerificationVector pedersenVSS.VerificationVector[E, S] `cbor:"1"`
}

func (r *Round1Broadcast[E, S]) Bytes() []byte {
	return r.PedersenVerificationVector.Bytes()
}

type Round2Unicast[E GroupElement[E, S], S Scalar[S]] struct {
	Share *pedersenVSS.Share[S] `cbor:"1"`
}

func (r *Round2Unicast[E, S]) Bytes() []byte {
	return r.Share.Bytes()
}

type Round2Broadcast[E GroupElement[E, S], S Scalar[S]] struct {
	FeldmanVerificationVector feldman.VerificationVector[E, S]
}

func (r *Round2Broadcast[E, S]) Bytes() []byte {
	return r.FeldmanVerificationVector.Bytes()
}
