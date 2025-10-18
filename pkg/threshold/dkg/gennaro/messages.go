package gennaro

import (
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	pedersenVSS "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/pedersen"
)

type Round1Broadcast[E GroupElement[E, S], S Scalar[S]] struct {
	PedersenVerificationVector pedersenVSS.VerificationVector[E, S] `cbor:"verificationVector"`
}

type Round2Unicast[E GroupElement[E, S], S Scalar[S]] struct {
	Share *pedersenVSS.Share[S] `cbor:"share"`
}

type Round2Broadcast[E GroupElement[E, S], S Scalar[S]] struct {
	FeldmanVerificationVector feldman.VerificationVector[E, S]
}
