package gennaro

import (
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	pedersenVSS "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/pedersen"
)

// Round1Broadcast carries the dealer’s Pedersen VSS verification vector.
type Round1Broadcast[E GroupElement[E, S], S Scalar[S]] struct {
	PedersenVerificationVector pedersenVSS.VerificationVector[E, S] `cbor:"verificationVector"`
}

// Round2Unicast carries the dealer’s Pedersen share to a specific party.
type Round2Unicast[E GroupElement[E, S], S Scalar[S]] struct {
	Share *pedersenVSS.Share[S] `cbor:"share"`
}

// Round2Broadcast carries the Feldman VSS verification vector and proof of well-formedness.
type Round2Broadcast[E GroupElement[E, S], S Scalar[S]] struct {
	FeldmanVerificationVector feldman.VerificationVector[E, S] `cbor:"verificationVector"`
	Proof                     compiler.NIZKPoKProof            `cbor:"proof"`
}
