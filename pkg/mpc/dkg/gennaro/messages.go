package gennaro

import (
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	pedersenVSS "github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
)

// Round1Broadcast carries the dealer’s Pedersen VSS verification vector.
type Round1Broadcast[E GroupElement[E, S], S Scalar[S]] struct {
	PedersenVerificationVector pedersenVSS.VerificationVector[E, S] `cbor:"verificationVector"`
	Proof                      compiler.NIZKPoKProof                `cbor:"proof"`
}

func (*Round1Broadcast[E, S]) Validate(*Participant[E, S]) error { return nil }

// Round1Unicast carries the dealer’s Pedersen share to a specific party.
type Round1Unicast[E GroupElement[E, S], S Scalar[S]] struct {
	Share *pedersenVSS.Share[S] `cbor:"share"`
}

func (*Round1Unicast[E, S]) Validate(*Participant[E, S]) error { return nil }

// Round2Broadcast carries the Feldman VSS verification vector and proof of well-formedness.
type Round2Broadcast[E GroupElement[E, S], S Scalar[S]] struct {
	FeldmanVerificationVector feldman.VerificationVector[E, S] `cbor:"verificationVector"`
	Proof                     compiler.NIZKPoKProof            `cbor:"proof"`
}

func (*Round2Broadcast[E, S]) Validate(*Participant[E, S]) error { return nil }
