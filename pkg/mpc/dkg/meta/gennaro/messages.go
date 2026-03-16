package gennaro

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
	pedersenVSS "github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
)

// Round1Broadcast carries the dealer’s Pedersen VSS verification vector.
type Round1Broadcast[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	PedersenVerificationVector *pedersenVSS.VerificationVector[E, S] `cbor:"verificationVector"`
	Proof                      compiler.NIZKPoKProof                 `cbor:"proof"`
}

// Round1Unicast carries the dealer’s Pedersen share to a specific party.
type Round1Unicast[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	Share *pedersenVSS.Share[S] `cbor:"share"`
}

// Round2Broadcast carries the Feldman VSS verification vector and proof of well-formedness.
type Round2Broadcast[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	FeldmanVerificationVector *feldman.VerificationVector[E, S] `cbor:"verificationVector"`
	Proof                     compiler.NIZKPoKProof             `cbor:"proof"`
}
