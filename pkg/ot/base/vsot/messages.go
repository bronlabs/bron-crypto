package vsot

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
)

// Round1P2P carries B=bG and its proof of knowledge from the sender.
type Round1P2P[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigB  P                     `cbor:"bigB"`
	Proof compiler.NIZKPoKProof `cbor:"proof"`
}

// Validate performs basic sanity checks on the message.
func (r1 *Round1P2P[P, B, S]) Validate() error {
	if r1 == nil || r1.BigB.IsOpIdentity() {
		return ot.ErrInvalidArgument.WithMessage("invalid message")
	}

	return nil
}

// Round2P2P carries the receiver's A values derived from its choices.
type Round2P2P[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	BigA []P `cbor:"bigA"`
}

// Validate checks sizes and non-identity constraints.
func (r2 *Round2P2P[P, B, S]) Validate(xi, l int) error {
	if r2 == nil || len(r2.BigA) != (xi*l) {
		return ot.ErrInvalidArgument.WithMessage("invalid message")
	}
	for _, a := range r2.BigA {
		if a.IsOpIdentity() {
			return ot.ErrInvalidArgument.WithMessage("invalid message")
		}
	}

	return nil
}

// Round3P2P carries the sender's masked digest differences.
type Round3P2P struct {
	Xi [][]byte `cbor:"xi"`
}

// Validate checks sizes of Xi payloads.
func (r3 *Round3P2P) Validate(xi, l, h int) error {
	if r3 == nil || len(r3.Xi) != (xi*l) {
		return ot.ErrInvalidArgument.WithMessage("invalid message")
	}
	for _, x := range r3.Xi {
		if len(x) != h {
			return ot.ErrInvalidArgument.WithMessage("invalid message")
		}
	}

	return nil
}

// Round4P2P carries receiver-chosen digests.
type Round4P2P struct {
	RhoPrime [][]byte `cbor:"rhoPrime"`
}

// Validate checks sizes of rhoPrime payloads.
func (r4 *Round4P2P) Validate(xi, l, h int) error {
	if r4 == nil || len(r4.RhoPrime) != (xi*l) {
		return ot.ErrInvalidArgument.WithMessage("invalid message")
	}
	for _, x := range r4.RhoPrime {
		if len(x) != h {
			return ot.ErrInvalidArgument.WithMessage("invalid message")
		}
	}

	return nil
}

// Round5P2P carries sender openings of rho digests.
type Round5P2P struct {
	Rho0Digest [][]byte `cbor:"rho0Digest"`
	Rho1Digest [][]byte `cbor:"rho1Digest"`
}

// Validate checks payload sizes for both digest slices.
func (r5 *Round5P2P) Validate(xi, l, h int) error {
	if r5 == nil || len(r5.Rho0Digest) != (xi*l) || len(r5.Rho1Digest) != (xi*l) {
		return ot.ErrInvalidArgument.WithMessage("invalid message")
	}
	for i := range xi * l {
		if len(r5.Rho0Digest[i]) != h || len(r5.Rho1Digest[i]) != h {
			return ot.ErrInvalidArgument.WithMessage("invalid message")
		}
	}

	return nil
}
