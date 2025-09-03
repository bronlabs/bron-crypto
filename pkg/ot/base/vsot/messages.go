package vsot

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
)

type Round1P2P[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	bigB  P
	proof compiler.NIZKPoKProof
}

func (r1 *Round1P2P[P, B, S]) Validate() error {
	if r1 == nil || r1.bigB.IsOpIdentity() {
		return errs.NewValidation("invalid message")
	}

	return nil
}

type Round2P2P[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	bigA []P
}

func (r2 *Round2P2P[P, B, S]) Validate(xi, l int) error {
	if r2 == nil || len(r2.bigA) != (xi*l) {
		return errs.NewValidation("invalid message")
	}
	for _, a := range r2.bigA {
		if a.IsOpIdentity() {
			return errs.NewValidation("invalid message")
		}
	}

	return nil
}

type Round3P2P struct {
	xi [][]byte
}

func (r3 *Round3P2P) Validate(xi, l, h int) error {
	if r3 == nil || len(r3.xi) != (xi*l) {
		return errs.NewValidation("invalid message")
	}
	for _, x := range r3.xi {
		if len(x) != h {
			return errs.NewValidation("invalid message")
		}
	}

	return nil
}

type Round4P2P struct {
	rhoPrime [][]byte
}

func (r4 *Round4P2P) Validate(xi, l, h int) error {
	if r4 == nil || len(r4.rhoPrime) != (xi*l) {
		return errs.NewValidation("invalid message")
	}
	for _, x := range r4.rhoPrime {
		if len(x) != h {
			return errs.NewValidation("invalid message")
		}
	}

	return nil
}

type Round5P2P struct {
	rho0Digest [][]byte
	rho1Digest [][]byte
}

func (r5 *Round5P2P) Validate(xi, l, h int) error {
	if r5 == nil || len(r5.rho0Digest) != (xi*l) || len(r5.rho1Digest) != (xi*l) {
		return errs.NewValidation("invalid message")
	}
	for i := range xi * l {
		if len(r5.rho0Digest[i]) != h || len(r5.rho1Digest[i]) != h {
			return errs.NewValidation("invalid message")
		}
	}

	return nil
}
