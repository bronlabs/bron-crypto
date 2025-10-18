package rvole_softspoken

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/softspoken"
)

type Round1P2P = softspoken.Round1P2P

type Round2P2P[S algebra.PrimeFieldElement[S]] struct {
	ATilde [][]S
	Eta    []S
	Mu     []byte
}

func (r2 *Round2P2P[S]) Validate(xi, l, rho int) error {
	if r2 == nil {
		return errs.NewValidation("missing message")
	}
	if len(r2.ATilde) != xi {
		return errs.NewValidation("invalid message")
	}
	for _, a := range r2.ATilde {
		if len(a) != (l + rho) {
			return errs.NewValidation("invalid message")
		}
		for _, aa := range a {
			if aa.IsZero() {
				return errs.NewValidation("invalid message")
			}
		}
	}

	if len(r2.Eta) != rho {
		return errs.NewValidation("invalid message")
	}
	for _, e := range r2.Eta {
		if e.IsZero() {
			return errs.NewValidation("invalid message")
		}
	}

	if len(r2.Mu) != (base.CollisionResistanceBytesCeil) {
		return errs.NewValidation("invalid message")
	}

	return nil
}
