package rvole

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

// MultiplyMessage is Alice's message: the masked rows ã, the check value η and
// the check digest μ. The subpackages wrap it in their round messages.
type MultiplyMessage[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	ATilde [][]S  `cbor:"aTilde"`
	Eta    []S    `cbor:"eta"`
	Mu     []byte `cbor:"mu"`
}

// ValidateMultiply checks that the message comes from Bob's counterparty and
// that it carries ξ rows of ℓ + ρ field elements, ρ values η and a full-length
// μ.
func (bob *Bob[M, P, B, S]) ValidateMultiply(m *MultiplyMessage[P, B, S], from sharing.ID) error {
	if m == nil {
		return ErrValidation.WithMessage("message must not be nil")
	}
	if from != bob.copartyID {
		return ErrValidation.WithMessage("message from party %d, expected %d", from, bob.copartyID)
	}
	xi, width := bob.suite.xi, bob.suite.l+rho
	if len(m.ATilde) != xi {
		return ErrValidation.WithMessage("message holds %d rows, expected %d", len(m.ATilde), xi)
	}
	for j, row := range m.ATilde {
		if len(row) != width {
			return ErrValidation.WithMessage("row %d holds %d elements, expected %d", j, len(row), width)
		}
		for i, e := range row {
			if err := bob.validateElement(e); err != nil {
				return errs.Wrap(err).WithMessage("row %d, element %d", j, i)
			}
		}
	}
	if len(m.Eta) != rho {
		return ErrValidation.WithMessage("message holds %d eta values, expected %d", len(m.Eta), rho)
	}
	for k, e := range m.Eta {
		if err := bob.validateElement(e); err != nil {
			return errs.Wrap(err).WithMessage("eta %d", k)
		}
	}
	if len(m.Mu) != base.CollisionResistanceBytesCeil {
		return ErrValidation.WithMessage("mu holds %d bits, expected %d", len(m.Mu)*8, base.CollisionResistance)
	}
	return nil
}

func (p *participant[P, B, S]) validateElement(e S) error {
	if utils.IsNil(e) {
		return ErrValidation.WithMessage("element must not be nil")
	}
	if e.Structure().Name() != p.suite.field.Name() {
		return ErrValidation.WithMessage("element of %s, expected %s", e.Structure().Name(), p.suite.field.Name())
	}
	return nil
}
