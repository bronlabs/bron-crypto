package ecbbot

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/ot"
)

// Round1P2P carries the sender's initial key-agreement message mS.
type Round1P2P[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	Ms G `cbor:"ms"` // mS ∈ Point
}

func (m *Round1P2P[G, S]) Validate(*Receiver[G, S], sharing.ID) error {
	if m == nil || utils.IsNil(m.Ms) {
		return ot.ErrValidation.WithMessage("invalid message")
	}
	if m.Ms.IsOpIdentity() || !m.Ms.IsTorsionFree() {
		return ot.ErrValidation.WithMessage("invalid message")
	}

	return nil
}

// Round2P2P carries the POPF programs derived by the receiver.
type Round2P2P[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	Phi [][2][]G `cbor:"phi"` // Φ ∈ [ξ][2][L]Point
}

func (m *Round2P2P[G, S]) Validate(p *Sender[G, S], _ sharing.ID) error {
	if m == nil {
		return ot.ErrValidation.WithMessage("invalid message")
	}
	if len(m.Phi) != p.suite.Xi() {
		return ot.ErrValidation.WithMessage("invalid message")
	}
	for _, phi := range m.Phi {
		if len(phi[0]) != p.suite.L() || len(phi[1]) != p.suite.L() {
			return ot.ErrValidation.WithMessage("invalid message")
		}
	}

	return nil
}
