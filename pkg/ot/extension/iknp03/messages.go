package iknp03

import (
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/ot"
)

// RoundExtendP2P carries the receiver's κ masked columns u_i = t_i⁰ ⊕ t_i¹ ⊕ x,
// each l bits packed least-significant bit first. M only ties the message to
// the sender's type.
type RoundExtendP2P[M ot.Message] struct {
	U [][]byte `cbor:"u"`
}

// Validate checks that the message comes from the sender's counterparty and
// holds exactly κ columns of one common, positive length that is a multiple of
// blockBits and at most MaxExtension.
func (m *RoundExtendP2P[M]) Validate(sender *Sender[M], senderID sharing.ID) error {
	if m == nil || sender == nil {
		return ot.ErrValidation.WithMessage("message and sender must not be nil")
	}
	if senderID != sender.copartyID {
		return ot.ErrValidation.WithMessage("message from party %d, expected %d", senderID, sender.copartyID)
	}
	if kappa := ot.MessageBitLen[M](); len(m.U) != kappa {
		return ot.ErrValidation.WithMessage("message holds %d columns, expected %d", len(m.U), kappa)
	}
	l := len(m.U[0]) * 8
	if l == 0 || l%blockBits != 0 {
		return ot.ErrValidation.WithMessage("columns hold %d bits, expected a positive multiple of %d", l, blockBits)
	}
	if l > MaxExtension {
		return ot.ErrValidation.WithMessage("message extends %d OTs, at most %d allowed", l, MaxExtension)
	}
	for i, column := range m.U {
		if len(column)*8 != l {
			return ot.ErrValidation.WithMessage("column %d holds %d bits, expected %d", i, len(column)*8, l)
		}
	}
	return nil
}
