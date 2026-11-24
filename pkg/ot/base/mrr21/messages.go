package mrr21

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/ot"
)

// SenderRound1P2P carries the sender's key-agreement message m_S = a·G. Its
// content does not depend on the message type M; the parameter is there so
// that Validate names the receiver's type and the message implements
// network.Message for it.
type SenderRound1P2P[M ot.Message, G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	Ms G `cbor:"ms"`
}

// Validate checks that the message comes from the receiver's counterparty and
// that m_S is a present, non-identity group element; membership of the
// prime-order group is enforced by the element's decoder. An identity m_S would
// make every key derivable by anyone.
func (m *SenderRound1P2P[M, G, S]) Validate(receiver *Receiver[M, G, S], senderID sharing.ID) error {
	if m == nil || receiver == nil {
		return ot.ErrValidation.WithMessage("message and receiver must not be nil")
	}
	if senderID != receiver.copartyID {
		return ot.ErrValidation.WithMessage("message from party %d, expected %d", senderID, receiver.copartyID)
	}
	if utils.IsNil(m.Ms) {
		return ot.ErrValidation.WithMessage("m_S must not be nil")
	}
	if m.Ms.IsOpIdentity() {
		return ot.ErrValidation.WithMessage("m_S must not be the identity")
	}
	return nil
}

// ReceiverRound1P2P carries the receiver's L programmed POPFs, one per OT. As
// for SenderRound1P2P, M only ties the message to the sender's type.
type ReceiverRound1P2P[M ot.Message, G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	Phis []*MasnyRindalPopf[G, S] `cbor:"phis"`
}

// Validate checks that the message comes from the sender's counterparty, that
// it holds exactly L POPFs, and that each is present and well formed (both
// elements non-nil and non-identity).
func (m *ReceiverRound1P2P[M, G, S]) Validate(sender *Sender[M, G, S], senderID sharing.ID) error {
	if m == nil || sender == nil {
		return ot.ErrValidation.WithMessage("message and sender must not be nil")
	}
	if senderID != sender.copartyID {
		return ot.ErrValidation.WithMessage("message from party %d, expected %d", senderID, sender.copartyID)
	}
	if len(m.Phis) != sender.l {
		return ot.ErrValidation.WithMessage("message holds %d POPFs, expected %d", len(m.Phis), sender.l)
	}
	for i, phi := range m.Phis {
		if phi == nil {
			return ot.ErrValidation.WithMessage("POPF %d must not be nil", i)
		}
		if err := phi.validate(); err != nil {
			return errs.Join(ot.ErrValidation, errs.Wrap(err)).WithMessage("POPF %d is invalid", i)
		}
	}
	return nil
}
