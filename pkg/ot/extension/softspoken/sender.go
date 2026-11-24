package softspoken

import (
	"crypto/subtle"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/binaryfields/bf128"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/iknp03"
)

// Sender is the sender of the random OT extension: it runs the F_COTe sender,
// verifies the receiver's consistency-check responses and hashes both rows of
// every OT. Its PRGs and Δ persist across extensions.
type Sender struct {
	cote      *iknp03.Sender[Message]
	ctx       *session.Context
	copartyID sharing.ID
	failed    bool
}

// NewSender builds a sender from the base-OT receiver output, exactly κ = 128
// chosen seeds and the choice bits that become Δ (see iknp03.NewSender).
func NewSender(ctx *session.Context, baseOTReceiverOutput *ot.ReceiverOutput[iknp03.Seed]) (*Sender, error) {
	cote, err := iknp03.NewSender[Message](ctx, baseOTReceiverOutput)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create SoftSpokenOT sender")
	}
	ctx.Transcript().AppendDomainSeparator(protocolDomainSeparator)
	return &Sender{cote: cote, ctx: ctx, copartyID: copartyOf(ctx), failed: false}, nil
}

// Extend runs one extension on the receiver's message: the F_COTe extension,
// the consistency check q̄ⁱ = t̄ⁱ + Δ_i·x̄ for every i, evaluated for all i
// before deciding so that the abort does not reveal which column failed, and
// the randomisation v_{0,j} = H(j, q_j), v_{1,j} = H(j, q_j ⊕ Δ) for j ∈ [l]
// under a salt extracted from the transcript once the responses are bound to it.
// A failed check is an identifiable abort attributed to the receiver. Any
// failure after the F_COTe extension has run leaves the PRGs and the
// transcript ahead of the receiver's, so the sender then refuses every further
// extension; a validation failure leaves the state untouched and does not.
func (s *Sender) Extend(extend *RoundExtendP2P) (*ot.SenderOutput[Message], error) {
	if s.failed {
		return nil, ot.ErrRound.WithMessage("sender aborted in an earlier extension")
	}
	if extend == nil {
		return nil, ot.ErrInvalidArgument.WithMessage("extend message must not be nil")
	}
	if err := extend.Validate(s, s.copartyID); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid extend message")
	}

	output, err := s.extend(extend)
	if err != nil {
		s.failed = true
		return nil, err
	}
	return output, nil
}

// extend is the body of Extend after validation; every error it returns
// latches the sender as failed.
func (s *Sender) extend(extend *RoundExtendP2P) (*ot.SenderOutput[Message], error) {
	coteOutput, q, err := s.cote.Extend(extend.COTEMessage)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("COTe extension failed")
	}
	lPrime := coteOutput.InferredL()
	l := lPrime - sigma
	m := l / sigma

	// Consistency check.
	chi, err := extractChallenge(s.ctx.Transcript(), m)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("consistency check")
	}
	delta := coteOutput.Delta()
	consistent := 1
	for i, qi := range q {
		qBlocks, err := toBlocks(qi)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("consistency check, column %d", i)
		}
		qResponse, err := universalHash(chi, qBlocks)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("consistency check, column %d", i)
		}
		deltaI := uint64((delta[i/8] >> (i % 8)) & 0b1)
		expected := bf128.NewField().Select(deltaI, extend.TResponse[i], extend.TResponse[i].Add(extend.XResponse))
		consistent &= subtle.ConstantTimeCompare(qResponse.Bytes(), expected.Bytes())
	}
	if consistent != 1 {
		return nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, s.copartyID).WithMessage("SoftSpokenOT consistency check failed")
	}
	appendResponse(s.ctx.Transcript(), extend.XResponse, extend.TResponse)

	// Randomisation of the first l rows.
	hash, err := extractRandomiser(s.ctx.Transcript())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("randomisation")
	}
	messages := make([][2]Message, l)
	for j := range l {
		row := coteOutput.Messages()[j]
		if messages[j][0], err = hash.hash(uint64(j), row); err != nil {
			return nil, errs.Wrap(err).WithMessage("randomisation, row %d", j)
		}
		subtle.XORBytes(row[:], row[:], delta[:])
		if messages[j][1], err = hash.hash(uint64(j), row); err != nil {
			return nil, errs.Wrap(err).WithMessage("randomisation, row %d", j)
		}
	}
	output, err := ot.NewSenderOutput(messages)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot build sender output")
	}
	return output, nil
}
