package softspoken

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/binaryfields/bf128"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/iknp03"
)

// Receiver is the receiver of the random OT extension: it runs the F_COTe
// receiver on ℓ + sigma random choice bits, answers the consistency check and
// hashes its rows. Its PRGs persist across extensions; the sender must run
// the matching extensions in the same order.
type Receiver struct {
	cote   *iknp03.Receiver[Message]
	ctx    *session.Context
	prng   io.Reader
	failed bool
}

// NewReceiver builds a receiver from the base-OT sender output, exactly κ = 128
// pairs of seeds (see iknp03.NewReceiver), drawing the random choice bits of
// every extension from prng, which must be cryptographically secure.
func NewReceiver(ctx *session.Context, baseOTSenderOutput *ot.SenderOutput[iknp03.Seed], prng io.Reader) (*Receiver, error) {
	if prng == nil {
		return nil, ot.ErrInvalidArgument.WithMessage("prng must not be nil")
	}
	cote, err := iknp03.NewReceiver[Message](ctx, baseOTSenderOutput)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create SoftSpokenOT receiver")
	}
	ctx.Transcript().AppendDomainSeparator(protocolDomainSeparator)
	return &Receiver{cote: cote, ctx: ctx, prng: prng, failed: false}, nil
}

// Extend produces l random OTs, l a positive multiple of sigma with l + sigma
// at most iknp03.MaxExtension: it draws
// ℓ' = l + sigma random choice bits x, runs the F_COTe extension on them,
// answers the Fiat–Shamir challenge with x̄ and t̄¹..t̄^κ and outputs, for
// j ∈ [l], the choice bit x_j and v_{x_j,j} = H(j, t_j) under a salt extracted
// from the transcript once the responses are bound to it. Any failure after the
// F_COTe extension has run leaves the PRGs and the transcript ahead of the
// sender's, so the receiver then refuses every further extension.
func (r *Receiver) Extend(l int) (*ot.ReceiverOutput[Message], *RoundExtendP2P, error) {
	if r.failed {
		return nil, nil, ot.ErrRound.WithMessage("receiver aborted in an earlier extension")
	}
	if l <= 0 || l%sigma != 0 {
		return nil, nil, ot.ErrInvalidArgument.WithMessage("l must be a positive multiple of %d, got %d", sigma, l)
	}
	const maxLength = iknp03.MaxExtension - sigma
	if l > maxLength {
		return nil, nil, ot.ErrInvalidArgument.WithMessage("l must be at most %d, got %d", maxLength, l)
	}

	output, message, err := r.extend(l)
	if err != nil {
		r.failed = true
		return nil, nil, err
	}
	return output, message, nil
}

// extend is the body of Extend after validation; every error it returns
// latches the receiver as failed.
func (r *Receiver) extend(l int) (*ot.ReceiverOutput[Message], *RoundExtendP2P, error) {
	lPrime := l + sigma
	m := l / sigma

	x := make(ot.Choices, lPrime/8)
	if _, err := io.ReadFull(r.prng, x); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot sample choice bits")
	}
	coteOutput, coteMessage, t, err := r.cote.Extend(x)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("COTe extension failed")
	}

	// Consistency check: the challenge is bound to the F_COTe columns, which
	// the IKNP03 receiver has just appended to the transcript.
	chi, err := extractChallenge(r.ctx.Transcript(), m)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("consistency check")
	}
	xBlocks, err := toBlocks(x)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("consistency check")
	}
	xResponse, err := universalHash(chi, xBlocks)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("consistency check")
	}
	tResponse := make([]*bf128.FieldElement, len(t))
	for i, ti := range t {
		tBlocks, err := toBlocks(ti)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("consistency check, column %d", i)
		}
		tResponse[i], err = universalHash(chi, tBlocks)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("consistency check, column %d", i)
		}
	}
	appendResponse(r.ctx.Transcript(), xResponse, tResponse)

	// Randomisation of the first l rows; the last sigma rows only served the check.
	hash, err := extractRandomiser(r.ctx.Transcript())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("randomisation")
	}
	messages := make([]Message, l)
	for j := range l {
		if messages[j], err = hash.hash(uint64(j), coteOutput.Messages()[j]); err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("randomisation, row %d", j)
		}
	}
	output, err := ot.NewReceiverOutput(x[:l/8], messages)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot build receiver output")
	}
	return output, &RoundExtendP2P{COTEMessage: coteMessage, XResponse: xResponse, TResponse: tResponse}, nil
}
