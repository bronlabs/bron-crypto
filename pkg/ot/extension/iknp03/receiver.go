package iknp03

import (
	"crypto/subtle"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/ot"
)

// Receiver is the receiver of the semi-honest IKNP03 extension, realising
// F_COTe only (see the package documentation). It plays the base-OT sender, so
// it holds both seeds of every base OT, expanded by one PRG each for the life of
// the Receiver. Each Extend consumes the next l bits of every PRG; the sender
// must run the matching Extend with the same l, in the same order. M is the
// type of the output rows and fixes κ.
type Receiver[M ot.Message] struct {
	ctx       *session.Context
	copartyID sharing.ID
	prgs      [][2]*PRG
}

// NewReceiver builds a receiver from the output of κ base OTs run with the
// roles reversed: baseOTSenderOutput must hold exactly κ = MessageBitLen[M]
// pairs of seeds. The seeds must stay secret.
func NewReceiver[M ot.Message](ctx *session.Context, baseOTSenderOutput *ot.SenderOutput[Seed]) (*Receiver[M], error) {
	copartyID, err := validateSession(ctx)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create IKNP03 receiver")
	}
	if baseOTSenderOutput == nil {
		return nil, ot.ErrInvalidArgument.WithMessage("base OT sender output must not be nil")
	}
	if err := validateBaseCount[M](baseOTSenderOutput.InferredL()); err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create IKNP03 receiver")
	}

	pairs := baseOTSenderOutput.Messages()
	prgs := make([][2]*PRG, len(pairs))
	for i := range pairs {
		for c := range byte(2) {
			prgs[i][c], err = NewPRG(pairs[i][c], i, c)
			if err != nil {
				return nil, errs.Wrap(err).WithMessage("cannot seed PRG %d of base OT %d", c, i)
			}
		}
	}

	ctx.Transcript().AppendDomainSeparator(protocolDomainSeparator)
	return &Receiver[M]{
		ctx:       ctx,
		copartyID: copartyID,
		prgs:      prgs,
	}, nil
}

// Ctx returns the session the receiver runs in.
func (r *Receiver[M]) Ctx() *session.Context {
	return r.ctx
}

// Extend runs one extension for the l choice bits in choices, l a positive
// multiple of 64 and at most MaxExtension: for every base OT i it expands both seeds into t_i⁰, t_i¹ of
// l bits, sends u_i = t_i⁰ ⊕ t_i¹ ⊕ x, and keeps the transposed columns of t⁰
// as its outputs, so that output j equals the sender's q_j ⊕ x_j·Δ. The
// untransposed columns t⁰ are returned as well, for consistency checks built on
// top.
func (r *Receiver[M]) Extend(choices ot.Choices) (*ot.ReceiverOutput[M], *RoundExtendP2P[M], [][]byte, error) {
	l := choices.BitLen()
	if l == 0 || l%blockBits != 0 {
		return nil, nil, nil, ot.ErrInvalidArgument.WithMessage("choices holds %d bits, expected a positive multiple of %d", l, blockBits)
	}
	if l > MaxExtension {
		return nil, nil, nil, ot.ErrInvalidArgument.WithMessage("choices holds %d bits, at most %d allowed per extension", l, MaxExtension)
	}

	k := len(r.prgs)
	t0 := make([][]byte, k)
	u := make([][]byte, k)
	for i := range k {
		t0i := make([]byte, l/8)
		if _, err := r.prgs[i][0].Read(t0i); err != nil {
			return nil, nil, nil, errs.Wrap(err).WithMessage("cannot expand seed 0 of base OT %d", i)
		}
		t1i := make([]byte, l/8)
		if _, err := r.prgs[i][1].Read(t1i); err != nil {
			return nil, nil, nil, errs.Wrap(err).WithMessage("cannot expand seed 1 of base OT %d", i)
		}
		ui := make([]byte, l/8)
		subtle.XORBytes(ui, t0i, t1i)
		subtle.XORBytes(ui, ui, choices)

		t0[i] = t0i
		u[i] = ui
	}

	output, err := ot.NewReceiverOutput(slices.Clone(choices), transposeColumns[M](t0))
	if err != nil {
		return nil, nil, nil, errs.Wrap(err).WithMessage("cannot build receiver output")
	}

	r.ctx.Transcript().AppendBytes(uLabel, u...)
	return output, &RoundExtendP2P[M]{U: u}, t0, nil
}
