package iknp03

import (
	"crypto/subtle"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/ot"
)

// Sender is the sender of the semi-honest IKNP03 extension, realising F_COTe
// only (see the package documentation). It plays the base-OT receiver: its
// base-OT choice bits are the correlation Δ of every extension, and its chosen
// seeds are expanded by one PRG each for the life of the Sender. Δ and the
// seeds must stay secret; Δ is the same for all extensions by design. M is the
// type of the output rows and of Δ, and fixes κ.
type Sender[M ot.Message] struct {
	ctx       *session.Context
	copartyID sharing.ID
	delta     M
	prgs      []*PRG
}

// NewSender builds a sender from the output of κ base OTs run with the roles
// reversed: baseOTReceiverOutput must hold exactly κ = MessageBitLen[M] chosen
// seeds and the κ choice bits that become Δ.
func NewSender[M ot.Message](ctx *session.Context, baseOTReceiverOutput *ot.ReceiverOutput[Seed]) (*Sender[M], error) {
	copartyID, err := validateSession(ctx)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create IKNP03 sender")
	}
	if baseOTReceiverOutput == nil {
		return nil, ot.ErrInvalidArgument.WithMessage("base OT receiver output must not be nil")
	}
	if err := validateBaseCount[M](baseOTReceiverOutput.InferredL()); err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create IKNP03 sender")
	}

	choices := baseOTReceiverOutput.Choices()
	seeds := baseOTReceiverOutput.Messages()
	prgs := make([]*PRG, len(seeds))
	for i := range seeds {
		prgs[i], err = NewPRG(seeds[i], i, (choices[i/8]>>(i%8))&0b1)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot seed PRG of base OT %d", i)
		}
	}
	var delta M
	copy(ot.MessageAsSlice(&delta), choices)

	ctx.Transcript().AppendDomainSeparator(protocolDomainSeparator)
	return &Sender[M]{
		ctx:       ctx,
		copartyID: copartyID,
		delta:     delta,
		prgs:      prgs,
	}, nil
}

// Extend runs one extension on the receiver's message: for every base OT i it
// expands its chosen seed into t_i of l bits and forms q_i = Δ_i·u_i ⊕ t_i,
// which equals t_i⁰ ⊕ Δ_i·x; the transposed columns q_j = t_j ⊕ x_j·Δ, with Δ,
// are the correlated output. The untransposed columns q are returned as well,
// for consistency checks built on top.
func (s *Sender[M]) Extend(extend *RoundExtendP2P[M]) (*ot.SenderCorrelatedOutput[M], [][]byte, error) {
	if extend == nil {
		return nil, nil, ot.ErrInvalidArgument.WithMessage("extend message must not be nil")
	}
	if err := extend.Validate(s, s.copartyID); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid extend message")
	}

	k := len(s.prgs)
	l := len(extend.U[0]) * 8
	q := make([][]byte, k)
	for i := range k {
		ti := make([]byte, l/8)
		if _, err := s.prgs[i].Read(ti); err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot expand seed of base OT %d", i)
		}
		mask := -((s.delta[i/8] >> (i % 8)) & 0b1)
		qi := sliceutils.Map(extend.U[i], func(b byte) byte { return b & mask })
		subtle.XORBytes(qi, qi, ti)
		q[i] = qi
	}

	output, err := ot.NewSenderCorrelatedOutput(transposeColumns[M](q), s.delta)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot build sender output")
	}

	s.ctx.Transcript().AppendBytes(uLabel, extend.U...)
	return output, q, nil
}
