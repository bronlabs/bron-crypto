package dkg

import (
	"context"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/lindell17"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/exchange"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

const (
	// ProtocolName identifies Lindell17 DKG round-completion notifications.
	ProtocolName = "ECDSA_LINDELL17_DKG"

	r1CorrelationID = "BRON_CRYPTO_LINDELL17_DKG_R1"
	r2CorrelationID = "BRON_CRYPTO_LINDELL17_DKG_R2"
	r3CorrelationID = "BRON_CRYPTO_LINDELL17_DKG_R3"
	r4CorrelationID = "BRON_CRYPTO_LINDELL17_DKG_R4"
	r5CorrelationID = "BRON_CRYPTO_LINDELL17_DKG_R5"
	r6CorrelationID = "BRON_CRYPTO_LINDELL17_DKG_R6"
	r7CorrelationID = "BRON_CRYPTO_LINDELL17_DKG_R7"
)

func _[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]]() {
	var _ network.Runner[*lindell17.Shard[P, B, S]] = (*runner[P, B, S])(nil)
}

type runner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	participant *Participant[P, B, S]
}

// NewRunner constructs a network runner that drives all eight Lindell17 DKG
// rounds over the complete MSP shareholder set. In production, paillierKeyLen
// must be at least DefaultPaillierKeyLen. prng must be cryptographically secure
// and safe for concurrent use, and nic must name a supported compiler. All
// participants in one session must use the same paillierKeyLen and nic.
func NewRunner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
	ctx *session.Context,
	baseShard *mpc.BaseShard[P, S],
	paillierKeyLen int,
	curve ecdsa.Curve[P, B, S],
	prng io.Reader,
	nic compiler.Name,
) (network.Runner[*lindell17.Shard[P, B, S]], error) {
	participant, err := NewParticipant(ctx, baseShard, paillierKeyLen, curve, prng, nic)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create participant")
	}
	return &runner[P, B, S]{participant: participant}, nil
}

// Run executes the eight protocol rounds and emits a completion notification
// after each local round succeeds.
func (r *runner[P, B, S]) Run(ctx context.Context, rt *network.Router, callback network.NotificationCallback) (*lindell17.Shard[P, B, S], error) {
	quorum := r.participant.ctx.Quorum()

	r1Out, err := r.participant.Round1()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 1")
	}
	network.NotifyRoundCompleted(callback, ProtocolName, 1)
	r2In, err := exchange.BroadcastExchange(ctx, rt, r1CorrelationID, quorum, r1Out)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 1 messages")
	}

	r2Out, err := r.participant.Round2(r2In)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 2")
	}
	network.NotifyRoundCompleted(callback, ProtocolName, 2)
	r3In, err := exchange.BroadcastExchange(ctx, rt, r2CorrelationID, quorum, r2Out)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 2 messages")
	}

	r3Out, err := r.participant.Round3(r3In)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 3")
	}
	network.NotifyRoundCompleted(callback, ProtocolName, 3)
	r4In, err := exchange.BroadcastExchange(ctx, rt, r3CorrelationID, quorum, r3Out)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 3 messages")
	}

	r4Out, err := r.participant.Round4(r4In)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 4")
	}
	network.NotifyRoundCompleted(callback, ProtocolName, 4)
	r5In, err := exchange.UnicastExchange(ctx, rt, r4CorrelationID, r4Out)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 4 messages")
	}

	r5Out, err := r.participant.Round5(r5In)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 5")
	}
	network.NotifyRoundCompleted(callback, ProtocolName, 5)
	r6In, err := exchange.UnicastExchange(ctx, rt, r5CorrelationID, r5Out)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 5 messages")
	}

	r6Out, err := r.participant.Round6(r6In)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 6")
	}
	network.NotifyRoundCompleted(callback, ProtocolName, 6)
	r7In, err := exchange.UnicastExchange(ctx, rt, r6CorrelationID, r6Out)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 6 messages")
	}

	r7Out, err := r.participant.Round7(r7In)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 7")
	}
	network.NotifyRoundCompleted(callback, ProtocolName, 7)
	r8In, err := exchange.UnicastExchange(ctx, rt, r7CorrelationID, r7Out)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot exchange round 7 messages")
	}

	shard, err := r.participant.Round8(r8In)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot run round 8")
	}
	network.NotifyRoundCompleted(callback, ProtocolName, 8)
	return shard, nil
}
